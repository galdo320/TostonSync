// TostónSync — save watcher and upload pipeline.
//
// Architecture:
//   - watch_thread: opens kqueue, registers EVFILT_VNODE on every
//     savedata_prospero/ directory found under /user/home/. When
//     NOTE_WRITE fires it updates that title's "dirty" + "last_dirty"
//     timestamps and signals the trigger thread.
//
//   - trigger_thread: ticks every second. Walks the title table and,
//     for each dirty title, evaluates the configured triggers. When a
//     trigger fires it enqueues an upload job. Manual sync_all() and
//     the on_shutdown path enqueue everything dirty in one pass.
//
//   - worker_thread (×N): pulls jobs off the queue, zips the save
//     folder, checks CRC32 against cache, calls gdrive_upload, and
//     hands off to retention_enforce_title.
//
//   - process_watch_thread: cheap PID poll (1 Hz) over the running
//     title's PID so we can detect "game closed" without depending on
//     any Sony-private notification.

#include "watcher.h"
#include "backup_control.h"
#include "rollback_archive.h"
#include "config.h"
#include "backup_names.h"
#include "log.h"
#include "fs.h"
#include "version.h"
#include "zip.h"
#include "gdrive.h"
#include "usb.h"
#include "history.h"
#include "titlename.h"
#include "retention.h"
#include "pfs_keys.h"
#include "pfs_resign.h"
#include "sdimg_restore.h"
#include "import_session.h"
#include "raw_selected_commit.h"
#include "json.h"
#include "sfo.h"
#include "sha256.h"
#include "migration_inspect.h"
#include "dest_dedup.h"
#include "backup_lock.h"
#include "backup_job_state.h"
#include "backup_failure.h"
#include "backup_retry.h"
#include "live_cadence.h"
#include "at_io.h"
#include "savemount.h"

#include <dirent.h>
#include <errno.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>   // u_short / u_int — must precede <sys/event.h>
#include <sys/event.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <fcntl.h>
#include <time.h>
#include <unistd.h>

#define MAX_TITLES 128

typedef struct {
    char     title_id[16];
    char     user_uid[16];    // owning PS5 user's directory name under
                              // /user/home/. Two profiles playing the
                              // same game get two title_t entries.
    char     path[256];       // full path to savedata_prospero/<title>
    int      watch_fd;        // open(O_RDONLY) for kqueue
    bool     dirty;
    int64_t  last_dirty_unix;
    int64_t  last_change_mtime; // newest sdimg mtime last seen; a poll detects
                               // in-game saves that kqueue NOTE_WRITE misses.
    int64_t  last_upload_unix;
    int64_t  last_deferred_dirty_unix;
    uint32_t last_crc32;
    uint64_t last_zip_size;   // size of the last uploaded archive
    int      pid_if_running;  // 0 when nothing running for this title
    bool     was_running;
    bool     upload_in_flight; // set when enqueued, cleared when worker
                               // finishes — keeps a once-per-second
                               // trigger from refiring while the upload
                               // is still on the queue.
    jobs_ref_t observation_job; // correlation only; protected by s_titles_lock
    bool     service_note_emitted;
    bool     backup_retry_journal; // also suppresses obsolete GameClose recovery
    bool     backup_retry_checked;
    int64_t  backup_retry_at;
    int64_t  backup_retry_dirty_unix;
    unsigned backup_retry_failures;
    unsigned backup_retry_mask;
    unsigned backup_retry_planned_mask;
    bool     backup_usb_no_replay;
    char     backup_retry_trigger[16];
    unsigned coalesced_count;
    char     game_name[64];   // human title, resolved while the game runs
    session_saves_state_t session;
} title_t;

typedef struct job {
    unsigned long job_id;
    int64_t     queued_unix;
    unsigned    coalesced_count;
    char        title_id[16];
    char        user_uid[16];  // owning PS5 user for this job; "" means
                               // "first user that owns the title" for
                               // legacy callers (single-user restores).
    bool        is_restore;
    bool        force_backup;  // explicit UI/manual request bypasses dedup
    bool        retrying;
    int64_t     dirty_unix;    // last_dirty snapshot when upload was queued.
    char        trigger[16];   // why this backup runs: Live/GameClose/Shutdown/
                               // Idle/Interval/Manual — shown in the filename.
    char        source[24];    // exact queue caller for duplicate diagnostics
    char        destination[16]; // optional manual override; empty = Settings
    // Holds a Drive file_id, OR an absolute path (starting with '/')
    // when restoring straight from a USB drive. Sized for a full path.
    char        restore_ref[USB_PATH_MAX];
    char        restore_user[64]; // legacy source hint or the explicit destination UID
    bool        restore_uid_explicit; // never resolve this UID through aliases
    char        restore_import_id[48]; // only the admission that claimed this Import
    restore_scope_t restore_scope; // immutable approved selection; zero for legacy
    struct job* next;
} job_t;

static const config_t* s_cfg = NULL;
static title_t         s_titles[MAX_TITLES];
static size_t          s_title_count = 0;
static pthread_mutex_t s_titles_lock = PTHREAD_MUTEX_INITIALIZER;
// Watcher-owned path copies, observed under the existing title lock. They do
// not grant new config/save authority to the lifecycle side channel.
static char            s_lifecycle_state_dir[CFG_MAX_PATH];
static char            s_lifecycle_staging_dir[CFG_MAX_PATH];

static int             s_kq = -1;
// These three are read by other threads (httpd status, shutdown drain)
// without taking s_q_lock, so they are atomics rather than plain ints —
// cheap, lock-free, and free of the torn-read/visibility hazards the
// previous `volatile int`/plain-int versions had.
static atomic_int      s_running = 0;
static pthread_t       s_watch_th, s_trigger_th, s_proc_th;
static bool            s_watch_started = false;
static bool            s_trigger_started = false;
static bool            s_proc_started = false;
static pthread_t       s_workers[8];
static int             s_worker_count = 0;

static job_t*          s_q_head = NULL;
static job_t*          s_q_tail = NULL;
static atomic_int      s_q_depth = 0;
static atomic_int      s_jobs_active = 0;
static atomic_ulong    s_stage_seq = 1;
static atomic_ulong    s_job_seq = 1;
static char            s_run_id[48] = {0};
static atomic_uint     s_watcher_id = 0;
static pthread_mutex_t s_q_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t  s_q_cond = PTHREAD_COND_INITIALIZER;

static _Atomic int64_t s_last_sync_unix = 0;

typedef struct {
    char status[16];
    char destination[64];
    char fingerprint[65];
    char detail[768];
    bool notification_sent;
    unsigned retry_mask;
    unsigned unconfirmed_mask;
    bool usb_no_replay;
    bool copied;
    uint32_t crc;
    uint64_t zip_size;
} upload_result_t;

static int64_t now_unix(void) { return (int64_t)time(NULL); }
static int64_t monotonic_ms(void) {
    struct timespec ts;
    return clock_gettime(CLOCK_MONOTONIC, &ts) == 0
        ? (int64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000
        : now_unix() * 1000;
}
static bool safe_path_component(const char* s);
static void recover_backup_retries(void);
static bool manual_only_cfg(const config_t* cfg);

static bool lifecycle_admit(char* err, size_t err_sz) {
    if (lifecycle_operation_begin()) return true;
    if (err && err_sz) snprintf(err, err_sz,
        "Lifecycle stop is reserved; new work is not admitted");
    return false;
}

static bool lifecycle_terminal(void) {
    return lifecycle_state() >= LIFE_STOP_ACCEPTED;
}

static void upload_result_set(upload_result_t* result, const char* status,
                              const char* detail) {
    if (!result) return;
    snprintf(result->status, sizeof(result->status), "%s", status);
    snprintf(result->detail, sizeof(result->detail), "%s", detail);
}

static void backup_job_path(const char* user_uid, const char* title_id,
                            char* out, size_t out_sz) {
    snprintf(out, out_sz, "%s/jobs/backup.%s.%s.state",
             s_cfg->paths.state_dir,
             user_uid && user_uid[0] ? user_uid : "default", title_id);
}

static void backup_retry_path(const char* user_uid, const char* title_id,
                              char* out, size_t out_sz) {
    snprintf(out, out_sz, "%s/jobs/retry.%s.%s", s_cfg->paths.state_dir,
             user_uid, title_id);
}

static void backup_retry_init(backup_retry_t* retry, const char* user_uid,
                               const char* title_id, const char* reason) {
    memset(retry, 0, sizeof(*retry));
    retry->active = true;
    retry->planned_mask = retry->pending_mask = 3U;
    snprintf(retry->user_uid, sizeof(retry->user_uid), "%s", user_uid);
    snprintf(retry->title_id, sizeof(retry->title_id), "%s", title_id);
    snprintf(retry->reason, sizeof(retry->reason), "%s", reason);
}

static bool backup_retry_load(const char* user_uid, const char* title_id,
                               backup_retry_t* retry) {
    char path[420];
    backup_retry_path(user_uid, title_id, path, sizeof(path));
    bool ok = backup_retry_read(path, retry) &&
           strcmp(retry->user_uid, user_uid) == 0 &&
           strcmp(retry->title_id, title_id) == 0;
    if (ok && retry->retired_ftp)
        log_info("backup-queue: discarded retired FTP retry bit; USB/Drive preserved");
    return ok;
}

static bool backup_retry_save(const backup_retry_t* retry) {
    char path[420];
    backup_retry_path(retry->user_uid, retry->title_id, path, sizeof(path));
    if (backup_retry_write(path, retry)) return true;
    log_warn("backup-queue: could not persist retry state key=%s/%s; "
             "confirmed destination receipts retained", retry->user_uid, retry->title_id);
    return false;
}

static const char* backup_trigger_name(const char* trigger) {
    if (!trigger || !trigger[0]) return "Auto";
    if (strcmp(trigger, "Interval") == 0) return "Scheduled";
    static const char* allowed[] = {
        "Manual", "Auto", "GameClose", "Live", "Idle", "Startup",
        "Shutdown", "BeforeRestore", "Scheduled", "Imported", "Converted"
    };
    for (size_t i = 0; i < sizeof(allowed) / sizeof(allowed[0]); i++)
        if (strcmp(trigger, allowed[i]) == 0) return allowed[i];
    return "Auto";
}

static void backup_filename_component(const char* input,
                                      char* out, size_t out_sz) {
    size_t n = 0;
    bool underscore = false;
    for (const unsigned char* p = (const unsigned char*)input;
         p && *p && n + 1 < out_sz; p++) {
        if ((*p >= 'A' && *p <= 'Z') || (*p >= 'a' && *p <= 'z') ||
            (*p >= '0' && *p <= '9') || *p == '-') {
            out[n++] = (char)*p;
            underscore = false;
        } else if (!underscore && n) {
            out[n++] = '_';
            underscore = true;
        }
    }
    while (n && out[n - 1] == '_') n--;
    out[n] = '\0';
}

// Copy `in` to `out`, dropping characters that would break a one-line JSON
// string (quote, backslash, control chars). Keeps the manifest always-valid.
static void json_clean(const char* in, char* out, size_t out_sz) {
    size_t j = 0;
    for (size_t i = 0; in && in[i] && j + 1 < out_sz; i++) {
        unsigned char c = (unsigned char)in[i];
        if (c == '"' || c == '\\' || c < 0x20) continue;
        out[j++] = (char)c;
    }
    out[j] = '\0';
}

static void json_write_string(FILE* f, const char* value) {
    fputc('"', f);
    for (const unsigned char* p = (const unsigned char*)(value ? value : "");
         *p; p++) {
        if (*p == '"' || *p == '\\') fputc('\\', f);
        if (*p >= 0x20) fputc(*p, f);
    }
    fputc('"', f);
}

static bool finish_json_file(FILE* f, const char* tmp, const char* final) {
    bool ok = f && fflush(f) == 0 && fsync(fileno(f)) == 0;
    if (f && fclose(f) != 0) ok = false;
    if (ok) ok = rename(tmp, final) == 0;
    if (!ok) unlink(tmp);
    return ok;
}

static bool write_migration_manifest(const char* title_root,
                                     const char* title_id,
                                     const char* title_name,
                                     const char* user_uid,
                                     time_t created,
                                     size_t expected_slots,
                                     const migration_report_t* source) {
    char path[420], tmp[440];
    snprintf(path, sizeof(path), "%s/manifest.json", title_root);
    snprintf(tmp, sizeof(tmp), "%s.tmp", path);
    FILE* f = fopen(tmp, "wb");
    if (!f) return false;

    char utc[32];
    struct tm gm;
    gmtime_r(&created, &gm);
    strftime(utc, sizeof(utc), "%Y-%m-%dT%H:%M:%SZ", &gm);
    fputs("{\"format\":\"tostonsync.migration_decrypted\","
          "\"format_version\":1,\"app\":\"TostónSync\","
          "\"app_version\":", f);
    json_write_string(f, TOSTONSYNC_VERSION);
    fputs(",\"platform\":\"ps5\",\"title_id\":", f);
    json_write_string(f, title_id);
    fputs(",\"title_name\":", f);
    json_write_string(f, title_name && title_name[0] ? title_name : title_id);
    fputs(",\"backup_type\":\"PORTABLE\",\"trigger\":\"Manual\"", f);
    fputs(",\"created_at_utc\":", f);
    json_write_string(f, utc);
    fprintf(f, ",\"created_at_epoch\":%lld", (long long)created);
    fputs(",\"source_user_uid\":", f);
    json_write_string(f, user_uid);
    fputs(",\"source_console_name\":", f);
    json_write_string(f, source ? source->source_console_name :
                        s_cfg && s_cfg->console.name[0]
                             ? s_cfg->console.name : "This PS5");
    fputs(",\"source_console_type\":", f);
    json_write_string(f, source ? source->source_console_type :
                        s_cfg && s_cfg->console.type[0]
                             ? s_cfg->console.type : "PS5");
    if (source) {
        fputs(",\"recovered_from_raw\":true,\"source_created_at_utc\":", f);
        json_write_string(f, source->created_at_utc);
        fprintf(f, ",\"recovered_active_images\":%zu,"
                   "\"service_images_retained_in_original\":%zu",
                expected_slots, source->service_images);
    }
    fputs(",\"save_dirs\":[", f);

    DIR* d = opendir(title_root);
    size_t slots = 0;
    bool ok = d != NULL;
    while (ok) {
        errno = 0;
        struct dirent* e = readdir(d);
        if (!e) { if (errno) ok = false; break; }
        if (strncmp(e->d_name, "sdimg_", 6) != 0 ||
            !safe_path_component(e->d_name)) continue;
        char dir[640], sfo_path[720];
        int dn = snprintf(dir, sizeof(dir), "%s/%s", title_root, e->d_name);
        int sn = snprintf(sfo_path, sizeof(sfo_path), "%s/sce_sys/param.sfo", dir);
        struct stat st;
        if (dn < 0 || (size_t)dn >= sizeof(dir) ||
            sn < 0 || (size_t)sn >= sizeof(sfo_path) ||
            lstat(dir, &st) != 0 || !S_ISDIR(st.st_mode)) {
            ok = false;
            break;
        }
        sfo_info_t sfo;
        size_t payloads = 0;
        if (sfo_parse(sfo_path, &sfo) != 0 ||
            strcmp(sfo.title_id, title_id) != 0 || !sfo.dir_name[0] ||
            !migration_count_plain_payload(dir, &payloads) || !payloads) {
            ok = false;
            break;
        }
        if (slots++) fputc(',', f);
        fputs("{\"save_dir\":", f); json_write_string(f, sfo.dir_name);
        fputs(",\"source_image\":", f); json_write_string(f, e->d_name);
        fputs(",\"subtitle\":", f); json_write_string(f, sfo.sub_title);
        fputs(",\"format\":", f); json_write_string(f, sfo.format);
        fputs(",\"payload_files\":[", f);
        DIR* pd = opendir(dir);
        if (!pd) ok = false;
        bool first = true;
        while (ok) {
            errno = 0;
            struct dirent* pe = readdir(pd);
            if (!pe) { if (errno) ok = false; break; }
            if (!strcmp(pe->d_name, ".") || !strcmp(pe->d_name, "..") ||
                !strcmp(pe->d_name, "sce_sys")) continue;
            char pp[760];
            int pn = snprintf(pp, sizeof(pp), "%s/%s", dir, pe->d_name);
            if (!safe_path_component(pe->d_name) ||
                pn < 0 || (size_t)pn >= sizeof(pp) || lstat(pp, &st) != 0 ||
                (!S_ISREG(st.st_mode) && !S_ISDIR(st.st_mode))) {
                ok = false;
                break;
            }
            if (!S_ISREG(st.st_mode) || st.st_size <= 0) continue;
            if (!first) fputc(',', f);
            json_write_string(f, pe->d_name);
            first = false;
        }
        if (pd && closedir(pd) != 0) ok = false;
        // Keep the v1 direct-file list for older readers; the recursive count
        // also represents games whose payload lives only in nested folders.
        fprintf(f, "],\"payload_file_count\":%zu}", payloads);
    }
    if (d && closedir(d) != 0) ok = false;
    fputs("]}\n", f);
    if (slots != expected_slots) ok = false;
    if (!ok) {
        fclose(f);
        unlink(tmp);
        return false;
    }
    return finish_json_file(f, tmp, path);
}

static bool write_checksum_entries(FILE* f, const char* root,
                                   const char* metadata_root,
                                   const char* relative, int depth,
                                   size_t* count, bool* first) {
    if (depth < 0 || *count >= 16384) return false;
    char dir[768];
    snprintf(dir, sizeof(dir), "%s%s%s", root,
             relative && relative[0] ? "/" : "", relative ? relative : "");
    DIR* d = opendir(dir);
    if (!d) return false;
    bool ok = true;
    struct dirent* e;
    while (ok && (e = readdir(d)) != NULL) {
        if (!safe_path_component(e->d_name)) continue;
        char rel[768], path[1024];
        snprintf(rel, sizeof(rel), "%s%s%s", relative && relative[0] ? relative : "",
                 relative && relative[0] ? "/" : "", e->d_name);
        snprintf(path, sizeof(path), "%s/%s", root, rel);
        struct stat st;
        if (lstat(path, &st) != 0) { ok = false; break; }
        if (S_ISDIR(st.st_mode)) {
            ok = write_checksum_entries(f, root, metadata_root, rel, depth - 1,
                                        count, first);
        } else if (S_ISREG(st.st_mode)) {
            if ((strcmp(dir, metadata_root) == 0 &&
                 (strcmp(e->d_name, "manifest.json") == 0 ||
                  strcmp(e->d_name, "checksums.json") == 0)) ||
                (strcmp(dir, root) == 0 &&
                 strcmp(e->d_name, "checksums.tmp") == 0)) continue;
            char hash[65];
            if (!sha256_file_hex(path, hash)) { ok = false; break; }
            if (!*first) fputc(',', f);
            json_write_string(f, rel);
            fputc(':', f);
            json_write_string(f, hash);
            *first = false;
            (*count)++;
        }
    }
    closedir(d);
    return ok;
}

static bool write_migration_checksums(const char* stage,
                                      const char* title_root) {
    char path[420], tmp[440];
    snprintf(path, sizeof(path), "%s/checksums.json", title_root);
    snprintf(tmp, sizeof(tmp), "%s/checksums.tmp", stage);
    FILE* f = fopen(tmp, "wb");
    if (!f) return false;
    fputc('{', f);
    size_t count = 0;
    bool first = true;
    bool ok = write_checksum_entries(f, stage, title_root, "", 8, &count, &first);
    fputs("}\n", f);
    if (!ok || !count) {
        fclose(f);
        unlink(tmp);
        return false;
    }
    return finish_json_file(f, tmp, path);
}

static unsigned long next_stage_seq(void) {
    return atomic_fetch_add(&s_stage_seq, 1);
}

// Last backup progress/outcome. Queue depth alone used to drop to zero as
// soon as a worker picked up the job, making a long decrypt/compress pass look
// idle in the UI even though the backup was still running.
// state: -1 none, 2 running, 1 ok, 3 skipped, 0 failed,
//        4 interrupted, 5 pending final.
static pthread_mutex_t s_backup_lock = PTHREAD_MUTEX_INITIALIZER;
static char    s_backup_title[64] = {0};
static char    s_backup_msg[768]  = {0};
static int     s_backup_state     = -1;
static int64_t s_backup_unix      = 0;

static void set_last_backup_at(const char* title, int state, const char* msg,
                               int64_t when) {
    pthread_mutex_lock(&s_backup_lock);
    snprintf(s_backup_title, sizeof(s_backup_title), "%s", title ? title : "");
    snprintf(s_backup_msg, sizeof(s_backup_msg), "%s", msg ? msg : "");
    s_backup_state = state;
    s_backup_unix = when;
    pthread_mutex_unlock(&s_backup_lock);
}

static void set_last_backup(const char* title, int state, const char* msg) {
    set_last_backup_at(title, state, msg, now_unix());
}

static bool service_note_once(const char* user_uid, const char* title_id) {
    bool first = false;
    pthread_mutex_lock(&s_titles_lock);
    for (size_t i = 0; i < s_title_count; i++)
        if (strcmp(s_titles[i].title_id, title_id) == 0 &&
            strcmp(s_titles[i].user_uid, user_uid ? user_uid : "") == 0) {
            first = !s_titles[i].service_note_emitted;
            s_titles[i].service_note_emitted = true;
            break;
        }
    pthread_mutex_unlock(&s_titles_lock);
    return first;
}

void watcher_last_backup(char* title, size_t tn, int* state,
                         char* msg, size_t mn, int64_t* when) {
    pthread_mutex_lock(&s_backup_lock);
    if (title) snprintf(title, tn, "%s", s_backup_title);
    if (msg)   snprintf(msg, mn, "%s", s_backup_msg);
    if (state) *state = s_backup_state;
    if (when)  *when = s_backup_unix;
    pthread_mutex_unlock(&s_backup_lock);
}

// Record a backup that happened OUTSIDE the daemon (the browser's Google Drive
// upload), so the Home "Last backup" tile and last-sync time reflect it just
// like a USB/FTP backup. `label` is the friendly game name (or title id).
void watcher_note_external_backup(const char* label, const char* dests) {
    if (!lifecycle_operation_begin()) return;
    char msg[96];
    snprintf(msg, sizeof(msg), "Saved to %s",
             (dests && dests[0]) ? dests : "Drive");
    set_last_backup(label ? label : "", 1, msg);
    s_last_sync_unix = now_unix();
    lifecycle_operation_end();
}

// Last restore outcome, surfaced to the UI so the user gets real feedback
// (the "queued" toast only confirms enqueue; the actual work runs async here).
// state: -1 none, 2 running, 1 ok, 0 failed.
static pthread_mutex_t s_restore_lock = PTHREAD_MUTEX_INITIALIZER;
static char    s_restore_title[16] = {0};
static char    s_restore_msg[96]   = {0};
static int     s_restore_state     = -1;
static int64_t s_restore_unix      = 0;
static bool s_restore_selective;
static size_t s_restore_available, s_restore_selected, s_restore_written;
static portable_transaction_report_t s_portable_transaction;

void watcher_last_portable_transaction(portable_transaction_report_t* report) {
    pthread_mutex_lock(&s_restore_lock);
    if (report) *report = s_portable_transaction;
    pthread_mutex_unlock(&s_restore_lock);
}

static void set_restore_scope_result(const restore_scope_t* scope, size_t written) {
    pthread_mutex_lock(&s_restore_lock);
    s_restore_selective = scope && scope->selection.specified;
    s_restore_available = scope ? scope->available_slots : 0;
    s_restore_selected = scope ? scope->selection.count : 0;
    s_restore_written = written;
    pthread_mutex_unlock(&s_restore_lock);
}

void watcher_last_restore_scope(bool* selective, size_t* available,
                                 size_t* selected, size_t* written) {
    pthread_mutex_lock(&s_restore_lock);
    if (selective) *selective = s_restore_selective;
    if (available) *available = s_restore_available;
    if (selected) *selected = s_restore_selected;
    if (written) *written = s_restore_written;
    pthread_mutex_unlock(&s_restore_lock);
}

static void set_last_restore(const char* title, int state, const char* msg) {
    pthread_mutex_lock(&s_restore_lock);
    snprintf(s_restore_title, sizeof(s_restore_title), "%s", title ? title : "");
    snprintf(s_restore_msg, sizeof(s_restore_msg), "%s", msg ? msg : "");
    s_restore_state = state;
    s_restore_unix = now_unix();
    pthread_mutex_unlock(&s_restore_lock);
}

void watcher_last_restore(char* title, size_t tn, int* state,
                          char* msg, size_t mn, int64_t* when) {
    pthread_mutex_lock(&s_restore_lock);
    if (title) snprintf(title, tn, "%s", s_restore_title);
    if (msg)   snprintf(msg, mn, "%s", s_restore_msg);
    if (state) *state = s_restore_state;
    if (when)  *when = s_restore_unix;
    pthread_mutex_unlock(&s_restore_lock);
}

// --- Backup suppression during/after restore -------------------------------
// A restore writes directly into the live save directory. Those writes trip
// the kqueue NOTE_WRITE watcher, which used to treat them as a normal in-game
// change and immediately fire a backup — racing the restore, producing the
// "zip failed" we saw and risking a half-written snapshot clobbering history.
//
// We guard with a simple per-title time window: do_restore_job opens it at the
// start and refreshes it on completion. do_upload_job refuses to run while the
// window is open. A pure time window (no "active" flag) is robust against the
// many early-return paths in do_restore_job: even if a path forgets to close
// it, it auto-expires, and suppressing backups for a few minutes after a
// *failed* restore is the safe behaviour anyway (don't snapshot a broken save).
#define SUPPRESS_MAX 16
static pthread_mutex_t s_suppress_lock = PTHREAD_MUTEX_INITIALIZER;
static char    s_suppress_title[SUPPRESS_MAX][16];
static int64_t s_suppress_until[SUPPRESS_MAX];

static void backup_suppress_for(const char* title_id, int seconds) {
    if (!title_id || !title_id[0]) return;
    int64_t until = now_unix() + seconds;
    pthread_mutex_lock(&s_suppress_lock);
    int slot = -1, oldest = 0;
    for (int i = 0; i < SUPPRESS_MAX; i++) {
        if (strcmp(s_suppress_title[i], title_id) == 0) { slot = i; break; }
        if (s_suppress_until[i] < s_suppress_until[oldest]) oldest = i;
    }
    if (slot < 0) {
        slot = oldest;  // reuse the most-expired slot
        snprintf(s_suppress_title[slot], sizeof(s_suppress_title[slot]),
                 "%s", title_id);
    }
    if (until > s_suppress_until[slot]) s_suppress_until[slot] = until;
    pthread_mutex_unlock(&s_suppress_lock);
}

static bool backup_suppressed(const char* title_id) {
    if (!title_id || !title_id[0]) return false;
    int64_t now = now_unix();
    bool yes = false;
    pthread_mutex_lock(&s_suppress_lock);
    for (int i = 0; i < SUPPRESS_MAX; i++)
        if (strcmp(s_suppress_title[i], title_id) == 0) {
            yes = (now < s_suppress_until[i]);
            break;
        }
    pthread_mutex_unlock(&s_suppress_lock);
    return yes;
}

// Save I/O gate. Backups, browser exports and slot inspection are readers;
// restore and target checks are writers. This closes the window where a backup that had
// already started before backup_suppress_for() could keep reading/mounting the
// same save while restore replaced it. Waiting writers block new readers so a
// busy backup schedule cannot starve a restore forever.
static pthread_mutex_t s_save_io_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t  s_save_io_cond = PTHREAD_COND_INITIALIZER;
static unsigned        s_save_io_readers = 0;
static unsigned        s_save_io_writers_waiting = 0;
static bool            s_save_io_writer = false;
// ponytail: one counter protects all transient ZIPs, including HTTP delivery.
// Per-path leases are unnecessary while cleanup is a rare explicit action.
static unsigned        s_scratch_users = 0;
static bool            s_scratch_cleaning = false;

static bool save_export_ready(char* err, size_t err_sz);

// Dequeue checks admission while holding q, then io. Releases must drop io
// before taking q: the condition and admission check cannot lose a wakeup.
static void save_io_wake_workers(void) {
    pthread_mutex_lock(&s_q_lock);
    pthread_cond_broadcast(&s_q_cond);
    pthread_mutex_unlock(&s_q_lock);
}

static void scratch_begin_use(void) {
    pthread_mutex_lock(&s_save_io_lock);
    while (s_scratch_cleaning)
        pthread_cond_wait(&s_save_io_cond, &s_save_io_lock);
    s_scratch_users++;
    pthread_mutex_unlock(&s_save_io_lock);
}

void watcher_release_backup_file(const char* path, bool temporary) {
    if (temporary && path && path[0]) unlink(path);
    pthread_mutex_lock(&s_save_io_lock);
    if (s_scratch_users > 0) s_scratch_users--;
    pthread_mutex_unlock(&s_save_io_lock);
}

static bool scratch_begin_cleanup(void) {
    if (!lifecycle_operation_begin()) return false;
    pthread_mutex_lock(&s_save_io_lock);
    bool idle = !s_save_io_writer && !s_save_io_readers &&
                !s_save_io_writers_waiting && !s_scratch_users;
    if (idle) s_save_io_writer = s_scratch_cleaning = true;
    pthread_mutex_unlock(&s_save_io_lock);
    if (!idle) lifecycle_operation_end();
    return idle;
}

static void scratch_end_cleanup(void) {
    pthread_mutex_lock(&s_save_io_lock);
    s_save_io_writer = s_scratch_cleaning = false;
    pthread_cond_broadcast(&s_save_io_cond);
    pthread_mutex_unlock(&s_save_io_lock);
    save_io_wake_workers();
    lifecycle_operation_end();
}

static bool save_io_begin_read(void) {
    if (!lifecycle_operation_begin()) return false;
    pthread_mutex_lock(&s_save_io_lock);
    while (s_save_io_writer || s_save_io_writers_waiting > 0)
        pthread_cond_wait(&s_save_io_cond, &s_save_io_lock);
    s_save_io_readers++;
    pthread_mutex_unlock(&s_save_io_lock);
    return true;
}

static void save_io_end_read(void) {
    pthread_mutex_lock(&s_save_io_lock);
    if (s_save_io_readers > 0) s_save_io_readers--;
    if (s_save_io_readers == 0) pthread_cond_broadcast(&s_save_io_cond);
    pthread_mutex_unlock(&s_save_io_lock);
    save_io_wake_workers();
    lifecycle_operation_end();
}

// Backup dequeue owns q here. Recovery/busy means leave the exact job asleep
// in the queue, without running-state writes, failure counters or requeue.
static bool save_io_try_begin_read(void) {
    if (!lifecycle_operation_begin()) return false;
    pthread_mutex_lock(&s_save_io_lock);
    bool available = !s_save_io_writer && !s_save_io_writers_waiting;
    if (available) s_save_io_readers++;
    pthread_mutex_unlock(&s_save_io_lock);
    if (!available) { lifecycle_operation_end(); return false; }
    if (save_export_ready(NULL, 0)) return true;
    pthread_mutex_lock(&s_save_io_lock);
    s_save_io_readers--;
    if (!s_save_io_readers) pthread_cond_broadcast(&s_save_io_cond);
    pthread_mutex_unlock(&s_save_io_lock);
    lifecycle_operation_end();
    return false; // Caller still holds q; do not wake q recursively.
}

static bool save_io_begin_write(void) {
    if (!lifecycle_operation_begin()) return false;
    pthread_mutex_lock(&s_save_io_lock);
    s_save_io_writers_waiting++;
    while (s_save_io_writer || s_save_io_readers > 0)
        pthread_cond_wait(&s_save_io_cond, &s_save_io_lock);
    s_save_io_writers_waiting--;
    s_save_io_writer = true;
    pthread_mutex_unlock(&s_save_io_lock);
    return true;
}

static void save_io_end_write(void) {
    pthread_mutex_lock(&s_save_io_lock);
    s_save_io_writer = false;
    pthread_cond_broadcast(&s_save_io_cond);
    pthread_mutex_unlock(&s_save_io_lock);
    save_io_wake_workers();
    lifecycle_operation_end();
}

static bool save_io_try_begin_inspection(void) {
    if (!lifecycle_operation_begin()) return false;
    pthread_mutex_lock(&s_save_io_lock);
    bool available = !s_save_io_writer && !s_save_io_readers &&
                     !s_save_io_writers_waiting && !s_scratch_cleaning;
    if (available) {
        s_save_io_writer = true;
        s_scratch_users++;
    }
    pthread_mutex_unlock(&s_save_io_lock);
    if (!available) lifecycle_operation_end();
    return available;
}


static void title_names_path(char* out, size_t out_sz) {
    snprintf(out, out_sz, "%s/title_names.json", s_cfg->paths.state_dir);
}

// Cross-process "a restore is running" sentinel. A restore writes directly into
// the live save and must finish atomically — if a daemon update SIGKILLs us in
// the middle, the save is left half-written. We drop this file for the duration
// of every restore so the REPLACING daemon's takeover can see it and wait
// (instead of force-killing) until the restore completes and we exit cleanly.
static void restore_busy_path(char* out, size_t out_sz) {
    snprintf(out, out_sz, "%s/restore.busy", s_cfg->paths.state_dir);
}

static bool restore_recovery_required(const config_t* cfg) {
    if (!cfg) return true;
    const char* markers[] = {"restore.interrupted", "restore.busy", "raw-recovery.pending"};
    char path[512];
    struct stat st;
    for (size_t i = 0; i < sizeof(markers) / sizeof(markers[0]); i++) {
        int n = snprintf(path, sizeof(path), "%s/%s", cfg->paths.state_dir, markers[i]);
        if (n < 0 || (size_t)n >= sizeof(path) ||
            lstat(path, &st) == 0 || errno != ENOENT) return true;
    }
    return false;
}

static bool save_export_ready(char* err, size_t err_sz) {
    config_t cfg;
    if (config_snapshot(&cfg) && !restore_recovery_required(&cfg)) return true;
    if (err && err_sz) snprintf(err, err_sz,
        "Restore or RAW mount recovery requires inspection; backups and exports are paused");
    return false;
}

void watcher_target_check_end(void) {
    pthread_mutex_lock(&s_save_io_lock);
    if (s_scratch_users) s_scratch_users--;
    s_save_io_writer = false;
    pthread_cond_broadcast(&s_save_io_cond);
    pthread_mutex_unlock(&s_save_io_lock);
    save_io_wake_workers();
    lifecycle_operation_end();
}

int watcher_target_check_begin(char* err, size_t err_sz) {
    if (err && err_sz) err[0] = '\0';
    if (!save_io_try_begin_inspection()) {
        if (err && err_sz) snprintf(err, err_sz,
            "A backup, restore or save inspection is using the saves; try this check when it finishes. No images were mounted.");
        return 0;
    }
    if (!save_export_ready(err, err_sz)) {
        watcher_target_check_end();
        return -1;
    }
    return 1;
}

typedef struct { jobs_ref_t id; backup_control_t control; } usb_test_work_t;
static void* usb_test_worker(void* arg) {
    usb_test_work_t* work = arg;
    jobs_ref_t previous = jobs_bind(work->id);
    backup_control_t* bound = backup_control_bind(&work->control);
    jobs_phase(work->id, "usb", "preparing", 0, false);
    char detail[512] = {0};
    bool ok = usb_test_write(NULL, 0, detail, sizeof(detail));
    bool canceled = backup_control_finish_begin();
    const char* failure = usb_last_copy_failure();
    bool uncertain = !strcmp(failure, "test_cleanup_unknown");
    bool partial = !strcmp(failure, "test_timeout");
    jobs_backup_detail(work->id, detail);
    jobs_finish(work->id, uncertain || partial ? JOB_UNKNOWN : canceled ? JOB_FAILED : ok ? JOB_DONE : JOB_FAILED,
                uncertain ? "usb_test_cleanup_unknown" : partial ? "usb_test_partial" :
                canceled ? "usb_test_canceled" : ok ? NULL :
                !strcmp(failure,"identity_unconfirmed") ? "usb_test_unconfirmed" :
                !strcmp(failure,"not_usable") ? "usb_test_unavailable" : "usb_test_failed");
    backup_control_bind(bound);backup_control_end(&work->control);jobs_bind(previous);
    free(work);
    atomic_fetch_sub(&s_jobs_active, 1);
    watcher_target_check_end();
    lifecycle_activity_end();
    return NULL;
}

bool watcher_test_usb(jobs_ref_t* admitted, char* detail,size_t detail_sz) {
    if (admitted) *admitted = 0;
    life_snapshot_t state;
    if (!admitted || !watcher_lifecycle_snapshot(&state) || state.jobs || state.queued ||
        state.import_work!=LIFE_CLEAR || state.recovery!=LIFE_CLEAR ||
        !save_io_try_begin_inspection()) {
        if (detail&&detail_sz)snprintf(detail,detail_sz,"Finish or cancel active work before the USB write test");return false;
    }
    usb_test_work_t* work = calloc(1, sizeof(*work));
    if (!work) {watcher_target_check_end();return false;}
    work->id = jobs_begin(JOB_USB_TEST, NULL, NULL, NULL, "usb");
    if (!work->id || !jobs_tracked(work->id) || !backup_control_begin(&work->control, work->id)) {
        jobs_finish(work->id, JOB_FAILED, "usb_test_not_admitted");
        free(work);watcher_target_check_end();return false;
    }
    // The worker owns a global lease; the HTTP thread keeps its own nesting.
    if (!lifecycle_activity_begin()) {
        jobs_finish(work->id, JOB_FAILED, "usb_test_not_admitted");
        backup_control_end(&work->control);free(work);watcher_target_check_end();return false;
    }
    jobs_ref_t id = work->id;
    pthread_attr_t attr;
    int rc = pthread_attr_init(&attr);
    if (!rc) {
        rc = pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
        if (!rc) {
            pthread_t thread;
            atomic_fetch_add(&s_jobs_active, 1);
            rc = pthread_create(&thread, &attr, usb_test_worker, work);
            if (rc) atomic_fetch_sub(&s_jobs_active, 1);
        }
        pthread_attr_destroy(&attr);
    }
    if (rc) {
        lifecycle_activity_end();
        jobs_finish(id, JOB_FAILED, "usb_test_not_admitted");
        backup_control_end(&work->control);free(work);watcher_target_check_end();return false;
    }
    lifecycle_operation_end();
    *admitted = id;
    return true;
}

static bool path_contains(const char* parent, const char* child) {
    size_t n = strlen(parent);
    return n && strncmp(parent, child, n) == 0 &&
           (parent[n - 1] == '/' || child[n] == '/' || child[n] == '\0');
}

static bool cleanup_overlaps(const char* root, const char* protected_path,
                              bool parent_only) {
    if (!protected_path || !protected_path[0]) return true;
    char* resolved = realpath(protected_path, NULL);
    if (!resolved && errno != ENOENT) return true;
    const char* path = resolved ? resolved : protected_path;
    bool overlap = path_contains(root, path) ||
                   (!parent_only && path_contains(path, root));
    free(resolved);
    return overlap;
}

static bool staging_cleanup_safe(const config_t* cfg, const char* root) {
    // A configured staging path must not turn "temporary files" cleanup into
    // deletion of daemon state, live saves, retained imports or USB backups.
    char* resolved = realpath(root, NULL);
    if (!resolved) return errno == ENOENT;
    char imports[768];
    snprintf(imports, sizeof(imports), "%s/imports", cfg->paths.state_dir);
    bool safe = !cleanup_overlaps(resolved, cfg->paths.state_dir, true) &&
                !cleanup_overlaps(resolved, cfg->paths.saves_root, false) &&
                !cleanup_overlaps(resolved, imports, false);
    import_session_info_t imported;
    if (safe && import_session_current(&imported) && imported.path[0])
        safe = !cleanup_overlaps(resolved, imported.path, false);
    usb_mount_t mounts[8];
    size_t count = safe ? usb_list_mounts(mounts, 8) : 0;
    for (size_t i = 0; safe && i < count; i++) {
        char folder[768];
        snprintf(folder, sizeof(folder), "%s/%s", mounts[i].path,
                 cfg->usb.folder[0] ? cfg->usb.folder : "TostónSync");
        safe = !cleanup_overlaps(resolved, folder, false);
    }
    free(resolved);
    return safe;
}

// Background-only: rmdir cannot remove a download or any nonempty directory.
void watcher_maintenance(void) {
    static time_t next;
    time_t now = time(NULL);
    if (now < next) return;
    next = now + 60;
    if (!scratch_begin_cleanup()) return;
    config_t cfg;
    int fd = config_snapshot(&cfg) && staging_cleanup_safe(&cfg, cfg.paths.staging_dir)
        ? open(cfg.paths.staging_dir, O_RDONLY | O_DIRECTORY | O_NOFOLLOW) : -1;
    DIR* dir = fd >= 0 ? fdopendir(fd) : NULL;
    if (!dir && fd >= 0) close(fd);
    if (dir) {
        struct dirent* entry;
        while ((entry = readdir(dir))) {
            const char* name = entry->d_name;
            if (strlen(name) != 13 || strncmp(name, "export.", 7)) continue;
            bool valid = true;
            for (size_t i = 7; i < 13; i++) {
                unsigned char c = (unsigned char)name[i];
                if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
                      (c >= '0' && c <= '9'))) valid = false;
            }
            if (!valid) continue;
            int child = toston_openat(fd, name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW, 0);
            if (child < 0) continue;
            struct stat held, named;
            if (!toston_fstat(child, &held) &&
                !toston_fstatat(fd, name, &named, AT_SYMLINK_NOFOLLOW) &&
                S_ISDIR(named.st_mode) && (held.st_mode & 0777) == 0700 &&
                held.st_uid == geteuid() && held.st_dev == named.st_dev && held.st_ino == named.st_ino)
                (void)unlinkat(fd, name, AT_REMOVEDIR);
            close(child);
        }
        closedir(dir);
    }
    scratch_end_cleanup();
}

bool watcher_cleanup_scratch(bool mounts, char* err, size_t err_sz) {
    if (err && err_sz) err[0] = '\0';
    config_t cfg;
    if (!config_snapshot(&cfg)) return false;
    char root[512];
    snprintf(root, sizeof(root), mounts ? "%s/mounts" : "%s",
             mounts ? cfg.paths.state_dir : cfg.paths.staging_dir);
    bool ok = false;
    DIR* dir = NULL;
    if (!scratch_begin_cleanup()) {
        if (err && err_sz) snprintf(err, err_sz,
            "A backup, restore, export or download is active; wait for it to finish before cleanup");
        return false;
    }
    if (restore_recovery_required(&cfg)) {
        if (err && err_sz) snprintf(err, err_sz,
            "Restore recovery is pending; cleanup cannot remove recovery files");
        goto cleanup_done;
    }
    if (!staging_cleanup_safe(&cfg, root)) {
        if (err && err_sz) snprintf(err, err_sz,
            "Staging overlaps saves, imports or app state; choose a separate staging folder before cleanup");
        goto cleanup_done;
    }
    dir = opendir(root);
    if (!dir) { ok = errno == ENOENT; goto cleanup_done; }
    struct dirent* e;
    // Preflight the whole directory before deleting even a stale ZIP. Retained
    // undo images and every interrupted-rotation sidecar are not disposable.
    if (!mounts) {
        while ((e = readdir(dir)) != NULL) {
            if (strstr(e->d_name, "_sdimg_rollback") != NULL ||
                strstr(e->d_name, ".portable.") != NULL ||
                strstr(e->d_name, ".saved-") != NULL ||
                strstr(e->d_name, ".native-modes.") != NULL ||
                strcmp(e->d_name, ".pending") == 0) {
                if (err && err_sz) snprintf(err, err_sz,
                    "Previous saves are retained; use Delete previous save rollback before staging cleanup");
                goto cleanup_done;
            }
            if (e->d_name[0] == '.') continue;
            char pending[1024];
            int n = snprintf(pending, sizeof(pending), "%s/%s/.pending", root, e->d_name);
            struct stat st;
            if (n < 0 || (size_t)n >= sizeof(pending) ||
                lstat(pending, &st) == 0 || (errno != ENOENT && errno != ENOTDIR)) {
                if (err && err_sz) snprintf(err, err_sz,
                    "Pending recovery files are retained; staging cleanup is blocked");
                goto cleanup_done;
            }
        }
        rewinddir(dir);
    }
    ok = true;
    while ((e = readdir(dir)) != NULL) {
        if (e->d_name[0] == '.') continue;
        char path[1024];
        int n = snprintf(path, sizeof(path), "%s/%s", root, e->d_name);
        struct stat st;
        if (n < 0 || (size_t)n >= sizeof(path)) { ok = false; break; }
        if (lstat(path, &st) != 0) { if (errno != ENOENT) ok = false; continue; }
        if (S_ISDIR(st.st_mode)) {
            // Never recursively traverse a potentially still-mounted save.
            if (mounts) { if (rmdir(path) != 0 && errno != ENOENT) ok = false; }
            else pfs_fs_rmrf(path);
        } else if (unlink(path) != 0 && errno != ENOENT) ok = false;
        if (lstat(path, &st) == 0 || errno != ENOENT) ok = false;
    }
cleanup_done:
    if (dir) closedir(dir);
    scratch_end_cleanup();
    if (!ok && err && err_sz && !err[0]) snprintf(err, err_sz,
        "Some files could not be safely removed; nonempty mount folders are preserved");
    return ok;
}

static char* read_title_names_cache(void) {
    if (!s_cfg) return NULL;
    char path[300];
    title_names_path(path, sizeof(path));
    FILE* f = fopen(path, "rb");
    if (!f) return NULL;
    if (fseek(f, 0, SEEK_END) != 0) { fclose(f); return NULL; }
    long sz = ftell(f);
    if (sz <= 0 || sz > 64 * 1024) { fclose(f); return NULL; }
    fseek(f, 0, SEEK_SET);
    char* buf = (char*)malloc((size_t)sz + 1);
    if (!buf) { fclose(f); return NULL; }
    size_t n = fread(buf, 1, (size_t)sz, f);
    fclose(f);
    buf[n] = '\0';
    return buf;
}

static void json_escape_small(const char* in, char* out, size_t out_sz) {
    if (!out || !out_sz) return;
    size_t j = 0;
    for (size_t i = 0; in && in[i] && j + 2 < out_sz; i++) {
        unsigned char c = (unsigned char)in[i];
        if (c == '"' || c == '\\') { out[j++] = '\\'; out[j++] = (char)c; }
        else if (c == '\n') { out[j++] = '\\'; out[j++] = 'n'; }
        else if (c == '\r') { out[j++] = '\\'; out[j++] = 'r'; }
        else if (c == '\t') { out[j++] = '\\'; out[j++] = 't'; }
        else if (c >= 0x20) out[j++] = (char)c;
    }
    out[j] = '\0';
    titlename_copy_utf8(out, out_sz, out);
}

static void save_title_names_cache_inner(void) {
    if (!s_cfg) return;
    static pthread_mutex_t cache_lock = PTHREAD_MUTEX_INITIALIZER;
    pthread_mutex_lock(&cache_lock);
    struct pair { char title_id[16]; char name[64]; } pairs[MAX_TITLES];
    size_t count = 0;

    pthread_mutex_lock(&s_titles_lock);
    for (size_t i = 0; i < s_title_count && count < MAX_TITLES; i++) {
        if (!s_titles[i].game_name[0]) continue;
        bool seen = false;
        for (size_t j = 0; j < count; j++)
            if (strcmp(pairs[j].title_id, s_titles[i].title_id) == 0) {
                seen = true; break;
            }
        if (seen) continue;
        snprintf(pairs[count].title_id, sizeof(pairs[count].title_id),
                 "%s", s_titles[i].title_id);
        titlename_copy_utf8(pairs[count].name, sizeof(pairs[count].name),
                            s_titles[i].game_name);
        count++;
    }
    pthread_mutex_unlock(&s_titles_lock);

    char path[300], tmp[320];
    title_names_path(path, sizeof(path));
    snprintf(tmp, sizeof(tmp), "%s.tmp", path);
    FILE* f = fopen(tmp, "w");
    if (!f) { pthread_mutex_unlock(&cache_lock); return; }
    fputc('{', f);
    for (size_t i = 0; i < count; i++) {
        char name[160];
        json_escape_small(pairs[i].name, name, sizeof(name));
        fprintf(f, "%s\"%s\":\"%s\"", i ? "," : "",
                pairs[i].title_id, name);
    }
    fputs("}\n", f);
    bool ok = !ferror(f);
    if (fclose(f) != 0) ok = false;
    if (ok) rename(tmp, path);
    else unlink(tmp);
    pthread_mutex_unlock(&cache_lock);
}

static void save_title_names_cache(void) {
    if (!lifecycle_operation_begin()) return;
    save_title_names_cache_inner();
    lifecycle_operation_end();
}

static bool set_title_name(const char* title_id, const char* name) {
    if (!title_id || !name || !name[0]) return false;
    char clean[sizeof(s_titles[0].game_name)];
    titlename_copy_utf8(clean, sizeof(clean), name);
    if (!clean[0]) return false;
    bool changed = false;
    pthread_mutex_lock(&s_titles_lock);
    for (size_t i = 0; i < s_title_count; i++) {
        if (strcmp(s_titles[i].title_id, title_id) != 0) continue;
        if (strcmp(s_titles[i].game_name, clean) == 0) continue;
        titlename_copy_utf8(s_titles[i].game_name, sizeof(s_titles[i].game_name),
                            clean);
        changed = true;
    }
    pthread_mutex_unlock(&s_titles_lock);
    if (changed) save_title_names_cache();
    return changed;
}

// A real PS5 TITLE_ID is CUSA#####/PPSA##### — letters, digits, underscore.
// Restore requests arrive over the unauthenticated LAN API and the id is
// later spliced into a filesystem path (.../savedata_prospero/<title_id>),
// so anything outside this charset (notably '/' or "..") is rejected to
// keep a crafted request from writing outside the saves tree.
static bool valid_title_id(const char* t) {
    if (!t || !t[0]) return false;
    for (size_t i = 0; t[i]; i++) {
        char c = t[i];
        bool ok = (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
                  (c >= '0' && c <= '9') || c == '_';
        if (!ok) return false;
    }
    return true;
}

// `valid_uid` mirrors `valid_title_id`: the UID is later spliced into
// filesystem paths and remote folder names, so anything outside this
// charset is rejected to keep crafted API input from writing outside the
// saves tree.
static bool valid_uid(const char* u) {
    if (!u) return false;
    if (!u[0]) return true;   // empty allowed: "pick first user"
    for (size_t i = 0; u[i]; i++) {
        char c = u[i];
        bool ok = (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
                  (c >= '0' && c <= '9') || c == '_';
        if (!ok) return false;
    }
    return true;
}

static bool safe_path_component(const char* s) {
    if (!s || !s[0]) return false;
    if (strcmp(s, ".") == 0 || strcmp(s, "..") == 0) return false;
    for (const unsigned char* p = (const unsigned char*)s; *p; p++) {
        if (*p < 0x20 || *p == 0x7f || *p == '/' || *p == '\\')
            return false;
    }
    return true;
}

// --------------------------------------------------------------------
// Title table.
// --------------------------------------------------------------------

static title_t* title_find_or_add(const char* user_uid,
                                  const char* title_id,
                                  const char* path) {
    static bool limit_warned = false;
    for (size_t i = 0; i < s_title_count; i++)
        if (strcmp(s_titles[i].title_id, title_id) == 0 &&
            strcmp(s_titles[i].user_uid, user_uid ? user_uid : "") == 0)
            return &s_titles[i];
    if (s_title_count >= MAX_TITLES) {
        if (!limit_warned) {
            log_warn("watcher: title limit reached (%d); additional saves will not be watched",
                     MAX_TITLES);
            limit_warned = true;
        }
        return NULL;
    }
    title_t* t = &s_titles[s_title_count++];
    memset(t, 0, sizeof(*t));
    strncpy(t->title_id, title_id, sizeof(t->title_id) - 1);
    if (user_uid) strncpy(t->user_uid, user_uid, sizeof(t->user_uid) - 1);
    strncpy(t->path,     path,     sizeof(t->path)     - 1);
    t->watch_fd = -1;
    return t;
}

static bool title_allowed_cfg(const config_t* cfg, const char* title_id) {
    if (!cfg) return false;
    // exclude wins over include_only.
    for (size_t i = 0; i < cfg->titles.exclude_count; i++)
        if (strcmp(cfg->titles.exclude[i], title_id) == 0) return false;
    if (cfg->titles.include_only_count == 0) return true;
    for (size_t i = 0; i < cfg->titles.include_only_count; i++)
        if (strcmp(cfg->titles.include_only[i], title_id) == 0) return true;
    return false;
}

static bool title_allowed(const char* title_id) {
    config_t cfg;
    return config_snapshot(&cfg) && title_allowed_cfg(&cfg, title_id);
}

// --------------------------------------------------------------------
// kqueue setup.
// --------------------------------------------------------------------

static void register_watch(title_t* t) {
    if (t->watch_fd >= 0) return;
    t->watch_fd = open(t->path, O_RDONLY);
    if (t->watch_fd < 0) return;
    struct kevent ke;
    EV_SET(&ke, t->watch_fd, EVFILT_VNODE,
           EV_ADD | EV_ENABLE | EV_CLEAR,
           NOTE_WRITE | NOTE_EXTEND | NOTE_DELETE | NOTE_RENAME,
           0, t);
    kevent(s_kq, &ke, 1, NULL, 0, NULL);
}

static void scan_and_register_inner(void) {
    config_t cfg;
    if (!config_snapshot(&cfg)) return;
    fs_dir_t dirs[MAX_TITLES];
    size_t n = fs_list_save_titles(cfg.paths.saves_root,
                                   dirs, MAX_TITLES);
    char* cache = read_title_names_cache();
    char need_lookup[MAX_TITLES][16];
    size_t need_count = 0;

    pthread_mutex_lock(&s_titles_lock);
    for (size_t i = 0; i < n; i++) {
        title_t* t = title_find_or_add(dirs[i].user_uid,
                                       dirs[i].name, dirs[i].path);
        if (!t) continue;
        register_watch(t);
        if (!t->game_name[0] && cache) {
            char cached[sizeof(t->game_name)];
            if (json_get_string(cache, t->title_id, cached, sizeof(cached)))
                titlename_copy_utf8(t->game_name, sizeof(t->game_name), cached);
        }
        // Metadata and app language can change after an automatic name was
        // cached. Revalidate every unique title in this existing scan only.
        bool seen = false;
        for (size_t j = 0; j < need_count; j++)
            if (strcmp(need_lookup[j], t->title_id) == 0) {
                seen = true; break;
            }
        if (!seen && need_count < MAX_TITLES) {
            snprintf(need_lookup[need_count],
                     sizeof(need_lookup[need_count]),
                     "%s", t->title_id);
            need_count++;
        }
    }
    pthread_mutex_unlock(&s_titles_lock);
    free(cache);

    for (size_t i = 0; i < need_count; i++) {
        char name[64] = {0};
        if (titlename_lookup(need_lookup[i], name, sizeof(name))) {
            if (set_title_name(need_lookup[i], name))
                log_info("watcher: %s = \"%s\"", need_lookup[i], name);
        }
    }
    recover_backup_retries(); // includes saves first discovered after startup
}

static void scan_and_register(void) {
    if (!lifecycle_operation_begin()) return;
    scan_and_register_inner();
    lifecycle_operation_end();
}

// --------------------------------------------------------------------
// Upload queue.
// --------------------------------------------------------------------

static bool enqueue_inner(const char* user_uid, const char* title_id,
                    bool is_restore, bool force_backup, const char* file_id,
                    int64_t dirty_unix, const char* trigger,
                    const char* destination, const char* source,
                    watcher_job_admission_t* observed, bool uid_explicit, const char* claimed_import_id) {
    if (destination && !strcmp(destination, "ftp")) {
        log_info("backup-queue: ignored retired FTP destination; no replacement scheduled");
        return false;
    }

    if (observed) memset(observed, 0, sizeof(*observed));
    if (!s_running) return false;
    if (!is_restore && !force_backup) {
        config_t cfg;
        if (!config_snapshot(&cfg) || manual_only_cfg(&cfg)) {
            // All backup callers own s_titles_lock here. Refusing automatic
            // work must neither publish retry intent nor strand its title.
            for (size_t i = 0; i < s_title_count; i++)
                if (strcmp(s_titles[i].title_id, title_id) == 0 &&
                    strcmp(s_titles[i].user_uid, user_uid ? user_uid : "") == 0) {
                    s_titles[i].upload_in_flight = false;
                    break;
                }
            return false;
        }
    }
    job_t* j = (job_t*)calloc(1, sizeof(*j));
    if (!j) {
        log_warn("watcher: out of memory enqueuing %s", title_id);
        // The caller set upload_in_flight before enqueuing; clear it so a
        // transient OOM doesn't block this title from ALL future backups.
        // IMPORTANT: every non-restore caller (trigger_main, kick_sync_now,
        // on_shutdown, interval) already HOLDS s_titles_lock around the loop
        // that calls enqueue(). Re-acquiring it here would self-deadlock the
        // watcher (the mutex is not recursive), so we clear the flag WITHOUT
        // locking — we're already inside the caller's critical section.
        if (!is_restore) {
            for (size_t i = 0; i < s_title_count; i++)
                if (strcmp(s_titles[i].title_id, title_id) == 0 &&
                    strcmp(s_titles[i].user_uid, user_uid ? user_uid : "") == 0) {
                    s_titles[i].upload_in_flight = false; break;
                }
        }
        return false;
    }
    strncpy(j->title_id, title_id, sizeof(j->title_id) - 1);
    if (user_uid) strncpy(j->user_uid, user_uid, sizeof(j->user_uid) - 1);
    j->job_id = atomic_fetch_add(&s_job_seq, 1);
    j->queued_unix = now_unix();
    j->is_restore = is_restore;
    j->restore_uid_explicit = is_restore && uid_explicit;
    if (is_restore && claimed_import_id) snprintf(j->restore_import_id,sizeof(j->restore_import_id),"%s",claimed_import_id);
    j->force_backup = force_backup;
    j->retrying = source && (strcmp(source, "destination_retry") == 0 ||
                            strcmp(source, "interrupted_retry") == 0);
    j->dirty_unix = dirty_unix;
    snprintf(j->trigger, sizeof(j->trigger), "%s",
             (trigger && trigger[0]) ? trigger : "Auto");
    snprintf(j->source, sizeof(j->source), "%s",
             (source && source[0]) ? source : "unknown");
    if (destination)
        snprintf(j->destination, sizeof(j->destination), "%s", destination);
    if (file_id) strncpy(j->restore_ref, file_id,
                         sizeof(j->restore_ref) - 1);
    if (is_restore && user_uid)
        snprintf(j->restore_user, sizeof(j->restore_user), "%s", user_uid);
    if (!is_restore) {
        // Every backup caller holds s_titles_lock here (same contract as the
        // OOM recovery above), so capture/reset without recursively locking.
        for (size_t i = 0; i < s_title_count; i++)
            if (strcmp(s_titles[i].title_id, title_id) == 0 &&
                strcmp(s_titles[i].user_uid, user_uid ? user_uid : "") == 0) {
                j->coalesced_count = s_titles[i].coalesced_count;
                s_titles[i].coalesced_count = 0;
                if (!force_backup) {
                    title_t* t = &s_titles[i];
                    // A final/shutdown trigger can continue an unchanged
                    // partial job too; only manual force discards skip policy.
                    j->retrying = j->retrying ||
                        ((t->backup_retry_at > 0 || t->backup_usb_no_replay) &&
                         dirty_unix <= t->backup_retry_dirty_unix);
                    backup_retry_t retry;
                    if (!j->retrying ||
                        !backup_retry_load(j->user_uid, j->title_id, &retry)) {
                        backup_retry_init(&retry, j->user_uid, j->title_id,
                                          j->trigger);
                        // An unreadable replay record cannot authorize another USB attempt.
                        retry.usb_no_replay = j->retrying;
                        if (retry.usb_no_replay) retry.pending_mask &= ~1U;
                    }
                    t->backup_usb_no_replay = retry.usb_no_replay;
                    retry.active = true;
                    retry.dirty_unix = dirty_unix;
                    retry.failures = t->backup_retry_failures;
                    retry.last_upload_unix = t->last_upload_unix;
                    retry.retry_at = now_unix() +
                        dest_retry_delay_seconds(retry.failures);
                    snprintf(retry.reason, sizeof(retry.reason), "%s", j->trigger);
                    // Publish durable intent before a worker can copy anything.
                    // Manual copies never replace this automatic backlog.
                    if (!backup_retry_save(&retry)) {
                        t->upload_in_flight = false;
                        t->dirty = true;
                        t->backup_retry_at = retry.retry_at;
                        t->backup_retry_dirty_unix = dirty_unix;
                        t->backup_retry_mask = retry.usb_no_replay ? 2U : 3U;
                        snprintf(t->backup_retry_trigger,
                                 sizeof(t->backup_retry_trigger), "%s", j->trigger);
                        free(j);
                        return false;
                    }
                    t->backup_retry_journal = true;
                    t->backup_retry_checked = true;
                }
                break;
            }
    }
    if (!is_restore && strcmp(j->trigger, "GameClose") == 0) {
        backup_job_state_t state = {0};
        state.job_id = j->job_id;
        state.started_at = j->queued_unix;
        snprintf(state.run_id, sizeof(state.run_id), "%s", s_run_id);
        snprintf(state.user_uid, sizeof(state.user_uid), "%s", j->user_uid);
        snprintf(state.title_id, sizeof(state.title_id), "%s", j->title_id);
        snprintf(state.reason, sizeof(state.reason), "%s", j->trigger);
        snprintf(state.source, sizeof(state.source), "%s", j->source);
        snprintf(state.destination, sizeof(state.destination), "%s",
                 j->destination[0] ? j->destination : "default");
        snprintf(state.status, sizeof(state.status), "pending");
        char state_path[420];
        backup_job_path(j->user_uid, j->title_id,
                        state_path, sizeof(state_path));
        if (!backup_job_state_write(state_path, &state))
            log_warn("backup-queue[job=%lu]: could not persist pending GameClose state",
                     j->job_id);
        set_last_backup(j->title_id, 5, "Pending final backup");
    }
    jobs_ref_t observation = jobs_watch_queued(j->job_id, is_restore ? JOB_RESTORE : JOB_FULL_BACKUP,
        is_restore && !uid_explicit ? NULL : j->user_uid, j->title_id, NULL, j->destination);
    if (!is_restore) for (size_t i = 0; i < s_title_count; i++)
        if (!strcmp(s_titles[i].title_id, j->title_id) && !strcmp(s_titles[i].user_uid, j->user_uid)) {
            s_titles[i].observation_job = observation;
            break;
        }
    if (observed) { observed->id = observation; observed->tracked = jobs_tracked(observation); }
    pthread_mutex_lock(&s_q_lock);
    if (s_q_tail) s_q_tail->next = j; else s_q_head = j;
    s_q_tail = j; s_q_depth++;
    if (!is_restore)
        log_info("backup-queue[job=%lu run=%s pid=%ld key=%s/%s reason=%s "
                 "source=%s dest=%s]: queued queued_at=%lld coalesced_count=%u",
                 j->job_id, s_run_id,
                 (long)getpid(), j->user_uid, j->title_id, j->trigger,
                 j->source, j->destination[0] ? j->destination : "default",
                 (long long)j->queued_unix, j->coalesced_count);
    pthread_cond_signal(&s_q_cond);
    pthread_mutex_unlock(&s_q_lock);
    return true;
}

static bool enqueue_observed(const char* user_uid, const char* title_id,
                    bool is_restore, bool force_backup, const char* file_id,
                    int64_t dirty_unix, const char* trigger,
                    const char* destination, const char* source,
                    watcher_job_admission_t* observed) {
    if (observed) memset(observed, 0, sizeof(*observed));
    // Admission precedes durable retry intent, not merely the queue append.
    if (!lifecycle_operation_begin()) return false;
    bool ok = enqueue_inner(user_uid, title_id, is_restore, force_backup,
                            file_id, dirty_unix, trigger, destination, source, observed, false, NULL);
    lifecycle_operation_end();
    return ok;
}

static bool enqueue(const char* user_uid, const char* title_id,
                    bool is_restore, bool force_backup, const char* file_id,
                    int64_t dirty_unix, const char* trigger,
                    const char* destination, const char* source) {
    // Admission precedes durable retry intent, not merely the queue append.
    if (!lifecycle_operation_begin()) return false;
    bool ok = enqueue_inner(user_uid, title_id, is_restore, force_backup,
                            file_id, dirty_unix, trigger, destination, source, NULL, false, NULL);
    lifecycle_operation_end();
    return ok;
}

static void recover_backup_retries(void) {
    config_t cfg;
    if (!config_snapshot(&cfg) || manual_only_cfg(&cfg)) return;
    pthread_mutex_lock(&s_titles_lock);
    for (size_t i = 0; i < s_title_count; i++) {
        title_t* t = &s_titles[i];
        if (t->backup_retry_checked || t->upload_in_flight) continue;
        t->backup_retry_checked = true;
        char path[420];
        backup_retry_path(t->user_uid, t->title_id, path, sizeof(path));
        struct stat st;
        if (lstat(path, &st) != 0 && errno == ENOENT) continue;
        t->backup_retry_journal = true;
        backup_retry_t retry;
        if (!backup_retry_load(t->user_uid, t->title_id, &retry)) {
            // Corrupt/incomplete records prove nothing. Recheck the current
            // configured targets against independently verified receipts.
            backup_retry_init(&retry, t->user_uid, t->title_id, "Auto");
            retry.dirty_unix = now_unix();
            retry.retry_at = now_unix() + 30;
            retry.usb_no_replay = true;
            retry.pending_mask &= ~1U;
            log_warn("backup-queue: invalid retry state key=%s/%s; "
                     "scheduling conservative destination recheck", t->user_uid, t->title_id);
        }
        if (retry.last_upload_unix > t->last_upload_unix)
            t->last_upload_unix = retry.last_upload_unix;
        t->backup_usb_no_replay = retry.usb_no_replay;
        t->backup_retry_dirty_unix = retry.dirty_unix;
        if (retry.cancel_guard || !retry.active) {
            if(retry.cancel_guard && t->last_dirty_unix<=retry.dirty_unix)t->dirty=false;
            t->backup_retry_at = 0;
            t->backup_retry_mask = t->backup_retry_failures = 0;
            continue;
        }
        unsigned pending = retry.pending_mask;
        for (unsigned d = 0; d < 3; d++)
            if (!dest_fingerprint_hex(retry.completed_identity[d]))
                pending |= retry.planned_mask & (1U << d);
        // Also close a crash after the final destination checkpoint but
        // before the terminal write. Fresh identities, not masks, decide skips.
        t->backup_retry_mask = pending ? pending : retry.planned_mask;
        t->backup_retry_planned_mask = retry.planned_mask;
        if (!t->backup_retry_mask) t->backup_retry_mask = 3U;
        if (retry.usb_no_replay) t->backup_retry_mask &= ~1U;
        if (!t->backup_retry_mask) {
            t->backup_retry_at = 0;
            if (t->last_dirty_unix <= retry.dirty_unix) t->dirty = false;
            continue;
        }
        t->backup_retry_at = retry.retry_at > 0 ? retry.retry_at : now_unix();
        if (t->backup_retry_at > now_unix() + 300)
            t->backup_retry_at = now_unix() + 300; // clock moved backwards
        t->backup_retry_failures = retry.failures;
        t->backup_retry_dirty_unix = retry.dirty_unix;
        if (t->last_dirty_unix < retry.dirty_unix)
            t->last_dirty_unix = retry.dirty_unix;
        t->dirty = true;
        snprintf(t->backup_retry_trigger, sizeof(t->backup_retry_trigger),
                 "%s", retry.reason);
        log_info("backup-queue: recovered pending key=%s/%s destinations=%u "
                 "retry_at=%lld failures=%u", t->user_uid, t->title_id,
                 t->backup_retry_mask, (long long)t->backup_retry_at,
                 t->backup_retry_failures);
    }
    pthread_mutex_unlock(&s_titles_lock);
}

static void recover_backup_jobs(void) {
    config_t replay_cfg;
    // Manual-only startup is inert: leave every persisted job/retry intact,
    // including other titles' pending/running records and timestamps.
    if (!config_snapshot(&replay_cfg) || manual_only_cfg(&replay_cfg)) return;
    char dir_path[384];
    snprintf(dir_path, sizeof(dir_path), "%s/jobs", s_cfg->paths.state_dir);
    DIR* dir = opendir(dir_path);
    if (!dir) return;
    struct dirent* ent;
    backup_job_state_t latest = {0};
    int64_t latest_at = 0;
    bool queued_retry = false;
    while ((ent = readdir(dir)) != NULL) {
        size_t len = strlen(ent->d_name);
        if (len < 7 || strcmp(ent->d_name + len - 6, ".state") != 0 ||
            !safe_path_component(ent->d_name)) continue;
        char path[512];
        snprintf(path, sizeof(path), "%s/%s", dir_path, ent->d_name);
        backup_job_state_t state;
        if (!backup_job_state_read(path, &state) ||
            !valid_uid(state.user_uid) || !valid_title_id(state.title_id))
            continue;
        if (!strcmp(state.destination, "ftp")) {
            log_info("backup-queue: retained retired FTP job without replay");
            continue;
        }
        bool stale =
            (strcmp(state.status, "running") == 0 ||
             strcmp(state.status, "pending") == 0) &&
            strcmp(state.run_id, s_run_id) != 0;
        bool retry = backup_job_state_needs_retry(&state, s_run_id);
        bool journal_backed = false;
        backup_retry_t cancel_fence;
        if(backup_retry_load(state.user_uid,state.title_id,&cancel_fence)&&cancel_fence.cancel_guard){retry=false;journal_backed=true;}
        for (size_t i = 0; i < s_title_count; i++)
            if (strcmp(s_titles[i].user_uid, state.user_uid) == 0 &&
                strcmp(s_titles[i].title_id, state.title_id) == 0)
                journal_backed = journal_backed || s_titles[i].backup_retry_journal;
        if (stale) {
            char previous[16];
            snprintf(previous, sizeof(previous), "%s", state.status);
            snprintf(state.status, sizeof(state.status), "interrupted");
            state.completed_at = now_unix();
            backup_job_state_write(path, &state);
            log_warn("backup[job=%lu key=%s/%s reason=%s]: interrupted "
                     "reason=suspend_or_network_lost previous_status=%s",
                     state.job_id, state.user_uid, state.title_id,
                     state.reason, previous);
            config_t cfg;
            bool es = config_snapshot(&cfg) &&
                      strcmp(cfg.general.language, "es") == 0;
            if (retry)
                log_info("activity:final_backup_interrupted|%s", state.title_id);
            log_notify(retry
                ? (es ? "Backup final interrumpido\nSe reintentará cuando Drive esté listo"
                      : "Final backup interrupted\nIt will retry when Drive is ready")
                : (es ? "El backup anterior fue interrumpido\nRevisa el estado"
                      : "Previous backup was interrupted\nCheck backup status"));

            if (retry && !journal_backed) {
                pthread_mutex_lock(&s_titles_lock);
                title_t* title = NULL;
                for (size_t i = 0; i < s_title_count; i++)
                    if (strcmp(s_titles[i].user_uid, state.user_uid) == 0 &&
                        strcmp(s_titles[i].title_id, state.title_id) == 0) {
                        title = &s_titles[i];
                        break;
                    }
                if (title && !title->upload_in_flight) {
                    title->upload_in_flight = true;
                    title->dirty = true;
                    title->last_dirty_unix = now_unix();
                    log_info("backup-queue: retrying interrupted final backup key=%s/%s",
                             state.user_uid, state.title_id);
                    if (enqueue(state.user_uid, state.title_id, false, false,
                                NULL, title->last_dirty_unix, "GameClose",
                                state.destination[0] &&
                                    strcmp(state.destination, "default") != 0
                                        ? state.destination : NULL,
                                "interrupted_retry"))
                        queued_retry = true;
                    else
                        title->upload_in_flight = false;
                } else if (!title) {
                    log_warn("backup-queue: cannot retry interrupted final backup; "
                             "save not found key=%s/%s", state.user_uid,
                             state.title_id);
                } else {
                    log_info("backup-queue: interrupted final backup already queued key=%s/%s",
                             state.user_uid, state.title_id);
                    queued_retry = true;
                }
                pthread_mutex_unlock(&s_titles_lock);
            }
        }
        int64_t state_at = state.completed_at > 0
            ? state.completed_at : state.started_at;
        if (state_at >= latest_at) {
            latest_at = state_at;
            latest = state;
        }
    }
    closedir(dir);
    if (!queued_retry && latest.title_id[0]) {
        int ui_state = strcmp(latest.status, "complete") == 0 ? 1 :
                       strcmp(latest.status, "failed") == 0 ? 0 :
                       strcmp(latest.status, "running") == 0 ? 2 :
                       strcmp(latest.status, "pending") == 0 ? 5 :
                       strcmp(latest.status, "interrupted") == 0 ? 4 : 3;
        const char* message = latest.detail[0] ? latest.detail :
                              ui_state == 1 ? "Last backup completed" :
                              ui_state == 4 ? "Last backup interrupted" :
                              ui_state == 5 ? "Pending final backup" :
                              latest.status;
        set_last_backup_at(latest.title_id, ui_state, message, latest_at);
    }
}

static job_t* dequeue_blocking(void) {
    pthread_mutex_lock(&s_q_lock);
    job_t* j = NULL;
    job_t* previous = NULL;
    bool admitted = false;
    while (s_running) {
        // Keep deferred backups in their original queue position. Admission
        // grants their full-job read lease before any checkpoint or save I/O.
        j = s_q_head;
        previous = NULL;
        if (j && lifecycle_operation_begin()) {
            admitted = j->is_restore || save_io_try_begin_read();
            if (admitted) break;
            // A retained rollback may clear the recovery barrier that blocks
            // this head backup. Its worker still checks UID and RAW markers.
            for (previous = j; previous->next; previous = previous->next) {
                if (previous->next->is_restore &&
                    strcmp(previous->next->restore_ref, "rollback:retained") == 0) {
                    j = previous->next;
                    break;
                }
            }
            if (previous->next) { admitted = true; break; }
            lifecycle_operation_end();
        }
        // A rejected reservation may return to RUNNING without a queue write.
        // The bounded wait lets the same untouched job retry admission then.
        struct timespec until;
        clock_gettime(CLOCK_REALTIME, &until);
        until.tv_sec++;
        pthread_cond_timedwait(&s_q_cond, &s_q_lock, &until);
    }
    if (!admitted) j = NULL;
    if (j) {
        if (previous) previous->next = j->next;
        else s_q_head = j->next;
        if (s_q_tail == j) s_q_tail = previous;
        s_q_depth--;
        atomic_fetch_add(&s_jobs_active, 1);
    }
    pthread_mutex_unlock(&s_q_lock);
    return j;
}

int watcher_queue_depth(void) { return s_q_depth; }
int watcher_active_jobs(void) { return s_jobs_active + (raw_selected_commit_active() ? 1 : 0); }

// --------------------------------------------------------------------
// Worker.
// --------------------------------------------------------------------

static bool restore_dir_has_savedata0(const char* dir);
static bool restore_dir_has_sdimg(const char* dir);

static void finish_backup_job(const job_t* job, const upload_result_t* result,
                               backup_retry_t* saved_retry) {
    pthread_mutex_lock(&s_titles_lock);
    for (size_t i = 0; i < s_title_count; i++) {
        title_t* t = &s_titles[i];
        if (strcmp(t->title_id, job->title_id) != 0 ||
            strcmp(t->user_uid, job->user_uid) != 0)
            continue;
        if (result->copied) {
            t->last_crc32       = result->crc;
            t->last_zip_size    = result->zip_size;
            t->last_upload_unix = now_unix();
        }
        backup_retry_t recovered;
        if (!job->force_backup && !saved_retry) {
            if (!backup_retry_load(job->user_uid, job->title_id, &recovered)) {
                backup_retry_init(&recovered, job->user_uid, job->title_id,
                                  job->trigger);
                recovered.usb_no_replay = job->retrying || t->backup_usb_no_replay;
                if (recovered.usb_no_replay) recovered.pending_mask &= ~1U;
            }
            saved_retry = &recovered;
        }
        if (saved_retry && saved_retry->last_upload_unix > t->last_upload_unix)
            t->last_upload_unix = saved_retry->last_upload_unix;
        if (saved_retry && result->usb_no_replay) saved_retry->usb_no_replay = true;
        unsigned blocked = (result->usb_no_replay ||
            (saved_retry && saved_retry->usb_no_replay)) ? 1U : 0U;
        bool generic_retry = (!result->usb_no_replay &&
                              strcmp(result->status, "failed") == 0) ||
            strcmp(result->detail, "Restore is settling") == 0 ||
            strcmp(result->detail,
                "Previous restore requires recovery; use Restore previous save") == 0;
        unsigned retry_mask = (result->retry_mask ? result->retry_mask :
                               generic_retry ? 3U : 0U) & ~blocked;
        bool canceled=backup_control_cancelled();
        if (canceled) {retry_mask=0;blocked=3U;}
        bool retry = !job->force_backup && retry_mask;
        if (!job->force_backup) t->backup_usb_no_replay = blocked!=0;
        else {
            backup_retry_t manual_backlog;
            if (backup_retry_load(job->user_uid, job->title_id, &manual_backlog)) {
                t->backup_usb_no_replay = manual_backlog.usb_no_replay;
                if (manual_backlog.usb_no_replay) {
                    t->backup_retry_mask &= ~1U;
                    t->backup_retry_dirty_unix = manual_backlog.dirty_unix;
                    t->backup_retry_journal = true;
                }
            }
        }
        if (retry) {
            t->dirty = true;
            if (t->backup_retry_failures < 5) t->backup_retry_failures++;
            t->backup_retry_at = now_unix() +
                dest_retry_delay_seconds(t->backup_retry_failures);
            t->backup_retry_mask = retry_mask;
            t->backup_retry_dirty_unix = job->dirty_unix;
            snprintf(t->backup_retry_trigger, sizeof(t->backup_retry_trigger),
                     "%s", job->trigger);
            log_info("backup-queue: retry pending key=%s/%s delay_seconds=%u destinations=%u",
                     job->user_uid, job->title_id,
                     dest_retry_delay_seconds(t->backup_retry_failures),
                     t->backup_retry_mask);
        } else if (!job->force_backup || !t->backup_retry_at) {
            t->backup_retry_at = 0;
            t->backup_retry_failures = 0;
            t->backup_retry_mask = 0;
            if (t->last_dirty_unix <= job->dirty_unix) t->dirty = false;
        }
        if (!job->force_backup && !canceled) {
            saved_retry->active = retry;
            saved_retry->dirty_unix = job->dirty_unix;
            saved_retry->last_upload_unix = t->last_upload_unix;
            saved_retry->retry_at = t->backup_retry_at;
            saved_retry->failures = t->backup_retry_failures;
            saved_retry->pending_mask = retry ? t->backup_retry_mask : 0;
            saved_retry->planned_mask |= saved_retry->pending_mask;
            t->backup_retry_planned_mask = saved_retry->planned_mask;
            snprintf(saved_retry->reason, sizeof(saved_retry->reason), "%s", job->trigger);
            // Do not release this title for another job until its checkpoint
            // is committed. On failure the earlier durable intent remains.
            if (!backup_retry_save(saved_retry)) {
                t->dirty = true;
                t->backup_retry_at = now_unix() + 30;
                t->backup_retry_mask = (saved_retry->planned_mask
                    ? saved_retry->planned_mask : 3U) & ~blocked;
                if (!t->backup_retry_mask) {
                    t->backup_retry_at = 0;
                    if (t->last_dirty_unix <= job->dirty_unix) t->dirty = false;
                }
                t->backup_retry_dirty_unix = job->dirty_unix;
                snprintf(t->backup_retry_trigger, sizeof(t->backup_retry_trigger),
                         "%s", job->trigger);
            }
        }
        t->upload_in_flight = false;
        if (t->observation_job == jobs_watch_id(job->job_id)) t->observation_job = 0;
        break;
    }
    pthread_mutex_unlock(&s_titles_lock);
    jobs_ref_t observation = jobs_watch_id(job->job_id);
    jobs_backup_detail(observation, result->detail);
    if (!strcmp(result->status, "canceled")) {
        jobs_phase(observation, NULL, "skipped", 0, false);
        jobs_finish(observation, JOB_DONE, "backup_skipped");
    } else jobs_finish(observation, (!strcmp(result->status,"unknown") || !strcmp(result->status,"unconfirmed")) ? JOB_UNKNOWN : !strcmp(result->status, "complete") ? JOB_DONE : JOB_FAILED,
                       !strcmp(result->status,"unconfirmed") ? "backup_unconfirmed" : !strcmp(result->status,"unknown") ? "backup_cancel_unsaved" : !strcmp(result->status, "complete") ? NULL : backup_control_cancelled()?"backup_canceled":"backup_failed");
}

static bool dest_attemptable(const char* dest, const config_t* cfg) {
    if (!dest || !cfg) return false;
    if (strcmp(dest, "usb") == 0)
        return cfg->usb.enabled && usb_is_present();
    if (strcmp(dest, "drive") == 0)
        return gdrive_get_state() == GDRIVE_STATE_READY;
    return false;
}

static bool dest_retry_attemptable(const char* dest, const config_t* cfg) {
    return dest_attemptable(dest, cfg) ||
        (dest && strcmp(dest, "drive") == 0 && gdrive_recovery_due());
}

static bool dest_configured(const char* dest, const config_t* cfg) {
    if (strcmp(dest, "usb") == 0) return cfg->usb.enabled;
    if (strcmp(dest, "drive") == 0) {
        gdrive_state_t state = gdrive_get_state();
        return state == GDRIVE_STATE_READY || state == GDRIVE_STATE_ERROR;
    }
    return false;
}

static unsigned backup_configured_mask(const config_t* cfg) {
    static const char* defaults[] = { "drive", "usb" };
    size_t count = cfg->destinations.order_count;
    if ((!count && !cfg->destinations.order_explicit) || count > CFG_MAX_DESTS) count = 2;
    unsigned mask = 0;
    for (size_t i = 0; i < count; i++) {
        const char* d = cfg->destinations.order_count ? cfg->destinations.order[i] : defaults[i];
        int index = dest_fingerprint_index(d);
        if (index >= 0 && dest_configured(d, cfg)) mask |= 1U << index;
    }
    return mask;
}

static bool dest_fingerprint_path(char* out, size_t out_sz,
                                  const char* user_uid, const char* title_id,
                                  const char* dest, const char* identity) {
    if ((dest_fingerprint_index(dest) < 0 && (!dest || strcmp(dest, "ftp"))) ||
        !dest_fingerprint_hex(identity))
        return false;
    // One small record per real target, so switching A -> B -> A keeps A's
    // confirmation across restarts without a growing in-memory cache.
    int n = snprintf(out, out_sz, "%s/fingerprint.v3.%s.%s.%s.%s",
             s_cfg->paths.state_dir,
             (user_uid && user_uid[0]) ? user_uid : "default", title_id,
             dest, identity);
    return n > 0 && (size_t)n < out_sz;
}

static void dest_fingerprints_load(const char* user_uid, const char* title_id,
                                   const char* dest, const char* identity,
                                   dest_fingerprint_t* out) {
    memset(out, 0, sizeof(*out));
    char path[512];
    if (!dest_fingerprint_path(path, sizeof(path), user_uid, title_id,
                               dest, identity)) return;
    int fd = open(path, O_RDONLY | O_NOFOLLOW | O_NONBLOCK);
    if (fd < 0) return;
    struct stat st;
    if (fstat(fd, &st) != 0 || !S_ISREG(st.st_mode)) { close(fd); return; }
    FILE* f = fdopen(fd, "r");
    if (!f) { close(fd); return; }
    dest_fingerprint_read(f, out);
    fclose(f);
}

static bool dest_fingerprints_save(const char* user_uid, const char* title_id,
                                   const char* dest,
                                   const dest_fingerprint_t* state) {
    char path[512], tmp[540] = {0};
    int dirfd = -1, fd = -1;
    bool ok = false;
    if (dest_fingerprint_index(dest) < 0 || !state ||
        !dest_fingerprint_path(path, sizeof(path), user_uid, title_id,
                                         dest, state->identity)) goto done;
    struct stat st;
    if (lstat(path, &st) == 0 ? !S_ISREG(st.st_mode) : errno != ENOENT) goto done;
    snprintf(tmp, sizeof(tmp), "%s.tmp.XXXXXX", path);
    dirfd = open(s_cfg->paths.state_dir, O_RDONLY | O_DIRECTORY | O_NOFOLLOW);
    if (dirfd < 0) goto done;
    fd = mkstemp(tmp); // Exclusive private file, never reuse a stale PID temp.
    if (fd < 0) goto done;
    bool private_file = fchmod(fd, 0600) == 0;
    FILE* f = fdopen(fd, "w");
    if (!f) { close(fd); goto done; }
    ok = private_file && dest_fingerprint_write(f, state) &&
         fflush(f) == 0 && fsync(fileno(f)) == 0;
    if (fclose(f) != 0) ok = false;
    if (ok) ok = rename(tmp, path) == 0;
    if (ok && fsync(dirfd) != 0) {
        // Match the retry journal's filesystem boundary. Unsupported directory
        // sync is not a power-loss guarantee; ordinary I/O errors fail closed.
        ok = errno == EINVAL || errno == ENOTSUP;
    }
done:
    if (dirfd >= 0 && close(dirfd) != 0) ok = false;
    if (!ok) {
        if (fd >= 0) unlink(tmp);
        log_warn("backup dedupe: could not save %s confirmation; next backup may repeat", dest);
    }
    return ok;
}

static bool dest_current_identity(const char* dest, const char* store_key,
                                   const char* title_id, char out[65]) {
    out[0] = '\0';
    if (strcmp(dest, "usb") == 0)
        return usb_backup_identity(store_key, title_id, out);
    if (strcmp(dest, "drive") == 0)
        return gdrive_backup_identity(store_key, title_id, out);
    return false;
}

// A receipt proves a past upload, not current existence. Every skip path,
// including a recovered partial job, must revalidate the specific archive.
// No background polling: this runs only for an otherwise matching backup.
// ponytail: identity/ref/size check presence, not full content integrity;
// use a separate integrity audit to detect same-size external modifications.
static bool dest_receipt_present(const char* dest, const char* store_key,
                                  const char* title_id,
                                  const dest_fingerprint_t* receipt) {
    if (strcmp(dest, "usb") == 0)
        return usb_backup_exists(store_key, title_id, receipt->ref,
                                 receipt->size_bytes, receipt->identity);
    if (strcmp(dest, "drive") == 0)
        return gdrive_backup_exists(store_key, title_id, receipt->ref,
                                    receipt->size_bytes, receipt->identity);
    return false;
}

static bool note_destination_fingerprint(const char* user_uid,
                                         const char* title_id,
                                         const char* dest,
                                         const char sha256[65],
                                         const char identity[65],
                                         const char* ref, uint64_t size_bytes) {
    dest_fingerprint_t state = {0};
    if (!dest_fingerprint_record(&state, identity, sha256, ref, size_bytes, true)) {
        log_info("backup dedupe: %s copy succeeded but receipt is incomplete; not caching", dest);
        return false;
    }
    return dest_fingerprints_save(user_uid, title_id, dest, &state);
}

// USB rename/FTP STOR can overwrite the same name (same-second manual jobs or
// clock rollback). Old same-size proof must not survive a failed replacement.
// Invalidate across identities: the actual target may change before the copy.
// ponytail: scan the small receipt directory only on copies; index if target
// churn makes this measurable, not a remote lookup or background poll.
static bool dest_receipts_before_copy(const char* user_uid, const char* title_id,
                                      const char* dest, const char* filename) {
    if (strcmp(dest, "usb")) return true;
    char prefix[128];
    int n = snprintf(prefix, sizeof(prefix), "fingerprint.v3.%s.%s.%s.",
                     user_uid, title_id, dest);
    if (n < 0 || (size_t)n >= sizeof(prefix)) return false;
    int dirfd = open(s_cfg->paths.state_dir, O_RDONLY | O_DIRECTORY | O_NOFOLLOW);
    if (dirfd < 0) return false;
    DIR* dir = fdopendir(dirfd);
    if (!dir) { close(dirfd); return false; }
    bool ok = true;
    for (;;) {
        errno = 0;
        struct dirent* e = readdir(dir);
        if (!e) { if (errno) ok = false; break; }
        if (strncmp(e->d_name, prefix, (size_t)n) ||
            !dest_fingerprint_hex(e->d_name + n)) continue;
        int fd = toston_openat(dirfd, e->d_name, O_RDONLY | O_NOFOLLOW | O_NONBLOCK, 0);
        if (fd < 0) { if (errno == ENOENT) continue; ok = false; break; }
        struct stat st;
        if (fstat(fd, &st) || !S_ISREG(st.st_mode)) { close(fd); ok = false; break; }
        FILE* f = fdopen(fd, "r");
        if (!f) { close(fd); ok = false; break; }
        dest_fingerprint_t proof = {0};
        bool valid = dest_fingerprint_read(f, &proof);
        bool readable = !ferror(f);
        if (fclose(f) || !readable) { ok = false; break; }
        if (valid && !strcmp(proof.identity, e->d_name + n) &&
            !strcmp(proof.ref, filename) && unlinkat(dirfd, e->d_name, 0)) {
            ok = false; break;
        }
    }
    // Unlike a new receipt, an old reusable proof must be durably gone before
    // overwriting its archive. Unsupported sync cannot authorize that overwrite.
    if (ok && fsync(dirfd)) ok = false;
    if (closedir(dir)) ok = false;
    if (!ok) log_warn("backup dedupe: could not invalidate %s overwrite proof; copy not started", dest);
    return ok;
}

static void dest_list_add(char* list, size_t list_sz, const char* dest) {
    if (!list || list_sz == 0 || !dest || !dest[0]) return;
    if (list[0]) strncat(list, ",", list_sz - strlen(list) - 1);
    strncat(list, dest, list_sz - strlen(list) - 1);
}

// Try ONE backup destination ("usb"/"ftp"/"drive"). Returns true only if the
// copy actually landed. A destination that is disabled or unavailable returns
// false WITHOUT an error log, so cascade mode can quietly move to the next.
static bool dest_try(const char* dest, const config_t* cfg,
                     const char* store_key, const char* title_id,
                     const char* filename, const char* staging,
                     uint64_t zsize, const char* user_alias,
                     char out_identity[65], char out_ref[128], bool allow_marker,
                     backup_destination_failure_t* failure) {
    *failure = (backup_destination_failure_t){0};
    out_identity[0] = '\0';
    out_ref[0] = '\0';
    if (strcmp(dest, "usb") == 0) {
        if (!cfg->usb.enabled) { failure->code = BACKUP_USB_DISABLED; return false; }
        if (!usb_is_present()) { failure->code = BACKUP_USB_ABSENT; return false; }
        set_last_backup(title_id, 2, "Writing USB backup");
        jobs_phase(jobs_bound(), dest, "transferring", zsize, true);
        if (usb_copy_backup_authorized(store_key, title_id, filename, staging,
                                       out_identity, false, allow_marker)) {
            snprintf(out_ref, 128, "%s", filename);
            return true;
        }
        log_warn("watcher: USB backup failed for %s/%s", user_alias, title_id);
        failure->code = backup_usb_failure(usb_last_copy_failure());
        return false;
    }

    if (strcmp(dest, "drive") == 0) {
        gdrive_state_t drive_state = gdrive_get_state();
        if (drive_state != GDRIVE_STATE_READY) {
            failure->code = backup_drive_unavailable(drive_state); return false;
        }
        uint64_t title_cap = retention_parse_size(
            cfg->retention.max_total_size_per_title_str);
        if (title_cap && zsize > title_cap) {
            // Retention would immediately delete this archive, so it cannot
            // become a successful-copy confirmation for dedupe.
            log_warn("watcher: Drive backup exceeds the per-title retention cap");
            *failure = (backup_destination_failure_t){BACKUP_DRIVE_TITLE_CAP, 0, title_cap, zsize};
            return false;
        }
        retention_global_decision_t decision;
        if (retention_check_global(cfg, zsize, &decision)) {
            log_warn("watcher: skipping Drive upload — global cap would be exceeded");
            *failure = (backup_destination_failure_t){BACKUP_DRIVE_GLOBAL_CAP,
                decision.counted_bytes, decision.cap_bytes, zsize};
            return false;
        }
        char file_id[GDRIVE_FILEID_MAX] = {0};
        jobs_phase(jobs_bound(), dest, "transferring", zsize, true);
        if (gdrive_upload_identified(store_key, title_id, filename, staging,
                                     file_id, out_identity)) {
            snprintf(out_ref, 128, "%s", file_id);
            return true;
        }
        log_warn("watcher: Drive upload failed for %s/%s", user_alias, title_id);
        failure->code = BACKUP_DRIVE_FAILED;
        return false;
    }
    return false;
}

// Housekeeping must not sit between provider acceptance and its checkpoint.
// ponytail: no distributed transaction; a crash before the receipt may repeat
// the copy. Never infer acceptance from an unconfirmed filename or size alone.
static void dest_post_copy(const char* dest, const config_t* cfg,
                            const char* store_key, const char* title_id,
                            const char* ref, const char* copied_identity) {
    // Unknown identity proves neither that cleanup is still on the copied
    // target nor that an older catalog belongs to it. Never prune in that case.
    if (!ref || !ref[0] || !dest_fingerprint_hex(copied_identity)) return;
    if (strcmp(dest, "usb") == 0) {
        if (!usb_enforce_retention_identified(store_key, title_id, ref, copied_identity))
            log_warn("retention: USB cleanup deferred; accepted copy remains confirmed");
    }
    else if (strcmp(dest, "drive") == 0) {
        retention_result_t result = retention_enforce_title_identified(
            cfg, store_key, title_id, ref, copied_identity);
        if (!result.deferred) gdrive_refresh_quota();
    }
}

// Friendly destination names for on-screen toasts. Internal tokens
// (usb/drive/ftp/local) become human labels; a multi-destination list like
// "usb,drive" becomes "USB + Google Drive".
static const char* dest_pretty(const char* d) {
    if (!d) return "";
    if (strcmp(d, "usb")   == 0) return "USB";
    if (strcmp(d, "drive") == 0) return "Google Drive";
    if (strcmp(d, "ftp")   == 0) return "FTP";
    if (strcmp(d, "local") == 0) return "local storage";
    return d;
}
static void dests_pretty(const char* dests, char* out, size_t n) {
    if (!out || n == 0) return;
    out[0] = '\0';
    char tmp[64];
    snprintf(tmp, sizeof(tmp), "%s", dests ? dests : "");
    char* sp = NULL;
    for (char* tok = strtok_r(tmp, ",", &sp); tok; tok = strtok_r(NULL, ",", &sp)) {
        const char* p = dest_pretty(tok);
        if (out[0]) strncat(out, " + ", n - strlen(out) - 1);
        strncat(out, p, n - strlen(out) - 1);
    }
}

typedef struct {
    uint64_t bytes;
    uint64_t active_bytes;
    uint64_t hash_xor;
    uint64_t hash_sum;
    size_t   files;
    size_t   active_files;
    size_t   active_images;
    size_t   service_images;
    size_t   missing_service_images;
    char     first_missing[128];
} raw_snapshot_t;

static uint64_t raw_meta_hash(const char* name, const struct stat* st) {
    uint64_t h = 1469598103934665603ULL;
    for (const unsigned char* p = (const unsigned char*)name; *p; p++) {
        h ^= *p;
        h *= 1099511628211ULL;
    }
    h ^= (uint64_t)st->st_size;
    h *= 1099511628211ULL;
    h ^= (uint64_t)st->st_mtime;
#if defined(__APPLE__)
    h ^= (uint64_t)st->st_mtimespec.tv_nsec;
#else
    h ^= (uint64_t)st->st_mtim.tv_nsec;
#endif
    return h;
}

static bool raw_snapshot_capture(const char* dir, raw_snapshot_t* out) {
    if (!dir || !out) return false;
    memset(out, 0, sizeof(*out));
    char active[64][128];
    size_t active_count = 0;
    DIR* d = opendir(dir);
    if (!d) return false;
    struct dirent* e;
    while ((e = readdir(d)) != NULL) {
        if (strcmp(e->d_name, ".") == 0 || strcmp(e->d_name, "..") == 0)
            continue;
        char path[512];
        int n = snprintf(path, sizeof(path), "%s/%s", dir, e->d_name);
        struct stat st;
        if (n < 0 || (size_t)n >= sizeof(path) || stat(path, &st) != 0)
            continue;
        if (!S_ISREG(st.st_mode)) continue;
        out->bytes += (uint64_t)st.st_size;
        out->files++;
        if (strncmp(e->d_name, "sdimg_sce_bu_", 13) == 0) {
            out->service_images++;
        } else {
            uint64_t h = raw_meta_hash(e->d_name, &st);
            out->hash_xor ^= h;
            out->hash_sum += h;
            out->active_bytes += (uint64_t)st.st_size;
            out->active_files++;
            if (strncmp(e->d_name, "sdimg_", 6) == 0) {
                out->active_images++;
                if (active_count < sizeof(active) / sizeof(active[0]))
                    snprintf(active[active_count++], sizeof(active[0]), "%s",
                             e->d_name + 6);
                else
                    out->missing_service_images++;
            }
        }
    }
    closedir(d);

    // Internal service images are optional. We record missing pairs only so
    // the UI/log can warn; normal restore uses the active images.
    if (out->service_images > 0) {
        for (size_t i = 0; i < active_count; i++) {
            char path[512];
            struct stat st;
            int n = snprintf(path, sizeof(path), "%s/sdimg_sce_bu_%s",
                             dir, active[i]);
            if (n >= 0 && (size_t)n < sizeof(path) &&
                stat(path, &st) == 0 && S_ISREG(st.st_mode))
                continue;
            out->missing_service_images++;
            if (!out->first_missing[0])
                snprintf(out->first_missing, sizeof(out->first_missing),
                         "sdimg_sce_bu_%s", active[i]);
        }
    }
    return out->active_files > 0;
}

static bool raw_snapshot_equal(const raw_snapshot_t* a,
                               const raw_snapshot_t* b) {
    return a && b && a->active_bytes == b->active_bytes &&
           a->active_files == b->active_files &&
           a->hash_xor == b->hash_xor && a->hash_sum == b->hash_sum &&
           a->active_images == b->active_images;
}

static bool raw_service_images_incomplete(const raw_snapshot_t* s) {
    return s && s->service_images > 0 && s->missing_service_images > 0;
}

static const char* raw_completeness(const raw_snapshot_t* s) {
    if (!s || s->service_images == 0) return "active_only_no_service_images";
    return raw_service_images_incomplete(s) ? "active_only_warning" : "complete";
}

// Acknowledgement is volatile. Only this one durable write authorizes a final
// cancellation; an I/O error stays UNKNOWN without an in-process retry.
static bool backup_cancel_record(const char* uid,const char* title,int64_t dirty,const char* reason,bool isolated) {
    backup_control_t* control=backup_control_bound();
    if(!control||!backup_control_cancelled())return false;
    if(control->cancel_result)return control->cancel_result>0;
    backup_retry_t state;
    if(isolated||!backup_retry_load(uid,title,&state))backup_retry_init(&state,uid,title,reason);
    state.cancel_guard=true;state.active=false;state.usb_no_replay=true;
    state.dirty_unix=dirty;state.pending_mask=state.planned_mask=0;
    state.retry_at=0;state.failures=0;
    bool ok;
    if(isolated){
        // Forced manual/individual work must not replace another automatic backlog.
        char path[512];int n=snprintf(path,sizeof(path),"%s/jobs/manual-cancel.%s.%llu",
            s_cfg->paths.state_dir,s_run_id,(unsigned long long)control->id);
        ok=n>0&&(size_t)n<sizeof(path)&&backup_retry_write(path,&state);
    }else ok=backup_retry_save(&state);
    control->cancel_result=ok?1:-1;
    if(!ok)log_warn("backup cancellation: request could not be saved; restart recovery is uncertain; no in-process retry");
    return ok;
}

static void backup_cleanup_staging(const char* path) {
    backup_control_t* control=backup_control_bound();
    if(!control||atomic_load(&control->state)==4){unlink(path);return;}
    if (!backup_control_publish_begin()) return;
    unlink(path);
    backup_control_publish_end(false,0);
}

static void do_upload_job_inner(const char* user_uid, const char* title_id,
                                int64_t dirty_unix, bool force_backup,
                                const char* trigger,
                                const char* destination,
                                upload_result_t* result,
                                backup_job_state_t* job_state,
                                const char* state_path,
                                backup_retry_t* retry, bool retrying) {
    // Read a consistent config snapshot for this whole job. `s_cfg` below
    // intentionally SHADOWS the shared global so every s_cfg-> access in this
    // function reads the local copy, never a half-applied Settings save.
    config_t cfgsnap;
    const config_t* s_cfg = config_snapshot(&cfgsnap) ? &cfgsnap : NULL;
    if (!s_cfg) {
        log_warn("watcher: no config for upload of %s", title_id);
        upload_result_set(result, "failed", "No configuration available");
        return;
    }
    if (restore_recovery_required(s_cfg)) {
        upload_result_set(result, "canceled",
                          "Previous restore requires recovery; use Restore previous save");
        return;
    }
    pthread_mutex_lock(&s_titles_lock);
    title_t* t = NULL;
    for (size_t i = 0; i < s_title_count; i++)
        if (strcmp(s_titles[i].title_id, title_id) == 0 &&
            strcmp(s_titles[i].user_uid, user_uid ? user_uid : "") == 0) {
            t = &s_titles[i]; break;
        }
    if (!t) {
        pthread_mutex_unlock(&s_titles_lock);
        upload_result_set(result, "canceled", "Save is no longer registered");
        return;
    }
    char src_path[256];
    strncpy(src_path, t->path, sizeof(src_path) - 1);
    src_path[sizeof(src_path) - 1] = '\0';
    char game[64];
    strncpy(game, t->game_name, sizeof(game) - 1);
    game[sizeof(game) - 1] = '\0';
    uint32_t prev_crc      = t->last_crc32;
    uint64_t prev_zip_size = t->last_zip_size;
    int64_t  prev_upload   = t->last_upload_unix;
    pthread_mutex_unlock(&s_titles_lock);

    set_last_backup(title_id, 2,
                    trigger && strcmp(trigger, "GameClose") == 0
                        ? "Final backup running…" : "Preparing backup");

    // A restore into this title is in progress (or just finished): its writes
    // are not a real in-game change. Do not race it with a backup.
    if (backup_suppressed(title_id)) {
        log_info("watcher: skipping backup for %s — restore in progress/just finished",
                 title_id);
        set_last_backup(title_id, 3, "Skipped while restore is settling");
        upload_result_set(result, "canceled", "Restore is settling");
        return;
    }

    // A manual/UI backup (force_backup) deliberately ignores the include/
    // exclude filters, as the UI advertises. Only the automatic path honours
    // title_allowed().
    if (!force_backup && !title_allowed(title_id)) {
        set_last_backup(title_id, 3, "Excluded by backup settings");
        upload_result_set(result, "canceled", "Excluded by backup settings");
        return;
    }

    // Resolve a stable, friendly user alias for every destination. When
    // no user_uid is recorded (e.g. legacy upload paths), fall back to
    // "default" so we still land somewhere reasonable.
    const char* user_alias = config_alias_for_uid(user_uid);
    const char* job_uid = (user_uid && user_uid[0]) ? user_uid : "default";

    // Last-chance name resolution if metadata became readable after
    // discovery; persist it so future UI loads do not need the game open.
    if (!game[0] && titlename_lookup(title_id, game, sizeof(game)))
        set_title_name(title_id, game);

    char staging[300];
    char ts[32];
    time_t now = time(NULL);
    struct tm tm; gmtime_r(&now, &tm);
    strftime(ts, sizeof(ts), "%Y%m%dT%H%M%SZ", &tm);
    unsigned long stage_id = next_stage_seq();
    snprintf(staging, sizeof(staging),
             "%s/%s_%s_%s_%ld_%lu.zip", s_cfg->paths.staging_dir,
             job_uid, title_id, ts, (long)getpid(), stage_id);

    // Normal/manual/automatic backups are always raw encrypted images.
    // Portable exports belong exclusively to Transfer.
    const char* zip_source = src_path;

    uint32_t crc = 0;
    char fingerprint[65] = {0};
    uint64_t zsize = 0;
    bool backup_ready = false;
    bool service_warning = false;
    raw_snapshot_t final_snapshot = {0};
    const char* capture_error = "Could not inspect save files";
    for (int attempt = 1; attempt <= 3 && !backup_ready; attempt++) {
        if (backup_control_cancelled()) break;
        raw_snapshot_t before, after;
        bool captured=raw_snapshot_capture(zip_source, &before);
        if (backup_control_cancelled()) break;
        if (!captured) {
            log_warn("watcher: cannot inspect %s/%s before backup (attempt %d)",
                     user_alias, title_id, attempt);
            if (attempt < 3) sleep(2);
            continue;
        }

        // Build the manifest from the same snapshot that the ZIP must match.
        char manifest[1536];
        char created_utc[32];
        struct tm gm; gmtime_r(&now, &gm);
        strftime(created_utc, sizeof(created_utc), "%Y-%m-%dT%H:%M:%SZ", &gm);
        const char* platform = (strncmp(title_id, "PPSA", 4) == 0) ? "PS5" :
                               (strncmp(title_id, "CUSA", 4) == 0) ? "PS4" : "";
        char m_name[96], m_console[64], m_console_type[32], m_missing[160];
        json_clean(game[0] ? game : title_id, m_name, sizeof(m_name));
        json_clean(s_cfg->console.name[0] ? s_cfg->console.name : "This PS5",
                   m_console, sizeof(m_console));
        json_clean(s_cfg->console.type[0] ? s_cfg->console.type : "PS5",
                   m_console_type, sizeof(m_console_type));
        json_clean(before.first_missing, m_missing, sizeof(m_missing));
        const char* backup_type = "RAW";
        const char* file_trigger = backup_trigger_name(trigger);
        snprintf(manifest, sizeof(manifest),
            "{\"format\":\"%s\",\"format_version\":1,"
            "\"tostonsync_version\":\"%s\",\"backup_format\":1,"
            "\"title_id\":\"%s\",\"title_name\":\"%s\",\"platform\":\"%s\","
            "\"backup_type\":\"%s\",\"trigger\":\"%s\","
            "\"user_uid\":\"%s\",\"source_console_name\":\"%s\"," 
            "\"source_console_type\":\"%s\"," 
            "\"created_at_utc\":\"%s\",\"created_at_epoch\":%lld,"
            "\"total_size\":%llu,\"raw_completeness\":\"%s\","
            "\"active_images\":%zu,\"service_images\":%zu,"
            "\"missing_service_images\":%zu,"
            "\"first_missing_service_image\":\"%s\"}",
            "tostonsync.encrypted_image",
            TOSTONSYNC_VERSION, title_id, m_name, platform,
            backup_type, file_trigger,
            job_uid, m_console, m_console_type, created_utc, (long long)now,
            (unsigned long long)before.bytes, raw_completeness(&before),
            before.active_images, before.service_images,
            before.missing_service_images, m_missing);

        bool zipped = zip_compress_directory_top_manifest_sha256(
            zip_source, title_id, staging, s_cfg->advanced.zip_mode_deflate,
            &crc, &zsize, manifest, fingerprint);
        if (backup_control_cancelled()) break;
        int nent = zipped ? zip_entry_count(staging) : 0;
        if (backup_control_cancelled()) break;
        bool stable = raw_snapshot_capture(zip_source, &after) &&
                      raw_snapshot_equal(&before, &after);
        if (backup_control_cancelled()) break;
        if (zipped && nent >= 2 && stable) {
            final_snapshot = after;
            service_warning = raw_service_images_incomplete(&after);
            backup_ready = true;
            break;
        }
        capture_error = (!zipped || nent < 2)
            ? "Could not create a valid backup ZIP"
            : "Backup failed: save was still changing";
        log_warn("Save was still changing; retrying backup for %s/%s "
                 "(attempt %d, entries=%d)",
                 user_alias, title_id, attempt, nent);
        backup_cleanup_staging(staging);
        if (attempt < 3) sleep(2);
    }
    if (!backup_ready) {
        set_last_backup(title_id, 0, capture_error);
        upload_result_set(result, "failed", capture_error);
        return;
    }
    if (job_state && state_path) {
        snprintf(job_state->fingerprint, sizeof(job_state->fingerprint), "%s",
                 fingerprint);
        backup_job_state_write(state_path, job_state);
    }
    if (prev_upload > 0 && zsize == prev_zip_size && crc != prev_crc)
        log_info("Save changed with same size — creating backup: %s/%s",
                 user_alias, title_id);
    // The shared constructor names uploads only; the archive bytes stay unchanged.
    const char* backup_type = "RAW";
    const char* file_trigger = backup_trigger_name(trigger);
    backup_names_t names;
    if (!backup_names_current(user_uid, title_id, game, file_trigger, now, &names)) {
        backup_cleanup_staging(staging);
        upload_result_set(result, "failed", "Backup names could not be validated");
        return;
    }
    char filename[128];
    snprintf(filename, sizeof(filename), "%s", names.filename);
    snprintf(game, sizeof(game), "%s", names.game);

    // Independent destinations. Any one succeeding counts as a backup,
    // so USB/FTP work with no Google sign-in and Drive works with no
    // drive plugged in. `dests` records which ones took the copy.
    bool any_ok = false;
    bool already_ok = false;
    char dests[64] = {0};
    char existing_dests[64] = {0};
    char failed_dests[64] = {0},canceled_dests[64]={0};
    bool checkpoint_failed=false;

    // Backups are stored under the STABLE PS5 user id (job_uid), never the
    // friendly alias. Renaming a user in the UI (e.g. 1234abcd -> "Alex")
    // therefore can NEVER split a user's saves into two destination folders —
    // the folder stays the UID and the UI shows the alias via the catalog's
    // canonicalization. (user_alias is kept only for human-readable logs.)
    const char* store_key = job_uid;

    // Walk the configured destination order. In cascade (fallback) mode we
    // STOP at the first that succeeds — so "if USB isn't there, go to Drive"
    // works, and a destination that's disabled/unavailable is skipped quietly.
    // In copy-to-all mode every enabled destination gets the backup.
    static const char* deford[CFG_MAX_DESTS] = { "drive", "usb" };
    const char* explicit_one = NULL;
    bool all_override = destination && strcmp(destination, "all") == 0;
    bool local_override = destination && strcmp(destination, "all-local") == 0;
    if (destination && (strcmp(destination, "usb") == 0 ||
                        strcmp(destination, "drive") == 0))
        explicit_one = destination;
    size_t nord = (explicit_one || all_override || local_override)
                    ? 2 : s_cfg->destinations.order_count;
    if ((!nord && !s_cfg->destinations.order_explicit) || nord > CFG_MAX_DESTS) nord = 2;
    const char* run_order[CFG_MAX_DESTS];
    for (size_t i = 0; i < nord; i++)
        run_order[i] = (explicit_one || all_override || local_override ||
                        !s_cfg->destinations.order_count)
                         ? deford[i] : s_cfg->destinations.order[i];
    bool final_copy_all = trigger && strcmp(trigger, "GameClose") == 0 &&
                          !explicit_one && !all_override && !local_override &&
                          !s_cfg->destinations.fallback;
    if (final_copy_all && dest_attemptable("usb", s_cfg)) {
        for (size_t i = 1; i < nord; i++)
            if (strcmp(run_order[i], "usb") == 0) {
                const char* first = run_order[0];
                run_order[0] = run_order[i];
                run_order[i] = first;
                break;
            }
        for (size_t i = 2; i < nord; i++)
            if (strcmp(run_order[i], "drive") == 0) {
                const char* second = run_order[1];
                run_order[1] = run_order[i];
                run_order[i] = second;
                break;
            }
    }
    if (retry) {
        result->usb_no_replay = retry->usb_no_replay;
        if (strcmp(retry->fingerprint, fingerprint) != 0)
            memset(retry->completed_identity, 0, sizeof(retry->completed_identity));
        snprintf(retry->fingerprint, sizeof(retry->fingerprint), "%s", fingerprint);
        retry->planned_mask = 0;
        for (size_t oi = 0; oi < nord; oi++) {
            const char* d = explicit_one ? explicit_one : run_order[oi];
            int index = dest_fingerprint_index(d);
            if (index >= 0 && !(local_override && strcmp(d, "drive") == 0) &&
                dest_configured(d, s_cfg)) retry->planned_mask |= 1U << index;
        }
        // Masks schedule work; only a matching identity AND a present archive
        // prove it can be skipped. Changed targets are new pending destinations.
        retry->pending_mask = retry->planned_mask & ~(retry->usb_no_replay ? 1U : 0U);
        if (!backup_retry_save(retry)) {
            backup_cleanup_staging(staging);
            upload_result_set(result, "failed", "Could not persist backup retry state");
            return;
        }
    }
    backup_destination_failure_t destination_failures[3] = {{0}};
    bool any_enabled = s_cfg->usb.enabled;
    for (size_t oi = 0; oi < nord; oi++) {
        const char* d = explicit_one ? explicit_one : run_order[oi];
        if (explicit_one && oi > 0) break;
        if (local_override && strcmp(d, "drive") == 0) continue;
        if(backup_control_cancelled()){
            if(dest_configured(d,s_cfg))dest_list_add(canceled_dests,sizeof(canceled_dests),d);
            continue;
        }
        if (force_backup && strcmp(d, "drive") == 0)
            (void)gdrive_activate(); // Actual manual Drive destination, not background retry.
        if (!strcmp(d, "drive") && gdrive_get_state() != GDRIVE_STATE_NOT_CONFIGURED)
            any_enabled = true;
        int dest_index = dest_fingerprint_index(d);
        if (dest_index < 0) continue;
        if (!dest_configured(d, s_cfg)) {
            destination_failures[dest_index].code = !strcmp(d, "usb") ? BACKUP_USB_DISABLED :
                backup_drive_unavailable(gdrive_get_state());
            continue;
        }
        if (dest_index == 0 && retry && retry->usb_no_replay) {
            result->usb_no_replay = true;
            destination_failures[0].code = BACKUP_USB_FAILED;
            dest_list_add(failed_dests, sizeof(failed_dests), d);
            continue;
        }
        // Recovery belongs in the worker, before fresh identity/receipt checks,
        // not in the scheduler or status polls. USB-first remains USB-first.
        if (strcmp(d, "drive") == 0 && gdrive_get_state() == GDRIVE_STATE_ERROR)
            (void)gdrive_ensure_ready();
        bool attempted = dest_attemptable(d, s_cfg);
        char identity[65] = {0};
        dest_fingerprint_t prev_dest_fingerprint = {0};
        bool use_dedupe = retrying || s_cfg->retention.dedup_by_hash;
        if (attempted && !force_backup && use_dedupe) {
            if (dest_current_identity(d, store_key, title_id, identity))
                dest_fingerprints_load(user_uid, title_id, d, identity,
                                        &prev_dest_fingerprint);
            else
                log_info("backup dedupe: %s identity unconfirmed; copy will not be skipped", d);
        }
        bool receipt_matches = attempted && !force_backup &&
            dest_fingerprint_matches(&prev_dest_fingerprint, identity, fingerprint,
                                     force_backup, use_dedupe);
        bool present = receipt_matches &&
            dest_receipt_present(d, store_key, title_id, &prev_dest_fingerprint);
        if (receipt_matches && !present)
            log_info("backup dedupe: %s archive missing or unconfirmed; copy required", d);
        // The retry journal's identity alone cannot bypass the existence check.
        if (present) {
            if (retry) {
                backup_retry_confirm(retry, dest_index, identity);
                if (!backup_retry_save(retry)) {
                    backup_cleanup_staging(staging);
                    upload_result_set(result, "failed", "Could not persist backup retry state");
                    return;
                }
            }
            already_ok = true;
            dest_list_add(existing_dests, sizeof(existing_dests), d);
            log_debug("watcher: %s/%s already present on %s; skipping destination",
                      user_alias, title_id, d);
            if (!all_override && !local_override &&
                (explicit_one || s_cfg->destinations.fallback)) break;
            continue;
        }
        bool drive_after_usb = false;
        if (final_copy_all && strcmp(d, "usb") == 0)
            for (size_t i = oi + 1; i < nord; i++)
                if (strcmp(run_order[i], "drive") == 0 &&
                    dest_attemptable("drive", s_cfg)) {
                    // Drive resolves its own current identity when its turn
                    // arrives. A USB confirmation says nothing about Drive.
                    drive_after_usb = true;
                    break;
                }
        if (attempted && job_state && state_path) {
            snprintf(job_state->destination, sizeof(job_state->destination),
                     "%s", d);
            backup_job_state_write(state_path, job_state);
        }
        if (attempted && !dest_receipts_before_copy(user_uid, title_id, d, filename)) {
            result->retry_mask = retry ? retry->pending_mask : 1U << dest_index;
            backup_cleanup_staging(staging);
            upload_result_set(result, "failed", "Could not invalidate backup overwrite confirmation");
            return;
        }
        backup_retry_t manual_usb_guard = {0};
        bool manual_usb_guarded = false;
        unsigned manual_usb_pending = 0;
        if (dest_index == 0) {
            // Commit the no-replay boundary before touching USB, including power loss.
            result->usb_no_replay = true;
            backup_retry_t* guard = retry;
            if (!guard && force_backup) {
                if (!backup_retry_load(user_uid, title_id, &manual_usb_guard)) {
                    backup_retry_init(&manual_usb_guard, user_uid, title_id, "Manual");
                    // Inactive USB-only intent blocks replay after a first manual failure
                    // without creating Drive/FTP work or an automatic retry schedule.
                    manual_usb_guard.active = false;
                    manual_usb_guard.planned_mask = 1U;
                    manual_usb_guard.pending_mask = 0;
                    manual_usb_guard.dirty_unix = dirty_unix;
                    snprintf(manual_usb_guard.fingerprint,
                             sizeof(manual_usb_guard.fingerprint), "%s", fingerprint);
                }
                // A manual attempt can observe newer content than an existing
                // backlog. Cover that generation without changing other pending
                // destinations, their schedule, fingerprint or confirmation proof.
                if (dirty_unix > manual_usb_guard.dirty_unix)
                    manual_usb_guard.dirty_unix = dirty_unix;
                manual_usb_guarded = true;
                manual_usb_pending = manual_usb_guard.pending_mask;
                guard = &manual_usb_guard;
            }
            if (guard) {
                guard->usb_no_replay = true;
                guard->pending_mask &= ~1U;
                if (!backup_retry_save(guard)) {
                    result->retry_mask = retry ? retry->pending_mask : 0;
                    backup_cleanup_staging(staging);
                    upload_result_set(result, "failed", "Could not persist USB one-attempt boundary");
                    return;
                }
            }
        }
        int64_t dest_started_ms = monotonic_ms();
        char copied_identity[65] = {0};
        char copied_ref[128] = {0};
        if (!attempted) {
            destination_failures[dest_index].code = !strcmp(d, "usb")
                ? BACKUP_USB_ABSENT : backup_drive_unavailable(gdrive_get_state());
            if (dest_index == 0) {
                usb_mount_t observed;
                if (usb_observe_selected(&observed)) {
                    usb_classify_mount(&observed, zsize, true);
                    if (observed.state != USB_READY && observed.state != USB_LOW_SPACE)
                        destination_failures[0].code = backup_usb_failure(
                            !strcmp(observed.reason, "file_too_large") ? observed.reason :
                            usb_state_name(observed.state));
                }
            }
        }
        bool provider_write=attempted && strcmp(d,"usb")!=0;
        bool publication_allowed=!provider_write || backup_control_publish_begin();
        bool dest_ok = attempted && publication_allowed && dest_try(d, s_cfg, store_key, title_id, filename,
                                staging, zsize, user_alias, copied_identity, copied_ref,
                                force_backup, &destination_failures[dest_index]);
        if (provider_write && publication_allowed) backup_control_publish_end(dest_ok,1U<<dest_index);
        int64_t dest_duration_ms = monotonic_ms() - dest_started_ms;
        if (dest_ok) {
            // Remember actual copies even if a later checkpoint or cancel fails.
            any_ok=true;dest_list_add(dests,sizeof(dests),d);
            // Checkpoint the provider's actual identity/ref immediately, before
            // logs, notifications, retention or another network operation.
            bool receipt_ok = note_destination_fingerprint(user_uid, title_id, d, fingerprint,
                                  copied_identity, copied_ref, zsize);
            if (!receipt_ok && dest_fingerprint_hex(copied_identity)) {
                result->unconfirmed_mask |= 1U << dest_index;
                result->retry_mask = retry ? retry->pending_mask : 1U << dest_index;
                if (dest_index == 0) result->retry_mask &= ~1U;
                log_warn("backup[job=%lu destination=%s]: copy accepted but receipt checkpoint failed",
                         job_state ? job_state->job_id : 0, d);
                upload_result_set(result, "unconfirmed", "Backup copied but confirmation could not be saved");
                checkpoint_failed=true;break;
            }
            // Unknown identity is a physical success, never reusable dedupe
            // proof. A recovered job still requires a fresh confirmed receipt.
            if (retry) {
                backup_retry_confirm(retry, dest_index, copied_identity);
                retry->last_upload_unix = now_unix();
                if (!backup_retry_save(retry)) {
                    result->retry_mask = retry->pending_mask | (1U << dest_index);
                    if (dest_index == 0) result->retry_mask &= ~1U;
                    log_warn("backup[job=%lu destination=%s]: copy accepted but retry checkpoint failed",
                             job_state ? job_state->job_id : 0, d);
                    upload_result_set(result, "failed", "Could not persist backup retry state");
                    checkpoint_failed=true;break;
                }
            }
            if (dest_index == 0 && dest_fingerprint_hex(copied_identity)) {
                if (manual_usb_guarded) {
                    manual_usb_guard.usb_no_replay = false;
                    manual_usb_guard.pending_mask = manual_usb_pending;
                    if (!backup_retry_save(&manual_usb_guard)) {
                        upload_result_set(result, "failed", "USB backup copied but confirmation could not be saved");
                        checkpoint_failed=true;break;
                    }
                }
                result->usb_no_replay = false;
            }
            // An accepted cancellation cannot be followed by retention deletion.
            if(backup_control_publish_begin()) {
                dest_post_copy(d, s_cfg, store_key, title_id, copied_ref, copied_identity);
                backup_control_publish_end(false,0);
            }
        }
        if (attempted)
            log_info("backup[job=%lu destination=%s]: %s duration_ms=%lld "
                     "size_bytes=%llu",
                     job_state ? job_state->job_id : 0, d,
                     dest_ok ? "complete" : "failed",
                     (long long)dest_duration_ms,
                     (unsigned long long)zsize);
        if (dest_ok) {
            log_info("activity:backup_complete|%s|%s|%lld",
                     game[0] ? game : title_id, d,
                     (long long)dest_duration_ms);
            if (drive_after_usb) {
                bool es = strcmp(s_cfg->general.language, "es") == 0;
                set_last_backup(title_id, 2,
                    "Safe local backup complete · USB: complete · Google Drive: uploading…");
                log_notify_level(NOTIFY_BALANCED, es
                    ? "Backup final guardado en USB\nGoogle Drive puede seguir sincronizando en segundo plano"
                    : "Final backup saved to USB\nGoogle Drive sync may continue in the background");
            }
            if (!all_override && !local_override &&
                (explicit_one || s_cfg->destinations.fallback)) break;
        } else if (backup_control_cancelled()) {
            dest_list_add(canceled_dests,sizeof(canceled_dests),d);
        } else if (attempted) {
            dest_list_add(failed_dests, sizeof(failed_dests), d);
        }
        if (!dest_ok && dest_index == 0) {
            result->usb_no_replay = true;
            if (retry) { retry->usb_no_replay = true; retry->pending_mask &= ~1U; }
        } else if (!dest_ok) result->retry_mask |= 1U << dest_index;
    }

    bool canceled=backup_control_finish_begin();
    if(canceled){
        result->retry_mask=0;result->usb_no_replay=true;
        for(size_t oi=0;oi<nord;oi++){
            const char* d=explicit_one?explicit_one:run_order[oi];
            if(explicit_one&&oi>0)break;
            if(local_override&&!strcmp(d,"drive"))continue;
            if(dest_configured(d,s_cfg)&&!strstr(dests,d)&&!strstr(failed_dests,d)&&!strstr(canceled_dests,d))
                dest_list_add(canceled_dests,sizeof(canceled_dests),d);
        }
    }
    if(checkpoint_failed&&!canceled){unlink(staging);return;}

    // Cascade promises one successful destination, not a copy on each one.
    if (s_cfg->destinations.fallback && !all_override && !local_override &&
        (any_ok || already_ok)) result->retry_mask = 0;

    if (retry && !canceled) {
        retry->pending_mask = result->retry_mask;
        if (!backup_retry_save(retry)) {
            backup_cleanup_staging(staging);
            upload_result_set(result, "failed", "Could not persist backup retry state");
            return;
        }
    }

    backup_cleanup_staging(staging);

    char failure_summary[768];
    backup_failure_summary(destination_failures, any_enabled, false,
                           failure_summary, sizeof(failure_summary));

    history_meta_t history_meta;
    memset(&history_meta, 0, sizeof(history_meta));
    snprintf(history_meta.raw_completeness,
             sizeof(history_meta.raw_completeness), "%s",
             raw_completeness(&final_snapshot));
    history_meta.active_images = final_snapshot.active_images;
    history_meta.service_images = final_snapshot.service_images;
    history_meta.missing_service_images =
        final_snapshot.missing_service_images;
    snprintf(history_meta.first_missing_service_image,
             sizeof(history_meta.first_missing_service_image), "%s",
             final_snapshot.first_missing);
    snprintf(history_meta.failed_dests, sizeof(history_meta.failed_dests),
             "%s", failed_dests);

    if(canceled){
        bool durable=backup_cancel_record(user_uid,title_id,dirty_unix,trigger,force_backup);
        history_meta.canceled=durable;history_meta.cancel_unknown=!durable;
        snprintf(history_meta.canceled_dests,sizeof(history_meta.canceled_dests),"%s",canceled_dests);
        snprintf(history_meta.status,sizeof(history_meta.status),"%s",any_ok?"partial":"failed");
        history_record(user_alias,title_id,game,filename,backup_type,file_trigger,zsize,crc,dests,&history_meta);
        snprintf(result->destination,sizeof(result->destination),"%s",dests);
        result->copied=any_ok;result->crc=crc;result->zip_size=zsize;
        upload_result_set(result,durable?"failed":"unknown",durable?"Backup canceled by user; no automatic retry":
            "Cancel request could not be saved; recovery after restart is uncertain");
        return;
    }

    if (!any_ok && already_ok && !result->retry_mask) {
        bool final = trigger && strcmp(trigger, "GameClose") == 0;
        log_debug("watcher: %s/%s unchanged on all reachable destinations, skipping",
                  user_alias, title_id);
        set_last_backup(title_id, final ? 1 : 3,
                        final ? "Final backup already up to date"
                              : "No backup needed — destinations already have this fingerprint");
        upload_result_set(result, "canceled",
                          "Destinations already have this fingerprint");
        snprintf(result->destination, sizeof(result->destination), "%s",
                 existing_dests[0] ? existing_dests : "configured");
        snprintf(result->fingerprint, sizeof(result->fingerprint), "%s",
                 fingerprint);
        if (final) {
            bool es = s_cfg && strcmp(s_cfg->general.language, "es") == 0;
            log_info("final_backup_up_to_date key=%s/%s destination=%s",
                     user_uid, title_id, result->destination);
            log_info("activity:final_backup_up_to_date|%s",
                     game[0] ? game : title_id);
            log_notify_level(NOTIFY_BALANCED, es
                ? "Backup final ya está al día\nNo se necesitó subir otro backup"
                : "Final backup already up to date\nNo new upload needed");
            result->notification_sent = true;
        }
        return;
    }

    if (!any_ok) {
        if (failed_dests[0]) {
            snprintf(history_meta.status, sizeof(history_meta.status),
                     "failed");
            history_record(user_alias, title_id, game, filename, backup_type,
                           file_trigger, zsize, crc, "", &history_meta);
        }
        bool manual = trigger && strcmp(trigger, "Manual") == 0;
        log_warn("%s: %s", manual ? "Backup failed" : "Automatic backup failed",
                 failure_summary);
        log_info("activity:%s|%s|%s", manual ? "backup_failed" : "automatic_backup_failed",
                 game, failure_summary);
        log_debug("no destination succeeded for %s/%s", user_alias, title_id);
        set_last_backup(title_id, 0, failure_summary);
        bool es = s_cfg && strcmp(s_cfg->general.language, "es") == 0;
        char localized[768], fntf[1024];
        backup_failure_summary(destination_failures, any_enabled, es, localized, sizeof(localized));
        snprintf(fntf, sizeof(fntf), "%s: %s\n%s", es
            ? (manual ? "Falló el respaldo" : "Falló el respaldo automático")
            : (manual ? "Backup failed" : "Automatic backup failed"),
            game[0] ? game : title_id, localized);
        log_notify(fntf);
        result->notification_sent = true;
        upload_result_set(result, "failed", failure_summary);
        return;
    }

    bool show_service_note = false;
    if (service_warning) {
        log_warn("Backup completed with warning: internal backup images are "
                 "incomplete for %s/%s. This is normally controlled by the "
                 "PS5/game, not TostónSync. Normal restore uses active saves only. "
                 "active_images=%zu service_images=%zu "
                 "missing_service_images=%zu first_missing=%s "
                 "backup_published=true", user_alias, title_id,
                 final_snapshot.active_images, final_snapshot.service_images,
                 final_snapshot.missing_service_images,
                 final_snapshot.first_missing[0]
                    ? final_snapshot.first_missing : "none");
        show_service_note = service_note_once(user_uid, title_id);
        if (show_service_note)
            log_info("activity:backup_completed_note|%s",
                     game[0] ? game : title_id);
    }

    char pretty_failed[96] = {0};
    if (failed_dests[0]) {
        char pretty_ok[96];
        dests_pretty(dests, pretty_ok, sizeof(pretty_ok));
        dests_pretty(failed_dests, pretty_failed, sizeof(pretty_failed));
        log_warn("Backup partially completed: %s (%s OK; %s failed)",
                 game[0] ? game : title_id, pretty_ok, pretty_failed);
        log_warn("Backup destination causes: %s", failure_summary);
    }

    snprintf(history_meta.status, sizeof(history_meta.status), "%s",
             failed_dests[0] ? "partial" :
             (service_warning ? "warning" : "ok"));
    history_record(user_alias, title_id, game, filename, backup_type,
                   file_trigger, zsize, crc, dests, &history_meta);

    result->copied = true;
    result->crc = crc;
    result->zip_size = zsize;
    s_last_sync_unix    = now_unix();
    char backup_msg[768];
    bool final = trigger && strcmp(trigger, "GameClose") == 0;
    if (final && strstr(dests, "usb") && strstr(dests, "drive"))
        snprintf(backup_msg, sizeof(backup_msg),
                 "USB: complete · Google Drive: complete");
    else if (final && strstr(dests, "usb") && strstr(failed_dests, "drive"))
        snprintf(backup_msg, sizeof(backup_msg),
                 "USB: complete · Google Drive: failed");
    else
        snprintf(backup_msg, sizeof(backup_msg),
                 "Saved to %s", dests);
    if (failure_summary[0]) {
        size_t len = strlen(backup_msg);
        snprintf(backup_msg + len, sizeof(backup_msg) - len, "; %s", failure_summary);
    }
    set_last_backup(title_id, 1, backup_msg);

    // On-screen PS5 toast (gated internally by general.notifications).
    char pdest[96];
    dests_pretty(dests, pdest, sizeof(pdest));
    const char* gname = game[0] ? game : title_id;
    bool es = s_cfg && strcmp(s_cfg->general.language, "es") == 0;
    bool manual = trigger && strcmp(trigger, "Manual") == 0;
    char ntf[1024];
    if (failed_dests[0]) {
        char localized[768];
        backup_failure_summary(destination_failures, any_enabled, es, localized, sizeof(localized));
        snprintf(ntf, sizeof(ntf), "%s: %s\n%s", es
                 ? "Respaldo parcial" : "Backup partially completed", gname, localized);
    }
    else if (final)
        snprintf(ntf, sizeof(ntf), "%s",
                 strstr(dests, "usb") && strstr(dests, "drive")
                   ? (es ? "Backup en Google Drive completado\nBackup final completado. Ya puedes usar Rest Mode"
                         : "Google Drive backup complete\nFinal backup complete. Safe to use Rest Mode")
                   : (es ? "Backup final completado\nYa puedes usar Rest Mode"
                         : "Final backup complete\nSafe to use Rest Mode"));
    else if (service_warning)
        snprintf(ntf, sizeof(ntf),
                 es ? "Backup completado con nota\nTu save activo fue respaldado. Falta una imagen interna administrada por PS5."
                    : "Backup completed with note\nThe active save was fully backed up. One optional PS5-managed service image was not present in the source folder.");
    else if (manual)
        snprintf(ntf, sizeof(ntf),
                 es ? "Respaldo completado: %s (%s)" : "Backup complete: %s (%s)",
                 gname, pdest);
    else
        snprintf(ntf, sizeof(ntf),
                 es ? "Respaldo automático completado: %s (%s)"
                    : "Auto backup complete: %s (%s)",
                 gname, pdest);
    int notify_level = failed_dests[0] ? NOTIFY_IMPORTANT :
                       (manual || final) ? NOTIFY_BALANCED : NOTIFY_ALL;
    if (final && !failed_dests[0])
        log_info("activity:final_backup_complete|%s", gname);
    if (!service_warning || final)
        log_notify_level(notify_level, ntf);
    else if (show_service_note)
        log_notify_level_quiet(notify_level, ntf);
    result->notification_sent = true;
    upload_result_set(result, "complete", backup_msg);
    snprintf(result->destination, sizeof(result->destination), "%s", dests);
    snprintf(result->fingerprint, sizeof(result->fingerprint), "%s",
             fingerprint);
}

static void do_upload_job(const job_t* job) {
    jobs_phase(jobs_watch_id(job->job_id), job->destination, "preparing", 0, false);
    // dequeue_blocking() admitted this backup with a read lease. Retain it
    // through terminal/retry checkpoints, including the early lock failure.
    char lock_path[420];
    snprintf(lock_path, sizeof(lock_path), "%s/backup.%s.%s.lock",
             s_cfg->paths.state_dir,
             job->user_uid[0] ? job->user_uid : "default", job->title_id);
    if (!backup_lock_acquire(lock_path)) {
        log_info("watcher: backup already in flight for %s/%s — coalescing event",
                 job->user_uid, job->title_id);
        log_info("backup[job=%lu key=%s/%s reason=%s]: canceled "
                 "reason=already_in_flight", job->job_id, job->user_uid,
                 job->title_id, job->trigger);
        upload_result_t result = {0};
        upload_result_set(&result, "failed", "Backup already in flight");
        finish_backup_job(job, &result, NULL);
        save_io_end_read();
        return;
    }

    int64_t started_at = now_unix();
    backup_job_state_t state = {0};
    state.job_id = job->job_id;
    state.started_at = started_at;
    snprintf(state.run_id, sizeof(state.run_id), "%s", s_run_id);
    snprintf(state.user_uid, sizeof(state.user_uid), "%s", job->user_uid);
    snprintf(state.title_id, sizeof(state.title_id), "%s", job->title_id);
    snprintf(state.reason, sizeof(state.reason), "%s", job->trigger);
    snprintf(state.source, sizeof(state.source), "%s", job->source);
    snprintf(state.destination, sizeof(state.destination), "%s",
             job->destination[0] ? job->destination : "default");
    snprintf(state.status, sizeof(state.status), "running");
    char state_path[420];
    backup_job_path(job->user_uid, job->title_id,
                    state_path, sizeof(state_path));
    if (!backup_job_state_write(state_path, &state))
        log_warn("backup[job=%lu]: could not persist running state",
                 job->job_id);
    log_info("backup[job=%lu run=%s pid=%ld key=%s/%s reason=%s source=%s]: "
             "started started_at=%lld coalesced_count=%u", job->job_id, s_run_id,
             (long)getpid(), job->user_uid, job->title_id, job->trigger,
             job->source,
             (long long)started_at, job->coalesced_count);
    if (strcmp(job->trigger, "GameClose") == 0) {
        config_t cfg;
        bool es = config_snapshot(&cfg) &&
                  strcmp(cfg.general.language, "es") == 0;
        char display[64];
        snprintf(display, sizeof(display), "%s", job->title_id);
        pthread_mutex_lock(&s_titles_lock);
        for (size_t i = 0; i < s_title_count; i++) {
            if (strcmp(s_titles[i].title_id, job->title_id) == 0 &&
                (!job->user_uid[0] ||
                 strcmp(s_titles[i].user_uid, job->user_uid) == 0)) {
                if (s_titles[i].game_name[0])
                    snprintf(display, sizeof(display), "%s",
                             s_titles[i].game_name);
                break;
            }
        }
        pthread_mutex_unlock(&s_titles_lock);
        log_info("activity:final_backup_in_progress|%s", display);
        log_notify_level(NOTIFY_BALANCED, es
            ? "Backup final en progreso\nNormalmente tarda menos de 1 minuto. Espera antes de usar Rest Mode."
            : "Final backup in progress\nUsually less than 1 minute. Please wait before Rest Mode.");
    }

    upload_result_t result = {0};
    upload_result_set(&result, "failed", "Backup ended without a result");
    backup_retry_t retry;
    backup_retry_t* retry_state = NULL;
    bool durable = true;
    if (!job->force_backup) {
        if (!backup_retry_load(job->user_uid, job->title_id, &retry)) {
            backup_retry_init(&retry, job->user_uid, job->title_id, job->trigger);
            retry.usb_no_replay = job->retrying;
            if (retry.usb_no_replay) retry.pending_mask &= ~1U;
        }
        retry_state = &retry;
        retry.active = true;
        retry.dirty_unix = job->dirty_unix;
        durable = backup_retry_save(&retry);
    }
    if (durable && !backup_control_cancelled()) {
        do_upload_job_inner(job->user_uid, job->title_id, job->dirty_unix,
                        job->force_backup, job->trigger, job->destination,
                        &result, &state, state_path, retry_state, job->retrying);
    } else
        upload_result_set(&result, "failed", "Could not persist backup retry state");

    if (backup_control_finish_begin()) {
        bool canceled=backup_cancel_record(job->user_uid,job->title_id,job->dirty_unix,job->trigger,job->force_backup);
        result.retry_mask=0;result.usb_no_replay=true;
        upload_result_set(&result,canceled?"failed":"unknown",canceled?"Backup canceled by user; no automatic retry":
            "Cancel request could not be saved; recovery after restart is uncertain");
    }
    state.completed_at = now_unix();
    snprintf(state.status, sizeof(state.status), "%s", result.status);
    if (result.destination[0])
        snprintf(state.destination, sizeof(state.destination), "%s",
                 result.destination);
    snprintf(state.fingerprint, sizeof(state.fingerprint), "%s",
             result.fingerprint);
    snprintf(state.detail, sizeof(state.detail), "%s", result.detail);
    if (!backup_job_state_write(state_path, &state))
        log_warn("backup[job=%lu]: could not persist terminal state=%s",
                 job->job_id, result.status);

    if (strcmp(result.status, "complete") == 0) {
        log_info("backup[job=%lu key=%s/%s reason=%s]: complete "
                 "destination=%s completed_at=%lld fingerprint=%s",
                 job->job_id, job->user_uid, job->title_id, job->trigger,
                 result.destination[0] ? result.destination : "unknown",
                 (long long)state.completed_at,
                 result.fingerprint[0] ? result.fingerprint : "unknown");
    } else {
        bool final_up_to_date =
            strcmp(job->trigger, "GameClose") == 0 &&
            strcmp(result.status, "canceled") == 0 &&
            strcmp(result.detail,
                   "Destinations already have this fingerprint") == 0;
        log_info("backup[job=%lu key=%s/%s reason=%s]: %s reason=%s "
                 "completed_at=%lld", job->job_id, job->user_uid,
                 job->title_id, job->trigger, result.status, result.detail,
                 (long long)state.completed_at);
        set_last_backup(job->title_id, final_up_to_date ? 1 :
                        (strcmp(result.status, "failed") == 0 ? 0 : 3),
                        final_up_to_date ? "Final backup already up to date"
                                         : result.detail);
        if ((strcmp(result.status, "failed") == 0 || !strcmp(result.status, "unconfirmed")) &&
            !result.notification_sent) {
            config_t cfg;
            bool es = config_snapshot(&cfg) &&
                      strcmp(cfg.general.language, "es") == 0;
            char notice[192];
            if (!strcmp(result.status, "unconfirmed")) {
                snprintf(notice, sizeof(notice), "%s", es
                    ? "Copia guardada, pero sin confirmar. Revisa el resultado antes de otra solicitud."
                    : "Backup copied but unconfirmed. Check the result before another request.");
            } else if (strcmp(job->trigger, "GameClose") == 0) {
                log_info("activity:final_backup_failed|%s", job->title_id);
                snprintf(notice, sizeof(notice), "%s", es
                    ? "Falló el backup final\nAbre Logs y diagnósticos para ver detalles"
                    : "Final backup failed\nOpen Logs & diagnostics for details");
            } else
                snprintf(notice, sizeof(notice),
                         job->force_backup ? (es ? "Falló el backup manual\n%s" : "Manual backup failed\n%s")
                            : (es ? "Falló el backup automático\n%s" : "Automatic backup failed\n%s"),
                         result.detail);
            log_notify(notice);
        }
    }
    // Terminal status and retry checkpoints must precede admitting another
    // job for this title (including a forced manual copy).
    backup_lock_release(lock_path);
    finish_backup_job(job, &result, retry_state);
    save_io_end_read();
}

static bool valid_usb_restore_ref(const char* ref);
static bool valid_restore_ref(const char* ref);
static bool resolve_local_restore_target(const char* title_id,
                                         char* uid, size_t uid_sz,
                                         char* target, size_t target_sz,
                                         char* err, size_t err_sz);

// Inspect marker metadata only. Reading a recovery journal is deliberately
// outside this operation, as are repair, cleanup and import inspection.
static void save_metadata_recovery_check(const config_t* cfg, const char* uid,
                                         const char* title,
                                         save_metadata_check_t* check, int* error,
                                         char* detail, size_t detail_sz) {
    const char* markers[] = {"restore.interrupted", "restore.busy", "raw-recovery.pending"};
    const char* suffixes[] = {"/.pending", ".next", ".previous", ".swap", ".apply",
                             "/.expansion-required", "/.expansion.sqlite"};
    *check = SAVE_METADATA_PASS;
    *error = 0;
    snprintf(detail, detail_sz, "No known pending-operation markers observed; journal contents were not read");
    for (size_t i = 0; i < 10; i++) {
        char path[768];
        int n = i < 3
            ? snprintf(path, sizeof(path), "%s/%s", cfg->paths.state_dir, markers[i])
            : snprintf(path, sizeof(path), "%s/restore_%s_%s_sdimg_rollback%s",
                       cfg->paths.staging_dir, uid, title, suffixes[i - 3]);
        struct stat st;
        if (n < 0 || (size_t)n >= sizeof(path)) {
            if (*check != SAVE_METADATA_FAIL) *check = SAVE_METADATA_UNKNOWN;
            *error = ENAMETOOLONG;
            snprintf(detail, detail_sz, "Pending-marker path exceeds bounds");
            continue;
        }
        if (lstat(path, &st) == 0) {
            // Journal existence alone does not reveal its terminal state.
            *check = i == 9 ? SAVE_METADATA_UNKNOWN : SAVE_METADATA_FAIL;
            snprintf(detail, detail_sz, "Operation evidence exists: %s; metadata only, no recovery performed",
                     i < 3 ? markers[i] : suffixes[i - 3]);
            if (i != 9) return;
        } else if (errno != ENOENT) {
            *check = SAVE_METADATA_UNKNOWN;
            *error = errno;
            snprintf(detail, detail_sz, "Pending-marker metadata unavailable (errno=%d)", *error);
        }
    }
}

static bool save_metadata_uid_valid(const char* uid) {
    return uid && uid[0] && strlen(uid) < 16 && valid_uid(uid);
}

static bool save_metadata_resolve_uid(const char* uid, const char* title_id,
                                      char* resolved, size_t resolved_sz,
                                      char* target, size_t target_sz,
                                      char* err, size_t err_sz) {
    if (!uid) return resolve_local_restore_target(title_id, resolved, resolved_sz,
                                                 target, target_sz, err, err_sz);
    if (resolved && resolved_sz) resolved[0] = 0;
    if (target && target_sz) target[0] = 0;
    config_t cfg;
    if (!resolved || resolved_sz <= strlen(uid) || !target || !target_sz ||
        !save_metadata_uid_valid(uid) || !valid_title_id(title_id) ||
        strlen(title_id) != 9 || !config_snapshot(&cfg)) goto unavailable;
    int n = snprintf(target, target_sz, "%s/%s/savedata_prospero/%s",
                     cfg.paths.saves_root, uid, title_id);
    if (n <= 0 || (size_t)n >= target_sz || target[0] != '/') goto unavailable;
    char path[512];
    if (strlen(target) >= sizeof(path)) goto unavailable;
    snprintf(path, sizeof(path), "%s", target);
    // Every component is observed without following symlinks; no cached owner.
    for (char* p = path + 1;; p++) {
        if (*p && *p != '/') continue;
        char saved = *p; *p = 0;
        struct stat st;
        bool ok = lstat(path, &st) == 0 && S_ISDIR(st.st_mode);
        *p = saved;
        if (!ok) goto unavailable;
        if (!saved) break;
    }
    snprintf(resolved, resolved_sz, "%s", uid);
    return true;
unavailable:
    if (err && err_sz) snprintf(err, err_sz, "Explicit metadata owner is unavailable or unsafe");
    return false;
}

static bool watcher_inspect_save_metadata_inner(const char* requested_uid,
                                                const char* title_id, watcher_save_metadata_t* out) {
    if (!out) return false;
    memset(out, 0, sizeof(*out));
    if (!valid_title_id(title_id) || strlen(title_id) != 9) return false;
    if (!lifecycle_operation_begin()) return false;
    snprintf(out->title_id, sizeof(out->title_id), "%s", title_id);
    snprintf(out->inventory.filesystem_detail, sizeof(out->inventory.filesystem_detail), "Not inspected");
    snprintf(out->inventory.registry_detail, sizeof(out->inventory.registry_detail), "Not inspected");
    snprintf(out->game_detail, sizeof(out->game_detail),
        "UNKNOWN: sandbox absence cannot demonstrate that the game is fully closed; no content or process memory read");
    bool leased = save_io_try_begin_inspection();
    if (!leased) {
        out->gate = SAVE_METADATA_FAIL;
        snprintf(out->gate_detail, sizeof(out->gate_detail), "Save-I/O gate busy; observational metadata only, no lease, waits or mounts");
    } else {
        out->gate = SAVE_METADATA_PASS;
        snprintf(out->gate_detail, sizeof(out->gate_detail), "Exclusive metadata-only lease acquired and released within this request");
    }
    config_t cfg;
    char target[320];
    if (!config_snapshot(&cfg)) {
        snprintf(out->uid_detail, sizeof(out->uid_detail), "Local paths unavailable");
        goto done;
    }
    if (!save_metadata_resolve_uid(requested_uid, title_id, out->uid, sizeof(out->uid),
                                      target, sizeof(target), out->uid_detail, sizeof(out->uid_detail))) {
        out->uid_check = strstr(out->uid_detail, "ambiguous") || strstr(out->uid_detail, "multiple")
                      ? SAVE_METADATA_FAIL : SAVE_METADATA_UNKNOWN;
        goto done;
    }
    out->uid_check = SAVE_METADATA_PASS;
    snprintf(out->uid_detail, sizeof(out->uid_detail), "Resolved from fresh local filesystem inventory; no source UID, alias or cached owner used");
    save_metadata_recovery_check(&cfg, out->uid, title_id, &out->recovery_clear,
                                 &out->recovery_errno, out->recovery_detail, sizeof(out->recovery_detail));
    if (fs_title_is_closed(title_id)) {
        out->game_closed = SAVE_METADATA_PASS;
        snprintf(out->game_detail, sizeof(out->game_detail), "Complete /mnt/sandbox traversal found no matching title directory; metadata observation only");
    } else if (fs_title_is_running(title_id)) {
        out->game_closed = SAVE_METADATA_FAIL;
        snprintf(out->game_detail, sizeof(out->game_detail), "Matching /mnt/sandbox title directory observed; metadata inventory is still read-only");
    }
    char db[512];
    snprintf(db, sizeof(db), "/system_data/savedata_prospero/%s/db/user/savedata.db", out->uid);
    // Neither game nor recovery UNKNOWN/FAIL authorizes a mount or prevents
    // lstat/registry observations. The collector has no save-content helpers.
    save_metadata_collect(target, db, title_id, &out->inventory);
    char fresh_uid[16], fresh_target[320], err[192];
    if (!save_metadata_resolve_uid(requested_uid, title_id, fresh_uid, sizeof(fresh_uid),
                                      fresh_target, sizeof(fresh_target), err, sizeof(err)) ||
        strcmp(fresh_uid, out->uid) || strcmp(fresh_target, target)) {
        out->uid_check = SAVE_METADATA_UNKNOWN;
        out->inventory.filesystem = SAVE_METADATA_UNKNOWN;
        out->inventory.registry = SAVE_METADATA_UNKNOWN;
        snprintf(out->uid_detail, sizeof(out->uid_detail), "Local owner inventory changed or became unavailable during observation");
        for (int service = 0; service < 2; service++) {
            save_metadata_entry_t* entries = service ? out->inventory.service : out->inventory.active;
            size_t count = service ? out->inventory.service_count : out->inventory.active_count;
            for (size_t i = 0; i < count; i++) {
                entries[i].registered = entries[i].sdimg = SAVE_METADATA_UNKNOWN;
                entries[i].rowid_available = false;
            }
        }
    }
done:
    if (leased) watcher_target_check_end();
    lifecycle_operation_end();
    return true;
}

bool watcher_inspect_save_metadata(const char* title_id, watcher_save_metadata_t* out) {
    return watcher_inspect_save_metadata_inner(NULL, title_id, out);
}

bool watcher_inspect_save_metadata_for_uid(const char* uid, const char* title_id,
                                          watcher_save_metadata_t* out) {
    if (!save_metadata_uid_valid(uid)) return false;
    return watcher_inspect_save_metadata_inner(uid, title_id, out);
}

static bool session_metadata_matches(const save_metadata_entry_t* entry,
                                     const session_saves_entry_t* snapshot) {
    return entry->metadata_available && entry->sdimg == SAVE_METADATA_PASS &&
           !strcmp(entry->type, "regular") && entry->service == snapshot->service &&
           !strcmp(entry->image_name, snapshot->image_name) &&
           entry->size == snapshot->size && entry->dev == snapshot->device &&
           entry->inode == snapshot->inode && entry->mode == snapshot->mode &&
           entry->mtime == snapshot->mtime && entry->mtime_nsec == snapshot->mtime_nsec &&
           entry->ctime == snapshot->ctime && entry->ctime_nsec == snapshot->ctime_nsec;
}

void watcher_copy_save_session(watcher_save_metadata_t* out) {
    if (!out) return;
    memset(&out->session, 0, sizeof(out->session));
    memset(out->session_active, -1, sizeof(out->session_active));
    memset(out->session_service, -1, sizeof(out->session_service));
    if (out->uid_check != SAVE_METADATA_PASS || out->game_closed != SAVE_METADATA_PASS)
        return;
    pthread_mutex_lock(&s_titles_lock);
    for (size_t i = 0; i < s_title_count; i++) {
        if (!strcmp(s_titles[i].user_uid, out->uid) &&
            !strcmp(s_titles[i].title_id, out->title_id)) {
            session_saves_report(&s_titles[i].session, &out->session);
            break;
        }
    }
    pthread_mutex_unlock(&s_titles_lock);
    if (out->session.baseline != SESSION_SAVES_OK) return;
    bool valid = out->gate == SAVE_METADATA_PASS &&
                 out->inventory.filesystem == SAVE_METADATA_PASS;
    size_t matched = 0;
    bool used[SESSION_SAVES_MAX_IMAGES] = {0};
    for (int service = 0; valid && service < 2; service++) {
        const save_metadata_entry_t* entries = service ? out->inventory.service : out->inventory.active;
        size_t count = service ? out->inventory.service_count : out->inventory.active_count;
        int8_t* changed = service ? out->session_service : out->session_active;
        if (count > SAVE_METADATA_MAX_ENTRIES) { valid = false; break; }
        for (size_t i = 0; valid && i < count; i++) {
            const save_metadata_entry_t* entry = &entries[i];
            // A registry-only row is not an image and cannot receive a badge.
            if (!entry->metadata_available && entry->stat_errno == ENOENT) continue;
            size_t j;
            for (j = 0; j < out->session.count; j++)
                if (!used[j] && session_metadata_matches(entry, &out->session.entries[j])) break;
            if (j == out->session.count) { valid = false; break; }
            used[j] = true;
            matched++;
            changed[i] = out->session.changed[j] ? 1 : 0;
        }
    }
    if (!valid || matched != out->session.count) {
        out->session.baseline = SESSION_SAVES_ERROR;
        memset(&out->session.counts, 0, sizeof(out->session.counts));
        out->session.count = 0;
        memset(out->session_active, -1, sizeof(out->session_active));
        memset(out->session_service, -1, sizeof(out->session_service));
    }
}

static bool resolve_restore_uid(const char* user_alias, const char* title_id,
                                char* out, size_t out_sz);
static bool resolve_restore_target(const char* user, const char* title_id,
                                   bool uid_explicit, char* out, size_t out_sz);

static bool restore_dir_has_savedata0(const char* dir) {
    char blob[320];
    snprintf(blob, sizeof(blob), "%s/savedata0.bin", dir);
    struct stat st;
    return stat(blob, &st) == 0 && S_ISREG(st.st_mode);
}

static bool restore_dir_has_sdimg(const char* dir) {
    DIR* d = opendir(dir);
    if (!d) return false;
    bool found = false;
    struct dirent* e;
    while ((e = readdir(d)) != NULL) {
        if (strncmp(e->d_name, "sdimg_", 6) != 0) continue;
        char p[360];
        snprintf(p, sizeof(p), "%s/%s", dir, e->d_name);
        struct stat st;
        if (stat(p, &st) == 0 && S_ISREG(st.st_mode)) {
            found = true;
            break;
        }
    }
    closedir(d);
    return found;
}

static bool make_download_zip_inner(const char* user_uid, const char* title_id,
                                    bool raw_encrypted,
                                    char* out_zip_path, size_t out_zip_path_sz,
                                    watcher_raw_info_t* raw_info,
                                    char* err, size_t err_sz) {
    if (out_zip_path && out_zip_path_sz) out_zip_path[0] = '\0';
    if (raw_info) memset(raw_info, 0, sizeof(*raw_info));
    if (err && err_sz) err[0] = '\0';
    if (!s_cfg) {
        if (err && err_sz) snprintf(err, err_sz, "Watcher is not ready");
        return false;
    }
    if (!valid_title_id(title_id) || !valid_uid(user_uid ? user_uid : "")) {
        if (err && err_sz) snprintf(err, err_sz, "Invalid title or user");
        return false;
    }

    char src_path[256] = {0};
    char uid[16] = {0};
    char game[64] = {0};
    bool game_running = false;
    pthread_mutex_lock(&s_titles_lock);
    for (size_t i = 0; i < s_title_count; i++) {
        title_t* t = &s_titles[i];
        if (strcmp(t->title_id, title_id) != 0) continue;
        if (user_uid && user_uid[0] && strcmp(t->user_uid, user_uid) != 0)
            continue;
        snprintf(src_path, sizeof(src_path), "%s", t->path);
        snprintf(uid, sizeof(uid), "%s",
                 t->user_uid[0] ? t->user_uid : "default");
        snprintf(game, sizeof(game), "%s", t->game_name);
        game_running = (t->pid_if_running != 0);
        break;
    }
    pthread_mutex_unlock(&s_titles_lock);

    if (!src_path[0]) {
        if (err && err_sz) snprintf(err, err_sz, "Save not found on this PS5");
        return false;
    }
    if (!fs_mkdir_p(s_cfg->paths.staging_dir)) {
        if (err && err_sz) snprintf(err, err_sz, "Cannot create staging folder");
        return false;
    }

    char ts[32];
    time_t now = time(NULL);
    struct tm tm;
    gmtime_r(&now, &tm);
    strftime(ts, sizeof(ts), "%Y%m%dT%H%M%SZ", &tm);
    unsigned long stage_id = next_stage_seq();

    char zip_path[300];
    snprintf(zip_path, sizeof(zip_path),
             "%s/download_%s_%s_%s_%s_%ld_%lu.zip",
             s_cfg->paths.staging_dir, uid, title_id,
             raw_encrypted ? "raw" : "decrypted", ts,
             (long)getpid(), stage_id);

    const char* zip_source = src_path;
    char kernel_stage[300] = {0};
    bool used_kernel_stage = false;
    raw_snapshot_t raw_before = {0};

    if (!raw_encrypted) {
        if (game_running) {
            if (err && err_sz)
                snprintf(err, err_sz, "Close the game before decrypted download");
            return false;
        }
        bool has_savedata0 = restore_dir_has_savedata0(src_path);
        bool has_sdimg = restore_dir_has_sdimg(src_path);
        if (!has_savedata0 && !has_sdimg) {
            if (err && err_sz)
                snprintf(err, err_sz, "No PS5 PFS image found for this save");
            return false;
        }
        snprintf(kernel_stage, sizeof(kernel_stage),
                 "%s/download_%s_%s_plain_%ld_%lu",
                 s_cfg->paths.staging_dir, uid, title_id,
                 (long)getpid(), stage_id);
        pfs_fs_rmrf(kernel_stage);
        bool staged = has_savedata0
            ? pfs_resign_backup_to_staging(src_path, kernel_stage)
            : pfs_resign_backup_sdimg_to_staging(src_path, kernel_stage);
        if (!staged) {
            pfs_fs_rmrf(kernel_stage);
            if (err && err_sz)
                snprintf(err, err_sz,
                         "Kernel decrypt failed. Load kstuff, close the game, then try again.");
            return false;
        }
        zip_source = kernel_stage;
        used_kernel_stage = true;
    }

    if (raw_encrypted && !raw_snapshot_capture(zip_source, &raw_before)) {
        if (err && err_sz) snprintf(err, err_sz, "No active save files found");
        return false;
    }

    uint32_t crc = 0;
    uint64_t zsize = 0;
    char manifest[1536], clean_name[96], clean_console[64],
         clean_console_type[32], created_utc[32], raw_meta[320] = {0};
    json_clean(game[0] ? game : title_id, clean_name, sizeof(clean_name));
    json_clean(s_cfg->console.name[0] ? s_cfg->console.name : "This PS5",
               clean_console, sizeof(clean_console));
    json_clean(s_cfg->console.type[0] ? s_cfg->console.type : "PS5",
               clean_console_type, sizeof(clean_console_type));
    strftime(created_utc, sizeof(created_utc), "%Y-%m-%dT%H:%M:%SZ", &tm);
    if (raw_encrypted) {
        char missing[160];
        json_clean(raw_before.first_missing, missing, sizeof(missing));
        snprintf(raw_meta, sizeof(raw_meta),
                 ",\"raw_completeness\":\"%s\",\"active_images\":%zu,"
                 "\"service_images\":%zu,\"missing_service_images\":%zu,"
                 "\"first_missing_service_image\":\"%s\"",
                 raw_completeness(&raw_before), raw_before.active_images,
                 raw_before.service_images, raw_before.missing_service_images,
                 missing);
    }
    snprintf(manifest, sizeof(manifest),
             "{\"format\":\"%s\",\"format_version\":1,"
             "\"tostonsync_version\":\"%s\",\"title_id\":\"%s\","
             "\"title_name\":\"%s\",\"platform\":\"ps5\","
             "\"backup_type\":\"%s\",\"trigger\":\"Manual\","
             "\"user_uid\":\"%s\",\"source_console_name\":\"%s\","
             "\"source_console_type\":\"%s\","
             "\"created_at_utc\":\"%s\",\"created_at_epoch\":%lld,"
             "\"total_size\":%llu%s}",
             raw_encrypted ? "tostonsync.encrypted_image"
                           : "tostonsync.decrypted_export",
             TOSTONSYNC_VERSION, title_id, clean_name,
             raw_encrypted ? "RAW" : "PORTABLE", uid, clean_console,
             clean_console_type, created_utc, (long long)now,
             (unsigned long long)(raw_encrypted ? raw_before.bytes
                                                : fs_dir_size(zip_source)),
             raw_meta);
    // PLK-compatible: wrap in a `<title_id>/` top folder (see do_upload_job).
    if (!zip_compress_directory_top_manifest(zip_source, title_id, zip_path,
                                             s_cfg->advanced.zip_mode_deflate,
                                             &crc, &zsize, manifest)) {
        if (used_kernel_stage) pfs_fs_rmrf(kernel_stage);
        unlink(zip_path);
        if (err && err_sz) snprintf(err, err_sz, "Could not create ZIP");
        return false;
    }
    if (zip_entry_count(zip_path) < 2) {
        if (used_kernel_stage) pfs_fs_rmrf(kernel_stage);
        unlink(zip_path);
        if (err && err_sz) snprintf(err, err_sz, "Backup ZIP validation failed");
        return false;
    }
    if (raw_encrypted) {
        raw_snapshot_t raw_after;
        if (!raw_snapshot_capture(zip_source, &raw_after) ||
            !raw_snapshot_equal(&raw_before, &raw_after)) {
            unlink(zip_path);
            if (err && err_sz)
                snprintf(err, err_sz, "Save changed while ZIP was created; try again");
            return false;
        }
        if (raw_service_images_incomplete(&raw_after))
            log_warn("watcher: raw download has optional internal-image warning "
                     "for %s/%s (active=%zu, internal=%zu, missing=%zu)",
                     uid, title_id, raw_after.active_images,
                     raw_after.service_images,
                     raw_after.missing_service_images);
        if (raw_info) {
            snprintf(raw_info->raw_completeness,
                     sizeof(raw_info->raw_completeness), "%s",
                     raw_completeness(&raw_after));
            raw_info->active_images = raw_after.active_images;
            raw_info->service_images = raw_after.service_images;
            raw_info->missing_service_images = raw_after.missing_service_images;
            snprintf(raw_info->first_missing_service_image,
                     sizeof(raw_info->first_missing_service_image), "%s",
                     raw_after.first_missing);
        }
    }
    if (used_kernel_stage) pfs_fs_rmrf(kernel_stage);
    snprintf(out_zip_path, out_zip_path_sz, "%s", zip_path);
    log_info("watcher: prepared %s ZIP for browser download/upload: %s/%s (%llu B)",
             raw_encrypted ? "raw" : "decrypted", uid, title_id,
             (unsigned long long)zsize);
    return true;
}

bool watcher_make_download_zip(const char* user_uid, const char* title_id,
                               bool raw_encrypted,
                               char* out_zip_path, size_t out_zip_path_sz,
                               watcher_raw_info_t* raw_info,
                               char* err, size_t err_sz) {
    if (!lifecycle_admit(err, err_sz)) return false;
    scratch_begin_use();
    if (!save_io_begin_read()) {
        watcher_release_backup_file(NULL, false);
        lifecycle_operation_end();
        return false;
    }
    bool ok = save_export_ready(err, err_sz) &&
              make_download_zip_inner(user_uid, title_id, raw_encrypted,
                                      out_zip_path, out_zip_path_sz,
                                      raw_info,
                                      err, err_sz);
    save_io_end_read();
    if (!ok) watcher_release_backup_file(NULL, false);
    lifecycle_operation_end();
    return ok;
}

typedef struct {
    char name[128];
    struct stat stat;
    char sha256[65];
} raw_selected_file_t;

static bool raw_selected_stat_equal(const struct stat* a, const struct stat* b) {
    return a->st_dev == b->st_dev && a->st_ino == b->st_ino &&
           a->st_size == b->st_size && a->st_mode == b->st_mode &&
           a->st_uid == b->st_uid && a->st_gid == b->st_gid &&
           a->st_nlink == b->st_nlink && a->st_mtime == b->st_mtime &&
           a->st_ctime == b->st_ctime &&
#if defined(__APPLE__) || defined(__FreeBSD__)
           a->st_flags == b->st_flags &&
#endif
#ifdef __APPLE__
           a->st_mtimespec.tv_nsec == b->st_mtimespec.tv_nsec &&
           a->st_ctimespec.tv_nsec == b->st_ctimespec.tv_nsec;
#else
           a->st_mtim.tv_nsec == b->st_mtim.tv_nsec &&
           a->st_ctim.tv_nsec == b->st_ctim.tv_nsec;
#endif
}

// Hash exactly the no-follow descriptor, with path/descriptor stability checks.
// Only selected encrypted files reach this helper; no PFS or database access.
static bool raw_selected_hash(const char* dir, raw_selected_file_t* file) {
    char path[512]; struct stat before, opened, after, closed;
    int n = snprintf(path, sizeof(path), "%s/%s", dir, file->name);
    if (n < 0 || (size_t)n >= sizeof(path)) { errno = ENAMETOOLONG; return false; }
    if (lstat(path, &before)) return false;
    if (!S_ISREG(before.st_mode) || before.st_size < 0) { errno = EINVAL; return false; }
    int fd = open(path, O_RDONLY | O_NOFOLLOW | O_NONBLOCK);
    if (fd < 0) return false;
    bool ok = !fstat(fd, &opened);
    int failure_errno = ok ? 0 : errno;
    if (ok && !raw_selected_stat_equal(&before, &opened)) { ok = false; failure_errno = EAGAIN; }
    sha256_ctx_t ctx; sha256_init(&ctx);
    unsigned char buf[32768], digest[32]; uint64_t bytes = 0;
    while (ok) {
        ssize_t got = read(fd, buf, sizeof(buf));
        if (got < 0) { if (errno == EINTR) continue; failure_errno = errno; ok = false; break; }
        if (!got) break;
        sha256_update(&ctx, buf, (size_t)got); bytes += (uint64_t)got;
    }
    if (ok && fstat(fd, &closed)) { ok = false; failure_errno = errno; }
    if (ok && !raw_selected_stat_equal(&opened, &closed)) { ok = false; failure_errno = EAGAIN; }
    if (close(fd) && ok) { ok = false; failure_errno = errno; }
    if (ok && lstat(path, &after)) { ok = false; failure_errno = errno; }
    if (ok && (!raw_selected_stat_equal(&before, &after) || bytes != (uint64_t)before.st_size))
        { ok = false; failure_errno = EAGAIN; }
    if (!ok) { memset(&ctx, 0, sizeof(ctx)); errno = failure_errno; return false; }
    sha256_final(&ctx, digest);
    for (size_t i = 0; i < sizeof(digest); i++)
        snprintf(file->sha256 + i * 2, 3, "%02x", digest[i]);
    file->stat = after;
    return true;
}

static bool raw_selected_services(const char* text, const restore_selection_t* active,
                                   restore_selection_t* services) {
    memset(services, 0, sizeof(*services)); services->specified = true;
    if (!text || strlen(text) >= RESTORE_SELECTION_MAX * 64) return false;
    while (*text) {
        const char* end = strchr(text, '\n');
        size_t n = end ? (size_t)(end - text) : strlen(text);
        if (!n || n >= 64 || services->count == RESTORE_SELECTION_MAX) return false;
        char name[64]; memcpy(name, text, n); name[n] = 0;
        if (!safe_path_component(name) || !restore_selection_contains(active, name) ||
            restore_selection_contains(services, name)) return false;
        snprintf(services->slots[services->count++], 64, "%s", name);
        if (!end) break;
        text = end + 1;
        if (!*text) return false;
    }
    return true;
}

static bool raw_selected_inventory(const save_metadata_report_t* r,
                                    char names[][64], size_t* count) {
    *count = 0;
    if (r->filesystem != SAVE_METADATA_PASS) return false;
    for (size_t i = 0; i < r->active_count; i++) {
        const save_metadata_entry_t* e = &r->active[i];
        if (e->sdimg != SAVE_METADATA_PASS || !e->metadata_available ||
            strcmp(e->type, "regular") || !safe_path_component(e->name) ||
            strlen(e->name) >= 64 || *count == RESTORE_SELECTION_MAX) return false;
        snprintf(names[(*count)++], 64, "%s", e->name);
    }
    return *count > 0;
}

bool watcher_make_raw_selected_zip(const char* uid, const char* title,
    const restore_selection_t* requested, const char* service_slots,
    bool game_closed_confirmed, char* out_path, size_t path_sz,
    watcher_raw_info_t* out, char* err, size_t err_sz) {
    if (out_path && path_sz) out_path[0] = 0;
    if (out) memset(out, 0, sizeof(*out));
    if (err && err_sz) err[0] = 0;
    const char* failure = "Explicit valid active selection and closed-game confirmation required";
    bool leased = false, ok = false;
    save_metadata_report_t* metadata = NULL;
    char zip_path[512] = {0}, target[320], fresh[320], resolved[16], fresh_uid[16];
    config_t cfg;
    restore_selection_t selection, services;
    raw_selected_file_t files[RESTORE_SELECTION_MAX * 2] = {0};
    const char* names[RESTORE_SELECTION_MAX * 2];
    char hashes[RESTORE_SELECTION_MAX * 2][65];
    size_t count = 0, available_count = 0;
    char available[RESTORE_SELECTION_MAX][64], after_names[RESTORE_SELECTION_MAX][64];
    if (!out_path || path_sz < sizeof(zip_path) || !out || !uid || !*uid ||
        strlen(uid) >= 16 || !valid_uid(uid) || !valid_title_id(title) ||
        strlen(title) != 9 || !requested || !requested->specified ||
        !requested->count || requested->count > RESTORE_SELECTION_MAX || !game_closed_confirmed)
        goto done;
    selection = *requested;
    for (size_t i = 0; i < selection.count; i++)
        if (!memchr(selection.slots[i], 0, 64) || !safe_path_component(selection.slots[i])) goto done;
    if (!raw_selected_services(service_slots, &selection, &services)) goto done;
    failure = "BUSY: exclusive save-I/O gate unavailable; no files read";
    if (!save_io_try_begin_inspection()) goto done;
    leased = true;
    failure = "RECOVERY_REQUIRED or local configuration unavailable";
    if (!save_export_ready(err, err_sz) || !config_snapshot(&cfg)) goto done;
    failure = "Fresh local UID/title owner is unavailable or differs from requested UID";
    if (!resolve_local_restore_target(title, resolved, sizeof(resolved), target, sizeof(target), NULL, 0) ||
        strcmp(uid, resolved)) goto done;
    save_metadata_check_t recovery; int recovery_errno; char detail[192];
    save_metadata_recovery_check(&cfg, uid, title, &recovery, &recovery_errno, detail, sizeof(detail));
    failure = "Pending-operation metadata is not PASS; no images copied";
    if (recovery != SAVE_METADATA_PASS) goto done;
    failure = "RUNNING_OBSERVED: close the game before downloading images";
    if (fs_title_is_running(title)) goto done;
    metadata = calloc(1, sizeof(*metadata));
    failure = "Filesystem inventory unavailable, unsafe or exceeds 32 active containers";
    if (!metadata) goto done;
    // Registration is not authority for encrypted byte copying. No database is
    // opened here; the same metadata-only filesystem collector supplies names.
    save_metadata_collect(target, NULL, title, metadata);
    if (!raw_selected_inventory(metadata, available, &available_count) ||
        !restore_selection_resolve(&selection, available, available_count, err, err_sz)) goto done;
    uint64_t total_bytes = 0;
    for (size_t i = 0; i < selection.count; i++) {
        bool declared = restore_selection_contains(&services, selection.slots[i]);
        char service_path[512]; struct stat service;
        snprintf(service_path, sizeof(service_path), "%s/sdimg_sce_bu_%s", target, selection.slots[i]);
        int rc = lstat(service_path, &service); int e = errno;
        failure = "Service inventory differs from explicit declaration or is UNKNOWN";
        if ((declared && (rc || !S_ISREG(service.st_mode))) ||
            (!declared && (!rc || e != ENOENT))) goto done;
        for (int auxiliary = 0; auxiliary <= (int)declared; auxiliary++) {
            raw_selected_file_t* f = &files[count];
            snprintf(f->name, sizeof(f->name), "sdimg_%s%s", auxiliary ? "sce_bu_" : "", selection.slots[i]);
            failure = "Selected encrypted image read/hash failed or changed during acquisition";
            if (!raw_selected_hash(target, f)) goto done;
            names[count] = f->name; snprintf(hashes[count], 65, "%s", f->sha256);
            if (UINT64_MAX - total_bytes < (uint64_t)f->stat.st_size) { errno = EOVERFLOW; goto done; }
            total_bytes += (uint64_t)f->stat.st_size; count++;
        }
    }
    // Always partial, even if the user explicitly selected all active names.
    time_t created = time(NULL); char utc[32]; struct tm tm;
    gmtime_r(&created, &tm); strftime(utc, sizeof(utc), "%Y-%m-%dT%H:%M:%SZ", &tm);
    char manifest[16384]; int n = snprintf(manifest, sizeof(manifest),
        "{\"format\":\"tostonsync.encrypted_image\",\"format_version\":1,"
        "\"tostonsync_version\":\"%s\",\"title_id\":\"%s\",\"user_uid\":\"%s\","
        "\"platform\":\"ps5\",\"backup_type\":\"RAW\",\"trigger\":\"Manual\","
        "\"created_at_utc\":\"%s\",\"created_at_epoch\":%lld,"
        "\"backup_scope\":\"selected_containers\",\"partial\":true,\"complete_recovery\":false,"
        "\"raw_completeness\":\"selected_partial\",\"available_slots\":%zu,\"selected_slots_count\":%zu,"
        "\"active_images\":%zu,\"service_images\":%zu,\"total_size\":%llu,\"selected_slots\":[",
        TOSTONSYNC_VERSION, title, uid, utc, (long long)created, available_count, selection.count,
        selection.count, services.count, (unsigned long long)total_bytes);
    if (n < 0 || (size_t)n >= sizeof(manifest)) goto done;
    size_t used = (size_t)n;
    for (size_t i = 0; i < selection.count + count; i++) {
        char escaped[256]; bool image = i >= selection.count;
        size_t index = image ? i - selection.count : i;
        json_escape_small(image ? files[index].name : selection.slots[index], escaped, sizeof(escaped));
        n = snprintf(manifest + used, sizeof(manifest) - used, "%s\"%s\"%s",
                     index ? "," : "", escaped,
                     !image && index + 1 == selection.count ? "],\"included_images\":[" : "");
        if (n < 0 || (size_t)n >= sizeof(manifest) - used) goto done;
        used += (size_t)n;
    }
    if (used + 3 >= sizeof(manifest)) goto done;
    memcpy(manifest + used, "]}", 3);
    static unsigned sequence;
    n = snprintf(zip_path, sizeof(zip_path), "%s/download_%s_%s_RAW_SELECTED_%lld_%d_%u.zip",
                 cfg.paths.staging_dir, uid, title, (long long)time(NULL), (int)getpid(), ++sequence);
    failure = "Could not create a new partial RAW ZIP; any new artifact is retained as evidence";
    if (n < 0 || (size_t)n >= sizeof(zip_path)) { zip_path[0] = 0; goto done; }
    snprintf(out_path, path_sz, "%s", zip_path);
    uint32_t crc; uint64_t zip_size; char fingerprint[65];
    if (!zip_compress_files_top_manifest_sha256(target, title, zip_path, names, count,
          cfg.advanced.zip_mode_deflate, &crc, &zip_size, manifest, fingerprint, hashes)) goto done;
    failure = "Source image metadata/hash changed after ZIP streaming; partial artifact retained";
    for (size_t i = 0; i < count; i++) {
        raw_selected_file_t after = files[i];
        if (!raw_selected_hash(target, &after) ||
            !raw_selected_stat_equal(&files[i].stat, &after.stat) || strcmp(files[i].sha256, after.sha256)) goto done;
    }
    failure = "UID, game state, recovery or container/service inventory changed during download";
    if (!resolve_local_restore_target(title, fresh_uid, sizeof(fresh_uid), fresh, sizeof(fresh), NULL, 0) ||
        strcmp(resolved, fresh_uid) || strcmp(target, fresh) || fs_title_is_running(title) ||
        !save_export_ready(NULL, 0)) goto done;
    save_metadata_recovery_check(&cfg, uid, title, &recovery, &recovery_errno, detail, sizeof(detail));
    if (recovery != SAVE_METADATA_PASS) goto done;
    save_metadata_collect(target, NULL, title, metadata);
    size_t after_count = 0;
    if (!raw_selected_inventory(metadata, after_names, &after_count) || after_count != available_count) goto done;
    restore_selection_t all_before = {.specified = true, .count = available_count};
    memcpy(all_before.slots, available, sizeof(available));
    if (!restore_selection_resolve(&all_before, after_names, after_count, NULL, 0)) goto done;
    for (size_t i = 0; i < selection.count; i++) {
        char path[512]; struct stat st;
        snprintf(path, sizeof(path), "%s/sdimg_sce_bu_%s", target, selection.slots[i]);
        bool exists = lstat(path, &st) == 0;
        if (restore_selection_contains(&services, selection.slots[i]) ? !exists : (exists || errno != ENOENT)) goto done;
    }
    migration_report_t inspected;
    failure = "Partial RAW CRC/checksums/scope validation failed; artifact retained";
    if (!migration_inspect_zip(zip_path, title, &inspected) || !inspected.valid ||
        !inspected.has_checksums || !inspected.selected_containers || inspected.strategy_ready ||
        strcmp(inspected.title_id, title) || strcmp(inspected.source_user_uid, uid) ||
        inspected.available_slots != available_count || inspected.save_dir_count != selection.count ||
        inspected.service_images != services.count || inspected.included_image_count != count) goto done;
    failure = "Could not hash the closed ZIP artifact";
    if (!sha256_file_hex(zip_path, out->zip_sha256)) goto done;
    out->selected_partial = true; out->available_slots = available_count; out->selected_slots = selection.count;
    out->active_images = selection.count; out->service_images = services.count;
    out->missing_service_images = selection.count - services.count;
    snprintf(out->raw_completeness, sizeof(out->raw_completeness), "selected_partial");
    snprintf(out->uid, sizeof(out->uid), "%s", uid); snprintf(out->title_id, sizeof(out->title_id), "%s", title);
    ok = true;
done:
    if (!ok && err && err_sz && !err[0]) snprintf(err, err_sz, "%s (errno=%d)", failure, errno);
    free(metadata);
    // No mount or durable writeback occurred. Failed ZIPs remain evidence;
    // successful ZIPs retain only the scratch lease until the consumer closes.
    if (leased) { if (ok) save_io_end_write(); else watcher_target_check_end(); }
    return ok;
}

typedef struct {
    config_t config;
    char uid[16], title[16], target[320];
    restore_selection_t active, services;
    char available[RESTORE_SELECTION_MAX][64];
    size_t available_count;
    bool barrier_armed;
    char barrier_work[512];
    struct stat barrier_stat;
    paired_backup_report_t* report;
} paired_manual_context_t;

static bool paired_observe(void* context, const char* path, paired_backup_observation_t* out,
                            char* err, size_t n) {
    (void)context;
    const char* leaf = strrchr(path, '/'); char parent[512]; raw_selected_file_t file = {0};
    size_t length = leaf ? (size_t)(leaf - path) : 0;
    if (!leaf || !length || length >= sizeof(parent) || strlen(leaf + 1) >= sizeof(file.name)) return false;
    memcpy(parent, path, length); parent[length] = 0;
    snprintf(file.name, sizeof(file.name), "%s", leaf + 1);
    if (!raw_selected_hash(parent, &file)) {
        if (err && n) snprintf(err, n, "Stable no-follow image hash failed (errno=%d)", errno);
        return false;
    }
    out->stat = file.stat; snprintf(out->sha256, sizeof(out->sha256), "%s", file.sha256); return true;
}
static bool paired_copy(void* context, const char* source, const char* copy_path,
                         const char* expected_sha, char* err, size_t n) {
    (void)context; pfs_attribute_image_t copy = {0};
    if (strlen(source) >= sizeof(copy.source) || strlen(copy_path) >= sizeof(copy.copy)) {
        if (err && n) snprintf(err, n, "Private encrypted copy path exceeds existing acquisition limits"); return false;
    }
    snprintf(copy.source, sizeof(copy.source), "%s", source); snprintf(copy.copy, sizeof(copy.copy), "%s", copy_path);
    bool ok = pfs_attributes_copy_private(&copy) && !strcmp(copy.sha256, expected_sha);
    if (!ok && err && n) snprintf(err, n, "Encrypted acquisition/hash verification failed (errno=%d)", errno);
    return ok;
}
static bool paired_convert(void* context, const char* clone, const char* plain, const char* title,
                            const char* slot, bool* uncertain, char* err, size_t n) {
    (void)context; *uncertain = false;
    bool ok = pfs_resign_recover_image_copy(clone, plain, title, slot, err, n);
    char marker[600]; struct stat st;
    int length = snprintf(marker, sizeof(marker), "%s.recovery_mount_pending", clone);
    if (length < 0 || (size_t)length >= sizeof(marker) || lstat(marker, &st) == 0 || errno != ENOENT)
        *uncertain = true;
    return ok && !*uncertain;
}
static bool paired_barrier(void* context, bool arm, const char* work, char* err, size_t n) {
    paired_manual_context_t* c = context;
    bool ok = watcher_raw_selected_barrier_held(arm, work, err, n);
    if (ok && arm) {
        char path[512]; int length = snprintf(path, sizeof(path), "%s/raw-recovery.pending", c->config.paths.state_dir);
        ok = length > 0 && (size_t)length < sizeof(path) && lstat(path, &c->barrier_stat) == 0 &&
            S_ISREG(c->barrier_stat.st_mode) && c->barrier_stat.st_nlink == 1 &&
            c->barrier_stat.st_size == (off_t)strlen(work);
        if (ok) { c->barrier_armed = true; snprintf(c->barrier_work, sizeof(c->barrier_work), "%s", work); }
    } else if (ok) c->barrier_armed = false;
    return ok;
}
static bool paired_recovery_clear(const paired_manual_context_t* c) {
    // Reuse the same known recovery paths as metadata inspection. The only
    // exception is the exact, pinned raw mount barrier owned by this capture.
    const char* markers[] = {"restore.interrupted", "restore.busy", "raw-recovery.pending"};
    const char* suffixes[] = {"/.pending", ".next", ".previous", ".swap", ".apply", "/.expansion-required", "/.expansion.sqlite"};
    for (size_t i = 0; i < 10; ++i) {
        char path[768]; struct stat st;
        int length = i < 3 ? snprintf(path, sizeof(path), "%s/%s", c->config.paths.state_dir, markers[i]) :
            snprintf(path, sizeof(path), "%s/restore_%s_%s_sdimg_rollback%s", c->config.paths.staging_dir,
                     c->uid, c->title, suffixes[i - 3]);
        if (length <= 0 || (size_t)length >= sizeof(path)) return false;
        if (i == 2 && c->barrier_armed) {
            if (lstat(path, &st) != 0 || !raw_selected_stat_equal(&st, &c->barrier_stat)) return false;
            int fd = open(path, O_RDONLY | O_NOFOLLOW | O_NONBLOCK); if (fd < 0) return false;
            struct stat opened, closed, final; char owner[512] = {0}; unsigned char tail;
            bool same = fstat(fd, &opened) == 0 && raw_selected_stat_equal(&st, &opened);
            ssize_t got = same ? read(fd, owner, sizeof(owner) - 1) : -1;
            same = same && got == (ssize_t)strlen(c->barrier_work) &&
                !memcmp(owner, c->barrier_work, (size_t)got) && read(fd, &tail, 1) == 0 &&
                fstat(fd, &closed) == 0 && raw_selected_stat_equal(&st, &closed) &&
                lstat(path, &final) == 0 && raw_selected_stat_equal(&st, &final);
            if (close(fd) != 0) same = false;
            if (!same) return false;
        } else if (lstat(path, &st) == 0 || errno != ENOENT) return false;
    }
    return true;
}
static bool paired_revalidate(void* context, char* err, size_t n) {
    paired_manual_context_t* c = context; char uid[16], target[320];
    if (!resolve_local_restore_target(c->title, uid, sizeof(uid), target, sizeof(target), err, n) ||
        strcmp(uid, c->uid) || strcmp(target, c->target) || fs_title_is_running(c->title) || !paired_recovery_clear(c)) {
        if (err && n && !err[0]) snprintf(err, n, "Fresh UID/title/game or recovery state changed/is UNKNOWN; capture blocked");
        return false;
    }
    save_metadata_report_t* metadata = calloc(1, sizeof(*metadata));
    if (!metadata) return false;
    char available[RESTORE_SELECTION_MAX][64]; size_t count = 0;
    save_metadata_collect(target, NULL, c->title, metadata);
    bool ok = raw_selected_inventory(metadata, available, &count) && count == c->available_count;
    free(metadata);
    restore_selection_t expected = {.specified=true, .count=c->available_count};
    memcpy(expected.slots, c->available, sizeof(expected.slots));
    if (ok) ok = restore_selection_resolve(&expected, available, count, err, n);
    for (size_t i = 0; ok && i < c->active.count; ++i) {
        char path[512]; struct stat st;
        int length = snprintf(path, sizeof(path), "%s/sdimg_sce_bu_%s", target, c->active.slots[i]);
        if (length <= 0 || (size_t)length >= sizeof(path)) { ok = false; break; }
        int result = lstat(path, &st), error = errno;
        bool declared = restore_selection_contains(&c->services, c->active.slots[i]);
        ok = declared ? result == 0 && S_ISREG(st.st_mode) && st.st_nlink == 1 : result != 0 && error == ENOENT;
    }
    if (!ok && err && n && !err[0]) snprintf(err, n, "Literal container/service inventory changed or is UNKNOWN");
    return ok;
}
static bool paired_finalize(void* context, const char* portable, const char* title_root,
                            const paired_capture_t* capture, const char* out_zip, char* err, size_t n) {
    paired_manual_context_t* c = context;
    char game_name[sizeof(s_titles[0].game_name)] = {0};
    pthread_mutex_lock(&s_titles_lock);
    for (size_t i = 0; i < s_title_count; ++i) {
        if (!strcmp(s_titles[i].title_id, capture->title_id) &&
            !strcmp(s_titles[i].user_uid, capture->source_uid)) {
            snprintf(game_name, sizeof(game_name), "%s", s_titles[i].game_name);
            break;
        }
    }
    pthread_mutex_unlock(&s_titles_lock);
    migration_report_t source = {0}, result = {0}; struct stat st;
    snprintf(source.title_id, sizeof(source.title_id), "%s", capture->title_id);
    snprintf(source.source_user_uid, sizeof(source.source_user_uid), "%s", capture->source_uid);
    snprintf(source.source_console_name, sizeof(source.source_console_name), "%s", c->config.console.name);
    snprintf(source.source_console_type, sizeof(source.source_console_type), "%s", c->config.console.type);
    time_t captured = (time_t)capture->started_at; struct tm tm;
    if (!gmtime_r(&captured, &tm)) return false;
    strftime(source.created_at_utc, sizeof(source.created_at_utc), "%Y-%m-%dT%H:%M:%SZ", &tm);
    source.service_images = c->services.count;
    uint32_t crc; uint64_t size;
    c->report->capture_diagnostic_attempted = true;
    paired_capture_diagnostic_init(&c->report->capture_diagnostic);
    bool ok = paired_capture_write_diagnostic(title_root, capture, err, n, &c->report->capture_diagnostic) &&
        write_migration_manifest(title_root, capture->title_id, game_name, capture->source_uid,
                                  captured, c->active.count, &source) &&
        write_migration_checksums(portable, title_root) &&
        lstat(out_zip, &st) != 0 && errno == ENOENT &&
        zip_compress_directory_complete(portable, out_zip, &crc, &size);
    if (ok) {
        bool inspected = migration_inspect_zip(out_zip, capture->title_id, &result);
        c->report->inspector_diagnostic_attempted = result.capture_diagnostic_attempted;
        c->report->inspector_title_diagnostic = result.capture_title_diagnostic;
        c->report->inspector_raw_diagnostic = result.capture_raw_diagnostic;
        c->report->scratch_before_create = result.scratch_before_create;
        c->report->scratch_after_cleanup = result.scratch_after_cleanup;
        c->report->capture_raw_scratch_after_cleanup = result.capture_raw_scratch_after_cleanup;
        ok = inspected && result.valid && result.format == MIGRATION_FORMAT_TOSTON_DECRYPTED && result.has_checksums &&
        result.strategy_ready && !strcmp(result.restore_strategy, "portable") &&
        !strcmp(result.title_id, capture->title_id) && !strcmp(result.source_user_uid, capture->source_uid) &&
        result.save_dir_count == c->active.count && result.service_dir_count == 0;
    }
    for (size_t i = 0; ok && i < c->active.count; ++i) {
        size_t occurrences = 0;
        for (size_t j = 0; j < result.save_dir_count; ++j) occurrences += !strcmp(c->active.slots[i], result.save_dirs[j]);
        ok = occurrences == 1;
    }
    if (!ok && err && n && !err[0]) snprintf(err, n, "Paired Portable manifest/checksums/inventory verification failed; RAW retained");
    return ok;
}

bool watcher_make_container_selected_backup(const char* uid, const char* title,
    const restore_selection_t* requested, const char* service_slots,
    bool game_closed_confirmed, paired_backup_report_t* out, char* err, size_t n) {
    if (out) { memset(out, 0, sizeof(*out)); snprintf(out->outcome, sizeof(out->outcome), "BLOCKED"); }
    if (err && n) err[0] = 0;
    if (!out || !uid || !valid_uid(uid) || strlen(uid) != 8 || !title || !valid_title_id(title) ||
        strlen(title) != 9 || !requested || !requested->specified || !requested->count ||
        requested->count > RESTORE_SELECTION_MAX || !game_closed_confirmed) {
        if (err && n) snprintf(err, n, "Explicit literal selection, UID/title and closed-game confirmation required"); return false;
    }
    paired_manual_context_t* c = calloc(1, sizeof(*c));
    paired_backup_request_t* req = calloc(1, sizeof(*req));
    bool leased = false, ok = false; save_metadata_report_t* metadata = NULL;
    if (!c || !req) goto done;
    c->active = *requested;
    c->report = out;
    if (!raw_selected_services(service_slots, &c->active, &c->services)) goto done;
    int admission = watcher_target_check_begin(err, n);
    if (admission != 1) goto done;
    leased = true;
    snprintf(c->uid, sizeof(c->uid), "%s", uid); snprintf(c->title, sizeof(c->title), "%s", title);
    char fresh_uid[16];
    if (!config_snapshot(&c->config) ||
        !resolve_local_restore_target(title, fresh_uid, sizeof(fresh_uid), c->target, sizeof(c->target), err, n) ||
        strcmp(fresh_uid, uid) || fs_title_is_running(title)) goto done;
    save_metadata_check_t recovery; int recovery_errno; char detail[192];
    save_metadata_recovery_check(&c->config, uid, title, &recovery, &recovery_errno, detail, sizeof(detail));
    if (recovery != SAVE_METADATA_PASS) goto done;
    metadata = calloc(1, sizeof(*metadata)); if (!metadata) goto done;
    save_metadata_collect(c->target, NULL, title, metadata);
    if (!raw_selected_inventory(metadata, c->available, &c->available_count) ||
        !restore_selection_resolve(&c->active, c->available, c->available_count, err, n) ||
        !paired_revalidate(c, err, n) ||
        !watcher_raw_selected_workspace_held(req->workspace, sizeof(req->workspace), err, n)) goto done;
    snprintf(req->source, sizeof(req->source), "%s", c->target);
    snprintf(req->uid, sizeof(req->uid), "%s", uid); snprintf(req->title_id, sizeof(req->title_id), "%s", title);
    req->active = c->active; req->services = c->services;
    req->available_slots = c->available_count; req->deflate = c->config.advanced.zip_mode_deflate;
    paired_backup_callbacks_t callbacks = {.context=c, .observe=paired_observe, .copy=paired_copy,
        .convert=paired_convert, .barrier=paired_barrier, .revalidate=paired_revalidate, .finalize_portable=paired_finalize};
    ok = paired_backup_run(req, &callbacks, out);
    if (!strcmp(out->outcome, "RAW_ONLY")) {
        char diagnostic[2048];
        size_t length = paired_backup_diagnostic_summary(out, diagnostic, sizeof(diagnostic));
        // One bounded WARN; the complete private diagnostics remain in result.json.
        log_warn("paired capture diagnostic: writer_attempted=%s inspector_attempted=%s barrier_retained=%s unmount_uncertain=%s summary_prefix=%.*s full_diagnostic=result.json",
            out->capture_diagnostic_attempted ? "true" : "false", out->inspector_diagnostic_attempted ? "true" : "false",
            out->barrier_retained ? "true" : "false", out->unmount_uncertain ? "true" : "false",
            length < sizeof(diagnostic) ? 720 : 0, length < sizeof(diagnostic) ? diagnostic : "");
    }
done:
    if (!ok && err && n && !err[0]) snprintf(err, n, "%s", out->detail[0] ? out->detail :
        "Selected paired capture unavailable or UNKNOWN; no fallback to all containers");
    free(metadata); free(req); free(c);
    if (leased) { if (ok) save_io_end_write(); else watcher_target_check_end(); }
    return ok;
}

typedef struct {
    const paired_backup_report_t* capture;
    const char* container;
    watcher_individual_backup_t* out;
    jobs_ref_t observation_job;
    config_t config;
    pthread_mutex_t lock;
    pthread_cond_t finished;
    bool done;
} individual_storage_context_t;

static void individual_storage_run(individual_storage_context_t* c) {
    const paired_backup_report_t* r = c->capture;
    watcher_individual_backup_t* out = c->out;
    if (!config_snapshot(&c->config)) {
        snprintf(out->error, sizeof(out->error), "storage_config_unavailable"); return;
    }
    backup_names_t names;
    if (!backup_save_names_current(r->uid, r->title_id, r->title_id,
            c->container, time(NULL), &names)) {
        snprintf(out->error, sizeof(out->error), "storage_name_unavailable"); return;
    }
    snprintf(out->filename, sizeof(out->filename), "%s", names.filename);
    snprintf(out->game, sizeof(out->game), "%s", names.game[0] ? names.game : r->title_id);
    out->size_bytes = r->portable_zip_size;
    static const char* defaults[CFG_MAX_DESTS] = {"drive", "usb"};
    size_t count = c->config.destinations.order_count;
    if ((!count && !c->config.destinations.order_explicit) || count > CFG_MAX_DESTS) count = 2;
    char saved[32] = {0}, canceled_destinations[32] = {0};
    for (size_t i = 0; i < count; i++) {
        const char* d = c->config.destinations.order_count
            ? c->config.destinations.order[i] : defaults[i];
        int index = !strcmp(d, "drive") ? 0 : !strcmp(d, "usb") ? 1 : -1;
        if (index < 0) continue;
        watcher_individual_destination_t* result = &out->destinations[index];
        if(backup_control_cancelled()) {
            if(dest_configured(d,&c->config)) {
                result->status="canceled";
                dest_list_add(canceled_destinations,sizeof(canceled_destinations),d);
            }
            continue;
        }
        if (!strcmp(d, "drive")) (void)gdrive_activate();
        if (!dest_configured(d, &c->config)) {
            result->failure.code = !strcmp(d, "usb") ? BACKUP_USB_DISABLED :
                backup_drive_unavailable(gdrive_get_state());
            continue;
        }
        if (!strcmp(d, "drive") && gdrive_get_state() == GDRIVE_STATE_ERROR)
            (void)gdrive_ensure_ready();
        if (!dest_attemptable(d, &c->config)) {
            result->failure.code = !strcmp(d, "usb") ? BACKUP_USB_ABSENT :
                backup_drive_unavailable(gdrive_get_state());
            continue;
        }
        bool ok = false;
        jobs_phase(c->observation_job, d, "transferring", out->size_bytes, true);
        int64_t started = monotonic_ms();
        result->status = "failed";
        bool external=strcmp(d,"usb")!=0;
        bool admitted=!external||backup_control_publish_begin();
        if(!admitted) {
            result->status="canceled";
            dest_list_add(canceled_destinations,sizeof(canceled_destinations),d);
            continue;
        }
        if (!strcmp(d, "usb")) {
            result->failure.code = BACKUP_USB_FAILED;
            ok = usb_copy_backup_authorized(r->uid, r->title_id,
                out->filename, r->artifact, NULL, true, true);
            if (!ok) result->failure.code = backup_usb_failure(usb_last_copy_failure());
        } else {
            retention_global_decision_t decision;
            if (retention_check_global(&c->config, out->size_bytes, &decision))
                result->failure = (backup_destination_failure_t){BACKUP_DRIVE_GLOBAL_CAP,
                    decision.counted_bytes, decision.cap_bytes, out->size_bytes};
            else {
                result->failure.code = BACKUP_DRIVE_FAILED;
                char file_id[GDRIVE_FILEID_MAX];
                ok = gdrive_upload_individual_identified(r->uid, r->title_id,
                    out->filename, r->artifact, file_id, NULL);
            }
        }
        if(external)backup_control_publish_end(ok,2U);
        if (ok) {
            result->status = "saved";
            result->failure = (backup_destination_failure_t){0};
            out->ok = true;
            size_t used = strlen(saved);
            snprintf(saved + used, sizeof(saved) - used, "%s%s", used ? "," : "", d);
            log_info("individual-backup[capture=%s destination=%s]: complete duration_ms=%lld size_bytes=%llu",
                r->capture_id, d, (long long)(monotonic_ms() - started), (unsigned long long)out->size_bytes);
            if (c->config.destinations.fallback) break;
        } else if(backup_control_cancelled()) {
            result->status="canceled";
            dest_list_add(canceled_destinations,sizeof(canceled_destinations),d);
        } else {
            const char* cause = !strcmp(d, "usb") ? "BACKUP_USB_FAILED" :
                result->failure.code == BACKUP_DRIVE_GLOBAL_CAP ? "BACKUP_DRIVE_GLOBAL_CAP" : "BACKUP_DRIVE_FAILED";
            log_warn("individual-backup[capture=%s destination=%s]: failed cause=%s", r->capture_id, d, cause);
        }
    }
    if(backup_control_finish_begin()) {
        bool durable=backup_cancel_record(r->uid,r->title_id,(int64_t)time(NULL),"Manual",true);
        history_meta_t meta={0};meta.canceled=durable;meta.cancel_unknown=!durable;
        snprintf(meta.status,sizeof(meta.status),"%s",saved[0]?"partial":"failed");
        snprintf(meta.canceled_dests,sizeof(meta.canceled_dests),"%s",canceled_destinations);
        history_record(r->uid,r->title_id,out->game,out->filename,"Portable","Manual",
                       out->size_bytes,0,saved,&meta);
        out->ok=false;snprintf(out->error,sizeof(out->error),"%s",durable?"backup_canceled":"backup_cancel_unsaved");
        return;
    }
    // Report passive absence for destinations skipped by fallback/order. This
    // never activates Drive or attempts an unconfigured destination.
    for (size_t i = 0; i < 2; i++) {
        watcher_individual_destination_t* d = &out->destinations[i];
        if (strcmp(d->status, "not_attempted") || d->failure.code != BACKUP_DEST_OK) continue;
        if (i == 1) d->failure.code = !c->config.usb.enabled ? BACKUP_USB_DISABLED :
            !usb_is_present() ? BACKUP_USB_ABSENT : BACKUP_DEST_OK;
        else if (gdrive_get_state() != GDRIVE_STATE_READY)
            d->failure.code = backup_drive_unavailable(gdrive_get_state());
    }
    if (out->ok) log_info("activity:individual_backup_complete|%s|%s", out->game, saved);
    else log_warn("activity:individual_backup_failed|%s", out->game);
}

static void* individual_storage_thread(void* arg) {
    individual_storage_context_t* c = arg;
    jobs_ref_t previous = jobs_bind(c->observation_job);
    backup_control_t control;
    if(backup_control_begin(&control,c->observation_job)){
        backup_control_t* bound=backup_control_bind(&control);
        individual_storage_run(c);
        if(backup_control_finish_begin()){
            bool durable=backup_cancel_record(c->capture->uid,c->capture->title_id,(int64_t)time(NULL),"Manual",true);
            c->out->ok=false;snprintf(c->out->error,sizeof(c->out->error),"%s",durable?"backup_canceled":"backup_cancel_unsaved");
        }
        if(backup_control_cancelled())jobs_finish(c->observation_job,
            control.cancel_result<0?JOB_UNKNOWN:JOB_FAILED,c->out->error);
        backup_control_bind(bound);backup_control_end(&control);
    }else snprintf(c->out->error,sizeof(c->out->error),"backup_control_unavailable");
    jobs_bind(previous);
    pthread_mutex_lock(&c->lock);
    c->done = true;
    pthread_cond_signal(&c->finished);
    pthread_mutex_unlock(&c->lock);
    return NULL;
}

void watcher_store_container_selected(const paired_backup_report_t* capture,
    const char* container, watcher_individual_backup_t* out) {
    memset(out, 0, sizeof(*out));
    for (size_t i = 0; i < 3; i++) out->destinations[i].status = "not_attempted";
    if (!capture || strcmp(capture->outcome, "PAIRED_VERIFIED") || !capture->migration_ready ||
        capture->barrier_retained || capture->unmount_uncertain || capture->selected_active_slots != 1 ||
        !capture->portable_zip_size || !capture->artifact[0] || !container) {
        snprintf(out->error, sizeof(out->error), "selected_capture_not_paired"); return;
    }
    individual_storage_context_t* c = calloc(1, sizeof(*c));
    if (!c) { snprintf(out->error, sizeof(out->error), "storage_memory_unavailable"); return; }
    c->capture = capture; c->container = container; c->out = out;
    c->observation_job = jobs_bound();
    int rc = pthread_mutex_init(&c->lock, NULL);
    if (rc) { snprintf(out->error, sizeof(out->error), "storage_thread_mutex_failed"); out->thread_error = rc; free(c); return; }
    rc = pthread_cond_init(&c->finished, NULL);
    if (rc) {
        snprintf(out->error, sizeof(out->error), "storage_thread_condition_failed"); out->thread_error = rc;
        pthread_mutex_destroy(&c->lock); free(c); return;
    }
    pthread_attr_t attr;
    rc = pthread_attr_init(&attr);
    if (rc) snprintf(out->error, sizeof(out->error), "storage_thread_attr_init_failed");
    else {
        rc = pthread_attr_setstacksize(&attr, 1024 * 1024);
        if (rc) snprintf(out->error, sizeof(out->error), "storage_thread_stack_failed");
        else {
            pthread_t thread;
            rc = pthread_create(&thread, &attr, individual_storage_thread, c);
            if (rc) snprintf(out->error, sizeof(out->error), "storage_thread_create_failed");
            else {
                rc = pthread_join(thread, NULL);
                if (rc) {
                    // A failed join cannot let the HTTP request release a live
                    // writer's workspace. Await completion without a second join.
                    pthread_mutex_lock(&c->lock);
                    while (!c->done) pthread_cond_wait(&c->finished, &c->lock);
                    pthread_mutex_unlock(&c->lock);
                    out->ok = false;
                    snprintf(out->error, sizeof(out->error), "storage_thread_join_unknown");
                }
            }
        }
        pthread_attr_destroy(&attr);
    }
    out->thread_error = rc;
    pthread_cond_destroy(&c->finished); pthread_mutex_destroy(&c->lock); free(c);
}

static bool copy_decrypted_export_slots(const char* slots_root,
                                         const char* title_root,
                                         size_t* copied) {
    *copied = 0;
    DIR* d = opendir(slots_root);
    if (!d) return false;
    bool ok = true;
    for (;;) {
        errno = 0;
        struct dirent* e = readdir(d);
        if (!e) { if (errno) ok = false; break; }
        if (!strcmp(e->d_name, ".") || !strcmp(e->d_name, "..")) continue;
        char src[640], dst[680];
        int sn = snprintf(src, sizeof(src), "%s/%s", slots_root, e->d_name);
        int dn = snprintf(dst, sizeof(dst), "%s/sdimg_%s", title_root, e->d_name);
        struct stat st;
        if (*copied >= MIGRATION_MAX_SLOTS || !safe_path_component(e->d_name) ||
            sn < 0 || (size_t)sn >= sizeof(src) ||
            dn < 0 || (size_t)dn >= sizeof(dst) ||
            lstat(src, &st) != 0 || !S_ISDIR(st.st_mode) ||
            !pfs_fs_copy_tree(src, dst)) {
            ok = false;
            break;
        }
        (*copied)++;
    }
    if (closedir(d) != 0) ok = false;
    return ok && *copied > 0;
}

static bool make_decrypted_zip_inner(const char* user_uid,
                                     const char* title_id,
                                     bool formal_migration,
                                     char* out_zip_path,
                                     size_t out_zip_path_sz,
                                     char* err, size_t err_sz) {
    if (out_zip_path && out_zip_path_sz) out_zip_path[0] = '\0';
    if (err && err_sz) err[0] = '\0';
    if (!s_cfg) {
        if (err && err_sz) snprintf(err, err_sz, "Watcher is not ready");
        return false;
    }
    if (!valid_title_id(title_id) || !valid_uid(user_uid ? user_uid : "")) {
        if (err && err_sz) snprintf(err, err_sz, "Invalid title or user");
        return false;
    }

    char src_path[256] = {0};
    char uid[16] = {0};
    char game[64] = {0};
    bool game_running = false;
    pthread_mutex_lock(&s_titles_lock);
    for (size_t i = 0; i < s_title_count; i++) {
        title_t* t = &s_titles[i];
        if (strcmp(t->title_id, title_id) != 0) continue;
        if (user_uid && user_uid[0] && strcmp(t->user_uid, user_uid) != 0)
            continue;
        snprintf(src_path, sizeof(src_path), "%s", t->path);
        snprintf(uid, sizeof(uid), "%s",
                 t->user_uid[0] ? t->user_uid : "default");
        snprintf(game, sizeof(game), "%s", t->game_name);
        game_running = (t->pid_if_running != 0);
        break;
    }
    pthread_mutex_unlock(&s_titles_lock);

    if (!src_path[0]) {
        if (err && err_sz) snprintf(err, err_sz, "Save not found on this PS5");
        return false;
    }
    if (game_running || !fs_title_is_closed(title_id)) {
        if (err && err_sz)
            snprintf(err, err_sz, "Game must be closed and its state readable before decrypted ZIP download");
        return false;
    }
    if (!restore_dir_has_sdimg(src_path)) {
        if (err && err_sz)
            snprintf(err, err_sz, "Decrypted export needs an sdimg_* save");
        return false;
    }
    if (!fs_mkdir_p(s_cfg->paths.staging_dir)) {
        if (err && err_sz) snprintf(err, err_sz, "Cannot create staging folder");
        return false;
    }

    char ts[32];
    time_t now = time(NULL);
    struct tm tm;
    gmtime_r(&now, &tm);
    strftime(ts, sizeof(ts), "%Y%m%dT%H%M%SZ", &tm);
    unsigned long stage_id = next_stage_seq();

    char plain_stage[300], garlic_stage[300], title_root[340], zip_path[320];
    snprintf(plain_stage, sizeof(plain_stage),
             "%s/download_%s_%s_plain_%ld_%lu",
             s_cfg->paths.staging_dir, uid, title_id,
             (long)getpid(), stage_id);
    snprintf(garlic_stage, sizeof(garlic_stage),
             "%s/download_%s_%s_garlic_%ld_%lu",
             s_cfg->paths.staging_dir, uid, title_id,
             (long)getpid(), stage_id);
    snprintf(title_root, sizeof(title_root), "%s/%s", garlic_stage, title_id);
    snprintf(zip_path, sizeof(zip_path),
             "%s/download_%s_%s_garlic_%s_%ld_%lu.zip",
             s_cfg->paths.staging_dir, uid, title_id, ts,
             (long)getpid(), stage_id);

    pfs_fs_rmrf(plain_stage);
    pfs_fs_rmrf(garlic_stage);
    bool ok = pfs_resign_backup_sdimg_to_staging(src_path, plain_stage);
    if (!ok) {
        pfs_fs_rmrf(plain_stage);
        if (err && err_sz)
            snprintf(err, err_sz,
                     "Kernel decrypt failed. Load kstuff, close the game, then try again.");
        return false;
    }
    if (!fs_mkdir_p(title_root)) {
        pfs_fs_rmrf(plain_stage);
        pfs_fs_rmrf(garlic_stage);
        if (err && err_sz) snprintf(err, err_sz, "Cannot create decrypted layout");
        return false;
    }

    char slots_root[340];
    snprintf(slots_root, sizeof(slots_root), "%s/slots", plain_stage);
    size_t copied = 0;
    if (!copy_decrypted_export_slots(slots_root, title_root, &copied)) {
        pfs_fs_rmrf(plain_stage);
        pfs_fs_rmrf(garlic_stage);
        if (err && err_sz)
            snprintf(err, err_sz, "Could not copy every decrypted save slot");
        return false;
    }
    // The watcher PID cache is asynchronous. Refuse a capture if the game
    // started while the kernel was dumping/copying its slots.
    if (!fs_title_is_closed(title_id)) {
        pfs_fs_rmrf(plain_stage);
        pfs_fs_rmrf(garlic_stage);
        if (err && err_sz)
            snprintf(err, err_sz, "Game started or its state became unavailable during export; close it and retry");
        return false;
    }

    if (formal_migration &&
        (!write_migration_manifest(title_root, title_id, game, uid, now,
                                   copied, NULL) ||
         !write_migration_checksums(garlic_stage, title_root))) {
        pfs_fs_rmrf(plain_stage);
        pfs_fs_rmrf(garlic_stage);
        if (err && err_sz)
            snprintf(err, err_sz, "Could not create migration metadata");
        return false;
    }

    uint32_t crc = 0;
    uint64_t zsize = 0;
    ok = zip_compress_directory(garlic_stage, zip_path,
                                s_cfg->advanced.zip_mode_deflate,
                                &crc, &zsize);
    pfs_fs_rmrf(plain_stage);
    pfs_fs_rmrf(garlic_stage);
    if (!ok) {
        unlink(zip_path);
        if (err && err_sz)
            snprintf(err, err_sz, "Could not create decrypted ZIP");
        return false;
    }

    // Validate exactly the archive the recipient will inspect, not merely
    // the subset for which the producer happened to write a manifest.
    migration_report_t report;
    if ((formal_migration &&
         (!migration_inspect_zip(zip_path, title_id, &report) ||
          report.format != MIGRATION_FORMAT_TOSTON_DECRYPTED ||
          !report.has_checksums || report.save_dir_count != copied ||
          !report.strategy_ready || strcmp(report.restore_strategy, "portable"))) ||
        !fs_title_is_closed(title_id)) {
        unlink(zip_path);
        if (err && err_sz)
            snprintf(err, err_sz, "ZIP verification or game-state check failed; retry with the game closed and its state readable");
        return false;
    }

    snprintf(out_zip_path, out_zip_path_sz, "%s", zip_path);
    log_info("watcher: built %s download ZIP for %s/%s (%zu slots, %llu B)",
             formal_migration ? "migration" : "Garlic-compatible",
             uid, title_id, copied,
             (unsigned long long)zsize);
    return true;
}

bool watcher_make_garlic_zip(const char* user_uid, const char* title_id,
                             char* out_zip_path, size_t out_zip_path_sz,
                             char* err, size_t err_sz) {
    if (!lifecycle_admit(err, err_sz)) return false;
    scratch_begin_use();
    if (!save_io_begin_read()) {
        watcher_release_backup_file(NULL, false);
        lifecycle_operation_end();
        return false;
    }
    bool ok = save_export_ready(err, err_sz) &&
              make_decrypted_zip_inner(user_uid, title_id, false,
                                       out_zip_path, out_zip_path_sz,
                                       err, err_sz);
    save_io_end_read();
    if (!ok) watcher_release_backup_file(NULL, false);
    lifecycle_operation_end();
    return ok;
}

bool watcher_make_migration_zip(const char* user_uid, const char* title_id,
                                char* out_zip_path, size_t out_zip_path_sz,
                                char* err, size_t err_sz) {
    if (!lifecycle_admit(err, err_sz)) return false;
    scratch_begin_use();
    if (!save_io_begin_read()) {
        watcher_release_backup_file(NULL, false);
        lifecycle_operation_end();
        return false;
    }
    bool ok = save_export_ready(err, err_sz) &&
              make_decrypted_zip_inner(user_uid, title_id, true,
                                       out_zip_path, out_zip_path_sz,
                                       err, err_sz);
    save_io_end_read();
    if (!ok) watcher_release_backup_file(NULL, false);
    lifecycle_operation_end();
    return ok;
}

// A crash while a kernel mount exists cannot be resolved by deleting files.
// Keep this durable guard until every private image is known to be unmounted.
static bool raw_recovery_marker_path(char* path, size_t cap) {
    int n = s_cfg ? snprintf(path, cap, "%s/raw-recovery.pending",
                             s_cfg->paths.state_dir) : -1;
    return n > 0 && (size_t)n < cap;
}

static bool raw_recovery_marker(bool create, const char* work) {
    char path[512];
    if (!raw_recovery_marker_path(path, sizeof(path))) return false;
    bool ok;
    if (create) {
        int fd = open(path, O_WRONLY | O_CREAT | O_EXCL, 0600);
        if (fd < 0) return false;
        size_t len = strlen(work);
        ok = write(fd, work, len) == (ssize_t)len && fsync(fd) == 0;
        if (close(fd) != 0) ok = false;
    } else {
        ok = unlink(path) == 0;
    }
    int dir = open(s_cfg->paths.state_dir, O_RDONLY | O_DIRECTORY);
    if (dir < 0) return false;
    if (fsync(dir) != 0) ok = false;
    if (close(dir) != 0) ok = false;
    return ok;
}

static bool recovery_has_room(const char* dir, uint64_t bytes) {
    struct statvfs sv;
    const uint64_t margin = 512ULL * 1024 * 1024;
    if (bytes > (UINT64_MAX - margin) / 4 || statvfs(dir, &sv) != 0 ||
        !sv.f_frsize || (uint64_t)sv.f_bavail > UINT64_MAX / sv.f_frsize)
        return false;
    // Decrypted files, the stored ZIP, and recipient-style ZIP verification
    // can coexist. Do not rely on compression to make the workspace fit.
    return (uint64_t)sv.f_bavail * sv.f_frsize >= bytes * 4 + margin;
}

static bool recover_raw_import_inner(const import_session_info_t* info,
                                     char* candidate, size_t candidate_sz,
                                     char* title, size_t title_sz,
                                     char* err, size_t err_sz) {
    candidate[0] = title[0] = '\0';
    migration_report_t raw;
    char work[560], extracted[600], portable[600], root[640], title_root[640];
    char verified[600], verified_title[640];
    bool guarded = false, cleanup_safe = true, made_work = false, ok = false;
    bool candidate_written = false;
    const char* failure = "RAW recovery preparation failed; original retained";
    struct stat st;
    if (!info || info->state != IMPORT_RECOVERING ||
        !import_session_validate_selected(info) ||
        !import_session_recovery_candidate(info, candidate, candidate_sz) ||
        !migration_inspect_zip(info->path, info->title_hint, &raw) ||
        raw.format != MIGRATION_FORMAT_ENCRYPTED_IMAGE || raw.selected_containers ||
        !valid_title_id(raw.title_id) || !raw.save_dir_count ||
        raw.save_dir_count > MIGRATION_MAX_SLOTS ||
        raw.active_images != raw.save_dir_count) {
        failure = "RAW inventory or original SHA-256 is invalid; original retained";
        goto done;
    }
    char imports[512];
    int in = snprintf(imports, sizeof(imports), "%s/imports", s_cfg->paths.state_dir);
    if (in < 0 || (size_t)in >= sizeof(imports) ||
        !safe_path_component(info->id) || !fs_mkdir_p(imports)) {
        failure = "Could not create private internal recovery storage; original retained";
        goto done;
    }
    char* resolved = realpath(imports, NULL);
    bool internal = resolved && strncmp(resolved, "/data/", 6) == 0;
    free(resolved);
    if (!internal) {
        failure = "RAW recovery requires private internal /data storage; original retained";
        goto done;
    }
    int wn = snprintf(work, sizeof(work), "%s/recovery_%s", imports, info->id);
    if (wn < 0 || (size_t)wn >= sizeof(work) ||
        lstat(work, &st) == 0 || errno != ENOENT ||
        lstat(candidate, &st) == 0 || errno != ENOENT) {
        failure = "Previous recovery files require inspection; original retained";
        goto done;
    }
    if (!raw_recovery_marker(true, work)) {
        failure = "Could not persist RAW mount safety guard; original retained";
        goto done;
    }
    guarded = true;
    if (mkdir(work, 0700) != 0) goto done;
    made_work = true;
    snprintf(extracted, sizeof(extracted), "%s/raw", work);
    snprintf(portable, sizeof(portable), "%s/portable", work);
    snprintf(title_root, sizeof(title_root), "%s/%s", portable, raw.title_id);
    snprintf(verified, sizeof(verified), "%s/verify", work);
    snprintf(verified_title, sizeof(verified_title), "%s/%s", verified, raw.title_id);
    if (!fs_mkdir_p(extracted) || !zip_extract_to_directory(info->path, extracted)) {
        failure = "Could not extract private RAW copies; original retained";
        goto done;
    }
    // Minimal supported layout: flat images or a single title-ID wrapper.
    // Never search heuristically for a different slot with a similar name.
    snprintf(root, sizeof(root), "%s/%s", extracted, raw.title_id);
    if (lstat(root, &st) != 0 && errno == ENOENT)
        snprintf(root, sizeof(root), "%s", extracted);
    uint64_t images_bytes = 0;
    for (size_t i = 0; i < raw.save_dir_count; i++) {
        char image[768];
        int n = snprintf(image, sizeof(image), "%s/sdimg_%s", root, raw.save_dirs[i]);
        if (!safe_path_component(raw.save_dirs[i]) ||
            n < 0 || (size_t)n >= sizeof(image) ||
            lstat(image, &st) != 0 || !S_ISREG(st.st_mode) || st.st_size <= 0 ||
            (uint64_t)st.st_size > UINT64_MAX - images_bytes) {
            failure = "RAW active-image inventory does not match extracted copies; original retained";
            goto done;
        }
        images_bytes += (uint64_t)st.st_size;
    }
    if (!recovery_has_room(work, images_bytes) ||
        !recovery_has_room(info->path, images_bytes) || !fs_mkdir_p(title_root)) {
        failure = "Not enough verified temporary space for RAW recovery; original retained";
        goto done;
    }
    for (size_t i = 0; i < raw.save_dir_count; i++) {
        char image[768], output[768], marker[800];
        snprintf(image, sizeof(image), "%s/sdimg_%s", root, raw.save_dirs[i]);
        snprintf(output, sizeof(output), "%s/sdimg_%s", title_root, raw.save_dirs[i]);
        if (!pfs_resign_recover_image_copy(image, output, raw.title_id,
                                          raw.save_dirs[i], err, err_sz)) {
            snprintf(marker, sizeof(marker), "%s.recovery_mount_pending", image);
            cleanup_safe = lstat(marker, &st) != 0 && errno == ENOENT;
            failure = err && err[0] ? NULL :
                "This PS5 cannot decrypt the RAW copy. Use the readable source PS5 to export a portable backup; original retained";
            goto done;
        }
        log_info("raw-recovery: decrypted and verified private slot %zu/%zu",
                 i + 1, raw.save_dir_count);
    }
    if (!write_migration_manifest(title_root, raw.title_id, raw.title_name,
                                   raw.source_user_uid, time(NULL),
                                   raw.save_dir_count, &raw) ||
        !write_migration_checksums(portable, title_root)) {
        failure = "Could not write complete recovery inventory/checksums; original retained";
        goto done;
    }
    uint32_t crc;
    uint64_t size;
    migration_report_t result;
    candidate_written = true;
    if (!zip_compress_directory_complete(portable, candidate, &crc, &size) ||
        !fs_mkdir_p(verified) || !zip_extract_to_directory(candidate, verified) ||
        !pfs_fs_verify_tree(title_root, verified_title) ||
        !migration_inspect_zip(candidate, raw.title_id, &result) ||
        result.format != MIGRATION_FORMAT_TOSTON_DECRYPTED ||
        !result.has_checksums || !result.strategy_ready ||
        strcmp(result.restore_strategy, "portable") ||
        result.save_dir_count != raw.save_dir_count ||
        !import_session_validate_selected(info)) {
        failure = "Recovered portable ZIP or original SHA-256 failed verification; original retained";
        goto done;
    }
    for (size_t i = 0; i < raw.save_dir_count; i++) {
        bool found = false;
        for (size_t j = 0; j < result.save_dir_count; j++)
            if (!strcmp(raw.save_dirs[i], result.save_dirs[j])) found = true;
        if (!found) {
            failure = "Recovered portable slot inventory changed; original retained";
            goto done;
        }
    }
    snprintf(title, title_sz, "%s", raw.title_id);
    ok = true;
done:
    if (cleanup_safe) {
        if (made_work) pfs_fs_rmrf(work);
        if (guarded && !raw_recovery_marker(false, work)) {
            failure = "RAW recovery safety checkpoint could not be cleared; inspect before retrying";
            ok = false;
        }
    }
    if (!ok) {
        if (candidate_written && candidate[0]) unlink(candidate);
        candidate[0] = title[0] = '\0';
        if (failure && err && err_sz) snprintf(err, err_sz, "%s", failure);
    }
    return ok;
}

bool watcher_recover_raw_import(const import_session_info_t* info,
                                char* candidate, size_t candidate_sz,
                                char* title, size_t title_sz,
                                char* err, size_t err_sz) {
    if (!candidate || !candidate_sz || !title || !title_sz) return false;
    candidate[0] = title[0] = '\0';
    if (err && err_sz) err[0] = '\0';
    if (!lifecycle_admit(err, err_sz)) return false;
    scratch_begin_use();
    // Exclusive so two recovery preparations cannot race over the durable
    // guard, and no other save mount overlaps a private recovery mount.
    if (!save_io_begin_write()) {
        watcher_release_backup_file(NULL, false);
        lifecycle_operation_end();
        return false;
    }
    bool ok = save_export_ready(err, err_sz) &&
              recover_raw_import_inner(info, candidate, candidate_sz,
                                       title, title_sz, err, err_sz);
    save_io_end_write();
    watcher_release_backup_file(NULL, false);
    lifecycle_operation_end();
    return ok;
}

static bool sdimg_active_image_name(const char* name) {
    if (!name || strncmp(name, "sdimg_", 6) != 0) return false;
    if (strncmp(name, "sdimg_sce_bu_", 13) == 0) return false;
    return safe_path_component(name + 6);
}

// Private description inspection owns one exclusive lease and mount barrier.
typedef struct {
    raw_selected_file_t original;
    sfo_info_t info;
    char copy[256];
    struct stat copy_stat;
    int parsed;
    bool copied;
} slot_description_image_t;

typedef struct {
    char uid[16], target[320], work[256], marker[512];
    struct stat target_stat, work_stat, marker_stat;
    bool workspace, barrier_attempted, retain_lease;
    size_t count;
    slot_description_image_t images[SAVE_METADATA_MAX_ENTRIES];
} slot_description_context_t;

static bool slot_description_identity(const char* requested_uid, const char* title,
                                      const slot_description_context_t* c,
                                      char* err, size_t err_sz) {
    char uid[16], target[320], checked[16], checked_target[320];
    if (!fs_title_is_closed(title) ||
        !save_metadata_resolve_uid(requested_uid, title, uid, sizeof(uid),
                                  target, sizeof(target), err, err_sz) ||
        !save_metadata_resolve_uid(uid, title, checked, sizeof(checked),
                                  checked_target, sizeof(checked_target), err, err_sz) ||
        strcmp(uid, checked) || strcmp(target, checked_target)) return false;
    if (!c) return true;
    struct stat st;
    return !strcmp(uid, c->uid) && !strcmp(target, c->target) &&
        lstat(target, &st) == 0 && raw_selected_stat_equal(&st, &c->target_stat);
}

static bool slot_description_inventory(const char* target, raw_selected_file_t* files,
                                       size_t* count, struct stat* directory) {
    *count = 0;
    struct stat before, opened, after;
    if (lstat(target, &before) || !S_ISDIR(before.st_mode)) return false;
    int fd = open(target, O_RDONLY | O_DIRECTORY | O_NOFOLLOW);
    if (fd < 0) return false;
    if (fstat(fd, &opened) || !raw_selected_stat_equal(&before, &opened)) {
        close(fd); return false;
    }
    DIR* d = fdopendir(fd);
    if (!d) { close(fd); return false; }
    bool ok = true, primary = true;
    for (;;) {
        const char* name;
        struct dirent* e = NULL;
        if (primary) name = "savedata0.bin";
        else {
            errno = 0; e = readdir(d);
            if (!e) { if (errno) ok = false; break; }
            name = e->d_name;
            if (strncmp(name, "sdimg_", 6) || !strncmp(name, "sdimg_sce_bu_", 13)) continue;
            if (!sdimg_active_image_name(name)) { ok = false; break; }
        }
        char path[256]; struct stat st;
        int n = snprintf(path, sizeof(path), "%s/%s", target, name);
        if (n < 0 || (size_t)n >= sizeof(path) || strlen(name) >= sizeof(files[0].name)) {
            ok = false; break;
        }
        int found = lstat(path, &st), error = errno;
        if (primary) {
            primary = false;
            if (found && error == ENOENT) continue;
        }
        if (found || !S_ISREG(st.st_mode) || st.st_nlink != 1 || st.st_size <= 0 ||
            *count == SAVE_METADATA_MAX_ENTRIES) { ok = false; break; }
        for (size_t i = 0; i < *count; i++)
            if (files[i].stat.st_dev == st.st_dev && files[i].stat.st_ino == st.st_ino) ok = false;
        if (!ok) break;
        raw_selected_file_t* file = &files[(*count)++];
        memset(file, 0, sizeof(*file));
        snprintf(file->name, sizeof(file->name), "%s", name);
        file->stat = st;
    }
    if (closedir(d)) ok = false;
    if (lstat(target, &after) || !raw_selected_stat_equal(&before, &after)) ok = false;
    if (ok) *directory = after;
    return ok && *count != 0;
}

static bool slot_description_workspace(const slot_description_context_t* c) {
    struct stat st;
    char* canonical = realpath(c->work, NULL);
    bool ok = canonical && !strcmp(canonical, c->work) &&
        !strncmp(c->work, "/data/", 6) &&
        !path_contains(c->work, c->target) && !path_contains(c->target, c->work) &&
        lstat(c->work, &st) == 0 && S_ISDIR(st.st_mode) && (st.st_mode & 0777) == 0700 &&
        st.st_dev == c->work_stat.st_dev && st.st_ino == c->work_stat.st_ino &&
        st.st_uid == c->work_stat.st_uid && st.st_gid == c->work_stat.st_gid;
    free(canonical);
    return ok;
}

static bool slot_description_marker(slot_description_context_t* c, bool pin) {
    char current[512]; struct stat st, opened, closed, final;
    if (!raw_recovery_marker_path(current, sizeof(current)) || strcmp(current, c->marker) ||
        lstat(c->marker, &st) || !S_ISREG(st.st_mode) || st.st_nlink != 1 ||
        (st.st_mode & 0777) != 0600 || st.st_size != (off_t)strlen(c->work) ||
        (!pin && !raw_selected_stat_equal(&st, &c->marker_stat))) return false;
    int fd = open(c->marker, O_RDONLY | O_NOFOLLOW | O_NONBLOCK);
    if (fd < 0) return false;
    char owner[256]; unsigned char tail;
    bool ok = fstat(fd, &opened) == 0 && raw_selected_stat_equal(&st, &opened);
    ssize_t n = ok ? read(fd, owner, sizeof(owner)) : -1;
    ok = ok && n == (ssize_t)strlen(c->work) && !memcmp(owner, c->work, (size_t)n) &&
        read(fd, &tail, 1) == 0 && fstat(fd, &closed) == 0 &&
        raw_selected_stat_equal(&st, &closed) && lstat(c->marker, &final) == 0 &&
        raw_selected_stat_equal(&st, &final);
    if (close(fd)) ok = false;
    if (ok && pin) c->marker_stat = final;
    return ok;
}

static bool slot_description_copy_owned(const slot_description_context_t* c,
                                        const slot_description_image_t* image,
                                        bool unchanged) {
    struct stat st;
    if (!slot_description_workspace(c) || lstat(image->copy, &st) ||
        !S_ISREG(st.st_mode) || st.st_nlink != 1 || (st.st_mode & 0777) != 0600 ||
        st.st_dev != image->copy_stat.st_dev || st.st_ino != image->copy_stat.st_ino ||
        st.st_uid != image->copy_stat.st_uid || st.st_gid != image->copy_stat.st_gid)
        return false;
    if (!unchanged) return true; // Native unmount may re-seal this owned clone.
    raw_selected_file_t observed = {0};
    const char* name = strrchr(image->copy, '/');
    if (!name || strlen(name + 1) >= sizeof(observed.name)) return false;
    snprintf(observed.name, sizeof(observed.name), "%s", name + 1);
    return raw_selected_stat_equal(&st, &image->copy_stat) &&
        raw_selected_hash(c->work, &observed) &&
        raw_selected_stat_equal(&observed.stat, &image->copy_stat) &&
        !strcmp(observed.sha256, image->original.sha256);
}

static bool slot_description_originals(const char* requested_uid, const char* title,
                                       slot_description_context_t* c,
                                       char* err, size_t err_sz) {
    if (!slot_description_identity(requested_uid, title, c, err, err_sz)) return false;
    raw_selected_file_t* current = calloc(SAVE_METADATA_MAX_ENTRIES, sizeof(*current));
    if (!current) return false;
    size_t count = 0; struct stat directory;
    bool ok = slot_description_inventory(c->target, current, &count, &directory) &&
        count == c->count && raw_selected_stat_equal(&directory, &c->target_stat);
    for (size_t i = 0; ok && i < c->count; i++) {
        raw_selected_file_t* original = &c->images[i].original;
        size_t j = 0;
        while (j < count && strcmp(current[j].name, original->name)) j++;
        ok = j < count && raw_selected_stat_equal(&current[j].stat, &original->stat);
        if (ok && c->images[i].copied) {
            ok = raw_selected_hash(c->target, &current[j]) &&
                raw_selected_stat_equal(&current[j].stat, &original->stat) &&
                !strcmp(current[j].sha256, original->sha256);
        }
    }
    free(current);
    return ok;
}

static bool slot_description_cleanup(slot_description_context_t* c) {
    if (!slot_description_workspace(c) ||
        (c->barrier_attempted && !slot_description_marker(c, false))) return false;
    for (size_t i = 0; i < c->count; i++) {
        slot_description_image_t* image = &c->images[i];
        if (!image->copied) continue;
        if (!slot_description_copy_owned(c, image, false) ||
            (c->barrier_attempted && !slot_description_marker(c, false)) ||
            unlink(image->copy)) return false;
    }
    int fd = open(c->work, O_RDONLY | O_DIRECTORY | O_NOFOLLOW);
    bool ok = fd >= 0 && fsync(fd) == 0;
    if (fd >= 0 && close(fd)) ok = false;
    if (!ok || !slot_description_workspace(c)) return false;
    // Keep the empty workspace when barrier retirement cannot be confirmed.
    if (c->barrier_attempted &&
        (!slot_description_marker(c, false) ||
         !watcher_raw_selected_barrier_held(false, c->work, NULL, 0))) return false;
    if (c->barrier_attempted) {
        struct stat st;
        if (lstat(c->marker, &st) == 0 || errno != ENOENT) return false;
    }
    if (!slot_description_workspace(c) || rmdir(c->work)) return false;
    c->workspace = false;
    char parent[256]; snprintf(parent, sizeof(parent), "%s", c->work);
    char* slash = strrchr(parent, '/');
    if (!slash || slash == parent) return false;
    *slash = 0;
    fd = open(parent, O_RDONLY | O_DIRECTORY | O_NOFOLLOW);
    ok = fd >= 0 && fsync(fd) == 0;
    if (fd >= 0 && close(fd)) ok = false;
    return ok;
}

static bool enumerate_save_slots_inner(const char* user_uid,
                                       const char* title_id,
                                       watcher_slot_cb_t cb,
                                       void* ud,
                                       char* err,
                                       size_t err_sz,
                                       bool* retain_lease) {
    if (err && err_sz) err[0] = '\0';
    if (!cb) {
        if (err && err_sz) snprintf(err, err_sz, "Internal slot callback missing");
        return false;
    }
    if (!s_cfg) {
        if (err && err_sz) snprintf(err, err_sz, "Watcher is not ready");
        return false;
    }
    if (!valid_title_id(title_id) || strlen(title_id) != 9 ||
        (user_uid && !save_metadata_uid_valid(user_uid))) {
        if (err && err_sz) snprintf(err, err_sz, "Invalid title or user");
        return false;
    }

    bool ok = false;
    const char* failure = "Closed game, exact owner or image inventory is unavailable";
    slot_description_context_t* c = calloc(1, sizeof(*c));
    raw_selected_file_t* inventory = calloc(SAVE_METADATA_MAX_ENTRIES, sizeof(*inventory));
    if (!c || !inventory) goto done;
    if (!slot_description_identity(user_uid, title_id, NULL, err, err_sz) ||
        !save_metadata_resolve_uid(user_uid, title_id, c->uid, sizeof(c->uid),
                                  c->target, sizeof(c->target), err, err_sz) ||
        !slot_description_inventory(c->target, inventory, &c->count, &c->target_stat)) goto done;
    for (size_t i = 0; i < c->count; i++) c->images[i].original = inventory[i];
    failure = "Private description workspace is unavailable";
    if (!raw_recovery_marker_path(c->marker, sizeof(c->marker))) goto done;
    if (!watcher_raw_selected_workspace_held(c->work, sizeof(c->work), err, err_sz)) {
        struct stat st;
        // Setup can fail after mkdir but before directory durability is known.
        if (c->work[0] && (lstat(c->work, &st) == 0 || errno != ENOENT)) c->retain_lease = true;
        goto done;
    }
    c->workspace = true;
    if (lstat(c->work, &c->work_stat) || !slot_description_workspace(c)) {
        c->retain_lease = true; goto done;
    }
    for (size_t i = 0; i < c->count; i++) {
        slot_description_image_t* image = &c->images[i];
        pfs_attribute_image_t copy = {0}; struct stat before, st;
        failure = "Private description acquisition or original stability failed";
        int n = snprintf(copy.source, sizeof(copy.source), "%s/%s", c->target, image->original.name);
        int cn = snprintf(image->copy, sizeof(image->copy), "%s/image-%zu.img", c->work, i);
        if (n < 0 || (size_t)n >= sizeof(copy.source) || cn < 0 || (size_t)cn >= sizeof(image->copy) ||
            !slot_description_identity(user_uid, title_id, c, err, err_sz) ||
            !slot_description_workspace(c) || lstat(copy.source, &before) ||
            !raw_selected_stat_equal(&before, &image->original.stat)) goto done;
        if (lstat(image->copy, &st) == 0 || errno != ENOENT) { c->retain_lease = true; goto done; }
        struct statvfs space;
        if (statvfs(c->work, &space) || !space.f_frsize ||
            (uint64_t)space.f_bavail > UINT64_MAX / space.f_frsize ||
            (uint64_t)space.f_bavail * space.f_frsize < (uint64_t)before.st_size) goto done;
        snprintf(copy.copy, sizeof(copy.copy), "%s", image->copy);
        if (!pfs_attributes_copy_private(&copy)) {
            // A failed helper may have created a partial file; it is not a
            // verified owned clone, so retain it instead of guessing cleanup.
            if (lstat(image->copy, &st) == 0 || errno != ENOENT) c->retain_lease = true;
            goto done;
        }
        if (!raw_selected_stat_equal(&before, &copy.outer_before) ||
            !raw_selected_stat_equal(&before, &copy.outer_after) ||
            lstat(image->copy, &image->copy_stat) ||
            !S_ISREG(image->copy_stat.st_mode) || image->copy_stat.st_nlink != 1 ||
            (image->copy_stat.st_mode & 0777) != 0600 ||
            (image->copy_stat.st_dev == before.st_dev && image->copy_stat.st_ino == before.st_ino)) {
            c->retain_lease = true; goto done;
        }
        image->copied = true;
        snprintf(image->original.sha256, sizeof(image->original.sha256), "%s", copy.sha256);
        failure = "Private description mount barrier is uncertain; preserve temporary files";
        if (!c->barrier_attempted) {
            c->barrier_attempted = true;
            if (!watcher_raw_selected_barrier_held(true, c->work, err, err_sz) ||
                !slot_description_marker(c, true)) { c->retain_lease = true; goto done; }
        }
        if (!slot_description_marker(c, false)) { c->retain_lease = true; goto done; }
        failure = "Game state or original changed before private description mount";
        if (!slot_description_identity(user_uid, title_id, c, err, err_sz) ||
            !slot_description_workspace(c)) goto done;
        raw_selected_file_t original = image->original;
        if (!raw_selected_hash(c->target, &original) ||
            !raw_selected_stat_equal(&original.stat, &image->original.stat) ||
            strcmp(original.sha256, image->original.sha256)) goto done;
        failure = "Private description copy or mount barrier ownership is uncertain; preserve temporary files";
        if (!slot_description_copy_owned(c, image, true) ||
            !slot_description_marker(c, false)) { c->retain_lease = true; goto done; }
        if (!fs_title_is_closed(title_id)) {
            failure = "Close the game before inspecting slots"; goto done;
        }
        image->parsed = pfs_read_image_param_sfo(image->copy, &image->info);
        if (image->parsed == PFS_SFO_READ_UNMOUNT_UNCERTAIN) {
            failure = "Save inspection unmount is uncertain; preserve temporary files";
            c->retain_lease = true; goto done;
        }
        if (!slot_description_marker(c, false)) { c->retain_lease = true; goto done; }
    }
    failure = "Original save inventory changed during description inspection";
    if (!slot_description_originals(user_uid, title_id, c, err, err_sz)) goto done;
    ok = true;
done:
    if (c && c->workspace && !c->retain_lease) {
        if (!slot_description_originals(user_uid, title_id, c, err, err_sz) ||
            !slot_description_cleanup(c)) {
            c->retain_lease = true;
            if (ok) failure = "Description safety checkpoint cleanup is uncertain; preserve temporary files";
            ok = false;
        }
    }
    if (c && c->retain_lease) {
        *retain_lease = true;
        log_warn("slot-descriptions: safety reservation retained; mounts or private evidence require review");
    }
    if (ok) {
        for (size_t i = 0; i < c->count; i++) {
            const slot_description_image_t* image = &c->images[i];
            const char* fallback = !strcmp(image->original.name, "savedata0.bin")
                ? "savedata0" : image->original.name + 6;
            const char* dir = image->parsed == 0 && image->info.dir_name[0] ? image->info.dir_name : fallback;
            const char* sub = image->parsed == 0 && image->info.sub_title[0] ? image->info.sub_title : "Save Data";
            const char* detail = image->parsed == 0 ? image->info.detail : "";
            bool sys = strstr(sub, "System") != NULL || strstr(dir, "System") != NULL;
            cb(dir, sub, detail, image->original.name, (uint64_t)image->original.stat.st_size, sys, ud);
        }
    } else if (err && err_sz && !err[0]) snprintf(err, err_sz, "%s", failure);
    free(inventory);
    free(c);
    return ok;
}

bool watcher_enumerate_save_slots(const char* user_uid,
                                  const char* title_id,
                                  watcher_slot_cb_t cb,
                                  void* ud,
                                  char* err,
                                  size_t err_sz) {
    if (watcher_target_check_begin(err, err_sz) != 1) return false;
    bool retain_lease = false;
    bool ok = enumerate_save_slots_inner(user_uid, title_id, cb, ud,
                                         err, err_sz, &retain_lease);
    // A safety reservation is state, not a held mutex. Log/status stay usable;
    // neither cleanup nor another save operation may guess that a mount ended.
    if (!retain_lease) watcher_target_check_end();
    return ok;
}

static bool restore_dir_has_plain_pfs_layout(const char* dir) {
    if (!dir || !dir[0]) return false;
    char p[360];
    snprintf(p, sizeof(p), "%s/pfs", dir);
    struct stat st;
    return stat(p, &st) == 0 && S_ISDIR(st.st_mode);
}

static bool restore_dir_has_plain_slot_layout(const char* dir) {
    if (!dir || !dir[0]) return false;
    char p[360];
    snprintf(p, sizeof(p), "%s/sce_sys/param.sfo", dir);
    struct stat st;
    if (stat(p, &st) != 0 || !S_ISREG(st.st_mode)) return false;
    sfo_info_t info;
    return sfo_parse(p, &info) == 0 && info.dir_name[0];
}

static bool restore_dir_has_plain_sdimg_set_layout(const char* dir) {
    if (!dir || !dir[0]) return false;
    if (pfs_fs_is_plain_sdimg_marker(dir)) return true;

    char slots[360];
    snprintf(slots, sizeof(slots), "%s/slots", dir);
    struct stat st;
    if (stat(slots, &st) == 0 && S_ISDIR(st.st_mode))
        return true;

    // A decrypted "set" is any folder whose CHILD directories are themselves
    // save slots (each carrying sce_sys/param.sfo). Accept any child name —
    // not just "sdimg_*" — so Garlic/community exports that use bare slot
    // names (slot0, SaveGames<hash>, ManualSave0, SLOT01, …) are recognized.
    // "sce_sys" is skipped: that is THIS folder's own metadata (a single
    // slot), which restore_dir_has_plain_slot_layout() handles instead.
    DIR* d = opendir(dir);
    if (!d) return false;
    bool found = false;
    struct dirent* e;
    while ((e = readdir(d)) != NULL && !found) {
        if (e->d_name[0] == '.') continue;
        if (strcmp(e->d_name, "sce_sys") == 0) continue;
        char child[400];
        snprintf(child, sizeof(child), "%s/%s", dir, e->d_name);
        if (stat(child, &st) != 0 || !S_ISDIR(st.st_mode)) continue;
        char sfo[480];
        snprintf(sfo, sizeof(sfo), "%s/sce_sys/param.sfo", child);
        if (stat(sfo, &st) == 0 && S_ISREG(st.st_mode)) {
            sfo_info_t info;
            found = (sfo_parse(sfo, &info) == 0 && info.dir_name[0]);
        }
    }
    closedir(d);
    return found;
}

static bool restore_dir_payload_state(const char* dir,
                                      bool* out_plain,
                                      bool* out_raw,
                                      bool* out_plain_slot,
                                      bool* out_plain_sdimg) {
    bool is_plain = pfs_fs_is_plain_pfs_marker(dir) ||
                    restore_dir_has_plain_pfs_layout(dir);
    bool is_plain_sdimg = restore_dir_has_plain_sdimg_set_layout(dir);
    bool has_raw = restore_dir_has_savedata0(dir) || restore_dir_has_sdimg(dir);
    bool has_plain_slot = restore_dir_has_plain_slot_layout(dir);
    if (out_plain) *out_plain = is_plain;
    if (out_raw)   *out_raw   = has_raw;
    if (out_plain_slot) *out_plain_slot = has_plain_slot;
    if (out_plain_sdimg) *out_plain_sdimg = is_plain_sdimg;
    return is_plain || has_raw || has_plain_slot || is_plain_sdimg;
}

static bool restore_name_skip(const char* name) {
    return !name || !name[0] || name[0] == '.' ||
           strcmp(name, "__MACOSX") == 0;
}

static bool locate_restore_payload_rec(const char* dir,
                                       const char* title_id,
                                       int depth,
                                       char* out,
                                       size_t out_sz) {
    if (!dir || !out || out_sz == 0 || depth < 0) return false;
    if (restore_dir_payload_state(dir, NULL, NULL, NULL, NULL)) {
        snprintf(out, out_sz, "%s", dir);
        return true;
    }
    DIR* d = opendir(dir);
    if (!d) return false;

    // Prefer a directory named like the TITLE_ID. Old/debug zips sometimes
    // wrapped the actual save dir in one or two parent folders.
    if (title_id && title_id[0]) {
        struct dirent* e;
        while ((e = readdir(d)) != NULL) {
            if (restore_name_skip(e->d_name)) continue;
            if (strcmp(e->d_name, title_id) != 0) continue;
            char child[360];
            snprintf(child, sizeof(child), "%s/%s", dir, e->d_name);
            struct stat st;
            if (stat(child, &st) == 0 && S_ISDIR(st.st_mode) &&
                locate_restore_payload_rec(child, title_id, depth - 1,
                                           out, out_sz)) {
                closedir(d);
                return true;
            }
        }
        rewinddir(d);
    }

    struct dirent* e;
    while ((e = readdir(d)) != NULL) {
        if (restore_name_skip(e->d_name)) continue;
        char child[360];
        snprintf(child, sizeof(child), "%s/%s", dir, e->d_name);
        struct stat st;
        if (stat(child, &st) != 0 || !S_ISDIR(st.st_mode)) continue;
        if (locate_restore_payload_rec(child, title_id, depth - 1,
                                       out, out_sz)) {
            closedir(d);
            return true;
        }
    }
    closedir(d);
    return false;
}

static bool locate_restore_payload_root(const char* extracted_root,
                                        const char* title_id,
                                        char* out,
                                        size_t out_sz) {
    if (!out || out_sz == 0) return false;
    out[0] = '\0';
    return locate_restore_payload_rec(extracted_root, title_id, 4,
                                      out, out_sz);
}

static void log_restore_root_preview(const char* root) {
    DIR* d = opendir(root);
    if (!d) {
        log_warn("watcher: extracted restore root cannot be listed: %s", root);
        return;
    }
    char names[256] = {0};
    size_t used = 0, shown = 0;
    struct dirent* e;
    while ((e = readdir(d)) != NULL && shown < 10) {
        if (restore_name_skip(e->d_name)) continue;
        int n = snprintf(names + used, sizeof(names) - used, "%s%s",
                         used ? ", " : "", e->d_name);
        if (n <= 0 || (size_t)n >= sizeof(names) - used) break;
        used += (size_t)n;
        shown++;
    }
    closedir(d);
    log_warn("watcher: extracted restore root entries: %s",
             names[0] ? names : "(empty)");
}

// Garlic-style finalize for a savedata0.bin restore: read the (already
// restored) sce_sys/param.sfo for the real SAVEDATA_DIRECTORY + metadata and
// register the slot in savedata.db so the system sees the restored save. The
// param.sfo itself is a plain file in the save dir (not inside the image), so
// it was restored from the backup's metadata and needs no re-seal. If the
// crypto.fix_zeroed_sfo flag is on and that param.sfo is zeroed, rebuild it in
// place (best-effort; an HMAC is only embedded if one can be harvested).
static void savedata0_finalize_db(const char* uid, const char* title_id,
                                  const char* dest) {
    if (!uid || !uid[0] || !title_id || !dest) return;

    char sfo_path[1024];
    snprintf(sfo_path, sizeof(sfo_path), "%s/sce_sys/param.sfo", dest);
    sfo_info_t info;
    int pr = sfo_parse(sfo_path, &info);

    if (pr == -2 && s_cfg->crypto.fix_zeroed_sfo) {
        log_warn("watcher: %s param.sfo is zeroed — rebuilding (best-effort)",
                 title_id);
        sfo_info_t meta;
        memset(&meta, 0, sizeof(meta));
        snprintf(meta.title_id, sizeof(meta.title_id), "%s", title_id);
        snprintf(meta.game_title_id, sizeof(meta.game_title_id), "%s", title_id);
        snprintf(meta.dir_name, sizeof(meta.dir_name), "savedata0");
        snprintf(meta.format, sizeof(meta.format), "ppr");
        char game[64] = {0};
        if (titlename_lookup(title_id, game, sizeof(game)) && game[0])
            snprintf(meta.main_title, sizeof(meta.main_title), "%s", game);
        else
            snprintf(meta.main_title, sizeof(meta.main_title), "%s", title_id);
        if (sfo_write(sfo_path, &meta, NULL) == 0)
            pr = sfo_parse(sfo_path, &info);
    }

    const char* dir_name = (pr == 0 && info.dir_name[0]) ? info.dir_name
                                                         : "savedata0";
    uint64_t bytes = 0;
    char img[1024];
    if (save_find_primary_image(dest, img, sizeof(img))) {
        struct stat st;
        if (stat(img, &st) == 0) bytes = (uint64_t)st.st_size;
    }

    char db_err[160] = {0};
    if (savedata_db_update_single(uid, title_id, dir_name, bytes,
                                  pr == 0 ? &info : NULL, db_err, sizeof(db_err)))
        log_info("watcher: savedata.db updated for %s/%s (savedata0.bin)",
                 title_id, dir_name);
    else
        log_warn("watcher: savedata.db update for %s skipped: %s", title_id,
                 db_err[0] ? db_err : "unknown");
}

static void notify_restore_result(const char* title_id, bool ok) {
    char game[96];
    if (!titlename_lookup(title_id, game, sizeof(game)) || !game[0])
        snprintf(game, sizeof(game), "%s", title_id);
    bool es = s_cfg && strcmp(s_cfg->general.language, "es") == 0;
    char text[160];
    snprintf(text, sizeof(text),
             ok ? (es ? "Restauración completada: %s" : "Restore complete: %s")
                : (es ? "Falló la restauración: %s" : "Restore failed: %s"),
             game);
    log_notify(text);
}

static void notify_transfer_finalizing(void) {
    bool es = s_cfg && strcmp(s_cfg->general.language, "es") == 0;
    log_notify(es ? "Finalizando el save restaurado…\nNo abras el juego todavía."
                  : "Finalizing restored save…\nPlease do not open the game yet.");
}

static void notify_transfer_complete(void) {
    bool es = s_cfg && strcmp(s_cfg->general.language, "es") == 0;
    log_notify(es ? "Transferencia completada\nYa puedes abrir el juego"
                  : "Transfer complete\nSafe to open the game");
}

static void notify_transfer_rollback(void) {
    bool es = s_cfg && strcmp(s_cfg->general.language, "es") == 0;
    log_notify(es ? "Falló la transferencia — save original restaurado\n"
                    "Los datos transferidos no pasaron la validación."
                  : "Transfer failed — original save restored\n"
                    "The transferred data did not pass validation.");
}

static bool restore_manifest_is_formal_portable(const char* stage,
                                                const char* title_id) {
    char paths[2][420];
    snprintf(paths[0], sizeof(paths[0]), "%s/manifest.json", stage);
    snprintf(paths[1], sizeof(paths[1]), "%s/%s/manifest.json", stage,
             title_id);
    for (size_t i = 0; i < 2; i++) {
        FILE* f = fopen(paths[i], "rb");
        if (!f) continue;
        char buf[65536], format[64] = {0};
        size_t n = fread(buf, 1, sizeof(buf) - 1, f);
        bool complete = feof(f) != 0;
        fclose(f);
        buf[n] = '\0';
        if (complete &&
            json_get_string(buf, "format", format, sizeof(format)) &&
            strcmp(format, "tostonsync.migration_decrypted") == 0)
            return true;
    }
    return false;
}

static bool read_restore_marker(const char* path, char title[16], char owner[16]) {
    title[0] = owner[0] = '\0';
    FILE* f = fopen(path, "r");
    if (!f) return false;
    long long stamp = 0;
    char parsed_title[17] = {0}, parsed_owner[17] = {0}, extra[2];
    int fields = fscanf(f, "%lld %16s %16s %1s", &stamp,
                        parsed_title, parsed_owner, extra);
    fclose(f);
    if (stamp <= 0 || fields < 2 || fields > 3 ||
        strlen(parsed_title) >= 16 || !valid_title_id(parsed_title) ||
        strlen(parsed_owner) >= 16 || !valid_uid(parsed_owner)) return false;
    snprintf(title, 16, "%s", parsed_title);
    snprintf(owner, 16, "%s", parsed_owner);
    return true;
}

static bool restore_marker_matches(const char* path, const char* title_id,
                                    const char* uid) {
    char title[16], owner[16];
    return read_restore_marker(path, title, owner) &&
           strcmp(title, title_id) == 0 &&
           (!owner[0] || strcmp(owner, uid) == 0);
}

static bool write_restore_marker(const char* path, const char* title_id,
                                 const char* uid, bool create) {
    char tmp[340];
    snprintf(tmp, sizeof(tmp), "%s.tmp", path);
    const char* output = create ? path : tmp;
    int fd = open(output, O_WRONLY | O_CREAT | (create ? O_EXCL : O_TRUNC), 0600);
    if (fd < 0) return false;
    FILE* f = fdopen(fd, "w");
    if (!f) { close(fd); unlink(output); return false; }
    bool written = fprintf(f, "%lld %s%s%s\n", (long long)now_unix(), title_id,
                           uid && uid[0] ? " " : "", uid ? uid : "") > 0;
    if (!written) { fclose(f); unlink(output); return false; }
    if (!finish_json_file(f, output, path)) return false;
    sync();
    return true;
}

static bool do_restore_job_inner(const char* user_uid,
                           const char* title_id, const char* ref,
                           unsigned long restore_job_id,
                           char resolved_uid[16], const restore_scope_t* scope,
                           bool* portable_recovery_required, bool uid_explicit, restore_sources_t* originals) {
    *portable_recovery_required = false;
    // Consistent config snapshot for the whole restore; `s_cfg` shadows the
    // shared global so no s_cfg-> read here can observe a half-applied save.
    config_t cfgsnap;
    const config_t* s_cfg = config_snapshot(&cfgsnap) ? &cfgsnap : NULL;
    if (!s_cfg) {
        set_last_restore(title_id, 0, "Config not ready");
        notify_restore_result(title_id, false);
        return false;
    }
    if (!valid_restore_ref(ref)) {
        log_warn("watcher: refusing restore from invalid backup reference");
        set_last_restore(title_id, 0, "Invalid backup reference");
        notify_restore_result(title_id, false);
        return false;
    }
    bool reported = false;
    bool from_rollback = strcmp(ref, "rollback:retained") == 0;
    bool from_upload = strncmp(ref, "upload:", 7) == 0;
    const char* upload_path = from_upload ? ref + 7 : NULL;
    #define RESTORE_FAIL(msg_) do { \
        log_warn("restore[job=%lu title=%s]: phase=failed detail=%s", \
                 restore_job_id, title_id ? title_id : "", (msg_)); \
        set_last_restore(title_id, 0, (msg_)); \
        if (!reported) notify_restore_result(title_id, false); \
        reported = true; \
    } while (0)

    // `ref` is either a Drive file_id or, when it starts with '/', an
    // absolute path to a zip already on a USB drive (no download needed).
    bool from_usb = (ref[0] == '/');
    log_info("watcher: [bc] restore start title=%s from=%s", title_id,
             from_rollback ? "Retained rollback" :
             from_upload ? "Upload" : from_usb ? "USB" :
             "Drive");
    log_info("restore[job=%lu title=%s]: phase=preparing", restore_job_id,
             title_id);
    // Suppress the watcher's own backup of the restore writes for the duration
    // plus a settle window. Refreshed on success below.
    backup_suppress_for(title_id, 300);
    log_info("watcher: backups suppressed for %s during restore", title_id);
    set_last_restore(title_id, 2, "Restoring…");

    char tmp[300] = {0};
    const char* zip_path;
    char actual_uid[16] = {0};
    if (from_rollback) {
        zip_path = NULL;
    } else if (from_upload) {
        zip_path = upload_path;
    } else if (from_usb) {
        zip_path = ref;                       // already on the stick, no copy
    } else {
        snprintf(tmp, sizeof(tmp), "%s/restore_job_%lu.zip",
                 s_cfg->paths.staging_dir, restore_job_id);
        (void)gdrive_activate(); // Explicitly queued Drive restore/download.
        if (!gdrive_download(ref, tmp)) {
            log_warn("watcher: Drive download failed for restore of %s", title_id);
            RESTORE_FAIL("Drive download failed");
            unlink(tmp);
            return false;
        }
        zip_path = tmp;
    }

    // Inspect once before resolving the target: a portable archive's user is
    // source provenance, never authority to select a destination profile.
    char restore_stage[300] = {0};
    bool formal_portable = false, checksums_present = false;
    bool portable_payload = false;
    if (!from_rollback) {
        snprintf(restore_stage, sizeof(restore_stage), "%s/restore_job_%lu",
                 s_cfg->paths.staging_dir, restore_job_id);
        pfs_fs_rmrf(restore_stage);
        if (!fs_mkdir_p(restore_stage) ||
            !zip_extract_to_directory(zip_path, restore_stage)) {
            RESTORE_FAIL("Could not extract backup zip");
            pfs_fs_rmrf(restore_stage);
            if (!from_usb) unlink(tmp);
            return false;
        }
        formal_portable =
            restore_manifest_is_formal_portable(restore_stage, title_id);
        char checksum_err[128] = {0};
        if (!migration_verify_extracted_checksums(
                restore_stage, &checksums_present,
                checksum_err, sizeof(checksum_err))) {
            RESTORE_FAIL(checksum_err[0] ? checksum_err
                                         : "Backup checksum verification failed");
            pfs_fs_rmrf(restore_stage);
            if (!from_usb) unlink(tmp);
            return false;
        }
        if (!restore_sources_capture(originals, restore_stage)) {
            RESTORE_FAIL("Could not pin original backup members; no saves changed");
            return false;
        }
        if (checksums_present)
            log_info("restore[job=%lu title=%s]: phase=checksums_verified",
                     restore_job_id, title_id);
        char root[360];
        if (locate_restore_payload_root(restore_stage, title_id,
                                        root, sizeof(root)))
            restore_dir_payload_state(root, NULL, NULL, NULL, &portable_payload);
    }
    const bool automatic_portable =
        formal_portable && checksums_present && portable_payload;
    if (automatic_portable && !scope) {
        RESTORE_FAIL("Portable Restore requires an explicit approved container selection");
        return false;
    }
    if (scope && (!automatic_portable || !from_upload ||
                  strcmp(scope->title_id, title_id))) {
        RESTORE_FAIL("Selective restore requires the approved formal portable import");
        if (restore_stage[0]) pfs_fs_rmrf(restore_stage);
        if (!from_usb) unlink(tmp);
        return false;
    }
    if (!resolve_restore_target(automatic_portable ? NULL : user_uid, title_id,
                                !automatic_portable && uid_explicit, actual_uid, sizeof(actual_uid))) {
        RESTORE_FAIL("Choose a local PS5 user; the target is missing or ambiguous");
        if (restore_stage[0]) pfs_fs_rmrf(restore_stage);
        if (!from_usb) unlink(tmp);
        return false;
    }
    if (scope && strcmp(actual_uid, scope->target_uid)) {
        RESTORE_FAIL("Selective restore target UID changed; check compatibility again");
        if (restore_stage[0]) pfs_fs_rmrf(restore_stage);
        if (!from_usb) unlink(tmp);
        return false;
    }
    snprintf(resolved_uid, 16, "%s", actual_uid);
    char busy[300];
    restore_busy_path(busy, sizeof(busy));
    if (!write_restore_marker(busy, title_id, actual_uid, false)) {
        RESTORE_FAIL("Could not persist restore recovery state; target was not touched");
        if (restore_stage[0]) pfs_fs_rmrf(restore_stage);
        if (!from_usb) unlink(tmp);
        return false;
    }
    // All durable recovery paths are keyed by the resolved destination UID.
    char restore_base[300];
    snprintf(restore_base, sizeof(restore_base), "%s/restore_%s_%s",
             s_cfg->paths.staging_dir, actual_uid, title_id);

    pthread_mutex_lock(&s_titles_lock);
    char dest[256] = {0};
    bool target_running = false;
    for (size_t i = 0; i < s_title_count; i++) {
        if (strcmp(s_titles[i].title_id, title_id) != 0) continue;
        if (strcmp(s_titles[i].user_uid, actual_uid) != 0) continue;
        strncpy(dest, s_titles[i].path, sizeof(dest) - 1);
        target_running = (s_titles[i].pid_if_running != 0);
        break;
    }
    pthread_mutex_unlock(&s_titles_lock);
    if (!dest[0]) {
        fs_dir_t users[16];
        size_t n = fs_list_users(s_cfg->paths.saves_root, users, 16);
        for (size_t i = 0; i < n; i++) {
            if (strcmp(users[i].user_uid, actual_uid) != 0) continue;
            snprintf(dest, sizeof(dest), "%s/savedata_prospero/%s",
                     users[i].path, title_id);
            break;
        }
        if (!dest[0]) {
            RESTORE_FAIL("Requested PS5 user not found on this console");
            if (restore_stage[0]) pfs_fs_rmrf(restore_stage);
            if (!from_usb) unlink(tmp);
            return false;
        }
    }
    if (target_running || !fs_title_is_closed(title_id)) {
        log_warn("watcher: refusing restore of %s while the game is running",
                 title_id);
        RESTORE_FAIL("Game must be closed and its state readable before restoring this save");
        if (restore_stage[0]) pfs_fs_rmrf(restore_stage);
        if (!from_usb) unlink(tmp);
        return false;
    }
    if (scope) {
        char state_sha[65], scope_err[192] = {0};
        // Neither HTTP approval nor enqueue is a lease. Revalidate the exact
        // ciphertext/inode prestate again in the worker, before native work.
        if (!portable_transaction_target_digest(scope, dest, state_sha, scope_err, sizeof(scope_err)) ||
            strcmp(state_sha, scope->target_state_sha256) ||
            !import_session_validate_restore_scope(scope, zip_path)) {
            RESTORE_FAIL("Portable selected source/target changed after approval; no publication");
            return false;
        }
    }
    if (from_rollback) {
        char rollback_dir[420], rollback_err[192] = {0};
        snprintf(rollback_dir, sizeof(rollback_dir),
                 "%s/restore_%s_%s_sdimg_rollback",
                 s_cfg->paths.staging_dir, actual_uid, title_id);
        log_info("restore[job=%lu title=%s]: phase=applying_retained_rollback",
                 restore_job_id, title_id);
        if (!sdimg_restore_apply_retained_rollback(
                dest, rollback_dir, rollback_err, sizeof(rollback_err))) {
            RESTORE_FAIL(rollback_err[0] ? rollback_err
                                         : "Previous save could not be restored");
            backup_suppress_for(title_id, 180);
            return false;
        }
        set_last_restore(title_id, 1, "Previous save restored");
        notify_restore_result(title_id, true);
        log_info("restore[job=%lu title=%s]: phase=complete result=rollback_applied",
                 restore_job_id, title_id);
        backup_suppress_for(title_id, 180);
        log_info("watcher: backups suppressed for %s for 180s after rollback",
                 title_id);
        return true;
    }
    log_info("watcher: [bc] extracted OK, dest=%s, routing restore", dest);

    // Our own manifest.json lives at the archive's top level. It must NEVER be
    // written into the live save, so strip it from the extracted tree before
    // any copy. Old PLK/pre-manifest zips simply won't have one. (The restore
    // preview reads it separately from the archive, not from here.)
    {
        char mp[420];
        snprintf(mp, sizeof(mp), "%s/manifest.json", restore_stage);
        unlink(mp);
        snprintf(mp, sizeof(mp), "%s/%s/manifest.json", restore_stage, title_id);
        unlink(mp);
        snprintf(mp, sizeof(mp), "%s/checksums.json", restore_stage);
        unlink(mp);
        snprintf(mp, sizeof(mp), "%s/%s/checksums.json", restore_stage, title_id);
        unlink(mp);
    }

    char restore_root[360];
    if (!locate_restore_payload_root(restore_stage, title_id,
                                     restore_root, sizeof(restore_root))) {
        log_warn("watcher: %s is not a TostónSync save backup for %s "
                 "(missing pfs/, plain-sdimg-v1 marker, savedata0.bin, sdimg_*, or sce_sys/param.sfo)",
                 zip_path, title_id);
        log_restore_root_preview(restore_stage);
        RESTORE_FAIL("Not a TostónSync backup zip");
        pfs_fs_rmrf(restore_stage);
        if (!from_usb) unlink(tmp);
        return false;
    }
    { char mp[420]; snprintf(mp, sizeof(mp), "%s/manifest.json", restore_root);
      unlink(mp); snprintf(mp, sizeof(mp), "%s/checksums.json", restore_root);
      unlink(mp); }
    bool is_plain = false;
    bool is_plain_slot = false;
    bool is_plain_sdimg = false;
    restore_dir_payload_state(restore_root, &is_plain, NULL,
                              &is_plain_slot, &is_plain_sdimg);
    if (is_plain && !pfs_fs_is_plain_pfs_marker(restore_root))
        log_warn("watcher: [bc] restore payload has legacy pfs/ layout "
                 "without .tostonsync_format marker");
    bool has_savedata0 = restore_dir_has_savedata0(restore_root);
    bool has_sdimg = restore_dir_has_sdimg(restore_root);
    // Automatic smart path: only TostónSync's checksummed portable format may
    // reach the destination-container writer. The writer independently
    // preflights every target slot and creates rollback before the first write.
    const bool migration_write = is_plain_sdimg && checksums_present &&
                                 formal_portable;
    const bool unsafe_reseal = false;
    if (strcmp(restore_root, restore_stage) != 0)
        log_info("watcher: [bc] restore payload found under %s", restore_root);
    if (is_plain_sdimg)
        log_info("watcher: [bc] restore payload uses plain-sdimg-v1 format");
    else if (has_sdimg && !has_savedata0)
        log_info("watcher: [bc] restore payload uses sdimg_* raw image format");
    bool ok = false;
    bool portable_transfer = false;
    if (is_plain_sdimg) {
        char sdimg_err[192] = {0};
        if (!migration_write) {
            log_warn("watcher: refusing non-formal portable restore for %s",
                     title_id);
            RESTORE_FAIL("Only verified TostónSync backups can be restored across consoles");
        } else if (!raw_recovery_marker(true, restore_base)) {
            *portable_recovery_required = true;
            RESTORE_FAIL("Could not persist portable mount safety guard; no images mounted");
        } else {
            *portable_recovery_required = true;
            set_last_restore(title_id, 2,
                             "Finalizing and validating restored save…");
            log_info("restore[job=%lu title=%s]: phase=finalizing_and_validating",
                     restore_job_id, title_id);
            notify_transfer_finalizing();
            size_t written = 0;
            portable_transaction_report_t transaction = {0};
            bool restored = scope
                ? sdimg_restore_portable_scope_from_payload(
                    restore_root, actual_uid, title_id, dest, restore_base,
                    scope, zip_path, &transaction, originals, &written,
                    sdimg_err, sizeof(sdimg_err))
                : sdimg_restore_plain_set_from_payload(
                    restore_root, actual_uid, title_id, dest, restore_base, originals,
                    sdimg_err, sizeof(sdimg_err));
            // Only the complete native mode/content/identity verification
            // closes this barrier. Any failure preserves private evidence and
            // blocks further kernel work, including automatic retries.
            if (restored && !raw_recovery_marker(false, restore_base)) {
                (void)raw_recovery_marker(true, restore_base);
                restored = false;
                snprintf(sdimg_err, sizeof(sdimg_err),
                         "Portable verification completed but mount safety checkpoint cleanup is uncertain; evidence retained");
                transaction.recovery_required = transaction.barrier_retained = true;
                snprintf(transaction.result, sizeof(transaction.result), "RECOVERY_REQUIRED");
                snprintf(transaction.detail, sizeof(transaction.detail), "%s", sdimg_err);
            }
            if (restored) {
                *portable_recovery_required = false;
                transaction.barrier_retained = false;
            }
            if (scope) {
                pthread_mutex_lock(&s_restore_lock);
                s_portable_transaction = transaction;
                pthread_mutex_unlock(&s_restore_lock);
                // A known rename is a write even when the later private
                // verification fails. Uncertain totals are serialized as null.
                set_restore_scope_result(scope, transaction.written_images);
                log_info("restore[job=%lu title=%s]: selected=%zu available=%zu "
                         "known_written=%zu verified=%zu uncertain=%s scope=%s result=%s", restore_job_id, title_id,
                         scope->selection.count, scope->available_slots,
                         transaction.written_images, written,
                         transaction.publication_uncertain ? "yes" : "no",
                         scope->receipt, restored ? "verified" : "failed");
            }
            if (restored) {
                ok = true;
                portable_transfer = true;
                log_info("watcher: restored %s via verified plain-sdimg import (%s)",
                         title_id, from_upload ? "Upload" : from_usb ? "USB" :
                         "Drive");
            } else {
                log_warn("watcher: plain-sdimg import failed for %s: %s", title_id,
                         sdimg_err[0] ? sdimg_err : "unknown error");
                if (strstr(sdimg_err,
                           "Transfer failed — original save restored") != NULL) {
                    log_warn("restore[job=%lu title=%s]: phase=failed_rolled_back",
                             restore_job_id, title_id);
                    set_last_restore(title_id, 0,
                                     "Transfer failed — original save restored");
                    notify_transfer_rollback();
                    reported = true;
                } else {
                    RESTORE_FAIL(sdimg_err[0] ? sdimg_err
                                             : "Plain sdimg import failed");
                }
            }
        }
    } else if (is_plain_slot) {
        char sdimg_err[192] = {0};
        log_info("watcher: [bc] restore payload uses plain slot folder");
        if (!migration_write) {
            log_warn("watcher: unsupported plain-slot restore for %s", title_id);
            RESTORE_FAIL("Unsupported backup format");
        } else if (!raw_recovery_marker(true, restore_base)) {
            *portable_recovery_required = true;
            RESTORE_FAIL("Could not persist portable mount safety guard; no images mounted");
        } else if (sdimg_restore_plain_slot_from_payload(
                       restore_root, actual_uid, title_id, dest, restore_base, originals,
                       sdimg_err, sizeof(sdimg_err))) {
            *portable_recovery_required = true;
            ok = raw_recovery_marker(false, restore_base);
            if (!ok) {
                (void)raw_recovery_marker(true, restore_base);
                RESTORE_FAIL("Portable mount safety checkpoint cleanup is uncertain; evidence retained");
            } else {
                *portable_recovery_required = false;
                log_info("watcher: restored %s via plain-slot import (%s)",
                         title_id, from_upload ? "Upload" : from_usb ? "USB" :
                         "Drive");
            }
        } else {
            *portable_recovery_required = true;
            log_warn("watcher: plain-slot import failed for %s: %s", title_id,
                     sdimg_err[0] ? sdimg_err : "unknown error");
            RESTORE_FAIL(sdimg_err[0] ? sdimg_err : "Plain slot import failed");
        }
    } else if (is_plain) {
        if (!migration_write) {
            log_warn("watcher: unsupported plain-PFS restore for %s", title_id);
            RESTORE_FAIL("Unsupported backup format");
        } else if (pfs_resign_restore_from_staging(restore_root, dest)) {
            ok = true;
            log_info("watcher: restored %s via kernel mount (%s)",
                     title_id, from_upload ? "Upload" : from_usb ? "USB" :
                     "Drive");
            savedata0_finalize_db(actual_uid, title_id, dest);
        } else if (s_cfg->crypto.auto_fallback_on_failure) {
            log_warn("watcher: kernel-restore failed for %s — plain-PFS "
                     "format cannot be applied via file copy, refusing "
                     "to silently leave the save in a broken state",
                     title_id);
            RESTORE_FAIL("Kernel restore failed; plain backup cannot be raw-copied");
        } else {
            log_warn("watcher: kernel-restore failed for %s", title_id);
            RESTORE_FAIL("Kernel restore failed");
        }
    } else if (has_sdimg && !has_savedata0) {
        char sdimg_err[192] = {0};
        log_info("watcher: [bc] restoring sdimg_* payload for %s/%s into %s",
                 actual_uid[0] ? actual_uid : "(unknown)", title_id, dest);
        if (sdimg_restore_from_payload(restore_root, actual_uid, title_id,
                                       dest, restore_base,
                                       originals, false, false,
                                       sdimg_err, sizeof(sdimg_err))) {
            ok = true;
            log_info("watcher: restored %s via sdimg indexed restore (%s)",
                     title_id, from_upload ? "Upload" : from_usb ? "USB" :
                     "Drive");
        } else {
            log_warn("watcher: sdimg restore failed for %s: %s", title_id,
                     sdimg_err[0] ? sdimg_err : "unknown error");
            RESTORE_FAIL(sdimg_err[0] ? sdimg_err : "sdimg restore failed");
        }
    } else if (unsafe_reseal && has_savedata0) {
        // Raw savedata0.bin backup + kernel access:
        // do a PROPER restore. The backup image is still sealed with its
        // own key (which this console can unwrap), so we decrypt them, read the
        // contents, and re-seal them into the EXISTING target image(s) — keeping
        // the target's own key/keystone. The target MUST already exist: if the
        // save was deleted, recreate it once in-game so the system registers a
        // fresh container, then restore. We never write raw files into a missing
        // save (that yields an unregistered, unplayable save — PS5 CE-107109-8).
        char tgt_primary[1024];
        if (!save_find_primary_image(dest, tgt_primary, sizeof(tgt_primary))) {
            log_warn("watcher: target save for %s does not exist — recreate it "
                     "in-game first, then restore. Refusing to write a broken "
                     "save.", title_id);
            RESTORE_FAIL("Save doesn't exist — open the game and create a save first");
        } else {
            char plain_stage[320];
            snprintf(plain_stage, sizeof(plain_stage), "%s_plain", restore_stage);
            pfs_fs_rmrf(plain_stage);
            log_info("watcher: [bc] decrypting backup blob for %s", title_id);
            char plain_pfs[400];
            snprintf(plain_pfs, sizeof(plain_pfs), "%s/pfs", plain_stage);
            if (!pfs_resign_backup_to_staging(restore_root, plain_stage)) {
                log_warn("watcher: could not decrypt backup blob for %s "
                         "(is kstuff loaded?)", title_id);
                RESTORE_FAIL("Kernel decrypt failed — is kstuff loaded?");
            } else if (!pfs_fs_dir_has_files(plain_pfs)) {
                // Safety net: a successful-looking decrypt that yielded no
                // files means something went wrong. Do NOT wipe the target to
                // re-seal an empty save into it.
                log_warn("watcher: decrypted backup for %s is empty — aborting "
                         "before touching the target save", title_id);
                RESTORE_FAIL("Decrypted backup was empty; target was not touched");
            } else {
                log_info("watcher: [bc] re-sealing into %s — payload %llu B",
                         dest,
                         (unsigned long long)pfs_fs_dir_bytes(plain_pfs));
                if (pfs_resign_restore_from_staging(plain_stage, dest)) {
                    ok = true;
                    log_info("watcher: restored %s via kernel re-seal (%s)",
                             title_id, from_upload ? "Upload" :
                             from_usb ? "USB" : "Drive");
                    savedata0_finalize_db(actual_uid, title_id, dest);
                } else {
                    log_warn("watcher: kernel re-seal restore failed for %s "
                             "(payload may not fit, or the kernel mount failed)",
                             title_id);
                    RESTORE_FAIL("Kernel re-seal failed");
                }
            }
            pfs_fs_rmrf(plain_stage);
        }
    } else {
        // The old savedata0 wipe/copy path had no durable recoverable commit.
        RESTORE_FAIL("Legacy savedata0 restore is unsupported; export a verified portable backup or use an exact sdimg backup");
    }
    if (ok) {
        if (portable_transfer) {
            set_last_restore(title_id, 1, "Transfer complete — safe to open game");
            notify_transfer_complete();
            log_info("restore[job=%lu title=%s]: phase=complete result=verified",
                     restore_job_id, title_id);
        } else {
            set_last_restore(title_id, 1, "Restore complete");
            notify_restore_result(title_id, true);
            log_info("restore[job=%lu title=%s]: phase=complete", restore_job_id,
                     title_id);
        }
    } else if (!reported)
        RESTORE_FAIL("Restore failed");
    // Keep ignoring this title's writes for a settle window so the restore's
    // own file changes are never captured as a fresh backup.
    backup_suppress_for(title_id, 180);
    log_info("watcher: backups suppressed for %s for 180s after restore",
             title_id);
    char retained_mount_guard[512];
    struct stat retained_mount_state;
    bool retain_evidence = *portable_recovery_required ||
        !raw_recovery_marker_path(retained_mount_guard, sizeof(retained_mount_guard)) ||
        lstat(retained_mount_guard, &retained_mount_state) == 0 || errno != ENOENT;
    if (!retain_evidence) pfs_fs_rmrf(restore_stage);
    // Reviewed imports stay on the PS5 until the user removes them. This also
    // keeps retry/review independent from the browser that supplied the ZIP.
    if (!retain_evidence && !from_upload && !from_usb) unlink(tmp); // never delete USB/user imports
    #undef RESTORE_FAIL
    return ok;
}

static void do_restore_job(const char* user_uid,
                           const char* title_id, const char* ref,
                           unsigned long restore_job_id,
                           const restore_scope_t* scope, bool uid_explicit, const char* claimed_import_id) {
    jobs_state_t observation_result = JOB_FAILED;
    const char* observation_error = "restore_blocked";
    // Exclusive against every save reader and against other restores. SQLite
    // is built single-threaded, and restore must never overlap a backup/export
    // that already had the same image mounted.
    char busy[300], interrupted[300];
    restore_busy_path(busy, sizeof(busy));
    snprintf(interrupted, sizeof(interrupted), "%s/restore.interrupted",
             s_cfg->paths.state_dir);
    import_session_info_t imported = {0};
    bool from_upload = ref && strncmp(ref, "upload:", 7) == 0;
    bool have_import = from_upload && import_session_current(&imported) &&
                       strcmp(import_session_selected_path(&imported), ref + 7) == 0;
    if (!save_io_begin_write()) {
        jobs_finish(jobs_watch_id(restore_job_id), JOB_UNKNOWN, "restore_admission_unknown");
        return;
    }
    // Revalidate the frozen destination before any recovery marker or staging write.
    if (uid_explicit && !watcher_restore_uid_is_local(user_uid)) {
        bool owned_claim = have_import && imported.state == IMPORT_COMMITTED &&
            claimed_import_id && !strcmp(imported.id,claimed_import_id) &&
            (!scope || !strcmp(imported.id, scope->import_id));
        bool released = !owned_claim || import_session_release_target_rejected(imported.id, user_uid);
        set_last_restore(title_id, 0, "The target user no longer exists on this PS5; review again before restoring");
        log_warn("restore[job=%lu title=%s]: target_uid_missing; owned_import_release=%s; no save writes",
                 restore_job_id, title_id, released ? "complete" : "unknown");
        save_io_end_write();
        jobs_finish(jobs_watch_id(restore_job_id), released ? JOB_FAILED : JOB_UNKNOWN,
                    released ? "restore_target_uid_missing" : "restore_target_release_unknown");
        return;
    }
    const char* identity_path = from_upload ? ref + 7 : ref && ref[0] == '/' ? ref : NULL;
    if (!scope && !import_session_restore_target_allowed(identity_path,user_uid,uid_explicit)) {
        save_io_end_write();
        jobs_finish(jobs_watch_id(restore_job_id),JOB_FAILED,"restore_scope_changed");
        return;
    }
    pthread_mutex_lock(&s_restore_lock);
    memset(&s_portable_transaction, 0, sizeof(s_portable_transaction));
    pthread_mutex_unlock(&s_restore_lock);
    set_restore_scope_result(scope, 0);
    // Admission and the worker both enforce the persisted server approval.
    // A generic upload: restore cannot bypass a selective import's scope.
    if (scope ? (!from_upload || !restore_scope_valid(scope) ||
                 strcmp(scope->title_id, title_id) ||
                 !import_session_validate_restore_scope(scope, ref + 7))
              : ((from_upload && !import_session_legacy_restore_allowed(ref + 7)) ||
                 (ref && ref[0] == '/' && import_session_path_requires_selection(ref)))) {
        restore_scope_t approved;
        have_import = scope && imported.state == IMPORT_COMMITTED &&
            !strcmp(imported.id, scope->import_id) &&
            import_session_get_restore_scope(scope->import_id, &approved) &&
            restore_scope_equal(scope, &approved);
        set_last_restore(title_id, 0,
                         "Restore selection changed or is not approved; check compatibility again");
        notify_restore_result(title_id, false);
        goto restore_done;
    }
    struct stat st;
    bool stale_busy = lstat(busy, &st) == 0 || errno != ENOENT;
    bool recovering = lstat(interrupted, &st) == 0 || errno != ENOENT;
    char raw_pending[512];
    bool raw_uncertain = !raw_recovery_marker_path(raw_pending, sizeof(raw_pending)) ||
                        lstat(raw_pending, &st) == 0 || errno != ENOENT;
    bool retained = strcmp(ref, "rollback:retained") == 0;
    char uid[16] = {0};
    if (uid_explicit) snprintf(uid, sizeof(uid), "%s", user_uid);
    if (raw_uncertain) {
        set_last_restore(title_id, 0, "RAW recovery mount state requires inspection before restoring");
        notify_restore_result(title_id, false);
        goto restore_done;
    }
    if ((stale_busy || recovering) &&
        (!retained || !resolve_restore_target(user_uid, title_id, uid_explicit, uid, sizeof(uid)) ||
         (stale_busy && !restore_marker_matches(busy, title_id, uid)) ||
         (recovering && !restore_marker_matches(interrupted, title_id, uid)))) {
        set_last_restore(title_id, 0,
                         "Interrupted restore requires recovery of the original save first");
        notify_restore_result(title_id, false);
        goto restore_done;
    }
    if (stale_busy) {
        if (recovering || rename(busy, interrupted) != 0) {
            set_last_restore(title_id, 0, "Restore recovery markers require manual inspection");
            notify_restore_result(title_id, false);
            goto restore_done;
        }
        recovering = true;
        sync();
    }
    if (!write_restore_marker(busy, title_id, uid, true)) {
        set_last_restore(title_id, 0, "Could not persist restore recovery state");
        notify_restore_result(title_id, false);
        goto restore_done;
    }
    bool portable_recovery_required = false;
    restore_sources_t originals = {0};
    bool ok = do_restore_job_inner(user_uid, title_id, ref, restore_job_id, uid,
                                  scope, &portable_recovery_required, uid_explicit, &originals);
    restore_sources_free(&originals);
    observation_result = ok ? JOB_DONE : JOB_FAILED;
    observation_error = ok ? NULL : "restore_failed";
    char rollback[420];
    snprintf(rollback, sizeof(rollback), "%s/restore_%s_%s_sdimg_rollback",
             s_cfg->paths.staging_dir, uid, title_id);
    bool pending = uid[0] && sdimg_restore_recovery_pending(rollback);
    bool mount_pending = !raw_recovery_marker_path(raw_pending, sizeof(raw_pending)) ||
                         lstat(raw_pending, &st) == 0 || errno != ENOENT;
    if (pending || mount_pending || portable_recovery_required) {
        observation_result = JOB_UNKNOWN;
        observation_error = "restore_recovery_incomplete";
        if (!recovering) (void)rename(busy, interrupted);
        else unlink(busy);
        set_last_restore(title_id, 0,
                         "Restore recovery is incomplete; backups are paused");
    } else {
        unlink(busy);
        if (retained && ok) unlink(interrupted);
    }
    sync();
restore_done:
    save_io_end_write();
    if (from_upload) {
        if (have_import) (void)import_session_unclaim(imported.id);
    }
    jobs_finish(jobs_watch_id(restore_job_id), observation_result, observation_error);
}

static void* worker_main(void* arg) {
    (void)arg;
    while (s_running) {
        job_t* j = dequeue_blocking();
        if (!j) continue;
        jobs_ref_t observation = jobs_watch_id(j->job_id);
        jobs_ref_t previous = jobs_bind(observation);
        jobs_phase(observation, j->destination, "preparing", 0, false);
        if (j->is_restore) do_restore_job(j->restore_user, j->title_id,
                                          j->restore_ref, j->job_id,
                            j->restore_scope.selection.specified ? &j->restore_scope : NULL,
                            j->restore_uid_explicit, j->restore_import_id);
        else {
            backup_control_t control;
            if (backup_control_begin(&control,observation)) {
                backup_control_t* bound=backup_control_bind(&control);
                do_upload_job(j);
                backup_control_bind(bound);backup_control_end(&control);
            } else {
                upload_result_t failed={0};
                upload_result_set(&failed,"failed","Could not register backup cancellation");
                finish_backup_job(j,&failed,NULL);save_io_end_read();
            }
        }
        jobs_finish(observation, JOB_UNKNOWN, "terminal_not_observed");
        jobs_bind(previous);
        atomic_fetch_sub(&s_jobs_active, 1);
        free(j);
        lifecycle_operation_end(); // dequeue admission spans terminal writes
    }
    return NULL;
}

// --------------------------------------------------------------------
// kqueue loop.
// --------------------------------------------------------------------

static void* watch_main(void* arg) {
    (void)arg;
    struct kevent events[16];
    struct timespec ts = {1, 0};
    while (s_running) {
        int n = kevent(s_kq, NULL, 0, events, 16, &ts);
        if (!s_running) break;
        if (n <= 0 || !lifecycle_operation_begin()) continue;
        int64_t now = now_unix();
        pthread_mutex_lock(&s_titles_lock);
        for (int i = 0; i < n; i++) {
            title_t* t = (title_t*)events[i].udata;
            if (!t) continue;
            if (t->dirty) t->coalesced_count++;
            t->dirty = true;
            t->last_dirty_unix = now;
        }
        pthread_mutex_unlock(&s_titles_lock);
        lifecycle_operation_end();
    }
    return NULL;
}

// --------------------------------------------------------------------
// Trigger evaluator.
// --------------------------------------------------------------------

static bool trig_enabled_cfg(const config_t* cfg, const char* mode) {
    if (!cfg) return false;
    for (size_t i = 0; i < cfg->triggers.modes_count; i++)
        if (strcmp(cfg->triggers.modes[i], mode) == 0) return true;
    return false;
}

static bool manual_only_cfg(const config_t* cfg) {
    return cfg && cfg->triggers.modes_count == 1 &&
           strcmp(cfg->triggers.modes[0], "manual") == 0;
}

static bool trig_enabled(const char* mode) {
    config_t cfg;
    return config_snapshot(&cfg) && trig_enabled_cfg(&cfg, mode);
}

static void* trigger_main(void* arg) {
    (void)arg;
    int64_t last_interval_fire = now_unix();
    while (s_running) {
        sleep(1);
        if (!s_running) break;
        if (!lifecycle_operation_begin()) continue;
        config_t cfg;
        if (!config_snapshot(&cfg) || manual_only_cfg(&cfg)) {
            lifecycle_operation_end();
            continue;
        }
        int64_t now = now_unix();
        // Snapshot the live trigger window so a zero or absent
        // change_settle_seconds (older configs) never collapses to
        // "fire every tick".
        int settle = cfg.triggers.change_settle_seconds;
        if (settle <= 0) settle = 30;

        unsigned pending_mask = 0, available_mask = 0;
        unsigned configured_mask = backup_configured_mask(&cfg);
        pthread_mutex_lock(&s_titles_lock);
        for (size_t i = 0; i < s_title_count; i++)
            if (s_titles[i].backup_retry_at > 0 &&
                now >= s_titles[i].backup_retry_at)
                pending_mask |= (s_titles[i].backup_retry_mask | configured_mask) &
                    ~(s_titles[i].backup_usb_no_replay ? 1U : 0U);
        pthread_mutex_unlock(&s_titles_lock);
        static const char* retry_dests[] = { "usb", "drive" };
        for (unsigned i = 0; i < 2; i++)
            if ((pending_mask & (1U << i)) && dest_retry_attemptable(retry_dests[i], &cfg))
                available_mask |= 1U << i;

        pthread_mutex_lock(&s_titles_lock);
        for (size_t i = 0; i < s_title_count; i++) {
            title_t* t = &s_titles[i];
            if (t->upload_in_flight) continue;
            if (!title_allowed_cfg(&cfg, t->title_id)) continue;

            const char* trg = NULL;
            bool retrying = false;
            // Game close backs up the FINAL state, so it fires even if no
            // mid-game "dirty" write was detected (one-shot per close).
            if (trig_enabled_cfg(&cfg, "on_game_close") &&
                t->was_running && t->pid_if_running == 0) {
                trg = "GameClose";
                t->was_running = false;
            } else if (t->backup_retry_at > 0 &&
                       (t->last_dirty_unix <= t->backup_retry_dirty_unix ||
                        (!trig_enabled_cfg(&cfg, "on_change") &&
                         !trig_enabled_cfg(&cfg, "on_idle") &&
                         !trig_enabled_cfg(&cfg, "interval")))) {
                // A removed provider must not strand work when the user adds
                // another one. Ordinary unavailable targets still keep backoff.
                unsigned retry_mask = (configured_mask != t->backup_retry_planned_mask ||
                                       cfg.destinations.fallback)
                    ? configured_mask : t->backup_retry_mask;
                if (t->backup_usb_no_replay) retry_mask &= ~1U;
                if (dest_retry_due(t->backup_retry_at, retry_mask,
                                   available_mask, now)) {
                    trg = t->backup_retry_trigger;
                    retrying = true;
                }
            } else if (t->dirty) {
                // on_change (Live): fires `settle` seconds after the last
                // detected save write; on_idle after the idle window.
                if (trig_enabled_cfg(&cfg, "on_change") &&
                    now - t->last_dirty_unix >= settle) {
                    if (live_backup_due(cfg.triggers.live_backup_mode, now,
                                        t->last_upload_unix)) {
                        trg = "Live";
                    } else if (t->last_deferred_dirty_unix !=
                               t->last_dirty_unix) {
                        log_info("backup-queue: deferred key=%s/%s "
                                 "reason=drive_min_interval "
                                 "latest_fingerprint=pending",
                                 t->user_uid, t->title_id);
                        t->last_deferred_dirty_unix = t->last_dirty_unix;
                    }
                }
                else if (trig_enabled_cfg(&cfg, "on_idle") &&
                         now - t->last_dirty_unix >= cfg.triggers.idle_seconds)
                    trg = "Idle";
            }
            if (trg) {
                if (strcmp(trg, "GameClose") == 0)
                    log_info("backup-queue: final game-close backup queued key=%s/%s",
                             t->user_uid, t->title_id);
                t->upload_in_flight = true;
                if (!enqueue(t->user_uid, t->title_id, false, false, NULL,
                        t->last_dirty_unix, trg, NULL,
                        retrying ? "destination_retry" :
                        strcmp(trg, "GameClose") == 0 ? "game_closed" :
                        strcmp(trg, "Live") == 0 ? "watcher_save_change" :
                        "watcher_idle")) {
                    t->upload_in_flight = false;
                    t->backup_retry_at = now + 30;
                    t->backup_retry_mask = t->backup_usb_no_replay ? 2U : 3U;
                    t->backup_retry_dirty_unix = t->last_dirty_unix;
                    if (trg != t->backup_retry_trigger)
                        snprintf(t->backup_retry_trigger,
                                 sizeof(t->backup_retry_trigger), "%s", trg);
                }
            }
        }
        pthread_mutex_unlock(&s_titles_lock);

        if (trig_enabled_cfg(&cfg, "interval") &&
            now - last_interval_fire >= cfg.triggers.interval_seconds) {
            last_interval_fire = now;
            pthread_mutex_lock(&s_titles_lock);
            for (size_t i = 0; i < s_title_count; i++) {
                if (s_titles[i].dirty && !s_titles[i].upload_in_flight &&
                    (!s_titles[i].backup_retry_at ||
                     s_titles[i].last_dirty_unix > s_titles[i].backup_retry_dirty_unix)) {
                    if (!title_allowed_cfg(&cfg, s_titles[i].title_id)) continue;
                    s_titles[i].upload_in_flight = true;
                    enqueue(s_titles[i].user_uid, s_titles[i].title_id,
                            false, false, NULL, s_titles[i].last_dirty_unix,
                            "Interval", NULL, "interval_timer");
                }
            }
            pthread_mutex_unlock(&s_titles_lock);
        }
        lifecycle_operation_end();
    }
    return NULL;
}

// --------------------------------------------------------------------
// "Game close" detector. Uses fs_get_running_title() which on PS5
// returns the TITLE_ID of the foregrounded title (CUSA/PPSA prefix),
// or empty string when at the menu.
// --------------------------------------------------------------------

static bool session_title_io_clear(const title_t* title) {
    if (title->upload_in_flight || pthread_mutex_trylock(&s_save_io_lock) != 0)
        return false;
    bool clear = !s_save_io_writer && !s_save_io_readers && !s_save_io_writers_waiting &&
                 !s_scratch_users && !s_scratch_cleaning;
    pthread_mutex_unlock(&s_save_io_lock);
    return clear;
}

static session_saves_baseline_t session_title_snapshot(const char* path,
                                                       session_saves_snapshot_t** out,
                                                       void* context) {
    const title_t* title = context;
    *out = NULL;
    if (!session_title_io_clear(title)) return SESSION_SAVES_ERROR;
    session_saves_baseline_t result = session_saves_snapshot(path, out);
    if (!session_title_io_clear(title)) {
        free(*out); *out = NULL;
        return SESSION_SAVES_ERROR;
    }
    return result;
}

static void session_title_observe(title_t* title, bool running) {
    session_saves_observation_t observation = running ? SESSION_SAVES_OPEN :
        fs_title_is_closed(title->title_id) ? SESSION_SAVES_CLOSED : SESSION_SAVES_UNKNOWN;
    if (session_saves_observe(&title->session, title->path, observation, now_unix(),
                              session_title_snapshot, title)) {
        char message[SESSION_SAVES_LOG_BYTES];
        if (session_saves_format_log(&title->session, s_run_id, (long)getpid(),
                                     title->game_name, title->title_id, title->user_uid,
                                     message, sizeof(message))) log_info("%s", message);
    }
}

static void* proc_main(void* arg) {
    (void)arg;
    while (s_running) {
        sleep(1);
        if (!s_running) break;
        if (!lifecycle_operation_begin()) continue;
        config_t cfg;
        bool have_cfg = config_snapshot(&cfg);

        // Running-state is decided per title by sandbox-dir EXISTENCE, not by
        // mtime. A game that pauses writes (cutscene, idle, in-game menu) still
        // has its /mnt/sandbox/<title>_* dir, so it stays "running" and the
        // on_game_close trigger only fires once the dir actually disappears.
        // The old mtime-15s heuristic could declare a game "closed" mid-play
        // and fire a backup of a still-changing save.
        pthread_mutex_lock(&s_titles_lock);
        for (size_t i = 0; i < s_title_count; i++) {
            bool running = fs_title_is_running(s_titles[i].title_id);
            int  was     = s_titles[i].pid_if_running;
            session_title_observe(&s_titles[i], running);
            if (running) {
                // Log the launch edge once so the device log proves whether
                // the daemon can SEE games run at all (needs kstuff + sandbox
                // escape). If this line never appears, on_game_close can't fire.
                if (!was) {
                    const char* display = s_titles[i].game_name[0]
                                          ? s_titles[i].game_name
                                          : s_titles[i].title_id;
                    log_info("watcher[run=%s pid=%ld watcher=1]: Game started: %s",
                             s_run_id, (long)getpid(), display);
                    log_debug("started title id: %s", s_titles[i].title_id);
                }
                s_titles[i].pid_if_running = 1;
                s_titles[i].was_running    = true;
            } else {
                if (was) {
                    const char* display = s_titles[i].game_name[0]
                                          ? s_titles[i].game_name
                                          : s_titles[i].title_id;
                    log_info("watcher[run=%s pid=%ld watcher=1]: Game closed: %s",
                             s_run_id, (long)getpid(), display);
                    log_info("activity:game_closed|%s", display);
                    if (have_cfg && trig_enabled_cfg(&cfg, "on_game_close") &&
                        title_allowed_cfg(&cfg, s_titles[i].title_id)) {
                        bool busy = s_titles[i].upload_in_flight;
                        bool es = strcmp(cfg.general.language, "es") == 0;
                        log_info("activity:%s|%s",
                                 busy ? "backup_already_running"
                                      : "final_backup_checking",
                                 display);
                        log_notify_level(NOTIFY_BALANCED,
                            busy
                              ? (es ? "Backup en progreso\nLa verificación final correrá cuando termine"
                                    : "Backup already running\nFinal check will run after it finishes")
                              : (es ? "Preparando backup final\nEspera antes de usar Rest Mode"
                                    : "Preparing final backup\nPlease wait before Rest Mode"));
                    }
                    log_debug("queued automatic backup: game close (%s)",
                              s_titles[i].title_id);
                }
                s_titles[i].pid_if_running = 0;   // sandbox gone => truly closed
            }
            // Detect in-game saves: the game writes INTO the existing sdimg_*
            // images, which does not fire kqueue NOTE_WRITE on the directory,
            // so poll the newest file mtime here. A bump marks the title dirty
            // so on_change/on_idle/interval can actually fire.
            int64_t mt = fs_dir_newest_mtime(s_titles[i].path);
            if (mt > 0) {
                if (s_titles[i].last_change_mtime == 0) {
                    s_titles[i].last_change_mtime = mt;   // baseline; don't fire
                } else if (mt > s_titles[i].last_change_mtime) {
                    s_titles[i].last_change_mtime = mt;
                    if (!s_titles[i].dirty) {
                        const char* display = s_titles[i].game_name[0]
                                              ? s_titles[i].game_name
                                              : s_titles[i].title_id;
                        log_info("watcher[run=%s pid=%ld watcher=1]: Save change detected: %s",
                                 s_run_id, (long)getpid(), display);
                        char change_ntf[160];
                        snprintf(change_ntf, sizeof(change_ntf),
                                 s_cfg && strcmp(s_cfg->general.language, "es") == 0
                                     ? "Cambio de save detectado: %s"
                                     : "Save change detected: %s",
                                 display);
                        log_notify_level_quiet(NOTIFY_ALL, change_ntf);
                    }
                    if (s_titles[i].dirty) s_titles[i].coalesced_count++;
                    s_titles[i].dirty = true;
                    s_titles[i].last_dirty_unix = now_unix();
                }
            }
        }
        pthread_mutex_unlock(&s_titles_lock);

        // Resolve the human game name once, while a game is mounted (its
        // param.json/sfo is only readable while the game runs).
        char cur[16] = {0};
        fs_get_running_title(cur, sizeof(cur));
        if (cur[0]) {
            bool need_name = false;
            pthread_mutex_lock(&s_titles_lock);
            for (size_t i = 0; i < s_title_count; i++)
                if (strcmp(s_titles[i].title_id, cur) == 0 &&
                    !s_titles[i].game_name[0]) need_name = true;
            pthread_mutex_unlock(&s_titles_lock);
            if (need_name) {
                char name[64] = {0};
                if (titlename_lookup(cur, name, sizeof(name))) {
                    if (set_title_name(cur, name))
                        log_info("watcher: %s = \"%s\"", cur, name);
                }
            }
        }

        // Periodically rescan for newly-installed games.
        static int rescan = 0;
        if (++rescan > 60) { rescan = 0; scan_and_register(); }
        lifecycle_operation_end();
    }
    return NULL;
}

// --------------------------------------------------------------------
// Lifecycle / public API.
// --------------------------------------------------------------------

static void close_title_watches(void) {
    pthread_mutex_lock(&s_titles_lock);
    for (size_t i = 0; i < s_title_count; i++) {
        if (s_titles[i].watch_fd >= 0) close(s_titles[i].watch_fd);
        s_titles[i].watch_fd = -1;
    }
    pthread_mutex_unlock(&s_titles_lock);
}

static void recover_restore_status(void) {
    static bool notified = false;
    char path[300], title[16], owner[16];
    snprintf(path, sizeof(path), "%s/restore.interrupted", s_cfg->paths.state_dir);
    struct stat st;
    if (lstat(path, &st) != 0 && errno == ENOENT) {
        notified = false;
        return;
    }
    bool known = read_restore_marker(path, title, owner);
    set_last_restore(known ? title : "", 0, known
        ? "Interrupted restore: keep game closed; use Restore previous save. Backups paused."
        : "Recovery required: keep games closed and inspect recovery files. Backups paused.");
    log_warn("restore: interrupted recovery title=%s user=%s; backups paused; no automatic writes",
             known ? title : "unknown", known && owner[0] ? owner : "unknown");
    if (!notified) {
        bool es = strcmp(s_cfg->general.language, "es") == 0;
        log_notify_level(NOTIFY_IMPORTANT, es
            ? "Restauración interrumpida — backups pausados\nMantén el juego cerrado y revisa la recuperación en TostónSync."
            : "Restore interrupted — backups paused\nKeep the game closed and review recovery in TostónSync.");
        notified = true;
    }
}

static bool watcher_start_inner(const config_t* cfg) {
    int expected = 0;
    if (!atomic_compare_exchange_strong(&s_running, &expected, 1)) {
        log_warn("watcher: start ignored — watcher is already running");
        return false;
    }
    snprintf(s_run_id, sizeof(s_run_id), "%ld-%lld", (long)getpid(),
             (long long)now_unix());
    unsigned watcher_id = atomic_fetch_add(&s_watcher_id, 1) + 1;
    s_cfg = cfg;
    pthread_mutex_lock(&s_titles_lock);
    snprintf(s_lifecycle_state_dir, sizeof(s_lifecycle_state_dir), "%s", cfg->paths.state_dir);
    snprintf(s_lifecycle_staging_dir, sizeof(s_lifecycle_staging_dir), "%s", cfg->paths.staging_dir);
    pthread_mutex_unlock(&s_titles_lock);
    s_kq = kqueue();
    if (s_kq < 0) {
        s_running = 0;
        log_warn("watcher: kqueue() failed");
        return false;
    }
    fs_mkdir_p(cfg->paths.state_dir);
    fs_mkdir_p(cfg->paths.staging_dir);
    char jobs_dir[384];
    snprintf(jobs_dir, sizeof(jobs_dir), "%s/jobs", cfg->paths.state_dir);
    fs_mkdir_p(jobs_dir);
    chmod(cfg->paths.state_dir, 0700);
    chmod(cfg->paths.staging_dir, 0700);
    chmod(jobs_dir, 0700);
    scan_and_register();
    recover_backup_retries();
    recover_backup_jobs();
    recover_restore_status();

    s_watch_started = false;
    s_trigger_started = false;
    s_proc_started = false;
    s_worker_count = 0;

    // The zip compressor, FTP transfer, and PFS copy helpers all use 64 KB
    // I/O buffers, and these run on the worker/proc threads. The SDK's
    // default thread stack is too small to hold a buffer that large, so the
    // first real backup overflows the stack and the process dies with no log
    // (a silent SIGSEGV). Give every thread an explicit, generous 1 MB stack.
    pthread_attr_t st_attr;
    pthread_attr_t* st_attrp = NULL;
    bool attr_initialized = pthread_attr_init(&st_attr) == 0;
    if (attr_initialized &&
        pthread_attr_setstacksize(&st_attr, 1024 * 1024) == 0)
        st_attrp = &st_attr;

    int thread_error = pthread_create(&s_watch_th, st_attrp,
                                      watch_main, NULL);
    if (thread_error != 0) goto thread_fail;
    s_watch_started = true;
    thread_error = pthread_create(&s_trigger_th, st_attrp,
                                  trigger_main, NULL);
    if (thread_error != 0) goto thread_fail;
    s_trigger_started = true;
    thread_error = pthread_create(&s_proc_th, st_attrp,
                                  proc_main, NULL);
    if (thread_error != 0) goto thread_fail;
    s_proc_started = true;

    int w = cfg->advanced.upload_workers;
    if (w < 1) w = 1;
    if (w > 8) w = 8;
    for (int i = 0; i < w; i++) {
        thread_error = pthread_create(&s_workers[i], st_attrp,
                                      worker_main, NULL);
        if (thread_error != 0) goto thread_fail;
        s_worker_count++;
    }

    if (attr_initialized) pthread_attr_destroy(&st_attr);

    log_info("watcher[run=%s pid=%ld watcher=%u]: Watching %d saves for automatic backups.",
             s_run_id, (long)getpid(), watcher_id, (int)s_title_count);
    log_debug("watcher: %d worker(s)", w);
    return true;

thread_fail:
    log_error("watcher: pthread_create failed (%d); stopping partial startup",
              thread_error);
    s_running = 0;
    pthread_cond_broadcast(&s_q_cond);
    if (s_kq >= 0) {
        close(s_kq);
        s_kq = -1;
    }
    if (s_watch_started) pthread_join(s_watch_th, NULL);
    if (s_trigger_started) pthread_join(s_trigger_th, NULL);
    if (s_proc_started) pthread_join(s_proc_th, NULL);
    for (int i = 0; i < s_worker_count; i++)
        pthread_join(s_workers[i], NULL);
    s_watch_started = false;
    s_trigger_started = false;
    s_proc_started = false;
    s_worker_count = 0;
    close_title_watches();
    if (attr_initialized) pthread_attr_destroy(&st_attr);
    return false;
}

bool watcher_start(const config_t* cfg) {
    if (!cfg || !lifecycle_operation_begin()) return false;
    bool ok = watcher_start_inner(cfg);
    lifecycle_operation_end();
    return ok;
}

void watcher_stop(void) {
    if (!s_running) { raw_selected_commit_join(); return; }
    s_running = 0;
    raw_selected_commit_join();
    pthread_cond_broadcast(&s_q_cond);
    if (s_kq >= 0) {
        close(s_kq);
        s_kq = -1;
    }
    if (s_watch_started) pthread_join(s_watch_th, NULL);
    if (s_trigger_started) pthread_join(s_trigger_th, NULL);
    if (s_proc_started) pthread_join(s_proc_th, NULL);
    for (int i = 0; i < s_worker_count; i++)
        pthread_join(s_workers[i], NULL);
    s_watch_started = false;
    s_trigger_started = false;
    s_proc_started = false;
    s_worker_count = 0;
    // A new kqueue cannot reuse registrations owned by the old one. Closing
    // these descriptors makes scan_and_register() register every title again.
    close_title_watches();
}

bool watcher_stop_checked(void) {
    if (!lifecycle_terminal() || lifecycle_operations() || watcher_active_jobs() ||
        watcher_queue_depth()) return false;
    s_running = 0;
    // The legacy RAW join exposes no status; its inactivity and admission count
    // are the authority here, not a claim that this void API verified a join.
    raw_selected_commit_join();
    if (raw_selected_commit_active() || lifecycle_operations()) return false;
    if (pthread_cond_broadcast(&s_q_cond)) return false;
    if (s_kq >= 0) {
        int fd = s_kq;
        s_kq = -1;
        if (close(fd)) return false;
    }
    if (s_watch_started) {
        if (pthread_join(s_watch_th, NULL)) return false;
        s_watch_started = false;
    }
    if (s_trigger_started) {
        if (pthread_join(s_trigger_th, NULL)) return false;
        s_trigger_started = false;
    }
    if (s_proc_started) {
        if (pthread_join(s_proc_th, NULL)) return false;
        s_proc_started = false;
    }
    for (int i = 0; i < s_worker_count; i++)
        if (pthread_join(s_workers[i], NULL)) return false;
    s_worker_count = 0;
    bool clear = true;
    pthread_mutex_lock(&s_titles_lock);
    for (size_t i = 0; i < s_title_count; i++) {
        if (s_titles[i].watch_fd >= 0) {
            int fd = s_titles[i].watch_fd;
            s_titles[i].watch_fd = -1;
            if (close(fd)) clear = false;
        }
    }
    pthread_mutex_unlock(&s_titles_lock);
    return clear && !watcher_active_jobs() && !watcher_queue_depth() &&
           !lifecycle_operations();
}

bool   watcher_is_running(void)        { return s_running != 0; }
int64_t watcher_last_sync_unix(void)   { return s_last_sync_unix; }

static void lifecycle_observe_marker(const char* path, life_check_t* check,
                                      life_snapshot_t* out) {
    struct stat st;
    if (lstat(path, &st) == 0) {
        *check = LIFE_BUSY;
        if (!out->reason[0]) snprintf(out->reason, sizeof(out->reason),
                                      "recovery_marker_present: %.128s", path);
    } else if (errno != ENOENT) {
        if (*check != LIFE_BUSY) *check = LIFE_UNKNOWN;
        if (!out->reason[0]) snprintf(out->reason, sizeof(out->reason),
                                      "recovery_marker_unknown: errno=%d %.112s", errno, path);
    }
}

bool watcher_lifecycle_snapshot(life_snapshot_t* out) {
    if (!out) return false;
    memset(out, 0, sizeof(*out));
    out->import_work = out->recovery = out->mounts = out->gate = out->checkpoint = LIFE_UNKNOWN;
    out->jobs = atomic_load(&s_jobs_active) + (raw_selected_commit_active() ? 1 : 0);
    out->queued = atomic_load(&s_q_depth);
    if (pthread_mutex_trylock(&s_q_lock) != 0) {
        snprintf(out->reason, sizeof(out->reason), "queue_lock_busy");
        return true;
    }
    out->jobs = atomic_load(&s_jobs_active) + (raw_selected_commit_active() ? 1 : 0);
    out->queued = atomic_load(&s_q_depth);
    pthread_mutex_unlock(&s_q_lock);

    struct { char uid[16], title[16]; } titles[MAX_TITLES];
    char state[CFG_MAX_PATH], staging[CFG_MAX_PATH];
    if (pthread_mutex_trylock(&s_titles_lock) != 0) {
        snprintf(out->reason, sizeof(out->reason), "title_metadata_busy");
        return true;
    }
    size_t count = s_title_count;
    if (count > MAX_TITLES) {
        pthread_mutex_unlock(&s_titles_lock);
        snprintf(out->reason, sizeof(out->reason), "title_count_unknown");
        return true;
    }
    snprintf(state, sizeof(state), "%s", s_lifecycle_state_dir);
    snprintf(staging, sizeof(staging), "%s", s_lifecycle_staging_dir);
    for (size_t i = 0; i < count; i++) {
        snprintf(titles[i].uid, sizeof(titles[i].uid), "%s", s_titles[i].user_uid);
        snprintf(titles[i].title, sizeof(titles[i].title), "%s", s_titles[i].title_id);
    }
    pthread_mutex_unlock(&s_titles_lock);
    if (pthread_mutex_trylock(&s_save_io_lock) != 0) {
        snprintf(out->reason, sizeof(out->reason), "save_io_gate_busy");
        return true;
    }
    out->gate = s_save_io_readers || s_save_io_writer || s_save_io_writers_waiting ||
                s_scratch_users || s_scratch_cleaning ? LIFE_BUSY : LIFE_CLEAR;
    pthread_mutex_unlock(&s_save_io_lock);
    out->import_work = import_session_lifecycle_snapshot();
    out->checkpoint = out->import_work;
    out->mounts = savemount_lifecycle_snapshot();
    if (!state[0] || !staging[0]) {
        snprintf(out->reason, sizeof(out->reason), "watcher_paths_unknown");
        return true;
    }
    out->recovery = LIFE_CLEAR;
    const char* markers[] = {"restore.busy", "restore.interrupted", "raw-recovery.pending"};
    const char* roots[] = {"/data/tostonsync", state};
    char path[768];
    for (size_t root = 0; root < 2; root++) {
        if (root && !strcmp(roots[0], roots[1])) continue;
        for (size_t i = 0; i < sizeof(markers) / sizeof(*markers); i++) {
            snprintf(path, sizeof(path), "%s/%s", roots[root], markers[i]);
            lifecycle_observe_marker(path, &out->recovery, out);
        }
    }
    // A retained closed rollback directory alone is historical evidence, not
    // pending work. Observe only its existing recovery/rotation sidecars.
    const char* suffixes[] = {"/.pending", ".next", ".previous", ".swap", ".apply",
                              "/.expansion-required", "/.expansion.sqlite"};
    for (size_t i = 0; i < count; i++)
        for (size_t j = 0; j < sizeof(suffixes) / sizeof(*suffixes); j++) {
            snprintf(path, sizeof(path), "%s/restore_%s_%s_sdimg_rollback%s",
                      staging, titles[i].uid, titles[i].title, suffixes[j]);
            lifecycle_observe_marker(path, &out->recovery, out);
        }
    if (!out->reason[0]) snprintf(out->reason, sizeof(out->reason), "%s",
        out->jobs ? "jobs_active" : out->queued ? "jobs_queued" :
        out->gate != LIFE_CLEAR ? "save_io_or_scratch_busy" :
        out->import_work == LIFE_BUSY ? "import_work_busy" :
        out->import_work == LIFE_UNKNOWN ? "import_checkpoint_unknown" :
        out->mounts == LIFE_BUSY ? "mounts_active_or_uncertain" :
        out->mounts == LIFE_UNKNOWN ? "mounts_unknown" : "quiescent_observed");
    return true;
}

int watcher_kick_sync_now_observed(watcher_jobs_admission_t* out) {
    if (out) { memset(out, 0, sizeof(*out)); out->complete = true; }
    if (!s_running || !lifecycle_operation_begin()) return 0;
    int accepted = 0;
    pthread_mutex_lock(&s_titles_lock);
    for (size_t i = 0; i < s_title_count; i++) {
        if (!title_allowed(s_titles[i].title_id)) continue;
        if (s_titles[i].upload_in_flight) {
            if (out) {
                watcher_job_admission_t item = {s_titles[i].observation_job, true,
                    jobs_tracked(s_titles[i].observation_job)};
                out->items[out->count++] = item;
                if (!item.id || !item.tracked) out->complete = false;
            }
            accepted++;
            continue;
        }
        s_titles[i].upload_in_flight = true;
        watcher_job_admission_t item = {0};
        if (enqueue_observed(s_titles[i].user_uid, s_titles[i].title_id, false, true,
                    NULL, s_titles[i].last_dirty_unix, "Manual", NULL,
                    "backup_all", &item)) {
            accepted++;
            if (out) {
                out->items[out->count++] = item;
                if (!item.id || !item.tracked) out->complete = false;
            }
        }
    }
    pthread_mutex_unlock(&s_titles_lock);
    lifecycle_operation_end();
    return accepted;
}

int watcher_kick_sync_now(void) { return watcher_kick_sync_now_observed(NULL); }

bool watcher_backup_title_async(const char* user_uid, const char* title_id) {
    return watcher_backup_title_to_async(user_uid, title_id, NULL);
}

bool watcher_backup_title_to_async(const char* user_uid, const char* title_id,
                                   const char* destination) {
    return watcher_backup_title_to_async_observed(user_uid, title_id, destination, NULL);
}

bool watcher_backup_title_to_async_observed(const char* user_uid, const char* title_id,
                                   const char* destination, watcher_job_admission_t* out) {
    if (out) memset(out, 0, sizeof(*out));
    if (!s_running) return false;
    if (!valid_title_id(title_id)) return false;
    if (!valid_uid(user_uid ? user_uid : "")) return false;
    if (destination && destination[0] &&
        strcmp(destination, "default") != 0 &&
        strcmp(destination, "usb") != 0 &&
        strcmp(destination, "drive") != 0 &&
        strcmp(destination, "all") != 0 &&
        strcmp(destination, "all-local") != 0)
        return false;
    if (!lifecycle_operation_begin()) return false;
    bool queued = false;
    pthread_mutex_lock(&s_titles_lock);
    for (size_t i = 0; i < s_title_count; i++) {
        if (strcmp(s_titles[i].title_id, title_id) != 0) continue;
        if (user_uid && user_uid[0] &&
            strcmp(s_titles[i].user_uid, user_uid) != 0) continue;
        // A manual "Backup now" overrides the include/exclude filter — the
        // user explicitly asked for this title, so we don't gate on
        // title_allowed() the way the automatic triggers do.
        if (!s_titles[i].upload_in_flight) {
            s_titles[i].upload_in_flight = true;
            // enqueue() clears upload_in_flight and returns false on OOM, so a
            // failed allocation is reported as NOT queued instead of a false
            // success (audit #8).
            queued = enqueue_observed(s_titles[i].user_uid, s_titles[i].title_id, false,
                             true, NULL, s_titles[i].last_dirty_unix, "Manual",
                             destination, "manual_backup", out);
        } else {
            queued = true;   // already has a job in flight
            if (out) {
                out->id = s_titles[i].observation_job;
                out->coalesced = true;
                out->tracked = jobs_tracked(out->id);
            }
        }
        break;   // exact match, or first owner when no uid was supplied
    }
    pthread_mutex_unlock(&s_titles_lock);
    lifecycle_operation_end();
    return queued;
}

void watcher_on_shutdown(void) {
    // Only an accepted lifecycle stop omits the ordinary SIGTERM flush. The
    // caller first joins the control server, resolving any transient reserve.
    if (lifecycle_terminal()) return;
    if (!lifecycle_operation_begin()) return;
    if (!trig_enabled("on_shutdown")) {
        lifecycle_operation_end();
        return;
    }
    pthread_mutex_lock(&s_titles_lock);
    for (size_t i = 0; i < s_title_count; i++)
        if (s_titles[i].dirty && !s_titles[i].upload_in_flight) {
            if (!title_allowed(s_titles[i].title_id)) continue;
            s_titles[i].upload_in_flight = true;
            enqueue(s_titles[i].user_uid, s_titles[i].title_id,
                    false, false, NULL, s_titles[i].last_dirty_unix,
                    "Shutdown", NULL, "shutdown_flush");
        }
    pthread_mutex_unlock(&s_titles_lock);
    // Drain the queue synchronously, but with a cap: a wedged destination
    // (e.g. an FTP server that accepts the connection then never replies)
    // must not be able to hold the whole shutdown — and therefore the
    // console power-off — open indefinitely. Past the deadline we give up
    // on the stragglers; their saves remain staged for the next run.
    const int max_wait_sec = 30;
    for (int waited = 0;
         (s_q_depth > 0 || s_jobs_active > 0) && waited < max_wait_sec;
         waited++)
        sleep(1);
    if (s_q_depth > 0 || s_jobs_active > 0)
        log_warn("watcher: shutdown drain timed out, %d queued and %d active",
                 (int)s_q_depth, (int)s_jobs_active);
    lifecycle_operation_end();
}

static bool path_has_dotdot_component(const char* p) {
    if (!p) return true;
    const char* s = p;
    while (*s) {
        while (*s == '/') s++;
        const char* e = strchr(s, '/');
        size_t len = e ? (size_t)(e - s) : strlen(s);
        if (len == 2 && s[0] == '.' && s[1] == '.') return true;
        if (!e) break;
        s = e + 1;
    }
    return false;
}

static bool valid_usb_restore_ref(const char* ref) {
    if (!ref || ref[0] != '/') return true;   // Drive file_id path
    if (path_has_dotdot_component(ref)) return false;
    size_t len = strlen(ref);
    if (len <= 4 || strcmp(ref + len - 4, ".zip") != 0) return false;

    usb_mount_t mounts[8];
    size_t n = usb_list_mounts(mounts, 8);
    for (size_t i = 0; i < n; i++) {
        size_t ml = strlen(mounts[i].path);
        if (strncmp(ref, mounts[i].path, ml) == 0 && ref[ml] == '/')
            return true;
    }
    return false;
}



static bool valid_upload_restore_ref(const char* ref) {
    if (!ref || strncmp(ref, "upload:", 7) != 0) return false;
    const char* p = ref + 7;
    if (!p[0] || p[0] != '/') return false;
    if (path_has_dotdot_component(p)) return false;
    size_t len = strlen(p);
    if (len <= 4 || strcmp(p + len - 4, ".zip") != 0) return false;
    // The importer may deliberately stage a large ZIP on USB. Trust the
    // reviewed session, not a path prefix supplied over HTTP.
    return import_session_owns_ready_path(p);
}

static bool valid_drive_file_id(const char* ref) {
    if (!ref || !ref[0]) return false;
    if (ref[0] == '/' || strncmp(ref, "ftp:", 4) == 0) return false;
    for (size_t i = 0; ref[i]; i++) {
        unsigned char c = (unsigned char)ref[i];
        bool ok = (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
                  (c >= '0' && c <= '9') || c == '_' || c == '-';
        if (!ok) return false;
    }
    return true;
}

static bool valid_restore_ref(const char* ref) {
    if (!ref || !ref[0]) return false;
    if (strcmp(ref, "rollback:retained") == 0) return true;
    if (strncmp(ref, "upload:", 7) == 0) return valid_upload_restore_ref(ref);
    if (ref[0] == '/') return valid_usb_restore_ref(ref);
    if (strncmp(ref, "ftp:", 4) == 0) return false; // Retired provider; never treat it as Drive.
    return valid_drive_file_id(ref);
}

static bool prepare_backup_file_inner(const char* ref,
                                 char* out_path, size_t out_path_sz,
                                 bool* temporary,
                                 char* err, size_t err_sz) {
    if (out_path && out_path_sz) out_path[0] = '\0';
    if (temporary) *temporary = false;
    if (err && err_sz) err[0] = '\0';
    if (!out_path || out_path_sz < 320 || !temporary ||
        !valid_restore_ref(ref) || strncmp(ref, "upload:", 7) == 0 ||
        strcmp(ref, "rollback:retained") == 0) {
        if (err && err_sz) snprintf(err, err_sz, "Invalid backup reference");
        return false;
    }
    scratch_begin_use();
    if (ref[0] == '/') {
        if (access(ref, R_OK) != 0) {
            if (err && err_sz) snprintf(err, err_sz, "Backup file is unavailable");
            watcher_release_backup_file(NULL, false);
            return false;
        }
        snprintf(out_path, out_path_sz, "%s", ref);
        return true;
    }

    config_t cfg;
    if (!config_snapshot(&cfg)) {
        if (err && err_sz) snprintf(err, err_sz, "Config not ready");
        watcher_release_backup_file(NULL, false);
        return false;
    }
    char workspace[768];
    int n = snprintf(workspace, sizeof(workspace), "%s/export.XXXXXX",
                     cfg.paths.staging_dir);
    if (n < 0 || (size_t)n >= sizeof(workspace) ||
        (size_t)n + sizeof("/copy.zip") > out_path_sz || !mkdtemp(workspace)) {
        watcher_release_backup_file(NULL, false);
        if (err && err_sz) snprintf(err, err_sz, "Could not reserve export staging folder");
        return false;
    }
    struct stat st;
    if (lstat(workspace, &st) != 0 || !S_ISDIR(st.st_mode) ||
        (st.st_mode & 0777) != 0700) {
        watcher_release_backup_file(NULL, false);
        if (err && err_sz) snprintf(err, err_sz, "Export staging folder is unavailable");
        return false;
    }
    snprintf(out_path, out_path_sz, "%s/copy.zip", workspace);
    bool downloaded = gdrive_download(ref, out_path);
    if (!downloaded || lstat(out_path, &st) != 0 || !S_ISREG(st.st_mode)) {
        // Preserve failed downloads; only a successful ZIP belongs to the caller's release.
        watcher_release_backup_file(NULL, false);
        out_path[0] = '\0';
        if (err && err_sz) snprintf(err, err_sz, "Could not download backup");
        return false;
    }
    *temporary = true;
    return true;
}

bool watcher_prepare_backup_file(const char* ref,
                                 char* out_path, size_t out_path_sz,
                                 bool* temporary,
                                 char* err, size_t err_sz) {
    if (!lifecycle_admit(err, err_sz)) return false;
    bool ok = prepare_backup_file_inner(ref, out_path, out_path_sz, temporary, err, err_sz);
    lifecycle_operation_end();
    return ok;
}

static bool verify_backup_inner(const char* ref, const char* title_hint,
                           char* out_report_json, size_t out_report_json_sz,
                           char* err, size_t err_sz) {
    if (out_report_json && out_report_json_sz) out_report_json[0] = '\0';
    if (err && err_sz) err[0] = '\0';
    if (!out_report_json || out_report_json_sz < 64 ||
        !valid_restore_ref(ref) || strncmp(ref, "upload:", 7) == 0 ||
        strcmp(ref, "rollback:retained") == 0 ||
        (title_hint && title_hint[0] && !valid_title_id(title_hint))) {
        if (err && err_sz) snprintf(err, err_sz, "Invalid backup reference");
        return false;
    }

    char zip_path[768] = {0};
    bool remove_tmp = false;
    if (!watcher_prepare_backup_file(ref, zip_path, sizeof(zip_path),
                                     &remove_tmp, err, err_sz)) return false;

    migration_report_t report;
    bool ok = migration_inspect_zip(zip_path,
                                    title_hint && title_hint[0]
                                        ? title_hint : NULL,
                                    &report);
    watcher_release_backup_file(zip_path, remove_tmp);
    if (!ok) {
        if (err && err_sz)
            snprintf(err, err_sz, "%s",
                     report.reason[0] ? report.reason : "Backup verification failed");
        return false;
    }
    migration_report_json(&report, out_report_json, out_report_json_sz);
    return true;
}

bool watcher_verify_backup(const char* ref, const char* title_hint,
                           char* out_report_json, size_t out_report_json_sz,
                           char* err, size_t err_sz) {
    if (!lifecycle_admit(err, err_sz)) return false;
    bool ok = verify_backup_inner(ref, title_hint, out_report_json,
                                   out_report_json_sz, err, err_sz);
    lifecycle_operation_end();
    return ok;
}

// Map a user_alias coming over the API back to the underlying UID by
// scanning config.users. If no alias matches, treat the input as
// already a UID (so callers can pass either). Empty input stays empty.
static void resolve_alias_to_uid(const char* alias, char* out, size_t out_sz) {
    if (!out || out_sz == 0) return;
    out[0] = '\0';
    if (!alias || !alias[0]) return;
    config_t cfg;
    if (config_snapshot(&cfg)) {
        for (size_t i = 0; i < cfg.users.count; i++) {
            if (strcmp(cfg.users.entries[i].alias, alias) == 0) {
                if (strlen(cfg.users.entries[i].uid) >= out_sz) return;
                strncpy(out, cfg.users.entries[i].uid, out_sz - 1);
                out[out_sz - 1] = '\0';
                return;
            }
        }
    }
    if (strlen(alias) >= out_sz) return;
    strncpy(out, alias, out_sz - 1);
    out[out_sz - 1] = '\0';
    // Unknown aliases are not authority to select another local profile.
    if (!valid_uid(out)) out[0] = '\0';
}

static bool resolve_local_restore_target(const char* title_id,
                                         char* uid, size_t uid_sz,
                                         char* target, size_t target_sz,
                                         char* err, size_t err_sz) {
    if (uid && uid_sz) uid[0] = '\0';
    if (target && target_sz) target[0] = '\0';
    if (!uid || !uid_sz || !target || !target_sz ||
        !valid_title_id(title_id)) return false;
    config_t cfg;
    if (!config_snapshot(&cfg)) {
        if (err && err_sz) snprintf(err, err_sz, "Could not read PS5 settings");
        return false;
    }
    fs_dir_t users[16];
    size_t count = fs_list_users(cfg.paths.saves_root, users, 16);
    if (!count) {
        if (err && err_sz) snprintf(err, err_sz,
            "Local PS5 user inventory is empty, unavailable or incomplete");
        return false;
    }
    char selected_uid[16] = {0}, selected_target[320] = {0};
    // Probe this title under every local user; the bounded watcher cache is
    // neither a complete inventory nor authority to select a restore owner.
    for (size_t i = 0; i < count; i++) {
        char base[300], path[320];
        int bn = snprintf(base, sizeof(base), "%s/savedata_prospero", users[i].path);
        int pn = snprintf(path, sizeof(path), "%s/%s", base, title_id);
        if (!valid_uid(users[i].user_uid) || bn < 0 || pn < 0 ||
            (size_t)bn >= sizeof(base) || (size_t)pn >= sizeof(path)) goto unavailable;
        struct stat st;
        if (lstat(base, &st) != 0) {
            if (errno == ENOENT) continue;
            goto unavailable;
        }
        if (!S_ISDIR(st.st_mode)) goto unavailable;
        if (lstat(path, &st) != 0) {
            if (errno == ENOENT) continue;
            goto unavailable;
        }
        if (!S_ISDIR(st.st_mode)) goto unavailable;
        if (selected_uid[0]) {
            if (err && err_sz) snprintf(err, err_sz,
                "Target title belongs to multiple local PS5 users");
            return false;
        }
        snprintf(selected_uid, sizeof(selected_uid), "%s", users[i].user_uid);
        snprintf(selected_target, sizeof(selected_target), "%s", path);
    }
    if (!selected_uid[0]) {
        if (count != 1) {
            if (err && err_sz) snprintf(err, err_sz,
                "Target PS5 user is ambiguous; no local title owner was found");
            return false;
        }
        snprintf(selected_uid, sizeof(selected_uid), "%s", users[0].user_uid);
        int n = snprintf(selected_target, sizeof(selected_target),
                         "%s/savedata_prospero/%s", users[0].path, title_id);
        if (n < 0 || (size_t)n >= sizeof(selected_target)) goto unavailable;
    }
    if (strlen(selected_uid) >= uid_sz || strlen(selected_target) >= target_sz)
        goto unavailable;
    snprintf(uid, uid_sz, "%s", selected_uid);
    snprintf(target, target_sz, "%s", selected_target);
    return true;
unavailable:
    if (err && err_sz) snprintf(err, err_sz,
        "Local save-owner inventory is unavailable, incomplete or unsafe");
    return false;
}

static bool resolve_restore_uid(const char* user_alias, const char* title_id,
                                char* out, size_t out_sz) {
    if (!out || !out_sz) return false;
    if (!user_alias || !user_alias[0]) {
        char target[320];
        return resolve_local_restore_target(title_id, out, out_sz,
                                             target, sizeof(target), NULL, 0);
    }
    resolve_alias_to_uid(user_alias, out, out_sz);
    config_t cfg;
    fs_dir_t users[16];
    if (!config_snapshot(&cfg)) return false;
    size_t count = fs_list_users(cfg.paths.saves_root, users, 16);
    if (!out[0] || !valid_uid(out)) return false;
    for (size_t i = 0; i < count; i++)
        if (strcmp(users[i].user_uid, out) == 0) return true;
    out[0] = '\0';
    return false;
}

bool watcher_restore_uid_is_local(const char* uid) {
    if (!restore_uid_valid(uid)) return false;
    config_t cfg;
    fs_dir_t users[16];
    if (!config_snapshot(&cfg)) return false;
    size_t count = fs_list_users(cfg.paths.saves_root, users, 16), matches = 0;
    for (size_t i = 0; i < count; i++)
        if (!strcmp(users[i].user_uid, uid)) matches++;
    return matches == 1;
}

static bool resolve_restore_target(const char* user, const char* title_id,
                                   bool uid_explicit, char* out, size_t out_sz) {
    if (!uid_explicit) return resolve_restore_uid(user, title_id, out, out_sz);
    if (!out || !out_sz) return false;
    out[0] = '\0';
    if (!valid_title_id(title_id) || !watcher_restore_uid_is_local(user) ||
        strlen(user) >= out_sz) return false;
    snprintf(out, out_sz, "%s", user);
    return true;
}

static bool retained_rollback_path(const char* user_alias,
                                   const char* title_id,
                                   char* out, size_t out_sz, bool uid_explicit) {
    char uid[16] = {0};
    config_t cfg;
    if (!valid_title_id(title_id) ||
        !resolve_restore_target(user_alias, title_id, uid_explicit, uid, sizeof(uid)) ||
        !config_snapshot(&cfg)) return false;
    int n = snprintf(out, out_sz, "%s/restore_%s_%s_sdimg_rollback",
                     cfg.paths.staging_dir, uid, title_id);
    return n > 0 && (size_t)n < out_sz;
}

bool watcher_retained_rollback_available(const char* user_alias,
                                         const char* title_id,
                                         size_t* image_count, bool uid_explicit) {
    char path[420];
    if (image_count) *image_count = 0;
    return retained_rollback_path(user_alias, title_id, path, sizeof(path), uid_explicit) &&
           sdimg_restore_retained_rollback_available(path, image_count);
}

static bool rollback_archive_name(const char* name,const char* canonical) {
    const char* leaf=strrchr(canonical,'/');leaf=leaf?leaf+1:canonical;
    const char* base_end=strstr(leaf,"_sdimg_rollback");
    if(!base_end)return false;
    size_t base=(size_t)(base_end-leaf);
    if(strncmp(name,leaf,base))return false;
    const char* kind=name+base;const char* date=NULL;
    const char* kinds[]={"_sdimg_rollback.saved-","_sdimg_rollback.previous.saved-",
        "_sdimg_rollback.apply.saved-","_plain_slot_imgbak.saved-","_plain_slot_snap.saved-"};
    for(size_t i=0;i<sizeof(kinds)/sizeof(kinds[0]);i++)
        if(!strncmp(kind,kinds[i],strlen(kinds[i])))date=kind+strlen(kinds[i]);
    if(!date && !strncmp(kind,"_plain_set_",11)){
        const char* p=kind+11;const char* first=p;while(isdigit((unsigned char)*p))p++;
        if(p>first&&!strncmp(p,".saved-",7))date=p+7;
    }
    if(!date||strlen(date)!=27)return false; // YYYY-MM-DD_HH-MM-SSZ-XXXXXX
    for(size_t i=0;i<21;i++){
        char expected=i==4||i==7||i==13||i==16||i==20?'-':i==10?'_':i==19?'Z':0;
        if(expected?date[i]!=expected:!isdigit((unsigned char)date[i]))return false;
    }
    for(size_t i=21;i<27;i++)if(!isalnum((unsigned char)date[i]))return false;
    return date[27]==0;
}
bool watcher_list_rollbacks(const char* user,const char* title,watcher_rollback_cb cb,void* context, bool uid_explicit) {
    char canonical[512],parent[512];
    if(!cb||!retained_rollback_path(user,title,canonical,sizeof(canonical),uid_explicit))return false;
    snprintf(parent,sizeof(parent),"%s",canonical);char* slash=strrchr(parent,'/');if(!slash)return false;*slash=0;
    struct stat st;uint64_t bytes=0;size_t images=0;
    if(!lstat(canonical,&st)){
        if(!rollback_tree_observe(canonical,&bytes,&images,0))return false;
        cb("current",(int64_t)st.st_mtime,bytes,images,context);
    }else if(errno!=ENOENT)return false;
    DIR* d=opendir(parent);if(!d)return false;bool ok=true;size_t count=0;
    for(;;){errno=0;struct dirent* e=readdir(d);if(!e){if(errno)ok=false;break;}
        if(!rollback_archive_name(e->d_name,canonical))continue;
        char path[800];int n=snprintf(path,sizeof(path),"%s/%s",parent,e->d_name);bytes=0;images=0;
        if(++count>128||n<0||(size_t)n>=sizeof(path)||lstat(path,&st)||!S_ISDIR(st.st_mode)||
            !rollback_tree_observe(path,&bytes,&images,0)){ok=false;break;}
        int archive=open(path,O_RDONLY|O_DIRECTORY|O_NOFOLLOW);
        bool shape=archive>=0&&rollback_archive_shape(archive);
        if(archive>=0)close(archive);
        if(!shape){ok=false;break;}
        // The readable archive name carries the old snapshot's timestamp.
        char snapshot[840];snprintf(snapshot,sizeof(snapshot),"%s/snapshot",path);
        if(lstat(snapshot,&st)){ok=false;break;}
        cb(e->d_name,(int64_t)st.st_mtime,bytes,images,context);
    }
    if(closedir(d))ok=false;return ok;
}
bool watcher_delete_archived_rollback(const char* user,const char* title,const char* id,char* err,size_t n, bool uid_explicit) {
    char canonical[512],path[800],parent[512];
    if(!retained_rollback_path(user,title,canonical,sizeof(canonical),uid_explicit)||!id||!rollback_archive_name(id,canonical)){
        if(err&&n)snprintf(err,n,"Invalid saved rollback identity");return false;
    }
    if(!save_io_begin_write())return false;
    bool ok=false;uint64_t bytes=0;struct stat st;
    char current[sizeof(canonical)];
    if(uid_explicit && (!retained_rollback_path(user,title,current,sizeof(current),true) || strcmp(current,canonical))){
        if(err&&n)snprintf(err,n,"Rollback target changed while waiting for save I/O");goto done;
    }
    if(sdimg_restore_recovery_pending(canonical)||restore_recovery_required(s_cfg)){
        if(err&&n)snprintf(err,n,"Recovery is pending; saved evidence cannot be deleted");goto done;
    }
    snprintf(parent,sizeof(parent),"%s",canonical);*strrchr(parent,'/')=0;
    int len=snprintf(path,sizeof(path),"%s/%s",parent,id);
    if(len<0||(size_t)len>=sizeof(path)||lstat(path,&st)||!S_ISDIR(st.st_mode)||!rollback_tree_size(path,&bytes,0)){
        if(err&&n)snprintf(err,n,"Saved rollback is unreadable or changed");goto done;
    }
    ok=rollback_delete_archive(parent,id);
    if(!ok&&err&&n)snprintf(err,n,"Could not delete saved rollback");
 done:save_io_end_write();return ok;
}

bool watcher_delete_retained_rollback(const char* user_alias,
                                      const char* title_id,
                                      char* err, size_t err_sz, bool uid_explicit) {
    char path[420];
    if (!retained_rollback_path(user_alias, title_id, path, sizeof(path), uid_explicit)) {
        if (err && err_sz) snprintf(err, err_sz, "Invalid rollback target");
        return false;
    }
    if (!save_io_begin_write()) {
        if (err && err_sz) snprintf(err, err_sz, "Lifecycle stop is reserved; rollback deletion not admitted");
        return false;
    }
    char current[sizeof(path)];
    if (uid_explicit && (!retained_rollback_path(user_alias, title_id, current, sizeof(current), true) ||
                         strcmp(current, path))) {
        save_io_end_write();
        if (err && err_sz) snprintf(err, err_sz, "Rollback target changed while waiting for save I/O");
        return false;
    }
    char marker[300];
    struct stat st;
    restore_busy_path(marker, sizeof(marker));
    bool blocked = lstat(marker, &st) == 0 || errno != ENOENT;
    snprintf(marker, sizeof(marker), "%s/restore.interrupted", s_cfg->paths.state_dir);
    blocked = blocked || lstat(marker, &st) == 0 || errno != ENOENT ||
              sdimg_restore_recovery_pending(path) || restore_recovery_required(s_cfg);
    if (blocked || !sdimg_restore_retained_rollback_available(path, NULL)) {
        save_io_end_write();
        if (err && err_sz) snprintf(err, err_sz, "%s", blocked
            ? "Recovery is pending; the last recovery copy cannot be deleted"
            : "No previous save is retained");
        return false;
    }
    pfs_fs_rmrf(path);
    bool remains = lstat(path, &st) == 0 || errno != ENOENT;
    sync();
    save_io_end_write();
    if (remains) {
        if (err && err_sz) snprintf(err, err_sz, "Could not delete retained rollback");
        return false;
    }
    log_info("watcher: retained rollback deleted for %s", title_id);
    return true;
}

bool watcher_resolve_portable_target_held(const char* title_id,
                                     char* uid, size_t uid_sz,
                                     char* err, size_t err_sz) {
    if (uid && uid_sz) uid[0] = '\0';
    if (err && err_sz) err[0] = '\0';
    if (!valid_title_id(title_id)) {
        if (err && err_sz) snprintf(err, err_sz, "Invalid portable target title");
        return false;
    }
    char target[320];
    bool ok = save_export_ready(err, err_sz);
    if (ok && !fs_title_is_closed(title_id)) {
        if (err && err_sz) snprintf(err, err_sz,
            "Game must be closed and its state readable before checking its save containers");
        ok = false;
    }
    if (ok) ok = resolve_local_restore_target(title_id, uid, uid_sz,
                                              target, sizeof(target), err, err_sz);
    if (ok) log_info("portable-target: resolved local uid=%s title=%s before mount", uid, title_id);
    return ok;
}

bool watcher_resolve_portable_target(const char* title_id,
                                     char* uid, size_t uid_sz,
                                     char* err, size_t err_sz) {
    if (!save_io_begin_read()) {
        if (err && err_sz) snprintf(err, err_sz, "Lifecycle stop is reserved; target check not admitted");
        return false;
    }
    bool ok = watcher_resolve_portable_target_held(title_id, uid, uid_sz, err, err_sz);
    save_io_end_read();
    return ok;
}

bool watcher_raw_selected_workspace_held(char* work, size_t work_sz,
    char* err, size_t err_sz) {
    config_t cfg; char parent[512];
    if (!work || !work_sz || !config_snapshot(&cfg)) goto failed;
    int n = snprintf(parent, sizeof(parent), "%s/forensics", cfg.paths.state_dir);
    if (n <= 0 || (size_t)n >= sizeof(parent) ||
        (mkdir(parent, 0700) != 0 && errno != EEXIST)) goto failed;
    struct stat st; char* canonical = realpath(parent, NULL);
    bool safe = canonical && !strcmp(canonical, parent) && !strncmp(parent, "/data/", 6) &&
        lstat(parent, &st) == 0 && S_ISDIR(st.st_mode);
    free(canonical);
    if (!safe) goto failed;
    n = snprintf(work, work_sz, "%s/raw-selected-preflight.XXXXXX", parent);
    if (n <= 0 || (size_t)n >= work_sz || !mkdtemp(work)) goto failed;
    // Make every new workspace directory entry durable before its path is
    // recorded by the native-mount barrier. Never remove evidence on failure.
    const char* directories[] = {cfg.paths.state_dir, parent, work};
    for (size_t i = 0; i < sizeof(directories) / sizeof(*directories); i++) {
        int fd = open(directories[i], O_RDONLY | O_DIRECTORY | O_NOFOLLOW);
        bool durable = fd >= 0 && fsync(fd) == 0;
        if (fd >= 0 && close(fd) != 0) durable = false;
        if (!durable) goto failed;
    }
    return true;
failed:
    if (err && err_sz) snprintf(err, err_sz, "New private RAW-selected evidence workspace unavailable (errno=%d)", errno);
    return false;
}

bool watcher_raw_selected_target_held(const char* expected_uid, const char* title,
    char* uid, size_t uid_sz, char* target, size_t target_sz,
    char* err, size_t err_sz) {
    if (!expected_uid || !valid_uid(expected_uid) || !valid_title_id(title) ||
        !fs_title_is_closed(title)) {
        if (err && err_sz) snprintf(err, err_sz, "Game closed state or exact target confirmation is unavailable");
        return false;
    }
    // Own RAW diagnostic marker is intentionally present on the final recheck.
    // Admission already checked recovery before arming it; never clear someone
    // else's barrier or use an imported owner/user hint as the local UID.
    if (!resolve_local_restore_target(title, uid, uid_sz, target, target_sz, err, err_sz)) return false;
    struct stat st;
    if (strcmp(uid, expected_uid) || lstat(target, &st) != 0 || !S_ISDIR(st.st_mode)) {
        if (err && err_sz) snprintf(err, err_sz, "Fresh local UID differs or destination title does not exist");
        return false;
    }
    return true;
}

bool watcher_raw_selected_barrier_held(bool create, const char* work,
    char* err, size_t err_sz) {
    char path[512];
    if (!work || !*work || strlen(work) >= 512 || !raw_recovery_marker_path(path, sizeof(path))) goto failed;
    if (!create) {
        // A private preflight can only retire the marker it owns. UNKNOWN,
        // symlinks, truncated/different content and other operations block.
        struct stat st, opened, closed, final; char owner[512] = {0};
        int fd = lstat(path, &st) == 0 && S_ISREG(st.st_mode) && st.st_nlink == 1 &&
            st.st_size == (off_t)strlen(work) && st.st_size < (off_t)sizeof(owner)
            ? open(path, O_RDONLY | O_NOFOLLOW) : -1;
        if (fd < 0) goto failed;
        bool same = fstat(fd, &opened) == 0 && raw_selected_stat_equal(&st, &opened);
        ssize_t bytes = same ? read(fd, owner, sizeof(owner) - 1) : -1;
        unsigned char tail;
        same = same && bytes == (ssize_t)strlen(work) && !memcmp(owner, work, (size_t)bytes) &&
            read(fd, &tail, 1) == 0 && fstat(fd, &closed) == 0 && raw_selected_stat_equal(&st, &closed) &&
            lstat(path, &final) == 0 && raw_selected_stat_equal(&st, &final);
        if (close(fd) != 0) same = false;
        // No other in-process operation may replace this marker under the
        // exclusive gate. External/path drift still prevents retiring it.
        if (same && (lstat(path, &final) != 0 || !raw_selected_stat_equal(&st, &final))) same = false;
        if (!same) goto failed;
    }
    if (!raw_recovery_marker(create, work)) {
        // Failed unlink/directory sync is uncertain. Re-arm if possible rather
        // than letting following operations silently treat uncertainty as clear.
        if (!create) (void)raw_recovery_marker(true, work);
        goto failed;
    }
    return true;
failed:
    if (err && err_sz) snprintf(err, err_sz, "RAW diagnostic barrier ownership/durability is uncertain (errno=%d)", errno);
    return false;
}

void watcher_inspect_pfs_attributes(pfs_attributes_report_t* report) {
    memset(report, 0, sizeof(*report));
    report->result = "ERROR";
    int admitted = watcher_target_check_begin(report->detail, sizeof(report->detail));
    if (admitted != 1) {
        report->result = admitted == 0 ? "BUSY" : "RECOVERY_REQUIRED";
        report->recovery_required = admitted < 0;
        return;
    }
    char uid[16] = {0}, parent[256]; bool guarded = false;
    if (!watcher_resolve_portable_target_held(PFS_ATTRIBUTES_TITLE, uid, sizeof(uid),
                                             report->detail, sizeof(report->detail)) ||
        strcmp(uid, PFS_ATTRIBUTES_UID)) {
        report->result = "TARGET_UNCONFIRMED";
        if (!report->detail[0]) snprintf(report->detail, sizeof(report->detail),
            "Fresh local UID %s does not match diagnostic UID %s", uid, PFS_ATTRIBUTES_UID);
        goto done;
    }
    // Keep metadata evidence out of ordinary staging cleanup. No export.
    int n = snprintf(parent, sizeof(parent), "%s/forensics", s_cfg->paths.state_dir);
    if (n < 0 || (size_t)n >= sizeof(parent) ||
        (mkdir(parent, 0700) != 0 && errno != EEXIST)) goto done;
    struct stat st;
    if (lstat(parent, &st) != 0 || !S_ISDIR(st.st_mode)) goto done;
    char* canonical = realpath(parent, NULL);
    n = canonical && !strncmp(canonical, "/data/", 6)
        ? snprintf(report->work, sizeof(report->work), "%s/pfs-attributes.XXXXXX", canonical) : -1;
    free(canonical);
    if (n < 0 || (size_t)n >= sizeof(report->work) || !mkdtemp(report->work)) {
        report->work[0] = 0; goto done;
    }
    if (!raw_recovery_marker(true, report->work)) {
        report->result = "BARRIER_ERROR";
        report->recovery_required = true;
        snprintf(report->detail, sizeof(report->detail), "Could not arm diagnostic safety barrier; no mount attempted");
        goto done;
    }
    guarded = true;
    pfs_attributes_compare(report);
done:
    if (!report->detail[0] && !strcmp(report->result, "ERROR"))
        snprintf(report->detail, sizeof(report->detail), "Diagnostic setup or observation failed (errno=%d)", errno);
    if (guarded && !report->recovery_required && !raw_recovery_marker(false, report->work)) {
        report->recovery_required = true; report->result = "RECOVERY_REQUIRED";
        snprintf(report->detail, sizeof(report->detail), "Could not clear diagnostic safety barrier; evidence retained");
    }
    watcher_target_check_end();
}

void watcher_private_mode_trial(pfs_mode_trial_report_t* report) {
    memset(report, 0, sizeof(*report));
    report->result = "ERROR";
    int admitted = watcher_target_check_begin(report->detail, sizeof(report->detail));
    if (admitted != 1) {
        report->result = admitted == 0 ? "BUSY" : "RECOVERY_REQUIRED";
        report->recovery_required = admitted < 0;
        return;
    }
    char uid[16] = {0}, parent[256];
    bool guarded = false;
    if (!watcher_resolve_portable_target_held(PFS_ATTRIBUTES_TITLE, uid, sizeof(uid),
                                             report->detail, sizeof(report->detail)) ||
        strcmp(uid, PFS_ATTRIBUTES_UID)) {
        report->result = "TARGET_UNCONFIRMED";
        if (!report->detail[0]) snprintf(report->detail, sizeof(report->detail),
            "Fresh local UID %s does not match trial UID %s", uid, PFS_ATTRIBUTES_UID);
        goto done;
    }
    int n = snprintf(parent, sizeof(parent), "%s/forensics", s_cfg->paths.state_dir);
    if (n < 0 || (size_t)n >= sizeof(parent) ||
        (mkdir(parent, 0700) != 0 && errno != EEXIST)) goto done;
    struct stat st;
    if (lstat(parent, &st) != 0 || !S_ISDIR(st.st_mode)) goto done;
    char* canonical = realpath(parent, NULL);
    n = canonical && !strncmp(canonical, "/data/", 6)
        ? snprintf(report->work, sizeof(report->work), "%s/pfs-mode-trial.XXXXXX", canonical) : -1;
    free(canonical);
    if (n < 0 || (size_t)n >= sizeof(report->work) || !mkdtemp(report->work)) {
        report->work[0] = 0; goto done;
    }
    if (!raw_recovery_marker(true, report->work)) {
        report->result = "BARRIER_ERROR";
        report->recovery_required = true;
        snprintf(report->detail, sizeof(report->detail), "Could not arm private-trial safety barrier; no mount attempted");
        goto done;
    }
    guarded = true;
    pfs_mode_trial_run(report);
done:
    if (!report->detail[0] && !strcmp(report->result, "ERROR"))
        snprintf(report->detail, sizeof(report->detail), "Private trial setup failed (errno=%d)", errno);
    // Failed/interrupted experiments never replay or clean their artifacts.
    // This is a mount/evidence guard, not permission to repair the live save.
    if (guarded) {
        if (strcmp(report->result, "PRIVATE_PASS") || !report->evidence_durable || report->recovery_required) {
            report->recovery_required = true;
            if (!strcmp(report->result, "PRIVATE_PASS")) {
                report->result = "RECOVERY_REQUIRED";
                snprintf(report->detail, sizeof(report->detail), "Private checks passed but durable evidence/barrier completion is uncertain; artifacts retained");
            }
        } else if (!raw_recovery_marker(false, report->work)) {
            // Removal can succeed before its directory fsync fails. Restore
            // the existing guard before releasing admission, never replay.
            bool rearmed = raw_recovery_marker(true, report->work);
            report->recovery_required = true;
            report->result = "RECOVERY_REQUIRED";
            snprintf(report->detail, sizeof(report->detail), "%s; evidence retained",
                rearmed ? "Private-trial barrier finalization failed; guard rearmed"
                        : "Private-trial barrier finalization failed; guard durability unconfirmed");
        }
    }
    watcher_target_check_end();
}

static bool watcher_revalidate_mode_candidate(pfs_candidate_publication_t* report) {
    pfs_mode_trial_report_t* trial = &report->trial;
    char uid[16] = {0}, target[320];
    // The exclusive owner already armed its barrier. Re-read local authority
    // directly; save_export_ready() would correctly reject every other caller.
    if (!fs_title_is_closed(PFS_ATTRIBUTES_TITLE) ||
        !resolve_local_restore_target(PFS_ATTRIBUTES_TITLE, uid, sizeof(uid),
            target, sizeof(target), trial->detail, sizeof(trial->detail)) ||
        strcmp(uid, PFS_ATTRIBUTES_UID) ||
        strcmp(target, "/user/home/" PFS_ATTRIBUTES_UID "/savedata_prospero/" PFS_ATTRIBUTES_TITLE)) {
        trial->result = "TARGET_UNCONFIRMED";
        if (!trial->detail[0]) snprintf(trial->detail, sizeof(trial->detail),
            "Publication requires the closed game and fresh exact local UID %s", PFS_ATTRIBUTES_UID);
        return false;
    }
    sdimg_target_slot_report_t registry = {0};
    uint64_t account_id = 0; uint32_t user_id = 0;
    if (!sdimg_diagnostic_target_owner(uid, PFS_ATTRIBUTES_TITLE, PFS_ATTRIBUTES_SLOT,
                                      &account_id, &user_id, &registry)) {
        report->registry = registry;
        trial->result = "TARGET_UNCONFIRMED";
        snprintf(trial->detail, sizeof(trial->detail), "%s", registry.detail);
        return false;
    }
    bool changed = report->identity_resolved &&
        (report->account_id != account_id || report->user_id != user_id ||
         report->registry.registry_rowid != registry.registry_rowid);
    report->registry = registry;
    if (changed) {
        trial->result = "TARGET_IDENTITY_CHANGED";
        snprintf(trial->detail, sizeof(trial->detail),
            "Exact target registry row or typed owner changed; no fallback or retry");
        return false;
    }
    report->account_id = account_id; report->user_id = user_id;
    report->identity_resolved = true;
    return true;
}

void watcher_publish_mode_candidate(pfs_candidate_publication_t* report) {
    memset(report, 0, sizeof(*report));
    pfs_mode_trial_report_t* trial = &report->trial;
    trial->result = "ERROR";
    int admitted = watcher_target_check_begin(trial->detail, sizeof(trial->detail));
    if (admitted != 1) {
        trial->result = admitted == 0 ? "BUSY" : "RECOVERY_REQUIRED";
        trial->recovery_required = admitted < 0;
        return;
    }
    char uid[16] = {0}, parent[256]; bool guarded = false;
    if (!watcher_resolve_portable_target_held(PFS_ATTRIBUTES_TITLE, uid, sizeof(uid),
                                             trial->detail, sizeof(trial->detail)) ||
        strcmp(uid, PFS_ATTRIBUTES_UID)) {
        trial->result = "TARGET_UNCONFIRMED";
        if (!trial->detail[0]) snprintf(trial->detail, sizeof(trial->detail),
            "Fresh local UID %s does not match publication UID %s", uid, PFS_ATTRIBUTES_UID);
        goto done;
    }
    if (!watcher_revalidate_mode_candidate(report)) goto done;
    int n = snprintf(parent, sizeof(parent), "%s/forensics", s_cfg->paths.state_dir);
    if (n < 0 || (size_t)n >= sizeof(parent) ||
        (mkdir(parent, 0700) != 0 && errno != EEXIST)) goto done;
    struct stat st;
    if (lstat(parent, &st) != 0 || !S_ISDIR(st.st_mode)) goto done;
    char* canonical = realpath(parent, NULL);
    n = canonical && !strncmp(canonical, "/data/", 6)
        ? snprintf(trial->work, sizeof(trial->work), "%s/pfs-mode-publication.XXXXXX", canonical) : -1;
    if (n < 0 || (size_t)n >= sizeof(trial->work) || !mkdtemp(trial->work)) {
        free(canonical); trial->work[0] = 0; goto done;
    }
    int parent_fd = open(canonical, O_RDONLY | O_DIRECTORY | O_NOFOLLOW);
    free(canonical);
    bool parent_durable = parent_fd >= 0;
    if (parent_fd >= 0) {
        if (fsync(parent_fd) != 0) parent_durable = false;
        if (close(parent_fd) != 0) parent_durable = false;
    }
    if (!parent_durable) {
        trial->result = "EVIDENCE_ERROR";
        snprintf(trial->detail, sizeof(trial->detail),
            "New publication workspace namespace is not durably confirmed; no publication attempted");
        goto done;
    }
    if (!raw_recovery_marker(true, trial->work)) {
        trial->result = "BARRIER_ERROR"; trial->recovery_required = true;
        snprintf(trial->detail, sizeof(trial->detail),
            "Could not arm publication safety barrier; no publication attempted");
        goto done;
    }
    guarded = true;
    pfs_candidate_publish_run(report, watcher_revalidate_mode_candidate);
done:
    if (!trial->detail[0] && !strcmp(trial->result, "ERROR"))
        snprintf(trial->detail, sizeof(trial->detail), "Publication setup failed (errno=%d)", errno);
    if (guarded) {
        if (strcmp(trial->result, "PUBLISHED_VERIFIED") || !trial->evidence_durable ||
            !report->post_verified || !report->final_hash_verified || !report->retained_unchanged ||
            trial->recovery_required) {
            trial->recovery_required = true;
            if (!strcmp(trial->result, "PUBLISHED_VERIFIED")) {
                trial->result = "RECOVERY_REQUIRED";
                snprintf(trial->detail, sizeof(trial->detail),
                    "Publication completion or durable evidence uncertain; barrier and artifacts retained");
            }
        } else if (!raw_recovery_marker(false, trial->work)) {
            bool rearmed = raw_recovery_marker(true, trial->work);
            trial->recovery_required = true; trial->result = "RECOVERY_REQUIRED";
            snprintf(trial->detail, sizeof(trial->detail), "%s; evidence retained",
                rearmed ? "Publication barrier finalization failed; guard rearmed"
                        : "Publication barrier finalization failed; guard durability unconfirmed");
        }
    }
    watcher_target_check_end();
}

static sdimg_target_preflight_result_t preflight_portable_target_inner(const char* expected_uid,
                                       const char* title_id,
                                       const char slots[][64],
                                       size_t slot_count,
                                       size_t* ready_count,
                                       sdimg_target_slot_report_t* reports,
                                       size_t report_cap,
                                       size_t* report_count,
                                       char* resolved_uid, size_t resolved_uid_sz,
                                       char* err, size_t err_sz) {
    if (resolved_uid && resolved_uid_sz) resolved_uid[0] = '\0';
    if (!fs_title_is_closed(title_id)) {
        if (err && err_sz) snprintf(err, err_sz,
                                    "Game must be closed and its state readable before checking its save containers");
        return SDIMG_TARGET_PREFLIGHT_BLOCKED;
    }
    char uid[16] = {0}, target[320];
    if (!resolve_local_restore_target(title_id, uid, sizeof(uid),
                                      target, sizeof(target), err, err_sz)) return SDIMG_TARGET_PREFLIGHT_BLOCKED;
    if (!resolved_uid || strlen(uid) >= resolved_uid_sz) {
        if (err && err_sz) snprintf(err, err_sz, "Resolved PS5 user could not be reported");
        return SDIMG_TARGET_PREFLIGHT_BLOCKED;
    }
    snprintf(resolved_uid, resolved_uid_sz, "%s", uid);
    if (expected_uid && expected_uid[0] && strcmp(expected_uid, uid) != 0) {
        if (err && err_sz) snprintf(err, err_sz,
            "Target PS5 user changed; confirm the freshly resolved local user again");
        return SDIMG_TARGET_PREFLIGHT_BLOCKED;
    }
    log_info("portable-target: resolved local uid=%s title=%s before mount", uid, title_id);
    // Only the explicit confirmed diagnostic uses strict exact-row lookup.
    // Automatic import commit passes NULL and keeps legacy Restore admission.
    if (expected_uid && expected_uid[0])
        return sdimg_diagnose_target_slots_checked(
            uid, title_id, target, slots, slot_count, ready_count,
            reports, report_cap, report_count, err, err_sz);
    return sdimg_restore_preflight_target_slots_checked(
        uid, title_id, target, slots, slot_count, ready_count,
        reports, report_cap, report_count, err, err_sz);
}

bool watcher_portable_target_state_held(const restore_scope_t* scope,
    char out_sha256[65], char* err, size_t err_sz) {
    char uid[16] = {0}, root[256];
    if (!scope || !scope->selection.specified || !scope->selection.count ||
        !valid_uid(scope->target_uid) || !valid_title_id(scope->title_id) ||
        strcmp(scope->restore_mode, RESTORE_MODE_PORTABLE_SELECTED) ||
        !resolve_restore_uid(NULL, scope->title_id, uid, sizeof(uid)) ||
        strcmp(uid, scope->target_uid)) {
        if (err && err_sz) snprintf(err, err_sz, "Portable selected target UID/title unavailable or changed");
        return false;
    }
    int n = snprintf(root, sizeof(root), "%s/%s/savedata_prospero/%s",
        s_cfg->paths.saves_root, uid, scope->title_id);
    if (n < 0 || n >= (int)sizeof(root)) return false;
    return portable_transaction_target_digest(scope, root, out_sha256, err, err_sz);
}

bool watcher_preflight_portable_target_held(const char* expected_uid,
                                       const char* title_id,
                                       const char slots[][64],
                                       size_t slot_count,
                                       size_t* ready_count,
                                       sdimg_target_slot_report_t* reports,
                                       size_t report_cap,
                                       size_t* report_count,
                                       char* resolved_uid, size_t resolved_uid_sz,
                                       char* err, size_t err_sz) {
    if (ready_count) *ready_count = 0;
    if (report_count) *report_count = 0;
    if (resolved_uid && resolved_uid_sz) resolved_uid[0] = '\0';
    if (err && err_sz) err[0] = '\0';
    char local_uid[16] = {0};
    char* reported_uid = resolved_uid ? resolved_uid : local_uid;
    size_t reported_uid_sz = resolved_uid ? resolved_uid_sz : sizeof(local_uid);
    // Reuse RAW recovery's durable mount barrier, under the same exclusive
    // save-I/O gate. An interrupted/uncertain check cannot race a backup or
    // cleanup, and a new daemon must inspect it rather than discard evidence.
    bool ok = false;
    if (save_export_ready(err, err_sz)) {
        char work[128];
        if (!valid_title_id(title_id) ||
            (expected_uid && expected_uid[0] && !valid_uid(expected_uid))) {
            if (err && err_sz) snprintf(err, err_sz, "Invalid portable target confirmation");
        } else {
            snprintf(work, sizeof(work), "portable-preflight title=%s", title_id);
            if (!raw_recovery_marker(true, work)) {
                if (err && err_sz) snprintf(err, err_sz,
                    "Could not persist target mount safety guard; no images mounted");
            } else {
                sdimg_target_preflight_result_t result =
                    preflight_portable_target_inner(expected_uid, title_id,
                        slots, slot_count, ready_count, reports, report_cap,
                        report_count, reported_uid, reported_uid_sz, err, err_sz);
                if (result != SDIMG_TARGET_PREFLIGHT_UNMOUNT_UNCERTAIN) {
                    ok = raw_recovery_marker(false, work) &&
                         result == SDIMG_TARGET_PREFLIGHT_READY;
                    if (!ok && result == SDIMG_TARGET_PREFLIGHT_READY && err && err_sz)
                        snprintf(err, err_sz,
                            "Target mount safety checkpoint could not be cleared; inspect before retrying");
                }
                // Uncertainty deliberately leaves both the durable barrier
                // and savemount's private backing/mount untouched.
            }
        }
    }
    return ok;
}

bool watcher_preflight_portable_target(const char* expected_uid,
                                       const char* title_id,
                                       const char slots[][64],
                                       size_t slot_count,
                                       size_t* ready_count,
                                       sdimg_target_slot_report_t* reports,
                                       size_t report_cap,
                                       size_t* report_count,
                                       char* resolved_uid, size_t resolved_uid_sz,
                                       char* err, size_t err_sz) {
    if (ready_count) *ready_count = 0;
    if (report_count) *report_count = 0;
    if (resolved_uid && resolved_uid_sz) resolved_uid[0] = '\0';
    if (watcher_target_check_begin(err, err_sz) != 1) return false;
    bool ok = watcher_preflight_portable_target_held(expected_uid, title_id,
        slots, slot_count, ready_count, reports, report_cap, report_count,
        resolved_uid, resolved_uid_sz, err, err_sz);
    watcher_target_check_end();
    return ok;
}

bool watcher_cancel_import(const char* id, char* err, size_t err_sz) {
    if (!save_io_begin_write()) {
        if (err && err_sz) snprintf(err, err_sz, "Lifecycle stop is reserved; import cancellation not admitted");
        return false;
    }
    bool ok = save_export_ready(err, err_sz) && import_session_cancel(id);
    save_io_end_write();
    return ok;
}

static int preserved_inventory_name_compare(const void* a, const void* b) {
    return strcmp(*(const char* const*)a, *(const char* const*)b);
}

static void preserved_inventory_field(sha256_ctx_t* hash, const char* value) {
    char length[32];
    int n = snprintf(length, sizeof(length), "%zu:", strlen(value));
    sha256_update(hash, length, (size_t)n);
    sha256_update(hash, value, strlen(value));
}

// Names and counts observed by the normal inspector, not a recursive payload
// digest. The full ZIP SHA separately binds manifest and payload bytes.
static bool preserved_inventory_digest(const migration_report_t* report,
                                        char out[65]) {
    if (!report || !report->valid || report->save_dir_count > MIGRATION_MAX_SLOTS ||
        report->service_dir_count > MIGRATION_MAX_SLOTS ||
        report->selected_slots_count > MIGRATION_MAX_SLOTS ||
        report->included_image_count > MIGRATION_MAX_SLOTS * 2) return false;
    sha256_ctx_t hash;
    sha256_init(&hash);
    preserved_inventory_field(&hash, "tostonsync.inspector-container-inventory.v1");
    preserved_inventory_field(&hash, migration_format_name(report->format));
    preserved_inventory_field(&hash, report->title_id);
    preserved_inventory_field(&hash, report->backup_scope);
    char counts[256];
    snprintf(counts, sizeof(counts), "%zu,%zu,%zu,%zu,%zu,%zu,%zu,%zu,%u",
        report->active_images, report->service_images, report->save_dir_count,
        report->service_dir_count, report->selected_slots_count,
        report->included_image_count, report->available_slots,
        report->missing_service_images, report->selected_containers ? 1U : 0U);
    preserved_inventory_field(&hash, counts);
    const char* names[MIGRATION_MAX_SLOTS * 2];
    const size_t count[] = {report->save_dir_count, report->service_dir_count,
                           report->selected_slots_count, report->included_image_count};
    const char* labels[] = {"active", "service", "selected", "included-images"};
    for (size_t group = 0; group < 4; group++) {
        preserved_inventory_field(&hash, labels[group]);
        for (size_t i = 0; i < count[group]; i++)
            names[i] = group == 0 ? report->save_dirs[i] :
                       group == 1 ? report->service_dirs[i] :
                       group == 2 ? report->selected_slots[i] : report->included_images[i];
        qsort(names, count[group], sizeof(names[0]), preserved_inventory_name_compare);
        for (size_t i = 0; i < count[group]; i++)
            preserved_inventory_field(&hash, names[i]);
    }
    uint8_t digest[32];
    sha256_final(&hash, digest);
    for (size_t i = 0; i < sizeof(digest); i++)
        snprintf(out + i * 2, 3, "%02x", digest[i]);
    return true;
}

bool watcher_preserve_import(const char* id, import_preserved_info_t* out,
                             char* err, size_t err_sz) {
    if (out) memset(out, 0, sizeof(*out));
    if (!id || !id[0] || !out) return false;
    if (watcher_target_check_begin(err, err_sz) != 1) return false;
    bool ok = false;
    import_session_info_t info = {0};
    import_preserve_metadata_t metadata = {0};
    migration_report_t* report = NULL;
    // A claim immediately makes the operational session COMMITTED. The core
    // rechecks READY/no claim under its lock before durable preservation.
    if (!import_session_status(id, &info) || info.state != IMPORT_READY ||
        strcmp(info.id, id) || !import_session_validate_selected(&info)) {
        if (err && err_sz) snprintf(err, err_sz,
            "Preserve requires the exact active verified READY import, with no worker claim");
        goto done;
    }
    report = calloc(1, sizeof(*report));
    if (!report || !migration_inspect_zip(info.path, NULL, report) ||
        !report->valid || !valid_title_id(report->title_id) ||
        strlen(report->source_user_uid) >= sizeof(metadata.source_uid) ||
        !preserved_inventory_digest(report, metadata.raw_inventory_sha256)) {
        if (err && err_sz) snprintf(err, err_sz,
            "Original ZIP inspection or observed source metadata is incomplete; session retained");
        goto done;
    }
    snprintf(metadata.source_format, sizeof(metadata.source_format), "%s",
             migration_format_name(report->format));
    snprintf(metadata.title_id, sizeof(metadata.title_id), "%s", report->title_id);
    snprintf(metadata.source_uid, sizeof(metadata.source_uid), "%s", report->source_user_uid);
    // Manifest fingerprints are UNKNOWN: the existing inspector does not
    // expose manifest bytes. Never substitute a hint or the inventory digest.
    if (info.portable_path[0]) {
        memset(report, 0, sizeof(*report));
        if (!migration_inspect_zip(info.portable_path, NULL, report) ||
            !report->valid || strcmp(report->title_id, metadata.title_id) ||
            !preserved_inventory_digest(report, metadata.portable_inventory_sha256)) {
            if (err && err_sz) snprintf(err, err_sz,
                "Portable ZIP inspection/title disagrees with the original; session retained");
            goto done;
        }
    }
    // Reobserve barriers after inspection. The core independently rehashes
    // both artifacts before publication and again after authority is released.
    ok = save_export_ready(err, err_sz) &&
         import_session_preserve(id, &metadata, out, err, err_sz);
done:
    free(report);
    watcher_target_check_end();
    return ok;
}

static bool restore_async_inner(const char* user_alias,
                           const char* title_id, const char* file_id,
                           watcher_job_admission_t* out, bool uid_explicit, const char* claimed_import_id) {
    if (out) memset(out, 0, sizeof(*out));
    if (!s_running) {
        set_last_restore(title_id, 0, "Watcher is not running");
        return false;
    }
    if (!title_id || !file_id) {
        set_last_restore(title_id, 0, "Missing restore target");
        return false;
    }
    if (!valid_title_id(title_id)) {
        log_warn("watcher: rejecting restore with invalid title_id");
        set_last_restore(title_id, 0, "Invalid title id");
        return false;
    }
    if (uid_explicit && !watcher_restore_uid_is_local(user_alias)) {
        set_last_restore(title_id, 0, "Explicit PS5 user is missing or ambiguous");
        return false;
    }
    // Catalog hints may name the source console's user. Resolve locality only
    // in the shared worker, after format/checksum verification identifies a
    // portable transfer; RAW and retained rollback keep their explicit owner.
    if (user_alias && strlen(user_alias) >= sizeof(((job_t*)0)->restore_user)) {
        set_last_restore(title_id, 0, "PS5 user hint is too long");
        return false;
    }
    if (!valid_restore_ref(file_id)) {
        log_warn("watcher: rejecting restore with invalid backup reference");
        set_last_restore(title_id, 0, "Invalid backup reference");
        return false;
    }
    const char* local_path = !strncmp(file_id, "upload:", 7) ? file_id + 7 :
                             file_id[0] == '/' ? file_id : NULL;
    if (local_path && import_session_preserved_path_blocked(local_path)) {
        set_last_restore(title_id, 0, "Preserved records are historical evidence, not Restore authority");
        return false;
    }
    if (!import_session_restore_target_allowed(local_path,user_alias,uid_explicit)) {
        set_last_restore(title_id,0,"Import target UID changed; review the bound profile again");
        return false;
    }
    if ((!strncmp(file_id, "upload:", 7) &&
         !import_session_legacy_restore_allowed(file_id + 7)) ||
        (file_id[0] == '/' && import_session_path_requires_selection(file_id))) {
        set_last_restore(title_id, 0, "Selective import requires its approved slot selection");
        return false;
    }
    if (!enqueue_inner(user_alias, title_id, true, false, file_id, 0, "", NULL,
                 "restore", out, uid_explicit, claimed_import_id)) {
        set_last_restore(title_id, 0, "Restore queue is full or unavailable");
        return false;
    }
    return true;
}

bool watcher_restore_async(const char* user_alias,
                           const char* title_id, const char* file_id) {
    if (!lifecycle_operation_begin()) return false;
    bool ok = restore_async_inner(user_alias, title_id, file_id, NULL, false, NULL);
    lifecycle_operation_end();
    return ok;
}

bool watcher_restore_async_observed(const char* user_alias,
                           const char* title_id, const char* file_id,
                           watcher_job_admission_t* out, bool uid_explicit, const char* claimed_import_id) {
    if (out) memset(out, 0, sizeof(*out));
    if (!lifecycle_operation_begin()) return false;
    bool ok = restore_async_inner(user_alias, title_id, file_id, out, uid_explicit, claimed_import_id);
    lifecycle_operation_end();
    return ok;
}

static bool restore_selected_async_inner(const restore_scope_t* scope,
                                    const char* file_id, watcher_job_admission_t* out) {
    if (out) memset(out, 0, sizeof(*out));
    if (!s_running || !scope || !scope->selection.specified ||
        !restore_scope_valid(scope) || !valid_title_id(scope->title_id) ||
        !watcher_restore_uid_is_local(scope->target_uid) ||
        !file_id || strncmp(file_id, "upload:", 7) ||
        !valid_restore_ref(file_id) ||
        import_session_preserved_path_blocked(file_id + 7) ||
        !import_session_validate_restore_scope(scope, file_id + 7))
        return false;
    job_t* j = (job_t*)calloc(1, sizeof(*j));
    if (!j) return false;
    j->job_id = atomic_fetch_add(&s_job_seq, 1);
    j->queued_unix = now_unix();
    j->is_restore = true;
    j->restore_scope = *scope;
    j->restore_uid_explicit = true;
    snprintf(j->restore_import_id,sizeof(j->restore_import_id),"%s",scope->import_id);
    snprintf(j->title_id, sizeof(j->title_id), "%s", scope->title_id);
    snprintf(j->user_uid, sizeof(j->user_uid), "%s", scope->target_uid);
    snprintf(j->restore_user, sizeof(j->restore_user), "%s", scope->target_uid);
    snprintf(j->restore_ref, sizeof(j->restore_ref), "%s", file_id);
    snprintf(j->source, sizeof(j->source), "restore_selected");
    jobs_ref_t observation = jobs_watch_queued(j->job_id, JOB_RESTORE, j->user_uid, j->title_id, NULL, NULL);
    if (out) { out->id = observation; out->tracked = jobs_tracked(observation); }
    pthread_mutex_lock(&s_q_lock);
    if (s_q_tail) s_q_tail->next = j; else s_q_head = j;
    s_q_tail = j;
    s_q_depth++;
    pthread_cond_signal(&s_q_cond);
    pthread_mutex_unlock(&s_q_lock);
    return true;
}

bool watcher_restore_selected_async(const restore_scope_t* scope,
                                    const char* file_id) {
    if (!lifecycle_operation_begin()) return false;
    bool ok = restore_selected_async_inner(scope, file_id, NULL);
    lifecycle_operation_end();
    return ok;
}

bool watcher_restore_selected_async_observed(const restore_scope_t* scope,
                                    const char* file_id, watcher_job_admission_t* out) {
    if (out) memset(out, 0, sizeof(*out));
    if (!lifecycle_operation_begin()) return false;
    bool ok = restore_selected_async_inner(scope, file_id, out);
    lifecycle_operation_end();
    return ok;
}

bool watcher_title_is_backed_up(const char* title_id) {
    return config_title_is_backed_up(title_id);
}

void watcher_enumerate_saves(
        void (*cb)(const char* user_alias, const char* user_uid,
                   const char* title_id, const char* game_name,
                   bool included, void* ud),
        void* ud) {
    if (!cb) return;
    struct item {
        char user_alias[32];
        char user_uid[16];
        char title_id[16];
        char game_name[64];
        bool included;
    } items[MAX_TITLES];
    size_t count = 0;

    pthread_mutex_lock(&s_titles_lock);
    for (size_t i = 0; i < s_title_count && count < MAX_TITLES; i++) {
        const char* alias = config_alias_for_uid(s_titles[i].user_uid);
        snprintf(items[count].user_alias, sizeof(items[count].user_alias),
                 "%s", alias ? alias : "default");
        snprintf(items[count].user_uid, sizeof(items[count].user_uid),
                 "%s", s_titles[i].user_uid);
        snprintf(items[count].title_id, sizeof(items[count].title_id),
                 "%s", s_titles[i].title_id);
        titlename_copy_utf8(items[count].game_name, sizeof(items[count].game_name),
                            s_titles[i].game_name);
        items[count].included = config_title_is_backed_up(s_titles[i].title_id);
        count++;
    }
    pthread_mutex_unlock(&s_titles_lock);

    for (size_t i = 0; i < count; i++)
        cb(items[i].user_alias, items[i].user_uid, items[i].title_id,
           items[i].game_name, items[i].included, ud);
}
