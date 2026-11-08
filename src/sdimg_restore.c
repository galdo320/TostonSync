// TostónSync — safe raw restore for PS5 sdimg_* savedata slots.

#include "sdimg_restore.h"
#include "rollback_archive.h"
#include "sdimg_expansion.h"
#include "fs.h"
#include "log.h"
#include "pfs_keys.h"
#include "pfs_resign.h"
#include "pfs_attributes.h"
#include "sha256.h"
#include "sfo.h"
#include "titlename.h"
#include "import_session.h"
#include "third_party/sqlite3.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#define SDIMG_MAX_ITEMS 64
#define SDIMG_NAME_MAX 160
#define SDIMG_PATH_MAX 1024

typedef struct {
    char      name[SDIMG_NAME_MAX];      // sdimg_<dir_name>
    char      dir_name[SDIMG_NAME_MAX];  // DB savedata.dir_name
    char      src[SDIMG_PATH_MAX];
    char      dst[SDIMG_PATH_MAX];
    uint64_t  bytes;
    bool      have_sfo;                  // param.sfo read OK from the image
    bool      sfo_zeroed;                // mounted but param.sfo was all-zero
    sfo_info_t sfo;                      // authentic metadata when have_sfo
} sdimg_item_t;

typedef struct {
    char main_title[128];
    char sub_title[256];
    char detail[512];
    char game_title_id[16];
    int  user_param;
    int  system_blocks;
    sqlite3_int64 account_id;
    sqlite3_int64 user_id;
} sdimg_db_seed_t;

static bool set_err(char* err, size_t err_sz, const char* fmt, ...) {
    if (err && err_sz) {
        va_list ap;
        va_start(ap, fmt);
        vsnprintf(err, err_sz, fmt, ap);
        va_end(ap);
    }
    return false;
}

static bool safe_component(const char* s) {
    if (!s || !s[0]) return false;
    if (strcmp(s, ".") == 0 || strcmp(s, "..") == 0) return false;
    for (const unsigned char* p = (const unsigned char*)s; *p; p++) {
        if (*p < 0x20 || *p == 0x7f || *p == '/' || *p == '\\')
            return false;
    }
    return true;
}

// "sdimg_sce_bu_*" are the save service's own internal backup images, not
// real, playable savedata slots. They must never be copied as a slot nor
// indexed in savedata.db — doing so (the v0.5.26 bug) inserted phantom
// "sce_bu_*" rows and corrupted the save. is_service_backup_name() flags them
// so every slot-iterating helper skips them.
static bool is_service_backup_name(const char* name) {
    if (!name) return false;
    if (strncmp(name, "sdimg_", 6) != 0) return false;
    return strncmp(name + 6, "sce_bu_", 7) == 0;
}

static bool sdimg_name_ok(const char* name) {
    if (!safe_component(name)) return false;
    if (strncmp(name, "sdimg_", 6) != 0) return false;
    if (is_service_backup_name(name)) return false;  // never a real slot
    return safe_component(name + 6);
}

static bool uid_ok(const char* uid) {
    if (!safe_component(uid)) return false;
    size_t n = strlen(uid);
    return n > 0 && n < 16;
}

static bool title_ok(const char* title_id) {
    if (!safe_component(title_id)) return false;
    size_t n = strlen(title_id);
    return n >= 4 && n < 16;
}

static bool copy_file_atomic(const char* src, const char* dst) {
    char tmp[SDIMG_PATH_MAX];
    int n = snprintf(tmp, sizeof(tmp), "%s.tostonsync_tmp_%ld",
                     dst, (long)getpid());
    if (n <= 0 || (size_t)n >= sizeof(tmp)) return false;

    int in = open(src, O_RDONLY);
    if (in < 0) return false;
    int out = open(tmp, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (out < 0) { close(in); return false; }

    char* buf = (char*)malloc(65536);
    if (!buf) {
        close(in); close(out); unlink(tmp);
        return false;
    }
    bool ok = true;
    ssize_t r;
    while ((r = read(in, buf, 65536)) > 0) {
        ssize_t off = 0;
        while (off < r) {
            ssize_t w = write(out, buf + off, (size_t)(r - off));
            if (w <= 0) { ok = false; break; }
            off += w;
        }
        if (!ok) break;
    }
    if (r < 0) ok = false;
    if (fsync(out) != 0) ok = false;
    if (close(out) != 0) ok = false;
    close(in);
    free(buf);

    char src_sha[65], tmp_sha[65];
    if (ok && (!sha256_file_hex(src, src_sha) ||
               !sha256_file_hex(tmp, tmp_sha) ||
               strcmp(src_sha, tmp_sha) != 0)) {
        log_warn("sdimg: SHA-256 mismatch before atomic replace %s -> %s",
                 src, dst);
        ok = false;
    }
    if (ok && rename(tmp, dst) != 0) ok = false;
    if (!ok) unlink(tmp);
    return ok;
}

// Shared with the registered-expansion journal. Neither helper creates a
// container or changes its identity; callers retain the exclusive save gate.
bool sdimg_restore_copy_verified(const char* src, const char* dst) {
    return copy_file_atomic(src, dst);
}

// Source paths are the extracted, checksum-validated RAW ZIP entries.
bool sdimg_restore_images_share_key(const char* a, const char* b) {
    return pfs_save_images_share_sealed_key(a, b);
}

static bool rollback_single_slot_image(const char* target_img,
                                       const char* image_backup,
                                       bool target_existed,
                                       char* err,
                                       size_t err_sz) {
    bool ok;
    if (target_existed) {
        ok = copy_file_atomic(image_backup, target_img);
    } else {
        ok = (unlink(target_img) == 0 || errno == ENOENT);
    }
    sync();
    if (!ok) {
        // Keep image_backup on disk: it is now the only known-good recovery
        // copy and must not be discarded merely to tidy staging.
        return set_err(err, err_sz,
                       "Rollback failed; recovery image kept at %s",
                       image_backup);
    }
    return rollback_archive_existing(image_backup, err, err_sz);
}

static bool name_in_items(const char* name, const sdimg_item_t* items,
                          size_t count) {
    for (size_t i = 0; i < count; i++)
        if (strcmp(name, items[i].name) == 0)
            return true;
    return false;
}

static bool name_in_names(const char* name, char names[][SDIMG_NAME_MAX],
                          size_t count) {
    for (size_t i = 0; i < count; i++)
        if (strcmp(name, names[i]) == 0)
            return true;
    return false;
}

// Any well-formed sdimg_* name, INCLUDING sdimg_sce_bu_* service backups. Used
// where we operate on the full on-disk image set (snapshot/rollback/cleanup),
// as opposed to sdimg_name_ok() which means "real, DB-indexable slot only".
static bool sdimg_any_name_ok(const char* name) {
    if (!safe_component(name)) return false;
    if (strncmp(name, "sdimg_", 6) != 0) return false;
    return safe_component(name + 6);
}

static size_t collect_target_sdimg_names(const char* target_title_dir,
                                         char names[][SDIMG_NAME_MAX],
                                         size_t max_names,
                                         bool include_service_backups,
                                         bool* overflow) {
    if (overflow) *overflow = false;
    DIR* d = opendir(target_title_dir);
    if (!d) {
        if (overflow) *overflow = true;
        return 0;
    }
    size_t n = 0;
    struct dirent* e;
    while ((errno = 0, e = readdir(d)) != NULL) {
        bool ok = include_service_backups ? sdimg_any_name_ok(e->d_name)
                                          : sdimg_name_ok(e->d_name);
        if (!ok) continue;
        char p[SDIMG_PATH_MAX];
        snprintf(p, sizeof(p), "%s/%s", target_title_dir, e->d_name);
        struct stat st;
        if (lstat(p, &st) != 0 || !S_ISREG(st.st_mode)) {
            // Silently skipping an unreadable image would create a partial
            // rollback and later treat the missing slot as safe to replace.
            if (overflow) *overflow = true;
            break;
        }
        if (n >= max_names) {
            if (overflow) *overflow = true;
            continue;
        }
        snprintf(names[n++], SDIMG_NAME_MAX, "%s", e->d_name);
    }
    if (errno != 0 && overflow) *overflow = true;
    if (closedir(d) != 0 && overflow) *overflow = true;
    return n;
}

static bool snapshot_existing_sdimg_set(const char* target_title_dir,
                                        char names[][SDIMG_NAME_MAX],
                                        size_t* inout_count,
                                        const char* rollback_dir,
                                        char* err,
                                        size_t err_sz) {
    // Snapshot BOTH real slots and sdimg_sce_bu_* service backups so a rollback
    // restores the exact on-disk set. Service backups carry no DB row, but are
    // part of the title's coherent save-service state.
    bool overflow = false;
    *inout_count = collect_target_sdimg_names(target_title_dir, names,
                                             SDIMG_MAX_ITEMS, true,
                                             &overflow);
    if (overflow)
        return set_err(err, err_sz,
                       "Existing save image set is unreadable or exceeds %d images; refusing partial snapshot",
                       SDIMG_MAX_ITEMS);
    for (size_t i = 0; i < *inout_count; i++) {
        char src[SDIMG_PATH_MAX], dst[SDIMG_PATH_MAX];
        snprintf(src, sizeof(src), "%s/%s", target_title_dir, names[i]);
        snprintf(dst, sizeof(dst), "%s/%s", rollback_dir, names[i]);
        if (!copy_file_atomic(src, dst))
            return set_err(err, err_sz, "Could not snapshot existing %s",
                           names[i]);
    }
    return true;
}

static bool old_sdimg_name_present(const char* name,
                                   char old_names[][SDIMG_NAME_MAX],
                                   size_t old_count) {
    for (size_t i = 0; i < old_count; i++)
        if (strcmp(name, old_names[i]) == 0) return true;
    return false;
}

static bool rollback_sdimg_set(const char* target_title_dir,
                               char old_names[][SDIMG_NAME_MAX],
                               size_t old_count,
                               const char* rollback_dir) {
    // Restore every known-good image atomically before deleting anything.
    // If one copy fails, leave both the current set and rollback_dir intact so
    // the recovery files are never destroyed by cleanup after a failed undo.
    bool ok = true;
    for (size_t i = 0; i < old_count; i++) {
        char src[SDIMG_PATH_MAX], dst[SDIMG_PATH_MAX];
        snprintf(src, sizeof(src), "%s/%s", rollback_dir, old_names[i]);
        snprintf(dst, sizeof(dst), "%s/%s", target_title_dir, old_names[i]);
        if (!copy_file_atomic(src, dst)) {
            log_warn("sdimg: rollback restore failed for %s", dst);
            ok = false;
        }
    }

    if (ok) {
        DIR* d = opendir(target_title_dir);
        if (d) {
            struct dirent* e;
            while ((errno = 0, e = readdir(d)) != NULL) {
                if (!sdimg_any_name_ok(e->d_name) ||
                    old_sdimg_name_present(e->d_name, old_names, old_count))
                    continue;
                char p[SDIMG_PATH_MAX];
                snprintf(p, sizeof(p), "%s/%s", target_title_dir, e->d_name);
                if (unlink(p) != 0 && errno != ENOENT) {
                    log_warn("sdimg: rollback cleanup failed for %s", p);
                    ok = false;
                }
            }
            if (errno != 0) ok = false;
            if (closedir(d) != 0) ok = false;
        } else ok = false;
    }
    sync();
    return ok;
}

bool sdimg_restore_retained_rollback_available(const char* rollback_dir,
                                               size_t* image_count) {
    char names[SDIMG_MAX_ITEMS][SDIMG_NAME_MAX];
    bool overflow = false;
    size_t count = collect_target_sdimg_names(rollback_dir, names,
                                              SDIMG_MAX_ITEMS, true,
                                              &overflow);
    bool valid = !overflow && count > 0;
    if (valid && sdimg_expansion_exists(rollback_dir)) {
        char uid[16], title[16], ignored[192];
        valid = sdimg_expansion_identity(rollback_dir, uid, title,
                                        ignored, sizeof(ignored));
    }
    if (image_count) *image_count = valid ? count : 0;
    return valid;
}

static bool recovery_path_exists(const char* path) {
    struct stat st;
    return lstat(path, &st) == 0 || errno != ENOENT;
}

bool sdimg_restore_recovery_pending(const char* rollback_dir) {
    if (sdimg_expansion_pending(rollback_dir)) return true;
    const char* suffixes[] = {"/.pending", ".next", ".previous", ".swap", ".apply"};
    char path[SDIMG_PATH_MAX];
    for (size_t i = 0; i < sizeof(suffixes) / sizeof(suffixes[0]); i++) {
        int n = snprintf(path, sizeof(path), "%s%s", rollback_dir, suffixes[i]);
        if (n < 0 || (size_t)n >= sizeof(path) || recovery_path_exists(path))
            return true;
    }
    return false;
}

static bool mark_restore_pending(const char* dir, char* err, size_t err_sz) {
    char path[SDIMG_PATH_MAX];
    snprintf(path, sizeof(path), "%s/.pending", dir);
    int fd = open(path, O_WRONLY | O_CREAT | O_EXCL, 0600);
    if (fd < 0)
        return set_err(err, err_sz, "Could not persist restore recovery state");
    bool ok = write(fd, "pending\n", 8) == 8 && fsync(fd) == 0;
    if (close(fd) != 0) ok = false;
    sync();
    return ok || set_err(err, err_sz, "Could not persist restore recovery state");
}

static bool finish_restore_snapshot(const char* dir, char* err, size_t err_sz) {
    char previous[SDIMG_PATH_MAX], pending[SDIMG_PATH_MAX];
    snprintf(previous, sizeof(previous), "%s.previous", dir);
    snprintf(pending, sizeof(pending), "%s/.pending", dir);
    // A legacy .previous is evidence too; archive it before clearing the barrier.
    if (!rollback_archive_existing(previous, err, err_sz) || unlink(pending) != 0)
        return set_err(err, err_sz,
                       "Save verified, but recovery cleanup is incomplete; keep the game closed");
    sync();
    return true;
}

static bool prepare_restore_snapshot(const char* target_title_dir,
                                     char names[][SDIMG_NAME_MAX],
                                     size_t* count, const char* rollback_dir,
                                     char* err, size_t err_sz) {
    if (sdimg_restore_recovery_pending(rollback_dir))
        return set_err(err, err_sz,
                       "Previous restore requires recovery. Use Restore previous save before retrying");
    char next[SDIMG_PATH_MAX], previous[SDIMG_PATH_MAX];
    if (snprintf(next, sizeof(next), "%s.next", rollback_dir) >= (int)sizeof(next) ||
        snprintf(previous, sizeof(previous), "%s.previous", rollback_dir) >= (int)sizeof(previous))
        return set_err(err, err_sz, "Rollback path is too long");
    if (!rollback_snapshot_space(target_title_dir, next, err, err_sz)) return false;
    if (!rollback_archive_existing(rollback_dir, err, err_sz)) return false;
    if (!fs_mkdir_p(next))
        return set_err(err, err_sz, "Could not create rollback snapshot folder");
    if (!snapshot_existing_sdimg_set(target_title_dir, names, count, next, err, err_sz) ||
        *count == 0) {
        pfs_fs_rmrf(next);
        return set_err(err, err_sz, "Could not snapshot the current save; nothing was changed");
    }
    if (!mark_restore_pending(next, err, err_sz)) return false;
    // Older copies are already archived before this new snapshot is created.
    if (rename(next, rollback_dir) != 0)
        return set_err(err, err_sz, "Could not activate rollback snapshot; recovery files retained");
    sync();
    return true;
}

static bool expansion_target_paths(const char* uid, const char* title,
                                   const char* target, char* db, size_t db_sz,
                                   char* err, size_t err_sz) {
    char expected[SDIMG_PATH_MAX];
    if (!uid_ok(uid) || !title_ok(title) ||
        snprintf(expected, sizeof(expected),
                 "/user/home/%s/savedata_prospero/%s", uid, title) >=
            (int)sizeof(expected) || !target || strcmp(target, expected) != 0 ||
        snprintf(db, db_sz,
                 "/system_data/savedata_prospero/%s/db/user/savedata.db", uid) >=
            (int)db_sz)
        return set_err(err, err_sz,
                       "Registered expansion target identity does not match; evidence retained");
    return true;
}

// Foundation only: no current restore/HTTP route calls this or a native
// creator. A future validated creator must hold the existing exclusive gate
// and durable restore.busy marker, with a freshly resolved UID and closed game.
bool sdimg_restore_expansion_begin_held(
    const char* uid, const char* title, const char* target,
    const char* rollback, const char* approved_images,
    const char* approved_rows_db, const char added_names[][128], size_t added_count,
    char* err, size_t err_sz) {
    char db[SDIMG_PATH_MAX], names[SDIMG_MAX_ITEMS][SDIMG_NAME_MAX];
    size_t count = 0;
    if (!expansion_target_paths(uid, title, target, db, sizeof(db), err, err_sz) ||
        !prepare_restore_snapshot(target, names, &count, rollback, err, err_sz))
        return false;
    // Leave .pending and both snapshots on arm failure. It is not permission
    // to publish anything; callers must stop without native or DB writes.
    return sdimg_expansion_arm(uid, title, target, db, rollback, approved_images,
                               approved_rows_db, added_names, added_count,
                               err, err_sz);
}

bool sdimg_restore_expansion_commit_held(const char* uid, const char* title,
    const char* target, const char* rollback, char* err, size_t err_sz) {
    char db[SDIMG_PATH_MAX], recorded_uid[16], recorded_title[16];
    if (!expansion_target_paths(uid, title, target, db, sizeof(db), err, err_sz) ||
        !sdimg_expansion_identity(rollback, recorded_uid, recorded_title, err, err_sz))
        return false;
    if (strcmp(uid, recorded_uid) || strcmp(title, recorded_title))
        return set_err(err, err_sz, "Registered expansion identity changed; recovery required");
    // This is a publication/SQL checkpoint, NOT proof of native acceptance.
    // Until the separate native creator is validated, COMMITTED remains a
    // recovery barrier and must not be advertised as a completed restore.
    return sdimg_expansion_commit(target, db, rollback, err, err_sz);
}

bool sdimg_restore_apply_retained_rollback(const char* target_title_dir,
                                           const char* rollback_dir,
                                           char* err, size_t err_sz) {
    if (sdimg_expansion_exists(rollback_dir)) {
        char uid[16], title[16], db[SDIMG_PATH_MAX], pending[SDIMG_PATH_MAX];
        // An explicit recovery attempt must retain the shared barrier even
        // when validation finds an uncertain COMMITTED plan or changed image.
        int n = snprintf(pending, sizeof(pending), "%s/.pending", rollback_dir);
        if (n < 0 || (size_t)n >= sizeof(pending) ||
            (!recovery_path_exists(pending) &&
             !mark_restore_pending(rollback_dir, err, err_sz))) return false;
        if (!sdimg_expansion_identity(rollback_dir, uid, title, err, err_sz) ||
            !expansion_target_paths(uid, title, target_title_dir, db, sizeof(db),
                                     err, err_sz) ||
            !sdimg_expansion_recover(target_title_dir, db, rollback_dir, err, err_sz))
            return false;
        // The journal/evidence remain. Unlike exact-set undo, expansion
        // recovery does not rotate a half-written six-image set into redo.
        return finish_restore_snapshot(rollback_dir, err, err_sz);
    }
    char current[SDIMG_MAX_ITEMS][SDIMG_NAME_MAX];
    char previous[SDIMG_MAX_ITEMS][SDIMG_NAME_MAX];
    bool current_overflow = false, previous_overflow = false;
    size_t current_count = collect_target_sdimg_names(
        target_title_dir, current, SDIMG_MAX_ITEMS, true, &current_overflow);
    size_t previous_count = collect_target_sdimg_names(
        rollback_dir, previous, SDIMG_MAX_ITEMS, true, &previous_overflow);
    if (current_overflow || previous_overflow || current_count == 0 ||
        previous_count == 0)
        return set_err(err, err_sz, "Rollback image set is missing or too large");
    if (current_count != previous_count)
        return set_err(err, err_sz,
                       "Rollback slot set differs from the current save");
    for (size_t i = 0; i < previous_count; i++) {
        if (!name_in_names(previous[i], current, current_count))
            return set_err(err, err_sz,
                           "Rollback slot set differs from the current save");
        char src[SDIMG_PATH_MAX], dst[SDIMG_PATH_MAX];
        snprintf(src, sizeof(src), "%s/%s", rollback_dir, previous[i]);
        snprintf(dst, sizeof(dst), "%s/%s", target_title_dir, previous[i]);
        if (!pfs_save_images_share_sealed_key(src, dst))
            return set_err(err, err_sz,
                           "Rollback key does not match the current slot; recovery files preserved");
    }

    char swap_dir[SDIMG_PATH_MAX], apply_dir[SDIMG_PATH_MAX], next_dir[SDIMG_PATH_MAX];
    snprintf(swap_dir, sizeof(swap_dir), "%s.swap", rollback_dir);
    snprintf(apply_dir, sizeof(apply_dir), "%s.apply", rollback_dir);
    snprintf(next_dir, sizeof(next_dir), "%s.next", rollback_dir);
    if (recovery_path_exists(swap_dir) || recovery_path_exists(apply_dir) ||
        recovery_path_exists(next_dir))
        return set_err(err, err_sz,
                       "Interrupted rollback needs review; recovery image sets were preserved");
    char pending[SDIMG_PATH_MAX];
    snprintf(pending, sizeof(pending), "%s/.pending", rollback_dir);
    if (recovery_path_exists(pending)) {
        // The live set may be only half-written. Never rotate that set into
        // the trusted rollback or offer it later as a healthy undo snapshot.
        if (!rollback_sdimg_set(target_title_dir, previous, previous_count,
                                rollback_dir))
            return set_err(err, err_sz, "Recovery incomplete; original images remain retained");
        return finish_restore_snapshot(rollback_dir, err, err_sz);
    }
    if (!rollback_snapshot_space(target_title_dir, swap_dir, err, err_sz)) return false;
    if (!fs_mkdir_p(swap_dir))
        return set_err(err, err_sz, "Could not create rollback swap folder");
    size_t snap_count = 0;
    if (!snapshot_existing_sdimg_set(target_title_dir, current, &snap_count,
                                     swap_dir, err, err_sz)) {
        pfs_fs_rmrf(swap_dir);
        return false;
    }
    if (!mark_restore_pending(swap_dir, err, err_sz)) return false;

    // Rotate directories before touching the live save. The canonical
    // rollback path always contains the current set, while .apply remains the
    // known-good previous set until the replacement has fully succeeded.
    if (rename(rollback_dir, apply_dir) != 0) {
        pfs_fs_rmrf(swap_dir);
        return set_err(err, err_sz, "Could not prepare retained rollback");
    }
    if (rename(swap_dir, rollback_dir) != 0) {
        (void)rename(apply_dir, rollback_dir);
        pfs_fs_rmrf(swap_dir);
        return set_err(err, err_sz, "Could not rotate retained rollback");
    }
    sync();
    if (rollback_sdimg_set(target_title_dir, previous, previous_count,
                           apply_dir)) {
        if (!rollback_archive_existing(apply_dir, err, err_sz) ||
            !finish_restore_snapshot(rollback_dir, err, err_sz)) return false;
        log_info("sdimg: retained rollback applied; current save retained for undo");
        return true;
    }

    // Best effort restores the set that was active when the user pressed the
    // button. If that succeeds, put the original rollback back in its stable
    // location so the request is safely retryable.
    if (rollback_sdimg_set(target_title_dir, current, current_count,
                           rollback_dir)) {
        char completed[SDIMG_PATH_MAX];
        snprintf(completed, sizeof(completed), "%s/.pending", rollback_dir);
        if (unlink(completed) != 0 || !rollback_archive_existing(rollback_dir, err, err_sz)) return false;
        if (rename(apply_dir, rollback_dir) == 0)
            return set_err(err, err_sz,
                           "Previous save could not be restored; current save was preserved");
    }
    return set_err(err, err_sz,
                   "Rollback failed; recovery image sets were preserved");
}

static bool rollback_sdimg_set_after_failure(
    const char* target_title_dir,
    char old_names[][SDIMG_NAME_MAX],
    size_t old_count,
    const char* rollback_dir,
    char* err,
    size_t err_sz) {
    char original[192] = {0};
    if (err && err_sz && err[0])
        snprintf(original, sizeof(original), "%s", err);

    if (rollback_sdimg_set(target_title_dir, old_names, old_count,
                           rollback_dir)) {
        log_info("sdimg: transfer failed; original target image set restored");
        return finish_restore_snapshot(rollback_dir, err, err_sz);
    }

    set_err(err, err_sz,
            "Restore failed and rollback was incomplete; recovery kept at %s%s%s",
            rollback_dir, original[0] ? " (original error: " : "",
            original[0] ? original : "");
    if (original[0] && err && err_sz) {
        size_t n = strlen(err);
        if (n + 1 < err_sz) snprintf(err + n, err_sz - n, ")");
    }
    return false;
}

static void rollback_plain_transfer_after_failure(
    const char* target_title_dir,
    char old_names[][SDIMG_NAME_MAX],
    size_t old_count,
    const char* rollback_dir,
    char* err,
    size_t err_sz) {
    char original[192] = {0};
    if (err && err_sz && err[0])
        snprintf(original, sizeof(original), "%s", err);
    if (rollback_sdimg_set_after_failure(target_title_dir, old_names, old_count,
                                         rollback_dir, err, err_sz))
        set_err(err, err_sz,
                "Transfer failed — original save restored%s%s",
                original[0] ? ": " : "", original);
}

static bool remove_sdimg_not_in_backup(const char* target_title_dir,
                                       const sdimg_item_t* items,
                                       size_t count,
                                       char* err,
                                       size_t err_sz) {
    DIR* d = opendir(target_title_dir);
    if (!d) return true;
    bool ok = true;
    struct dirent* e;
    while ((e = readdir(d)) != NULL) {
        if (!sdimg_name_ok(e->d_name)) continue;
        if (name_in_items(e->d_name, items, count)) continue;
        char p[SDIMG_PATH_MAX];
        snprintf(p, sizeof(p), "%s/%s", target_title_dir, e->d_name);
        if (unlink(p) != 0 && errno != ENOENT) {
            set_err(err, err_sz, "Could not remove old slot %s", e->d_name);
            ok = false;
            break;
        }
        log_info("sdimg: removed target slot not present in backup: %s",
                 e->d_name);
    }
    closedir(d);
    return ok;
}

// The slot's real dir_name is SAVEDATA_DIRECTORY inside its param.sfo, NOT the
// filename (a "sdimg_sce_bu_*" filename would otherwise yield a bogus slot).
// We can only read it when a *decrypted* param.sfo is present in the payload;
// raw sealed images don't expose one until mounted (that hookup is the kernel
// step). When found, prefer it; otherwise fall back to the filename suffix.
// Returns true if an override was applied.
static bool resolve_true_dir_name(const char* payload_dir, const char* name,
                                  char* out, size_t out_sz) {
    const char* suffix = name + 6;  // skip "sdimg_"
    const char* candidates[3];
    char c0[SDIMG_PATH_MAX], c1[SDIMG_PATH_MAX], c2[SDIMG_PATH_MAX];
    snprintf(c0, sizeof(c0), "%s/%s/sce_sys/param.sfo", payload_dir, suffix);
    snprintf(c1, sizeof(c1), "%s/%s.param.sfo", payload_dir, name);
    snprintf(c2, sizeof(c2), "%s/sce_sys/param.sfo", payload_dir);
    candidates[0] = c0; candidates[1] = c1; candidates[2] = c2;

    for (int i = 0; i < 3; i++) {
        struct stat st;
        if (stat(candidates[i], &st) != 0 || !S_ISREG(st.st_mode)) continue;
        sfo_info_t info;
        if (sfo_parse(candidates[i], &info) != 0) continue;
        if (!info.dir_name[0]) continue;
        if (!safe_component(info.dir_name)) continue;
        snprintf(out, out_sz, "%s", info.dir_name);
        log_info("sdimg: dir_name for %s resolved from param.sfo: %s",
                 name, info.dir_name);
        return true;
    }
    return false;
}

static size_t collect_sdimg_items(const char* payload_dir,
                                  const char* target_title_dir,
                                  sdimg_item_t* items,
                                  size_t max_items,
                                  bool* overflow,
                                  bool* unmount_uncertain) {
    if (overflow) *overflow = false;
    if (unmount_uncertain) *unmount_uncertain = false;
    DIR* d = opendir(payload_dir);
    if (!d) return 0;
    size_t n = 0;
    struct dirent* e;
    while ((e = readdir(d)) != NULL) {
        if (is_service_backup_name(e->d_name)) {
            log_info("sdimg: service backup image %s found; it will be "
                     "handled by the promotion path", e->d_name);
            continue;
        }
        if (!sdimg_name_ok(e->d_name)) continue;
        char src[SDIMG_PATH_MAX];
        snprintf(src, sizeof(src), "%s/%s", payload_dir, e->d_name);
        struct stat st;
        if (stat(src, &st) != 0 || !S_ISREG(st.st_mode)) continue;
        if (n >= max_items) {
            if (overflow) *overflow = true;
            continue;
        }

        memset(&items[n], 0, sizeof(items[n]));
        snprintf(items[n].name, sizeof(items[n].name), "%s", e->d_name);
        // Truth comes from param.sfo when available; filename is the fallback.
        if (!resolve_true_dir_name(payload_dir, e->d_name,
                                   items[n].dir_name, sizeof(items[n].dir_name)))
            snprintf(items[n].dir_name, sizeof(items[n].dir_name), "%s",
                     e->d_name + 6);
        snprintf(items[n].src, sizeof(items[n].src), "%s", src);
        snprintf(items[n].dst, sizeof(items[n].dst), "%s/%s",
                 target_title_dir, e->d_name);
        items[n].bytes = (uint64_t)st.st_size;

        // Read/dump kernel mount of the sealed backup copy to recover its
        // authentic param.sfo: the real SAVEDATA_DIRECTORY, block counts and
        // account id. Ordinary unavailability keeps the existing filename
        // fallback, but uncertain unmount must stop before service promotion
        // or any target mutation. Native mounts are not MOUNT_RO.
        int sr = pfs_read_image_param_sfo(items[n].src, &items[n].sfo);
        if (sr == PFS_SFO_READ_UNMOUNT_UNCERTAIN) {
            if (unmount_uncertain) *unmount_uncertain = true;
            closedir(d);
            return 0;
        }
        if (sr == 0 && items[n].sfo.dir_name[0] &&
            safe_component(items[n].sfo.dir_name)) {
            items[n].have_sfo = true;
            if (strcmp(items[n].sfo.dir_name, e->d_name + 6) != 0)
                log_warn("sdimg: %s SAVEDATA_DIRECTORY=%s differs from filename "
                         "— keeping filename for file/DB consistency",
                         e->d_name, items[n].sfo.dir_name);
        } else if (sr == -2) {
            items[n].sfo_zeroed = true;
            log_warn("sdimg: %s has a zeroed param.sfo — restoring raw image "
                     "but DB metadata will be best-effort", e->d_name);
        }
        n++;
    }
    closedir(d);
    return n;
}

// Service-backup (sdimg_sce_bu_*) images: copied to the target so the on-disk
// set exactly matches the backup, but never indexed in savedata.db. Leaving a
// STALE sce_bu_ behind (from a previous restore) while replacing the real
// slots can desync the save service and make it revert to the old state.
static size_t collect_service_backup_names(const char* payload_dir,
                                           char names[][SDIMG_NAME_MAX],
                                           size_t max_names,
                                           bool* overflow) {
    if (overflow) *overflow = false;
    DIR* d = opendir(payload_dir);
    if (!d) return 0;
    size_t n = 0;
    struct dirent* e;
    while ((e = readdir(d)) != NULL) {
        if (!is_service_backup_name(e->d_name)) continue;
        if (!sdimg_any_name_ok(e->d_name)) continue;
        char p[SDIMG_PATH_MAX];
        snprintf(p, sizeof(p), "%s/%s", payload_dir, e->d_name);
        struct stat st;
        if (stat(p, &st) != 0 || !S_ISREG(st.st_mode)) continue;
        if (n >= max_names) {
            if (overflow) *overflow = true;
            continue;
        }
        snprintf(names[n++], SDIMG_NAME_MAX, "%s", e->d_name);
    }
    closedir(d);
    return n;
}

static bool copy_service_backup_images(const char* payload_dir,
                                       const char* target_title_dir,
                                       char service_names[][SDIMG_NAME_MAX],
                                       size_t service_count,
                                       char* err, size_t err_sz) {
    for (size_t i = 0; i < service_count; i++) {
        char src[SDIMG_PATH_MAX], dst[SDIMG_PATH_MAX];
        snprintf(src, sizeof(src), "%s/%s", payload_dir, service_names[i]);
        snprintf(dst, sizeof(dst), "%s/%s", target_title_dir, service_names[i]);
        if (!copy_file_atomic(src, dst))
            return set_err(err, err_sz,
                           "Could not copy service backup image %s",
                           service_names[i]);
        log_info("sdimg: copied auxiliary service backup image %s",
                 service_names[i]);
    }
    return true;
}

static bool remove_service_backups_not_in_payload(const char* target_title_dir,
                                                  char service_names[][SDIMG_NAME_MAX],
                                                  size_t service_count,
                                                  char* err, size_t err_sz) {
    DIR* d = opendir(target_title_dir);
    if (!d) return true;
    bool ok = true;
    struct dirent* e;
    while ((e = readdir(d)) != NULL) {
        if (!is_service_backup_name(e->d_name)) continue;
        if (!sdimg_any_name_ok(e->d_name)) continue;
        if (name_in_names(e->d_name, service_names, service_count)) continue;
        char p[SDIMG_PATH_MAX];
        snprintf(p, sizeof(p), "%s/%s", target_title_dir, e->d_name);
        if (unlink(p) != 0 && errno != ENOENT) {
            set_err(err, err_sz,
                    "Could not remove stale service backup image %s",
                    e->d_name);
            ok = false;
            break;
        }
        log_info("sdimg: removed stale auxiliary service backup image %s",
                 e->d_name);
    }
    closedir(d);
    return ok;
}

static bool db_exec(sqlite3* db, const char* sql, char* err, size_t err_sz) {
    char* emsg = NULL;
    int rc = sqlite3_exec(db, sql, NULL, NULL, &emsg);
    if (rc != SQLITE_OK) {
        set_err(err, err_sz, "savedata.db error: %s",
                emsg ? emsg : sqlite3_errmsg(db));
        if (emsg) sqlite3_free(emsg);
        return false;
    }
    if (emsg) sqlite3_free(emsg);
    return true;
}

static bool ensure_savedata_table(sqlite3* db, char* err, size_t err_sz) {
    return db_exec(db,
        "CREATE TABLE IF NOT EXISTS savedata ("
        "id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,"
        "title_id NOT NULL, dir_name NOT NULL, main_title NOT NULL,"
        "sub_title, detail, tmp_dir_name, is_broken, user_param,"
        "blocks, free_blocks, size_kib, mtime NOT NULL,"
        "fake_broken, account_id, user_id, faked_owner,"
        "cloud_icon_url, cloud_revision, game_title_id NOT NULL, system_blocks)",
        err, err_sz);
}

static void seed_defaults(sdimg_db_seed_t* seed,
                          const char* uid,
                          const char* title_id) {
    memset(seed, 0, sizeof(*seed));
    char game[64] = {0};
    if (titlename_lookup(title_id, game, sizeof(game)) && game[0])
        snprintf(seed->main_title, sizeof(seed->main_title), "%s", game);
    else
        snprintf(seed->main_title, sizeof(seed->main_title), "%s", title_id);
    snprintf(seed->game_title_id, sizeof(seed->game_title_id), "%s", title_id);
    seed->user_id = (sqlite3_int64)strtoull(uid ? uid : "0", NULL, 16);
}

static void copy_text_col(sqlite3_stmt* st, int col, char* out, size_t out_sz) {
    if (!out || out_sz == 0) return;
    const unsigned char* txt = sqlite3_column_text(st, col);
    snprintf(out, out_sz, "%s", txt ? (const char*)txt : "");
}

static bool load_seed_with_stmt(sqlite3* db, sqlite3_stmt* st,
                                sdimg_db_seed_t* seed) {
    int rc = sqlite3_step(st);
    if (rc != SQLITE_ROW) return false;
    copy_text_col(st, 0, seed->main_title, sizeof(seed->main_title));
    copy_text_col(st, 1, seed->sub_title, sizeof(seed->sub_title));
    copy_text_col(st, 2, seed->detail, sizeof(seed->detail));
    seed->account_id    = sqlite3_column_int64(st, 3);
    seed->user_id       = sqlite3_column_int64(st, 4);
    copy_text_col(st, 5, seed->game_title_id, sizeof(seed->game_title_id));
    seed->user_param    = sqlite3_column_int(st, 6);
    seed->system_blocks = sqlite3_column_int(st, 7);
    if (!seed->main_title[0]) snprintf(seed->main_title,
                                       sizeof(seed->main_title), "Unknown");
    (void)db;
    return true;
}

static bool load_seed_exact(sqlite3* db, const char* title_id,
                            const char* dir_name, sdimg_db_seed_t* seed) {
    static const char* SQL =
        "SELECT main_title, COALESCE(sub_title,''), COALESCE(detail,''),"
        "COALESCE(account_id,0), COALESCE(user_id,0),"
        "COALESCE(game_title_id,title_id), COALESCE(user_param,0),"
        "COALESCE(system_blocks,0) "
        "FROM savedata WHERE title_id=? AND dir_name=? LIMIT 1";
    sqlite3_stmt* st = NULL;
    if (sqlite3_prepare_v2(db, SQL, -1, &st, NULL) != SQLITE_OK)
        return false;
    sqlite3_bind_text(st, 1, title_id, -1, SQLITE_STATIC);
    sqlite3_bind_text(st, 2, dir_name, -1, SQLITE_STATIC);
    bool ok = load_seed_with_stmt(db, st, seed);
    sqlite3_finalize(st);
    return ok;
}

static bool load_seed_for_title(sqlite3* db, const char* title_id,
                                sdimg_db_seed_t* seed) {
    static const char* SQL =
        "SELECT main_title, COALESCE(sub_title,''), COALESCE(detail,''),"
        "COALESCE(account_id,0), COALESCE(user_id,0),"
        "COALESCE(game_title_id,title_id), COALESCE(user_param,0),"
        "COALESCE(system_blocks,0) "
        "FROM savedata WHERE title_id=? LIMIT 1";
    sqlite3_stmt* st = NULL;
    if (sqlite3_prepare_v2(db, SQL, -1, &st, NULL) != SQLITE_OK)
        return false;
    sqlite3_bind_text(st, 1, title_id, -1, SQLITE_STATIC);
    bool ok = load_seed_with_stmt(db, st, seed);
    sqlite3_finalize(st);
    return ok;
}

static bool load_seed_any(sqlite3* db, sdimg_db_seed_t* seed) {
    static const char* SQL =
        "SELECT main_title, COALESCE(sub_title,''), COALESCE(detail,''),"
        "COALESCE(account_id,0), COALESCE(user_id,0),"
        "COALESCE(game_title_id,title_id), COALESCE(user_param,0),"
        "COALESCE(system_blocks,0) FROM savedata LIMIT 1";
    sqlite3_stmt* st = NULL;
    if (sqlite3_prepare_v2(db, SQL, -1, &st, NULL) != SQLITE_OK)
        return false;
    bool ok = load_seed_with_stmt(db, st, seed);
    sqlite3_finalize(st);
    return ok;
}

static bool load_owner_from_other_title(sqlite3* db, const char* title_id,
                                        sdimg_db_seed_t* seed) {
    static const char* SQL =
        "SELECT main_title, COALESCE(sub_title,''), COALESCE(detail,''),"
        "COALESCE(account_id,0), COALESCE(user_id,0),"
        "COALESCE(game_title_id,title_id), COALESCE(user_param,0),"
        "COALESCE(system_blocks,0) "
        "FROM savedata WHERE title_id<>? "
        "AND (COALESCE(account_id,0)<>0 OR COALESCE(user_id,0)<>0) "
        "LIMIT 1";
    sqlite3_stmt* st = NULL;
    if (sqlite3_prepare_v2(db, SQL, -1, &st, NULL) != SQLITE_OK)
        return false;
    sqlite3_bind_text(st, 1, title_id, -1, SQLITE_STATIC);
    bool ok = load_seed_with_stmt(db, st, seed);
    sqlite3_finalize(st);
    return ok;
}

static bool load_owner_any_nonzero(sqlite3* db, sdimg_db_seed_t* seed) {
    static const char* SQL =
        "SELECT main_title, COALESCE(sub_title,''), COALESCE(detail,''),"
        "COALESCE(account_id,0), COALESCE(user_id,0),"
        "COALESCE(game_title_id,title_id), COALESCE(user_param,0),"
        "COALESCE(system_blocks,0) "
        "FROM savedata "
        "WHERE COALESCE(account_id,0)<>0 OR COALESCE(user_id,0)<>0 "
        "LIMIT 1";
    sqlite3_stmt* st = NULL;
    if (sqlite3_prepare_v2(db, SQL, -1, &st, NULL) != SQLITE_OK)
        return false;
    bool ok = load_seed_with_stmt(db, st, seed);
    sqlite3_finalize(st);
    return ok;
}

static bool local_owner_for_slot(const char* uid,
                                 const char* title_id,
                                 const char* dir_name,
                                 uint64_t* out_account_id,
                                 uint32_t* out_user_id) {
    sdimg_db_seed_t seed;
    seed_defaults(&seed, uid, title_id);
    bool loaded = false;

    char db_path[SDIMG_PATH_MAX];
    snprintf(db_path, sizeof(db_path),
             "/system_data/savedata_prospero/%s/db/user/savedata.db", uid);
    sqlite3* db = NULL;
    if (sqlite3_open_v2(db_path, &db, SQLITE_OPEN_READONLY |
                        SQLITE_OPEN_NOMUTEX, NULL) == SQLITE_OK) {
        sdimg_db_seed_t owner;
        seed_defaults(&owner, uid, title_id);
        if (load_owner_from_other_title(db, title_id, &owner) ||
            load_owner_any_nonzero(db, &owner)) {
            seed.account_id = owner.account_id;
            seed.user_id    = owner.user_id;
            loaded = true;
        } else if (load_seed_exact(db, title_id, dir_name, &seed) ||
                   load_seed_for_title(db, title_id, &seed) ||
                   load_seed_any(db, &seed)) {
            loaded = true;
        }
    }
    if (db) sqlite3_close(db);

    // Never inherit identity from the imported SFO. Migration must bind the
    // new image to an identity proven to belong to this PS5 user.
    if (!loaded) return false;
    if (!seed.user_id)
        seed.user_id = (sqlite3_int64)strtoull(uid ? uid : "0", NULL, 16);

    if (out_account_id) *out_account_id = (uint64_t)seed.account_id;
    if (out_user_id)    *out_user_id    = (uint32_t)seed.user_id;
    log_info("sdimg: local owner for %s/%s -> aid=%llx uid=0x%x",
             title_id ? title_id : "(unknown)",
             dir_name ? dir_name : "(unknown)",
             (unsigned long long)(uint64_t)seed.account_id,
             (unsigned int)(uint32_t)seed.user_id);
    return true;
}

static sfo_info_t sfo_with_local_identity(const sfo_info_t* src,
                                          uint64_t account_id,
                                          uint32_t user_id) {
    sfo_info_t out;
    memset(&out, 0, sizeof(out));
    if (src) out = *src;
    // Local identity is authoritative, including a legitimate zero account
    // id for an offline PS5 profile. Never retain identity from the import.
    out.account_id = account_id;
    out.user_id = user_id;
    return out;
}

typedef struct {
    size_t source_files;
    size_t target_files;
    size_t verified_files;
    size_t missing_files;
    size_t mismatched_files;
} portable_verify_stats_t;

static bool portable_ignored_name(const char* name) {
    return !name || !name[0] || strcmp(name, ".") == 0 ||
           strcmp(name, "..") == 0 || strcmp(name, ".DS_Store") == 0 ||
           strcmp(name, "__MACOSX") == 0 || strncmp(name, "._", 2) == 0;
}

static bool portable_mutable_param(const char* rel) {
    return rel && strcmp(rel, "sce_sys/param.sfo") == 0;
}

static bool files_sha256_equal(const char* a, const char* b) {
    char ah[65], bh[65];
    return sha256_file_hex(a, ah) && sha256_file_hex(b, bh) &&
           strcmp(ah, bh) == 0;
}

// Compare the source portable tree with a read-back dump of the permanent
// target image. param.sfo is checked structurally below because its local
// account/user fields are intentionally patched; every other regular file,
// including sce_sys/keystone and the actual game payload, must match SHA-256.
static bool compare_portable_source_tree(const char* source_root,
                                         const char* target_root,
                                         const char* rel_root,
                                         portable_verify_stats_t* stats) {
    char source_dir[SDIMG_PATH_MAX], target_dir[SDIMG_PATH_MAX];
    if (rel_root && rel_root[0]) {
        if (snprintf(source_dir, sizeof(source_dir), "%s/%s", source_root,
                     rel_root) >= (int)sizeof(source_dir) ||
            snprintf(target_dir, sizeof(target_dir), "%s/%s", target_root,
                     rel_root) >= (int)sizeof(target_dir))
            return false;
    } else {
        snprintf(source_dir, sizeof(source_dir), "%s", source_root);
        snprintf(target_dir, sizeof(target_dir), "%s", target_root);
    }

    DIR* d = opendir(source_dir);
    if (!d) return false;
    bool ok = true;
    struct dirent* e;
    while ((errno = 0, e = readdir(d)) != NULL) {
        if (portable_ignored_name(e->d_name)) continue;
        char rel[SDIMG_PATH_MAX], source[SDIMG_PATH_MAX], target[SDIMG_PATH_MAX];
        int rn = (rel_root && rel_root[0])
            ? snprintf(rel, sizeof(rel), "%s/%s", rel_root, e->d_name)
            : snprintf(rel, sizeof(rel), "%s", e->d_name);
        if (rn < 0 || rn >= (int)sizeof(rel) ||
            snprintf(source, sizeof(source), "%s/%s", source_dir,
                     e->d_name) >= (int)sizeof(source) ||
            snprintf(target, sizeof(target), "%s/%s", target_dir,
                     e->d_name) >= (int)sizeof(target)) {
            ok = false;
            break;
        }
        struct stat ss;
        if (lstat(source, &ss) != 0) { ok = false; break; }
        if (S_ISDIR(ss.st_mode)) {
            if (!compare_portable_source_tree(source_root, target_root, rel,
                                              stats)) {
                ok = false;
                break;
            }
            continue;
        }
        if (!S_ISREG(ss.st_mode) || portable_mutable_param(rel)) continue;

        stats->source_files++;
        struct stat ts;
        if (stat(target, &ts) != 0 || !S_ISREG(ts.st_mode)) {
            stats->missing_files++;
            continue;
        }
        if (ss.st_size != ts.st_size || !files_sha256_equal(source, target)) {
            stats->mismatched_files++;
            continue;
        }
        stats->verified_files++;
    }
    if (errno != 0) ok = false;
    if (closedir(d) != 0) ok = false;
    return ok;
}

static bool count_portable_target_files(const char* root, const char* rel_root,
                                        size_t* count) {
    char dir[SDIMG_PATH_MAX];
    if (rel_root && rel_root[0]) {
        if (snprintf(dir, sizeof(dir), "%s/%s", root, rel_root) >=
            (int)sizeof(dir)) return false;
    } else {
        snprintf(dir, sizeof(dir), "%s", root);
    }
    DIR* d = opendir(dir);
    if (!d) return false;
    bool ok = true;
    struct dirent* e;
    while ((errno = 0, e = readdir(d)) != NULL) {
        if (portable_ignored_name(e->d_name)) continue;
        char rel[SDIMG_PATH_MAX], path[SDIMG_PATH_MAX];
        int rn = (rel_root && rel_root[0])
            ? snprintf(rel, sizeof(rel), "%s/%s", rel_root, e->d_name)
            : snprintf(rel, sizeof(rel), "%s", e->d_name);
        if (rn < 0 || rn >= (int)sizeof(rel) ||
            snprintf(path, sizeof(path), "%s/%s", dir, e->d_name) >=
            (int)sizeof(path)) { ok = false; break; }
        struct stat st;
        if (lstat(path, &st) != 0) { ok = false; break; }
        if (S_ISDIR(st.st_mode)) {
            if (!count_portable_target_files(root, rel, count)) {
                ok = false;
                break;
            }
        } else if (S_ISREG(st.st_mode) && !portable_mutable_param(rel)) {
            (*count)++;
        }
    }
    if (errno != 0) ok = false;
    if (closedir(d) != 0) ok = false;
    return ok;
}

static bool verify_portable_payload(const char* source_dir,
                                    const char* target_dump,
                                    const char* slot) {
    portable_verify_stats_t stats;
    memset(&stats, 0, sizeof(stats));
    bool walked = compare_portable_source_tree(source_dir, target_dump, "",
                                               &stats) &&
                  count_portable_target_files(target_dump, "",
                                              &stats.target_files);
    bool ok = walked && stats.source_files > 0 &&
              stats.source_files == stats.target_files &&
              stats.verified_files == stats.source_files &&
              stats.missing_files == 0 && stats.mismatched_files == 0;
    log_info("restore[slot=%s]: source_files=%zu target_files=%zu "
             "checksums_verified=%zu missing=%zu mismatched=%zu result=%s",
             slot ? slot : "(unknown)", stats.source_files, stats.target_files,
             stats.verified_files, stats.missing_files,
             stats.mismatched_files, ok ? "ok" : "failed");
    return ok;
}

// Returns true only if the freshly written image reads back as a valid,
// correctly-owned save for the expected slot. A failure here means the restore
// produced a broken/wrong image — the caller MUST abort and roll back instead
// of reporting success (the old warn-only behavior is what let a "successful"
// restore leave a corrupted save).
static bool verify_restored_image(const char* target_img,
                                  const char* target_dump,
                                  const char* source_dir,
                                  const char* expected_title,
                                  const char* expected_dir,
                                  uint64_t expected_account_id,
                                  uint32_t expected_user_id,
                                  const uint8_t expected_hmac[SFO_HMAC_LEN]) {
    sfo_info_t check, source;
    char sfo_path[SDIMG_PATH_MAX], source_sfo[SDIMG_PATH_MAX];
    snprintf(sfo_path, sizeof(sfo_path), "%s/sce_sys/param.sfo", target_dump);
    snprintf(source_sfo, sizeof(source_sfo), "%s/sce_sys/param.sfo",
             source_dir);
    if (sfo_parse(source_sfo, &source) != 0) {
        log_warn("sdimg: source metadata verify FAILED for %s", source_sfo);
        return false;
    }
    int r = sfo_parse(sfo_path, &check);
    if (r != 0) {
        log_warn("sdimg: post-restore verify FAILED for %s (param.sfo read=%d)",
                 target_img, r);
        return false;
    }
    log_info("sdimg: post-restore verify %s dir=%s aid=%llx uid=0x%x "
             "blocks=%llu hmac=%s",
             target_img, check.dir_name,
             (unsigned long long)check.account_id, check.user_id,
             (unsigned long long)check.blocks,
             check.has_hmac ? "yes" : "no");
    bool ok = true;
    if (expected_title && strcmp(check.title_id, expected_title) != 0) {
        log_warn("sdimg: verify mismatch — expected title %s, image says %s",
                 expected_title, check.title_id);
        ok = false;
    }
    if (expected_dir && strcmp(check.dir_name, expected_dir) != 0) {
        log_warn("sdimg: verify mismatch — expected dir %s, image says %s",
                 expected_dir, check.dir_name);
        ok = false;
    }
    if (check.account_id != expected_account_id) {
        log_warn("sdimg: verify mismatch — expected aid=%llx, image says %llx",
                 (unsigned long long)expected_account_id,
                 (unsigned long long)check.account_id);
        ok = false;
    }
    if (check.user_id != expected_user_id) {
        log_warn("sdimg: verify mismatch — expected uid=0x%x, image says 0x%x",
                 expected_user_id, check.user_id);
        ok = false;
    }
    if (check.user_param != source.user_param || check.blocks != source.blocks ||
        check.system_blocks != source.system_blocks ||
        strcmp(check.format, source.format) != 0 ||
        strcmp(check.main_title, source.main_title) != 0 ||
        strcmp(check.sub_title, source.sub_title) != 0 ||
        strcmp(check.detail, source.detail) != 0 ||
        strcmp(check.game_title_id, source.game_title_id) != 0) {
        log_warn("sdimg: verify mismatch — non-identity param.sfo metadata changed");
        ok = false;
    }
    if (!expected_hmac || !check.has_hmac ||
        memcmp(check.hmac, expected_hmac, SFO_HMAC_LEN) != 0) {
        log_warn("sdimg: verify mismatch — destination PARAMS HMAC missing or changed");
        ok = false;
    }
    log_info("restore[slot=%s]: metadata_verified=%s user_param=%u "
             "blocks=%llu system_blocks=%llu hmac=%s",
             expected_dir ? expected_dir : "(unknown)", ok ? "yes" : "no",
             check.user_param, (unsigned long long)check.blocks,
             (unsigned long long)check.system_blocks,
             check.has_hmac ? "destination-local" : "absent");
    return ok;
}

typedef struct {
    const char* plain_dir;
    const restore_sources_t* originals;
    char expected_sfo_sha256[65];
    const char* title_id;
    const char* dir_name;
    uint64_t account_id;
    uint32_t user_id;
    const uint8_t* params_hmac;
    bool complete_inventory;
    pfs_native_restore_report_t* native_report;
    char expected_sfo[SDIMG_PATH_MAX];
} portable_validation_context_t;

// Same tree contract in both directions, including empty directories/files.
// Only the exact SFO path is byte-mutable; its normal structural validator
// below still checks destination identity, HMAC and allowed transformation.
static bool portable_complete_tree(const char* a, const char* b,
                                    const char* rel, unsigned depth) {
    if (depth > 64) return false;
    struct stat as, bs;
    if (lstat(a, &as) || lstat(b, &bs)) return false;
    if (S_ISREG(as.st_mode))
        return S_ISREG(bs.st_mode) &&
            (portable_mutable_param(rel) ||
             (as.st_size == bs.st_size && files_sha256_equal(a, b)));
    if (!S_ISDIR(as.st_mode) || !S_ISDIR(bs.st_mode)) return false;
    DIR* d = opendir(a);
    if (!d) return false;
    bool ok = true; struct dirent* e;
    while ((errno = 0, e = readdir(d)) != NULL) {
        if (!strcmp(e->d_name, ".") || !strcmp(e->d_name, "..")) continue;
        char ap[SDIMG_PATH_MAX], bp[SDIMG_PATH_MAX], rp[SDIMG_PATH_MAX];
        int an = snprintf(ap, sizeof(ap), "%s/%s", a, e->d_name);
        int bn = snprintf(bp, sizeof(bp), "%s/%s", b, e->d_name);
        int rn = snprintf(rp, sizeof(rp), "%s%s%s", rel, rel[0] ? "/" : "", e->d_name);
        if (an < 0 || an >= (int)sizeof(ap) || bn < 0 || bn >= (int)sizeof(bp) ||
            rn < 0 || rn >= (int)sizeof(rp) || !portable_complete_tree(ap, bp, rp, depth + 1)) {
            ok = false; break;
        }
    }
    if (errno) ok = false;
    if (closedir(d)) ok = false;
    return ok;
}

static bool validate_native_portable_image(const char* image, const char* dump,
                                           void* opaque) {
    portable_validation_context_t* context = opaque;
    if (!restore_sources_tree_matches(context->originals, context->plain_dir)) {
        log_warn("sdimg: original Portable backup members changed; validation rejected");
        return false;
    }
    if (context->complete_inventory) {
        char observed[SDIMG_PATH_MAX];
        int n = snprintf(observed, sizeof(observed), "%s/sce_sys/param.sfo", dump);
        if (n < 0 || n >= (int)sizeof(observed)) return false;
        if (!context->expected_sfo[0]) {
            pfs_attribute_image_t expected = {0};
            int a = snprintf(expected.source, sizeof(expected.source), "%s/sce_sys/param.sfo", context->plain_dir);
            int b = snprintf(expected.copy, sizeof(expected.copy), "%s/EXPECTED.param.sfo", context->native_report->workspace);
            if (a < 0 || a >= (int)sizeof(expected.source) || b < 0 || b >= (int)sizeof(expected.copy) ||
                !pfs_attributes_copy_private(&expected) ||
                !sfo_patch_identity_hmac(expected.copy, context->account_id,
                                        context->user_id, context->params_hmac) ||
                !sha256_file_hex(expected.copy, context->expected_sfo_sha256)) return false;
            snprintf(context->expected_sfo, sizeof(context->expected_sfo), "%s", expected.copy);
        }
        // Reuse the SAME transform on a private reference; compare every SFO
        // byte, including unknown keys/padding, not only parsed known fields.
        char observed_sha[65];
        if (!sha256_file_hex(observed, observed_sha) ||
            strcmp(context->expected_sfo_sha256, observed_sha)) return false;
    }
    return (!context->complete_inventory ||
            (portable_complete_tree(context->plain_dir, dump, "", 0) &&
             portable_complete_tree(dump, context->plain_dir, "", 0))) &&
        verify_portable_payload(context->plain_dir, dump, context->dir_name) &&
        verify_restored_image(image, dump, context->plain_dir,
                              context->title_id, context->dir_name,
                              context->account_id, context->user_id,
                              context->params_hmac) &&
        restore_sources_tree_matches(context->originals, context->plain_dir);
}

static bool portable_publish_checked(void* tx, const char* candidate,
    const char* target, const char* sha, const char* pre, bool* renamed) {
    return portable_transaction_publish(tx, candidate, target, sha, pre, renamed);
}
static bool portable_verified_checked(void* tx, const char* target, const char* sha) {
    return portable_transaction_verified(tx, target, sha);
}

typedef struct { const restore_scope_t* scope; const char* canonical_zip_path; } portable_authority_t;
static bool portable_authority_current(void* opaque) {
    const portable_authority_t* authority = opaque;
    return authority && fs_title_is_closed(authority->scope->title_id) &&
        import_session_validate_restore_scope(
        authority->scope, authority->canonical_zip_path);
}

static bool restore_plain_dir_to_slot_image(const char* plain_dir,
                                            const char* target_img,
                                            const char* snap_dir,
                                            const char* title_id,
                                            const char* dir_name,
                                            uint64_t account_id,
                                            uint32_t user_id,
                                            bool strict_identity,
                                            bool* recovery_required,
                                            portable_transaction_t* transaction,
                                            const restore_sources_t* originals,
                                            char* err,
                                            size_t err_sz) {
    if (recovery_required) *recovery_required = false;
    if (!fs_title_is_closed(title_id))
        return set_err(err, err_sz,
                       "Game must be closed and its state readable before restoring slot %s",
                       dir_name ? dir_name : "(unknown)");
    struct stat before, after;
    if (stat(target_img, &before) != 0 || !S_ISREG(before.st_mode))
        return set_err(err, err_sz,
                       "Target slot %s does not exist. Create it in the game first.",
                       dir_name ? dir_name : "(unknown)");
    sfo_info_t target_before;
    int read_result = pfs_read_image_param_sfo(target_img, &target_before);
    if (read_result == PFS_SFO_READ_UNMOUNT_UNCERTAIN) {
        if (recovery_required) *recovery_required = true;
        return set_err(err, err_sz,
                       "Target slot %s mount cleanup is uncertain; evidence retained, keep the game closed",
                       dir_name ? dir_name : "(unknown)");
    }
    if (read_result != 0 ||
        !target_before.has_hmac)
        return set_err(err, err_sz,
                       "Target slot %s has no usable local PARAMS HMAC",
                       dir_name ? dir_name : "(unknown)");
    if (strict_identity &&
        (strcmp(target_before.title_id, title_id) != 0 ||
         strcmp(target_before.dir_name, dir_name) != 0 ||
         target_before.account_id != account_id ||
         target_before.user_id != user_id))
        return set_err(err, err_sz,
                       "Selected target slot %s identity changed before writeback",
                       dir_name ? dir_name : "(unknown)");
    log_info("sdimg: preserving existing target PPR for %s", target_img);
    restore_sources_t local = {0};
    if (!originals) {
        if (!restore_sources_capture(&local, plain_dir))
            return set_err(err, err_sz, "Could not pin original Portable content");
        originals = &local;
    }
    pfs_native_restore_report_t report = {0};
    portable_validation_context_t context = {
        .plain_dir = plain_dir, .originals = originals, .title_id = title_id, .dir_name = dir_name,
        .account_id = account_id, .user_id = user_id, .params_hmac = target_before.hmac,
        .complete_inventory = transaction != NULL, .native_report = &report
    };
    pfs_native_restore_transaction_t checked = {
        transaction, portable_publish_checked, portable_verified_checked
    };
    bool ok = pfs_resign_restore_plain_dir_into_existing_image_for_user_checked(
        plain_dir, target_img, snap_dir, account_id, user_id,
        target_before.hmac, &report, validate_native_portable_image, &context,
        transaction ? &checked : NULL);
    restore_sources_free(&local);
    log_info("restore[slot=%s]: permanent_image=%s mode_phase=%s "
             "pre_verified=%s closed_verified=%s post_verified=%s "
             "published=%s rename_attempted=%s unmount_uncertain=%s workspace=%s",
             dir_name ? dir_name : "(unknown)", target_img, report.phase,
             report.modes_pre_verified ? "yes" : "no",
             report.modes_closed_verified ? "yes" : "no",
             report.modes_post_verified ? "yes" : "no",
             report.published ? "yes" : "no",
             report.rename_attempted ? "yes" : "no",
             report.unmount_uncertain ? "yes" : "no", report.workspace);
    if (!ok || report.unmount_uncertain || !report.published ||
        !report.rename_attempted || !report.modes_pre_verified ||
        !report.modes_closed_verified || !report.modes_post_verified) {
        if (recovery_required) *recovery_required = true;
        return set_err(err, err_sz,
                       "Native portable restore for %s requires inspection; evidence retained at %s (%s)",
                       dir_name ? dir_name : "(unknown)",
                       report.workspace[0] ? report.workspace : snap_dir,
                       report.detail[0] ? report.detail : "validation failed");
    }
    char final_sha[65] = {0};
    bool verified = stat(target_img, &after) == 0 && S_ISREG(after.st_mode) &&
                    after.st_size == before.st_size &&
                    sha256_file_hex(target_img, final_sha);
    log_info("restore[slot=%s]: permanent_image=%s container_bytes_before=%llu "
             "container_bytes_after=%llu committed=%s final_sha256=%s",
             dir_name ? dir_name : "(unknown)", target_img,
             (unsigned long long)before.st_size,
             (unsigned long long)(verified ? after.st_size : 0),
             verified ? "yes" : "no", final_sha[0] ? final_sha : "unavailable");
    if (!verified) {
        if (recovery_required) *recovery_required = true;
        return set_err(err, err_sz,
                       "Native portable restore for %s requires inspection; final container validation failed, evidence retained",
                       dir_name ? dir_name : "(unknown)");
    }
    return true;
}

static bool row_exists(sqlite3* db, const char* title_id,
                       const char* dir_name) {
    sqlite3_stmt* st = NULL;
    if (sqlite3_prepare_v2(db,
            "SELECT 1 FROM savedata WHERE title_id=? AND dir_name=? LIMIT 1",
            -1, &st, NULL) != SQLITE_OK)
        return false;
    sqlite3_bind_text(st, 1, title_id, -1, SQLITE_STATIC);
    sqlite3_bind_text(st, 2, dir_name, -1, SQLITE_STATIC);
    bool yes = (sqlite3_step(st) == SQLITE_ROW);
    sqlite3_finalize(st);
    return yes;
}

static bool savedata_db_slot_exists(const char* uid, const char* title_id,
                                    const char* dir_name) {
    char db_path[SDIMG_PATH_MAX];
    snprintf(db_path, sizeof(db_path),
             "/system_data/savedata_prospero/%s/db/user/savedata.db", uid);
    sqlite3* db = NULL;
    bool ok = sqlite3_open_v2(db_path, &db,
                             SQLITE_OPEN_READONLY | SQLITE_OPEN_NOMUTEX,
                             NULL) == SQLITE_OK &&
              row_exists(db, title_id, dir_name);
    if (db) sqlite3_close(db);
    return ok;
}

static bool bind_text(sqlite3_stmt* st, int i, const char* v) {
    return sqlite3_bind_text(st, i, v ? v : "", -1, SQLITE_TRANSIENT)
           == SQLITE_OK;
}

static bool upsert_slot(sqlite3* db, const char* uid, const char* title_id,
                        const sdimg_item_t* item, bool allow_new_rows,
                        char* err, size_t err_sz) {
    sdimg_db_seed_t seed;
    seed_defaults(&seed, uid, title_id);
    bool exists = row_exists(db, title_id, item->dir_name);

    // --- Same-console restore safety (audit #1) ---
    // If this slot is ALREADY indexed in savedata.db, its row holds the
    // metadata the firmware itself wrote (blocks, size, mtime, identity).
    // The raw image was already copied atomically above; rewriting the row
    // from a backup's param.sfo can mis-set block counts and make a perfectly
    // good save show up as "corrupted/broken". PS5 Payload Manager likewise
    // restores raw images WITHOUT touching savedata.db for saves that already
    // exist. So we leave existing rows exactly as the console had them and
    // only INSERT genuinely new slots below.
    if (exists) {
        log_info("sdimg: savedata.db row already present for %s/%s — "
                 "leaving it untouched (no DB rewrite)",
                 title_id, item->dir_name);
        return true;
    }

    // --- New-save registration safety (audit #3) ---
    // This row does NOT exist yet: registering it means inventing savedata.db
    // metadata (block count estimated from file size, owner borrowed from
    // another row, possibly CREATE-ing the table) for a save this console has
    // never seen. On the RAW restore path that is unsafe and can leave a
    // phantom/broken entry, so new rows are refused there (allow_new_rows ==
    // false): a raw restore may only OVERWRITE a save that already exists.
    // The kernel/official paths (which actually create a proper PFS image)
    // pass allow_new_rows == true and may register.
    if (!allow_new_rows)
        return set_err(err, err_sz,
                       "Cannot restore %s (slot %s): this save is not registered "
                       "on this console. A raw restore can only overwrite an "
                       "existing save — open the game once to create it, then "
                       "restore over that original slot.",
                       title_id, item->dir_name);
    if (!item->have_sfo)
        return set_err(err, err_sz,
                       "Refusing to register %s: the backup has no readable "
                       "param.sfo.", item->dir_name);
    log_info("sdimg: registering NEW savedata.db entry for %s/%s", title_id,
             item->dir_name);

    if (!load_seed_exact(db, title_id, item->dir_name, &seed) &&
        !load_seed_for_title(db, title_id, &seed)) {
        // Only borrow owner identifiers from another save in this user's DB.
        // The title/name fields must remain tied to the title being restored.
        sdimg_db_seed_t owner;
        if (load_seed_any(db, &owner)) {
            seed.account_id = owner.account_id;
            seed.user_id    = owner.user_id;
        }
    }
    bool have_local_account = (seed.account_id != 0);
    bool have_local_user    = (seed.user_id != 0);
    // Keep account/user ownership from this PS5 when it exists. The backup's
    // param.sfo supplies the visible slot metadata, not the local identity.
    if (item->have_sfo) {
        // These are source-slot metadata, not console identity. Never inherit
        // them from an unrelated local DB row: Garlic registers the imported
        // values, including legitimate empty strings and zeroes.
        seed.user_param = (int)item->sfo.user_param;
        seed.system_blocks = (int)item->sfo.system_blocks;
        snprintf(seed.main_title, sizeof(seed.main_title), "%s",
                 item->sfo.main_title[0] ? item->sfo.main_title : title_id);
        snprintf(seed.sub_title, sizeof(seed.sub_title), "%s",
                 item->sfo.sub_title);
        snprintf(seed.detail, sizeof(seed.detail), "%s", item->sfo.detail);
        snprintf(seed.game_title_id, sizeof(seed.game_title_id), "%s",
                 item->sfo.game_title_id[0] ? item->sfo.game_title_id
                                            : title_id);
        if (item->sfo.account_id && !have_local_account)
            seed.account_id = (sqlite3_int64)item->sfo.account_id;
        if (item->sfo.user_id && !have_local_user)
            seed.user_id = (sqlite3_int64)item->sfo.user_id;
    }

    if (!seed.game_title_id[0])
        snprintf(seed.game_title_id, sizeof(seed.game_title_id), "%s", title_id);
    if (seed.user_id == 0)
        seed.user_id = (sqlite3_int64)strtoull(uid, NULL, 16);

    // Prefer the real SAVEDATA_BLOCKS from param.sfo; fall back to a byte-based
    // estimate (image size / 64 KiB) only when the SFO had no value.
    uint64_t blocks64 = (item->have_sfo && item->sfo.blocks)
                            ? item->sfo.blocks
                            : (item->bytes + 65535u) / 65536u;
    if (blocks64 == 0) blocks64 = 1;
    if (blocks64 > 0x7fffffffULL) blocks64 = 0x7fffffffULL;
    int blocks = (int)blocks64;
    int size_kib = blocks * 0x40;

    char mtime[64];
    time_t now = time(NULL);
    struct tm tm;
    gmtime_r(&now, &tm);
    strftime(mtime, sizeof(mtime), "%Y-%m-%dT%H:%M:%S.00Z", &tm);

    sqlite3_stmt* st = NULL;
    int rc;
    if (exists) {
        static const char* SQL =
            "UPDATE savedata SET main_title=?, mtime=?, account_id=?,"
            "user_id=?, blocks=?, free_blocks=?, size_kib=?,"
            "game_title_id=?, system_blocks=? "
            "WHERE title_id=? AND dir_name=?";
        rc = sqlite3_prepare_v2(db, SQL, -1, &st, NULL);
        if (rc != SQLITE_OK)
            return set_err(err, err_sz, "savedata.db update prepare failed: %s",
                           sqlite3_errmsg(db));
        int i = 1;
        bind_text(st, i++, seed.main_title);
        bind_text(st, i++, mtime);
        sqlite3_bind_int64(st, i++, seed.account_id);
        sqlite3_bind_int64(st, i++, seed.user_id);
        sqlite3_bind_int(st, i++, blocks);
        sqlite3_bind_int(st, i++, blocks);
        sqlite3_bind_int(st, i++, size_kib);
        bind_text(st, i++, seed.game_title_id);
        sqlite3_bind_int(st, i++, seed.system_blocks);
        bind_text(st, i++, title_id);
        bind_text(st, i++, item->dir_name);
    } else {
        static const char* SQL =
            "INSERT INTO savedata (title_id, dir_name, main_title, sub_title,"
            "detail, is_broken, user_param, blocks, free_blocks, size_kib,"
            "mtime, fake_broken, account_id, user_id, faked_owner,"
            "cloud_revision, game_title_id, system_blocks) "
            "VALUES (?,?,?,?,?,0,?,?,?,?,?,0,?,?,0,0,?,?)";
        rc = sqlite3_prepare_v2(db, SQL, -1, &st, NULL);
        if (rc != SQLITE_OK)
            return set_err(err, err_sz, "savedata.db insert prepare failed: %s",
                           sqlite3_errmsg(db));
        int i = 1;
        bind_text(st, i++, title_id);
        bind_text(st, i++, item->dir_name);
        bind_text(st, i++, seed.main_title);
        bind_text(st, i++, seed.sub_title);
        bind_text(st, i++, seed.detail);
        sqlite3_bind_int(st, i++, seed.user_param);
        sqlite3_bind_int(st, i++, blocks);
        sqlite3_bind_int(st, i++, blocks);
        sqlite3_bind_int(st, i++, size_kib);
        bind_text(st, i++, mtime);
        sqlite3_bind_int64(st, i++, seed.account_id);
        sqlite3_bind_int64(st, i++, seed.user_id);
        bind_text(st, i++, seed.game_title_id);
        sqlite3_bind_int(st, i++, seed.system_blocks);
    }

    rc = sqlite3_step(st);
    if (rc != SQLITE_DONE) {
        set_err(err, err_sz, "savedata.db write failed for %s: %s",
                item->dir_name, sqlite3_errmsg(db));
        sqlite3_finalize(st);
        return false;
    }
    sqlite3_finalize(st);
    log_info("sdimg: savedata.db %s %s/%s (%d blocks)",
             exists ? "updated" : "inserted", title_id, item->dir_name,
             blocks);
    return true;
}

static bool delete_slots_not_in_backup(sqlite3* db, const char* title_id,
                                       const sdimg_item_t* items,
                                       size_t count,
                                       char* err,
                                       size_t err_sz) {
    char sql[1600];
    size_t used = 0;
    int n = snprintf(sql + used, sizeof(sql) - used,
                     "DELETE FROM savedata WHERE title_id=? "
                     "AND dir_name NOT IN (");
    if (n <= 0 || (size_t)n >= sizeof(sql) - used)
        return set_err(err, err_sz, "savedata.db delete SQL too long");
    used += (size_t)n;
    for (size_t i = 0; i < count; i++) {
        n = snprintf(sql + used, sizeof(sql) - used, "%s?",
                     i ? "," : "");
        if (n <= 0 || (size_t)n >= sizeof(sql) - used)
            return set_err(err, err_sz, "savedata.db delete SQL too long");
        used += (size_t)n;
    }
    n = snprintf(sql + used, sizeof(sql) - used, ")");
    if (n <= 0 || (size_t)n >= sizeof(sql) - used)
        return set_err(err, err_sz, "savedata.db delete SQL too long");

    sqlite3_stmt* st = NULL;
    int rc = sqlite3_prepare_v2(db, sql, -1, &st, NULL);
    if (rc != SQLITE_OK)
        return set_err(err, err_sz, "savedata.db delete prepare failed: %s",
                       sqlite3_errmsg(db));
    sqlite3_bind_text(st, 1, title_id, -1, SQLITE_STATIC);
    for (size_t i = 0; i < count; i++)
        sqlite3_bind_text(st, (int)i + 2, items[i].dir_name, -1,
                          SQLITE_STATIC);
    rc = sqlite3_step(st);
    if (rc != SQLITE_DONE) {
        set_err(err, err_sz, "savedata.db delete failed: %s",
                sqlite3_errmsg(db));
        sqlite3_finalize(st);
        return false;
    }
    int changed = sqlite3_changes(db);
    sqlite3_finalize(st);
    if (changed > 0)
        log_info("sdimg: savedata.db removed %d stale slot row(s)", changed);
    return true;
}

// Remove phantom "sce_bu_*" rows a previous build may have inserted for this
// title. Service-backup images are not playable slots and must never appear
// in savedata.db. Safe to run every restore.
static bool delete_sce_bu_rows(sqlite3* db, const char* title_id,
                               char* err, size_t err_sz) {
    sqlite3_stmt* st = NULL;
    if (sqlite3_prepare_v2(db,
            "DELETE FROM savedata WHERE title_id=? "
            "AND dir_name LIKE 'sce_bu_%'",
            -1, &st, NULL) != SQLITE_OK)
        return set_err(err, err_sz, "savedata.db sce_bu cleanup prepare failed: %s",
                       sqlite3_errmsg(db));
    sqlite3_bind_text(st, 1, title_id, -1, SQLITE_STATIC);
    int rc = sqlite3_step(st);
    if (rc != SQLITE_DONE) {
        set_err(err, err_sz, "savedata.db sce_bu cleanup failed: %s",
                sqlite3_errmsg(db));
        sqlite3_finalize(st);
        return false;
    }
    int changed = sqlite3_changes(db);
    sqlite3_finalize(st);
    if (changed > 0)
        log_info("sdimg: removed %d stale sce_bu_* row(s) from savedata.db",
                 changed);
    return true;
}

static bool update_savedata_db(const char* uid, const char* title_id,
                               const sdimg_item_t* items, size_t count,
                               bool prune_missing_slots, bool allow_new_rows,
                               char* err, size_t err_sz) {
    char db_dir[SDIMG_PATH_MAX];
    char db_path[SDIMG_PATH_MAX];
    snprintf(db_dir, sizeof(db_dir),
             "/system_data/savedata_prospero/%s/db/user", uid);
    snprintf(db_path, sizeof(db_path), "%s/savedata.db", db_dir);
    if (!fs_mkdir_p(db_dir))
        return set_err(err, err_sz, "Could not create savedata.db folder");

    sqlite3* db = NULL;
    int rc = sqlite3_open_v2(db_path, &db,
                             SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE |
                             SQLITE_OPEN_NOMUTEX, NULL);
    if (rc != SQLITE_OK) {
        set_err(err, err_sz, "Could not open savedata.db: %s",
                db ? sqlite3_errmsg(db) : "unknown");
        if (db) sqlite3_close(db);
        return false;
    }
    sqlite3_busy_timeout(db, 5000);

    bool ok = ensure_savedata_table(db, err, err_sz) &&
              db_exec(db, "BEGIN IMMEDIATE", err, err_sz);
    for (size_t i = 0; ok && i < count; i++)
        ok = upsert_slot(db, uid, title_id, &items[i], allow_new_rows,
                         err, err_sz);
    if (ok && prune_missing_slots)
        ok = delete_slots_not_in_backup(db, title_id, items, count,
                                        err, err_sz);
    if (ok)
        ok = delete_sce_bu_rows(db, title_id, err, err_sz);

    if (ok) {
        ok = db_exec(db, "COMMIT", err, err_sz);
    } else {
        db_exec(db, "ROLLBACK", NULL, 0);
    }
    sqlite3_close(db);
    return ok;
}

// Build the metadata needed to rebuild a zeroed param.sfo for slot `item`,
// borrowing identity (account/user/title/system_blocks + the PARAMS HMAC) from
// a sibling slot in the same set whose param.sfo was readable.
static void build_fix_meta(const char* title_id, const sdimg_item_t* item,
                           const sdimg_item_t* items, size_t count,
                           sfo_info_t* meta, const uint8_t** hmac_out) {
    memset(meta, 0, sizeof(*meta));
    snprintf(meta->title_id, sizeof(meta->title_id), "%s", title_id);
    snprintf(meta->game_title_id, sizeof(meta->game_title_id), "%s", title_id);
    snprintf(meta->dir_name, sizeof(meta->dir_name), "%s", item->dir_name);
    snprintf(meta->format, sizeof(meta->format), "ppr");
    char game[64] = {0};
    if (titlename_lookup(title_id, game, sizeof(game)) && game[0])
        snprintf(meta->main_title, sizeof(meta->main_title), "%s", game);
    else
        snprintf(meta->main_title, sizeof(meta->main_title), "%s", title_id);
    meta->blocks = (item->bytes + 65535u) / 65536u;
    *hmac_out = NULL;
    for (size_t j = 0; j < count; j++) {
        if (!items[j].have_sfo) continue;
        if (items[j].sfo.account_id)   meta->account_id   = items[j].sfo.account_id;
        if (items[j].sfo.user_id)      meta->user_id      = items[j].sfo.user_id;
        if (items[j].sfo.system_blocks)meta->system_blocks= items[j].sfo.system_blocks;
        if (items[j].sfo.main_title[0])
            snprintf(meta->main_title, sizeof(meta->main_title), "%s",
                     items[j].sfo.main_title);
        if (items[j].sfo.has_hmac) *hmac_out = items[j].sfo.hmac;
        if (*hmac_out) break;  // a sibling with identity + HMAC is enough
    }
}

bool savedata_db_update_single(const char* user_uid, const char* title_id,
                               const char* dir_name, uint64_t bytes,
                               const sfo_info_t* sfo,
                               char* err, size_t err_sz) {
    if (!uid_ok(user_uid))
        return set_err(err, err_sz, "Missing PS5 user for savedata.db update");
    if (!title_ok(title_id))
        return set_err(err, err_sz, "Invalid TITLE ID for savedata.db update");
    if (!dir_name || !safe_component(dir_name))
        return set_err(err, err_sz, "Invalid save dir_name for savedata.db");

    sdimg_item_t item;
    memset(&item, 0, sizeof(item));
    snprintf(item.dir_name, sizeof(item.dir_name), "%s", dir_name);
    item.bytes = bytes;
    if (sfo) { item.have_sfo = true; item.sfo = *sfo; }
    // Single-slot imports must NOT prune the rest of the title. Garlic-style
    // restores can update one SAVEDATA_DIRECTORY while other slots remain valid.
    // Official/kernel single-slot registration path → may create a new row.
    return update_savedata_db(user_uid, title_id, &item, 1, false, true,
                              err, err_sz);
}

static bool sfo_title_matches(const sfo_info_t* sfo, const char* title_id) {
    if (!sfo || !title_id) return false;
    if (sfo->title_id[0] && strcmp(sfo->title_id, title_id) != 0)
        return false;
    if (sfo->game_title_id[0] && strcmp(sfo->game_title_id, title_id) != 0)
        return false;
    return true;
}

static bool plain_slot_info_from_dir(const char* plain_dir,
                                     const char* title_id,
                                     sfo_info_t* out,
                                     char* err,
                                     size_t err_sz) {
    char sfo_path[SDIMG_PATH_MAX];
    snprintf(sfo_path, sizeof(sfo_path), "%s/sce_sys/param.sfo", plain_dir);
    int sr = sfo_parse(sfo_path, out);
    if (sr == -2)
        return set_err(err, err_sz, "Plain slot param.sfo is zeroed/corrupt");
    if (sr != 0)
        return set_err(err, err_sz, "Plain slot is missing sce_sys/param.sfo");
    if (!out->dir_name[0] || !safe_component(out->dir_name))
        return set_err(err, err_sz, "Plain slot param.sfo has no valid SAVEDATA_DIRECTORY");
    if (!sfo_title_matches(out, title_id))
        return set_err(err, err_sz, "Plain slot TITLE_ID does not match %s", title_id);
    return true;
}

static bool plain_data_file_name(const char* name) {
    if (!safe_component(name)) return false;
    if (strcmp(name, "sce_sys") == 0) return false;
    if (strcmp(name, ".DS_Store") == 0) return false;
    if (strncmp(name, "._", 2) == 0) return false;
    return true;
}

static bool regular_files_equal(const char* a, const char* b) {
    struct stat sa, sb;
    if (stat(a, &sa) != 0 || stat(b, &sb) != 0) return false;
    if (!S_ISREG(sa.st_mode) || !S_ISREG(sb.st_mode)) return false;
    if (sa.st_size != sb.st_size) return false;

    int fa = open(a, O_RDONLY);
    if (fa < 0) return false;
    int fb = open(b, O_RDONLY);
    if (fb < 0) { close(fa); return false; }

    unsigned char* ba = (unsigned char*)malloc(32768);
    unsigned char* bb = (unsigned char*)malloc(32768);
    if (!ba || !bb) {
        free(ba); free(bb); close(fa); close(fb);
        return false;
    }

    bool same = true;
    for (;;) {
        ssize_t ra = read(fa, ba, 32768);
        ssize_t rb = read(fb, bb, 32768);
        if (ra != rb) { same = false; break; }
        if (ra < 0) { same = false; break; }
        if (ra == 0) break;
        if (memcmp(ba, bb, (size_t)ra) != 0) { same = false; break; }
    }
    free(ba); free(bb); close(fa); close(fb);
    return same;
}

static bool plain_data_payload_equal(const char* a_dir, const char* b_dir) {
    DIR* d = opendir(a_dir);
    if (!d) return false;
    size_t checked = 0;
    bool same = true;
    struct dirent* e;
    while ((e = readdir(d)) != NULL) {
        if (!plain_data_file_name(e->d_name)) continue;
        char a[SDIMG_PATH_MAX], b[SDIMG_PATH_MAX];
        snprintf(a, sizeof(a), "%s/%s", a_dir, e->d_name);
        snprintf(b, sizeof(b), "%s/%s", b_dir, e->d_name);
        struct stat st;
        if (stat(a, &st) != 0 || !S_ISREG(st.st_mode)) continue;
        checked++;
        if (!regular_files_equal(a, b)) { same = false; break; }
    }
    closedir(d);
    if (!same || checked == 0) return false;

    d = opendir(b_dir);
    if (!d) return false;
    while ((e = readdir(d)) != NULL) {
        if (!plain_data_file_name(e->d_name)) continue;
        char b[SDIMG_PATH_MAX], a[SDIMG_PATH_MAX];
        snprintf(b, sizeof(b), "%s/%s", b_dir, e->d_name);
        snprintf(a, sizeof(a), "%s/%s", a_dir, e->d_name);
        struct stat st;
        if (stat(b, &st) != 0 || !S_ISREG(st.st_mode)) continue;
        if (stat(a, &st) != 0) { same = false; break; }
    }
    closedir(d);
    return same;
}

bool sdimg_restore_plain_slot_from_payload(const char* plain_dir,
                                           const char* user_uid,
                                           const char* title_id,
                                           const char* target_title_dir,
                                           const char* stage_base,
                                          const restore_sources_t* originals,
                                           char* err,
                                           size_t err_sz) {
    if (!plain_dir || !target_title_dir || !stage_base)
        return set_err(err, err_sz, "Internal plain-slot restore path is missing");
    if (!uid_ok(user_uid))
        return set_err(err, err_sz, "Missing PS5 user for plain-slot restore");
    if (!title_ok(title_id))
        return set_err(err, err_sz, "Invalid TITLE ID for plain-slot restore");

    sfo_info_t sfo;
    if (!plain_slot_info_from_dir(plain_dir, title_id, &sfo, err, err_sz))
        return false;

    struct stat target_dir_st;
    if (stat(target_title_dir, &target_dir_st) != 0 ||
        !S_ISDIR(target_dir_st.st_mode))
        return set_err(err, err_sz,
                       "Target save does not exist. Create it in the game first.");

    char target_img[SDIMG_PATH_MAX];
    snprintf(target_img, sizeof(target_img), "%s/sdimg_%s",
             target_title_dir, sfo.dir_name);
    struct stat st;

    char snap_dir[SDIMG_PATH_MAX];
    snprintf(snap_dir, sizeof(snap_dir), "%s_plain_slot_snap", stage_base);
    if (!rollback_snapshot_space(target_img, snap_dir, err, err_sz) ||
        !rollback_archive_existing(snap_dir, err, err_sz)) return false;
    if (!fs_mkdir_p(snap_dir))
        return set_err(err, err_sz, "Could not create plain-slot rollback folder");

    log_info("sdimg: importing plain folder %s -> %s (dir=%s)",
             plain_dir, target_img, sfo.dir_name);
    uint64_t local_account_id = 0;
    uint32_t local_user_id = 0;
    if (!local_owner_for_slot(user_uid, title_id, sfo.dir_name,
                              &local_account_id, &local_user_id)) {
        pfs_fs_rmrf(snap_dir);
        return set_err(err, err_sz,
                       "Could not detect the local PS5 account. Create any "
                       "save once for this user, then retry.");
    }
    bool target_existed = (stat(target_img, &st) == 0 && S_ISREG(st.st_mode));
    sfo_info_t target_sfo;
    if (!target_existed ||
        !savedata_db_slot_exists(user_uid, title_id, sfo.dir_name) ||
        pfs_read_image_param_sfo(target_img, &target_sfo) != 0 ||
        strcmp(target_sfo.title_id, title_id) != 0 ||
        strcmp(target_sfo.dir_name, sfo.dir_name) != 0 ||
        target_sfo.account_id != local_account_id ||
        target_sfo.user_id != local_user_id) {
        pfs_fs_rmrf(snap_dir);
        return set_err(err, err_sz,
                       "Target slot %s is missing or not registered. Create "
                       "it in the game before restoring.", sfo.dir_name);
    }

    // Snapshot the exact target container before mounting it read/write.
    char img_backup[SDIMG_PATH_MAX];
    snprintf(img_backup, sizeof(img_backup), "%s_plain_slot_imgbak", stage_base);
    if (!rollback_archive_existing(img_backup, err, err_sz)) return false;
    if (target_existed && !copy_file_atomic(target_img, img_backup))
        return set_err(err, err_sz,
                       "Could not snapshot existing slot %s before restore",
                       sfo.dir_name);

    bool recovery_required = false;
    if (!restore_plain_dir_to_slot_image(plain_dir, target_img, snap_dir,
                                         title_id, sfo.dir_name, local_account_id,
                                         local_user_id, false, &recovery_required, NULL, originals,
                                         err, err_sz)) {
        if (recovery_required) return false;
        pfs_fs_rmrf(snap_dir);
        rollback_single_slot_image(target_img, img_backup, target_existed,
                                   err, err_sz);
        return false;
    }
    pfs_fs_rmrf(snap_dir);

    if (!rollback_archive_existing(img_backup, err, err_sz)) return false;
    sync();
    log_info("sdimg: imported plain slot %s/%s into existing active image; "
             "savedata.db preserved",
             title_id, sfo.dir_name);
    return true;
}

// Only the storage prefix is structural. Slot identity is an exact byte match;
// no case folding, Unicode conversion, aliases, or SFO-selected destination.
static bool selected_owner_for_slot(const char* uid, const char* title_id,
                                    const char* slot, uint64_t* account_id,
                                    uint32_t* user_id, char* err, size_t err_sz);

static const char* plain_selected_child(const char* child,
                                        const char selected_slots[][64],
                                        size_t selected_count) {
    for (size_t i = 0; i < selected_count; i++) {
        if (strcmp(child, selected_slots[i]) == 0 ||
            (strncmp(child, "sdimg_", 6) == 0 &&
             strcmp(child + 6, selected_slots[i]) == 0))
            return selected_slots[i];
    }
    return NULL;
}

static bool plain_folder_to_item(const char* plain_dir,
                                 const char* user_uid,
                                 const char* target_title_dir,
                                 const char* title_id,
                                 const char* stage_base,
                                 size_t ordinal,
                                 bool service_candidate,
                                 sdimg_item_t* items,
                                 size_t* count,
                                 const char* expected_selected_slot,
                                 size_t* written_count,
                                 bool* recovery_required,
                                 portable_transaction_t* transaction,
                                            const restore_sources_t* originals,
                                 char* err,
                                 size_t err_sz) {
    sfo_info_t sfo;
    if (!plain_slot_info_from_dir(plain_dir, title_id, &sfo, err, err_sz))
        return false;
    // Independently enforce the requested identity at the writer boundary.
    // A changed SFO can never redirect a selected folder to another image.
    if (expected_selected_slot &&
        strcmp(sfo.dir_name, expected_selected_slot) != 0)
        return set_err(err, err_sz,
                       "Selected slot identity changed: expected %s, found %s",
                       expected_selected_slot, sfo.dir_name);

    char target_img[SDIMG_PATH_MAX], snap_dir[SDIMG_PATH_MAX];
    int target_len = snprintf(target_img, sizeof(target_img), "%s/sdimg_%s",
                              target_title_dir, sfo.dir_name);
    if (expected_selected_slot &&
        (target_len < 0 || (size_t)target_len >= sizeof(target_img)))
        return set_err(err, err_sz, "Selected target image path is too long");
    if (transaction) {
        char base[SDIMG_PATH_MAX];
        if (!portable_transaction_slot_workspace(transaction, sfo.dir_name, base, sizeof(base)) ||
            snprintf(snap_dir, sizeof(snap_dir), "%s/restore", base) >= (int)sizeof(snap_dir))
            return set_err(err, err_sz, "Portable native workspace is outside authorized scope");
    } else snprintf(snap_dir, sizeof(snap_dir), "%s_plain_set_%zu", stage_base, ordinal);

    size_t idx = *count;
    for (size_t i = 0; i < *count; i++) {
        if (strcmp(items[i].dir_name, sfo.dir_name) == 0) {
            idx = i;
            break;
        }
    }
    if (idx != *count) {
        if (plain_data_payload_equal(items[idx].src, plain_dir)) {
            log_info("sdimg: plain folder %s matches existing %s data; keeping "
                     "the active slot metadata",
                     plain_dir, sfo.dir_name);
            return true;
        }
        if (service_candidate) {
            log_warn("sdimg: service snapshot %s also targets %s; keeping the "
                     "active slot and skipping automatic promotion",
                     plain_dir, sfo.dir_name);
            return true;
        }
    }

    if (!transaction && (!rollback_snapshot_space(target_img, snap_dir, err, err_sz) ||
        !rollback_archive_existing(snap_dir, err, err_sz))) return false;
    if (!transaction && !fs_mkdir_p(snap_dir))
        return set_err(err, err_sz, "Could not create plain-set scratch folder");

    log_info("sdimg: importing plain-set folder %s -> %s (dir=%s)",
             plain_dir, target_img, sfo.dir_name);
    uint64_t local_account_id = 0;
    uint32_t local_user_id = 0;
    if (expected_selected_slot) {
        if (!selected_owner_for_slot(user_uid, title_id, sfo.dir_name,
                                      &local_account_id, &local_user_id,
                                      err, err_sz)) {
            if (!transaction) pfs_fs_rmrf(snap_dir);
            return false;
        }
    } else if (!local_owner_for_slot(user_uid, title_id, sfo.dir_name,
                                      &local_account_id, &local_user_id)) {
        pfs_fs_rmrf(snap_dir);
        return set_err(err, err_sz,
                       "Could not detect the local PS5 account. Create any "
                       "save once for this user, then retry.");
    }
    sfo_info_t db_sfo = sfo_with_local_identity(&sfo, local_account_id,
                                                local_user_id);
    if (!restore_plain_dir_to_slot_image(plain_dir, target_img, snap_dir,
                                         title_id, sfo.dir_name, local_account_id,
                                         local_user_id,
                                         expected_selected_slot != NULL,
                                         recovery_required,
                                         transaction, originals,
                                         err, err_sz)) {
        if (!transaction && (!recovery_required || !*recovery_required)) pfs_fs_rmrf(snap_dir);
        return false;
    }
    if (written_count) (*written_count)++;
    if (!transaction) pfs_fs_rmrf(snap_dir);

    struct stat st;
    if (stat(target_img, &st) != 0 || !S_ISREG(st.st_mode))
        return set_err(err, err_sz, "Imported image missing for %s",
                       sfo.dir_name);

    if (idx == *count) {
        if (*count >= SDIMG_MAX_ITEMS)
            return set_err(err, err_sz, "Too many plain sdimg slots");
        memset(&items[idx], 0, sizeof(items[idx]));
        (*count)++;
    }

    snprintf(items[idx].name, sizeof(items[idx].name), "sdimg_%s",
             sfo.dir_name);
    snprintf(items[idx].dir_name, sizeof(items[idx].dir_name), "%s",
             sfo.dir_name);
    snprintf(items[idx].src, sizeof(items[idx].src), "%s", plain_dir);
    snprintf(items[idx].dst, sizeof(items[idx].dst), "%s", target_img);
    items[idx].bytes = (uint64_t)st.st_size;
    items[idx].have_sfo = true;
    items[idx].sfo = db_sfo;
    return true;
}

static bool import_plain_children(const char* root,
                                  const char* user_uid,
                                  const char* target_title_dir,
                                  const char* title_id,
                                  const char* stage_base,
                                  size_t* ordinal,
                                  bool service_candidate,
                                  sdimg_item_t* items,
                                  size_t* count,
                                  const char selected_slots[][64],
                                  size_t selected_count,
                                  size_t* written_count,
                                  bool* recovery_required,
                                  portable_transaction_t* transaction,
                                            const restore_sources_t* originals,
                                  char* err,
                                  size_t err_sz) {
    DIR* d = opendir(root);
    if (!d) return set_err(err, err_sz, "Could not open portable slot listing");
    bool ok = true;
    struct dirent* e;
    while ((errno = 0, e = readdir(d)) != NULL) {
        if (!safe_component(e->d_name)) continue;
        const char* selected = selected_slots
            ? plain_selected_child(e->d_name, selected_slots, selected_count)
            : NULL;
        if (selected_slots && !selected) continue;
        char plain_dir[SDIMG_PATH_MAX];
        snprintf(plain_dir, sizeof(plain_dir), "%s/%s", root, e->d_name);
        struct stat st;
        if (stat(plain_dir, &st) != 0) {
            ok = set_err(err, err_sz, "Could not inspect portable slot folder");
            break;
        }
        if (!S_ISDIR(st.st_mode)) {
            if (!selected_slots) continue;
            ok = set_err(err, err_sz, "Selected portable slot is not a folder");
            break;
        }
        char child_err[192] = {0};
        ok = plain_folder_to_item(plain_dir, user_uid, target_title_dir,
                                  title_id, stage_base, (*ordinal)++,
                                  service_candidate, items, count, selected,
                                  written_count, recovery_required, transaction, originals, child_err,
                                  sizeof(child_err));
        if (!ok && (!recovery_required || !*recovery_required) &&
            !selected_slots && strstr(child_err, "Plain slot") != NULL) {
            log_warn("sdimg: skipping invalid plain slot folder %s: %s",
                     plain_dir, child_err);
            ok = true;
            continue;
        }
        if (!ok) {
            set_err(err, err_sz, "%s", child_err[0] ? child_err
                                                     : "Plain slot import failed");
            break;
        }
    }
    if (errno != 0 && ok)
        ok = set_err(err, err_sz, "Could not finish portable slot listing");
    if (closedir(d) != 0 && ok)
        ok = set_err(err, err_sz, "Could not close portable slot listing");
    return ok;
}

typedef enum {
    DIAGNOSTIC_ROW_FOUND,
    DIAGNOSTIC_ROW_ABSENT,
    DIAGNOSTIC_SQLITE_ERROR
} diagnostic_row_state_t;

typedef struct {
    int sqlite_code;
    int sqlite_extended_code;
    char sqlite_message[160];
    int64_t rowid;
    uint64_t account_id;
    uint32_t user_id;
    bool owner_known;
} diagnostic_slot_row_t;

static diagnostic_row_state_t diagnostic_row_error(diagnostic_slot_row_t* row,
                                                    sqlite3* db, int rc) {
    row->sqlite_code = rc & 0xff;
    int extended = db ? sqlite3_extended_errcode(db) : rc;
    row->sqlite_extended_code = (extended & 0xff) == row->sqlite_code ? extended : rc;
    snprintf(row->sqlite_message, sizeof(row->sqlite_message), "%s",
             db ? sqlite3_errmsg(db) : sqlite3_errstr(rc));
    return DIAGNOSTIC_SQLITE_ERROR;
}

// This diagnostic must not borrow another row's owner or use Restore's
// default/alias/fallback identity. A SQLite error is never proof of absence.
static diagnostic_row_state_t diagnostic_read_slot_row(const char* uid,
                                     const char* title_id, const char* dir_name,
                                     diagnostic_slot_row_t* row) {
    memset(row, 0, sizeof(*row));
    char path[SDIMG_PATH_MAX];
    snprintf(path, sizeof(path),
             "/system_data/savedata_prospero/%s/db/user/savedata.db", uid);
    sqlite3* db = NULL;
    sqlite3_stmt* st = NULL;
    diagnostic_row_state_t result;
    int rc = sqlite3_open_v2(path, &db, SQLITE_OPEN_READONLY | SQLITE_OPEN_NOMUTEX, NULL);
    if (rc != SQLITE_OK) goto sqlite_error;
    rc = sqlite3_prepare_v2(db,
        "SELECT rowid, account_id, user_id FROM savedata "
        "WHERE title_id=? AND dir_name=?", -1, &st, NULL);
    if (rc != SQLITE_OK) goto sqlite_error;
    rc = sqlite3_bind_text(st, 1, title_id, -1, SQLITE_STATIC);
    if (rc != SQLITE_OK) goto sqlite_error;
    rc = sqlite3_bind_text(st, 2, dir_name, -1, SQLITE_STATIC);
    if (rc != SQLITE_OK) goto sqlite_error;
    rc = sqlite3_step(st);
    if (rc == SQLITE_DONE) {
        result = DIAGNOSTIC_ROW_ABSENT;
        goto finish;
    }
    if (rc != SQLITE_ROW) goto sqlite_error;
    bool typed_owner = sqlite3_column_type(st, 0) == SQLITE_INTEGER &&
                       sqlite3_column_type(st, 1) == SQLITE_INTEGER &&
                       sqlite3_column_type(st, 2) == SQLITE_INTEGER;
    row->rowid = sqlite3_column_int64(st, 0);
    sqlite3_int64 owner_uid = typed_owner ? sqlite3_column_int64(st, 2) : 0;
    row->owner_known = typed_owner && owner_uid > 0 && (uint64_t)owner_uid <= UINT32_MAX;
    if (row->owner_known) {
        // A typed zero account_id is a valid offline owner, not a default.
        row->account_id = (uint64_t)sqlite3_column_int64(st, 1);
        row->user_id = (uint32_t)owner_uid;
    }
    rc = sqlite3_step(st);
    if (rc == SQLITE_ROW) row->owner_known = false; // Ambiguous exact rows.
    else if (rc != SQLITE_DONE) goto sqlite_error;
    result = DIAGNOSTIC_ROW_FOUND;
    goto finish;
sqlite_error:
    // Capture before finalize/close can overwrite the first error.
    result = diagnostic_row_error(row, db, rc);
finish:
    rc = sqlite3_finalize(st);
    if (rc != SQLITE_OK && result != DIAGNOSTIC_SQLITE_ERROR)
        result = diagnostic_row_error(row, db, rc);
    if (db) {
        rc = sqlite3_close(db);
        if (rc != SQLITE_OK) {
            if (result != DIAGNOSTIC_SQLITE_ERROR)
                result = diagnostic_row_error(row, db, rc);
            (void)sqlite3_close_v2(db);
        }
    }
    return result;
}

static void sealed_key_fingerprint(const char* image, char out[17]) {
    uint8_t sealed[PFS_SEALED_KEY_SIZE], digest[32];
    out[0] = '\0';
    if (!pfs_read_sealed_key(image, sealed)) return;
    sha256_ctx_t ctx;
    sha256_init(&ctx);
    sha256_update(&ctx, sealed, sizeof(sealed));
    sha256_final(&ctx, digest);
    memset(sealed, 0, sizeof(sealed));
    snprintf(out, 17, "%02x%02x%02x%02x%02x%02x%02x%02x",
             digest[0], digest[1], digest[2], digest[3],
             digest[4], digest[5], digest[6], digest[7]);
    memset(digest, 0, sizeof(digest));
}

bool sdimg_diagnostic_target_owner(const char* uid, const char* title_id,
    const char* slot, uint64_t* account_id, uint32_t* user_id,
    sdimg_target_slot_report_t* report) {
    if (!report || !account_id || !user_id) return false;
    memset(report, 0, sizeof(*report));
    snprintf(report->dir_name, sizeof(report->dir_name), "%s", slot ? slot : "");
    if (!uid_ok(uid) || !title_ok(title_id) || !safe_component(slot)) {
        snprintf(report->status, sizeof(report->status), "invalid_identity");
        return false;
    }
    diagnostic_slot_row_t row;
    diagnostic_row_state_t state = diagnostic_read_slot_row(uid, title_id, slot, &row);
    snprintf(report->registry_status, sizeof(report->registry_status), "%s",
        state == DIAGNOSTIC_ROW_FOUND ? "ROW_FOUND" :
        state == DIAGNOSTIC_ROW_ABSENT ? "ROW_ABSENT" : "SQLITE_ERROR");
    report->sqlite_code = row.sqlite_code;
    report->sqlite_extended_code = row.sqlite_extended_code;
    snprintf(report->sqlite_message, sizeof(report->sqlite_message), "%s", row.sqlite_message);
    report->registry_rowid = row.rowid;
    bool ok = state == DIAGNOSTIC_ROW_FOUND && row.owner_known;
    snprintf(report->status, sizeof(report->status), "%s", ok ? "ready" :
        state == DIAGNOSTIC_SQLITE_ERROR ? "sqlite_error" :
        state == DIAGNOSTIC_ROW_ABSENT ? "missing_db_row" : "owner_inconclusive");
    snprintf(report->detail, sizeof(report->detail), "Slot %.63s: %s; SQLite %d extended=%d %.40s",
        slot, report->status, row.sqlite_code, row.sqlite_extended_code, row.sqlite_message);
    if (ok) { *account_id = row.account_id; *user_id = row.user_id; }
    return ok;
}

static sdimg_target_preflight_result_t preflight_target_slot_checked(
                                  const char* user_uid, const char* title_id,
                                  const char* target_title_dir,
                                  const char* dir_name,
                                  bool diagnostic,
                                  sdimg_target_slot_report_t* report,
                                  char* err, size_t err_sz) {
    if (report) {
        memset(report, 0, sizeof(*report));
        snprintf(report->dir_name, sizeof(report->dir_name), "%s", dir_name);
    }
#define SLOT_FAIL(code_, ...) do { \
    if (report) { \
        snprintf(report->status, sizeof(report->status), "%s", (code_)); \
        snprintf(report->detail, sizeof(report->detail), __VA_ARGS__); \
    } \
    (void)set_err(err, err_sz, __VA_ARGS__); \
    return SDIMG_TARGET_PREFLIGHT_BLOCKED; \
} while (0)
    char target_img[SDIMG_PATH_MAX];
    snprintf(target_img, sizeof(target_img), "%s/sdimg_%s",
             target_title_dir, dir_name);
    struct stat st;
    if (stat(target_img, &st) != 0) {
        int stat_errno = errno;
        if (report) report->stat_errno = stat_errno;
        bool denied = stat_errno == EACCES || stat_errno == EPERM;
        SLOT_FAIL(stat_errno == ENOENT ? "missing_container" :
                  denied ? "container_access_denied" : "container_stat_failed",
                  "Slot %s: %s (stat errno=%d: %.48s)", dir_name,
                  stat_errno == ENOENT ? "path not found" :
                  denied ? "access denied" : "stat failed",
                  stat_errno, strerror(stat_errno));
    }
    if (!S_ISREG(st.st_mode))
        SLOT_FAIL("container_wrong_type",
                  "Slot %s: container is not a regular file "
                  "(stat succeeded; mode=0%o)", dir_name, (unsigned)st.st_mode);
    if (report) report->container_bytes = (uint64_t)st.st_size;
    uint64_t account_id = 0;
    uint32_t user_id = 0;
    sfo_info_t target;
    if (diagnostic) {
        diagnostic_slot_row_t row;
        diagnostic_row_state_t state = diagnostic_read_slot_row(
            user_uid, title_id, dir_name, &row);
        if (report) {
            snprintf(report->registry_status, sizeof(report->registry_status), "%s",
                state == DIAGNOSTIC_ROW_FOUND ? "ROW_FOUND" :
                state == DIAGNOSTIC_ROW_ABSENT ? "ROW_ABSENT" : "SQLITE_ERROR");
            report->sqlite_code = row.sqlite_code;
            report->sqlite_extended_code = row.sqlite_extended_code;
            snprintf(report->sqlite_message, sizeof(report->sqlite_message), "%s",
                     row.sqlite_message);
            if (state == DIAGNOSTIC_ROW_FOUND) report->registry_rowid = row.rowid;
        }
        if (state == DIAGNOSTIC_SQLITE_ERROR)
            SLOT_FAIL("sqlite_error", "Slot %s: SQLite error %d (extended=%d): %.70s",
                dir_name, row.sqlite_code, row.sqlite_extended_code, row.sqlite_message);
        if (state == DIAGNOSTIC_ROW_ABSENT)
            SLOT_FAIL("missing_db_row", "Slot %s: exact database row absent (query completed)",
                      dir_name);
        if (!row.owner_known)
            SLOT_FAIL("owner_inconclusive", "Slot %s: exact row owner is incomplete or ambiguous; no defaults used",
                      dir_name);
        account_id = row.account_id;
        user_id = row.user_id;
    } else {
        // Legacy Restore admission and its owner reader are unchanged.
        if (!savedata_db_slot_exists(user_uid, title_id, dir_name))
            SLOT_FAIL("missing_db_row",
                      "Target slot %s is not registered by this PS5. Recreate "
                      "it in the game before restoring.", dir_name);
        if (!local_owner_for_slot(user_uid, title_id, dir_name,
                                  &account_id, &user_id))
            SLOT_FAIL("owner_unavailable",
                      "Target slot %s has no verifiable local owner", dir_name);
    }
    int read_result = pfs_read_image_param_sfo(target_img, &target);
    if (read_result == PFS_SFO_READ_UNMOUNT_UNCERTAIN) {
        const char* detail = "Target mount cleanup is uncertain; retained "
                             "evidence requires inspection before retrying";
        if (report) {
            snprintf(report->status, sizeof(report->status), "unmount_uncertain");
            snprintf(report->detail, sizeof(report->detail), "%s", detail);
        }
        (void)set_err(err, err_sz, "Target slot %s: %s", dir_name, detail);
        return SDIMG_TARGET_PREFLIGHT_UNMOUNT_UNCERTAIN;
    }
    if (read_result != 0)
        SLOT_FAIL("sfo_unreadable",
                  "Target slot %s param.sfo could not be read", dir_name);
    if (strcmp(target.title_id, title_id) != 0)
        SLOT_FAIL("title_mismatch",
                  "Target slot %s has a different TITLE ID", dir_name);
    if (strcmp(target.dir_name, dir_name) != 0)
        SLOT_FAIL("directory_mismatch",
                  "Target slot %s has a different save directory", dir_name);
    if (target.account_id != account_id || target.user_id != user_id)
        SLOT_FAIL("owner_mismatch",
                  "Target slot %s belongs to a different local owner", dir_name);
    if (!target.has_hmac)
        SLOT_FAIL("missing_hmac",
                  "Target slot %s has no usable local PARAMS HMAC", dir_name);
    char key_fp[17];
    sealed_key_fingerprint(target_img, key_fp);
    if (report) {
        snprintf(report->status, sizeof(report->status), "ready");
        snprintf(report->detail, sizeof(report->detail),
                 "Target container, database row and local identity are ready");
        snprintf(report->key_fingerprint,
                 sizeof(report->key_fingerprint), "%s", key_fp);
    }
    log_info("restore[slot=%s]: preflight=ready container_bytes=%llu "
             "key_fp=%s db_row=present", dir_name,
             (unsigned long long)st.st_size,
             key_fp[0] ? key_fp : "unavailable");
#undef SLOT_FAIL
    return SDIMG_TARGET_PREFLIGHT_READY;
}

static bool preflight_target_slot(const char* user_uid, const char* title_id,
                                  const char* target_title_dir,
                                  const char* dir_name,
                                  sdimg_target_slot_report_t* report,
                                  char* err, size_t err_sz) {
    return preflight_target_slot_checked(user_uid, title_id, target_title_dir,
                                         dir_name, false, report, err, err_sz) ==
           SDIMG_TARGET_PREFLIGHT_READY;
}

static sdimg_target_preflight_result_t preflight_target_slots_inner(
                                          const char* user_uid,
                                          const char* title_id,
                                          const char* target_title_dir,
                                          const char slots[][64],
                                          size_t slot_count,
                                          size_t* ready_count,
                                          sdimg_target_slot_report_t* reports,
                                          size_t report_cap,
                                          size_t* report_count,
                                          char* err, size_t err_sz,
                                          bool diagnostic) {
    size_t ready = 0;
    if (ready_count) *ready_count = 0;
    if (report_count) *report_count = 0;
    if (!uid_ok(user_uid) || !title_ok(title_id) || !target_title_dir ||
        !slots || slot_count == 0) {
        (void)set_err(err, err_sz, "Portable target information is incomplete");
        return SDIMG_TARGET_PREFLIGHT_BLOCKED;
    }
    // Reporting an imported slot name is not permission to inspect its target.
    // Leave every unattempted slot explicit, including after an early failure.
    size_t represented = reports ? (slot_count < report_cap ? slot_count : report_cap) : 0;
    for (size_t i = 0; i < represented; i++) {
        memset(&reports[i], 0, sizeof(reports[i]));
        snprintf(reports[i].dir_name, sizeof(reports[i].dir_name), "%s", slots[i]);
        snprintf(reports[i].status, sizeof(reports[i].status), "not_checked");
        snprintf(reports[i].detail, sizeof(reports[i].detail),
                 "Not checked; target preflight stopped before this slot");
    }
    if (report_count) *report_count = represented;
    struct stat st;
    if (stat(target_title_dir, &st) != 0) {
        int stat_errno = errno;
        (void)set_err(err, err_sz,
                      "Target save directory: stat failed (errno=%d: %.48s). "
                      "No slots checked.", stat_errno, strerror(stat_errno));
        return SDIMG_TARGET_PREFLIGHT_BLOCKED;
    }
    if (!S_ISDIR(st.st_mode)) {
        (void)set_err(err, err_sz,
                      "Target save path is not a directory "
                      "(stat succeeded; mode=0%o). No slots checked.",
                      (unsigned)st.st_mode);
        return SDIMG_TARGET_PREFLIGHT_BLOCKED;
    }
    for (size_t i = 0; i < slot_count; i++) {
        sdimg_target_slot_report_t* report =
            reports && i < report_cap ? &reports[i] : NULL;
        if (!safe_component(slots[i])) {
            if (report) {
                snprintf(report->dir_name, sizeof(report->dir_name), "%s",
                         slots[i]);
                snprintf(report->status, sizeof(report->status), "invalid_slot");
                snprintf(report->detail, sizeof(report->detail),
                         "Portable backup contains an invalid slot name");
            }
            if (ready_count) *ready_count = ready;
            (void)set_err(err, err_sz, "Portable backup contains an invalid slot name");
            return SDIMG_TARGET_PREFLIGHT_BLOCKED;
        }
        char slot_err[192] = {0};
        sdimg_target_preflight_result_t result = preflight_target_slot_checked(
            user_uid, title_id, target_title_dir, slots[i], diagnostic, report,
            slot_err, sizeof(slot_err));
        if (result != SDIMG_TARGET_PREFLIGHT_READY) {
            if (ready_count) *ready_count = ready;
            if (err && err_sz) snprintf(err, err_sz, "%s", slot_err);
            return result;
        }
        ready++;
    }
    if (ready_count) *ready_count = ready;
    return SDIMG_TARGET_PREFLIGHT_READY;
}

sdimg_target_preflight_result_t sdimg_restore_preflight_target_slots_checked(
        const char* user_uid, const char* title_id, const char* target_title_dir,
        const char slots[][64], size_t slot_count, size_t* ready_count,
        sdimg_target_slot_report_t* reports, size_t report_cap, size_t* report_count,
        char* err, size_t err_sz) {
    return preflight_target_slots_inner(user_uid, title_id, target_title_dir,
        slots, slot_count, ready_count, reports, report_cap, report_count,
        err, err_sz, false);
}

sdimg_target_preflight_result_t sdimg_diagnose_target_slots_checked(
        const char* user_uid, const char* title_id, const char* target_title_dir,
        const char slots[][64], size_t slot_count, size_t* ready_count,
        sdimg_target_slot_report_t* reports, size_t report_cap, size_t* report_count,
        char* err, size_t err_sz) {
    return preflight_target_slots_inner(user_uid, title_id, target_title_dir,
        slots, slot_count, ready_count, reports, report_cap, report_count,
        err, err_sz, true);
}

bool sdimg_restore_preflight_target_slots(const char* user_uid,
                                          const char* title_id,
                                          const char* target_title_dir,
                                          const char slots[][64],
                                          size_t slot_count,
                                          size_t* ready_count,
                                          sdimg_target_slot_report_t* reports,
                                          size_t report_cap,
                                          size_t* report_count,
                                          char* err, size_t err_sz) {
    return sdimg_restore_preflight_target_slots_checked(
        user_uid, title_id, target_title_dir, slots, slot_count, ready_count,
        reports, report_cap, report_count, err, err_sz) ==
        SDIMG_TARGET_PREFLIGHT_READY;
}

static bool preflight_plain_target_children(const char* root,
                                            const char* user_uid,
                                            const char* title_id,
                                            const char* target_title_dir,
                                            const char selected_slots[][64],
                                            size_t selected_count,
                                            size_t* count,
                                            char* err,
                                            size_t err_sz) {
    DIR* d = opendir(root);
    if (!d) return set_err(err, err_sz, "Could not open portable slot listing");
    bool ok = true;
    struct dirent* e;
    while ((errno = 0, e = readdir(d)) != NULL) {
        if (!safe_component(e->d_name)) continue;
        const char* selected = selected_slots
            ? plain_selected_child(e->d_name, selected_slots, selected_count)
            : NULL;
        if (selected_slots && !selected) continue;
        char plain_dir[SDIMG_PATH_MAX], sfo_path[SDIMG_PATH_MAX];
        snprintf(plain_dir, sizeof(plain_dir), "%s/%s", root, e->d_name);
        snprintf(sfo_path, sizeof(sfo_path), "%s/sce_sys/param.sfo", plain_dir);
        struct stat st;
        if (stat(plain_dir, &st) != 0) {
            ok = set_err(err, err_sz, "Could not inspect portable slot folder");
            break;
        }
        if (!S_ISDIR(st.st_mode)) {
            if (!selected_slots) continue;
            ok = set_err(err, err_sz, "Selected portable slot is not a folder");
            break;
        }
        if (stat(sfo_path, &st) != 0) {
            if (!selected_slots && errno == ENOENT) continue;
            ok = set_err(err, err_sz, "Could not inspect portable slot metadata");
            break;
        }
        if (!S_ISREG(st.st_mode)) {
            if (!selected_slots) continue;
            ok = set_err(err, err_sz, "Selected portable metadata is not a file");
            break;
        }

        sfo_info_t source;
        if (!plain_slot_info_from_dir(plain_dir, title_id, &source,
                                      err, err_sz)) {
            ok = false;
            break;
        }
        if (selected && strcmp(source.dir_name, selected) != 0) {
            ok = set_err(err, err_sz,
                         "Selected slot identity changed: expected %s, found %s",
                         selected, source.dir_name);
            break;
        }
        bool target_ready = selected_slots
            ? preflight_target_slot_checked(user_uid, title_id, target_title_dir,
                                             source.dir_name, true, NULL,
                                             err, err_sz) ==
                SDIMG_TARGET_PREFLIGHT_READY
            : preflight_target_slot(user_uid, title_id, target_title_dir,
                                     source.dir_name, NULL, err, err_sz);
        if (!target_ready) {
            ok = false;
            break;
        }
        (*count)++;
    }
    if (errno != 0 && ok)
        ok = set_err(err, err_sz, "Could not finish portable slot listing");
    if (closedir(d) != 0 && ok)
        ok = set_err(err, err_sz, "Could not close portable slot listing");
    return ok;
}

static bool selected_owner_for_slot(const char* uid, const char* title_id,
                                    const char* slot, uint64_t* account_id,
                                    uint32_t* user_id, char* err, size_t err_sz) {
    diagnostic_slot_row_t row;
    diagnostic_row_state_t state = diagnostic_read_slot_row(uid, title_id, slot,
                                                             &row);
    if (state == DIAGNOSTIC_SQLITE_ERROR)
        return set_err(err, err_sz,
                       "Slot %s: SQLite error %d (extended=%d): %.70s",
                       slot, row.sqlite_code, row.sqlite_extended_code,
                       row.sqlite_message);
    if (state == DIAGNOSTIC_ROW_ABSENT)
        return set_err(err, err_sz, "Slot %s: exact database row absent", slot);
    if (!row.owner_known)
        return set_err(err, err_sz,
                       "Slot %s: exact row owner is incomplete or ambiguous; no defaults used",
                       slot);
    *account_id = row.account_id;
    *user_id = row.user_id;
    return true;
}

static bool restore_plain_set_impl(const char* payload_dir,
                                          const char* user_uid,
                                          const char* title_id,
                                          const char* target_title_dir,
                                          const char* stage_base,
                                          const char selected_slots[][64],
                                          size_t selected_count,
                                          size_t* written_count,
                                          const restore_scope_t* scope,
                                          const char* canonical_zip_path,
                                          portable_transaction_report_t* transaction_report,
                                          const restore_sources_t* originals,
                                          char* err,
                                          size_t err_sz) {
    if (written_count) *written_count = 0;
    if (scope && (!restore_scope_valid(scope) ||
        strcmp(scope->restore_mode, RESTORE_MODE_PORTABLE_SELECTED) ||
        strcmp(scope->target_uid, user_uid ? user_uid : "") ||
        strcmp(scope->title_id, title_id ? title_id : "") ||
        selected_count != scope->selection.count || selected_slots != scope->selection.slots))
        return set_err(err, err_sz, "Portable durable scope/identity invalid");
    if (selected_slots && !scope)
        return set_err(err, err_sz, "Explicit Portable selection requires server-held durable approval");
    if ((!selected_slots && selected_count != 0) ||
        (selected_slots && (selected_count == 0 || selected_count > SDIMG_MAX_ITEMS)))
        return set_err(err, err_sz, "Invalid portable slot selection");
    for (size_t i = 0; i < selected_count; i++) {
        if (!memchr(selected_slots[i], '\0', 64) ||
            !safe_component(selected_slots[i]))
            return set_err(err, err_sz, "Invalid selected slot name");
        for (size_t j = 0; j < i; j++)
            if (strcmp(selected_slots[i], selected_slots[j]) == 0)
                return set_err(err, err_sz, "Duplicate selected slot: %s",
                               selected_slots[i]);
    }
    if (!payload_dir || !target_title_dir || !stage_base)
        return set_err(err, err_sz, "Internal plain-sdimg restore path is missing");
    if (!uid_ok(user_uid))
        return set_err(err, err_sz, "Missing PS5 user for plain-sdimg restore");
    if (!title_ok(title_id))
        return set_err(err, err_sz, "Invalid TITLE ID for plain-sdimg restore");
    struct stat target_dir_st;
    if (stat(target_title_dir, &target_dir_st) != 0 ||
        !S_ISDIR(target_dir_st.st_mode))
        return set_err(err, err_sz,
                       "Target save does not exist. Open the game and create "
                       "the save slots before restoring.");

    log_info("restore[title=%s]: phase=preparing", title_id);

    char slots_root[SDIMG_PATH_MAX];
    snprintf(slots_root, sizeof(slots_root), "%s/slots", payload_dir);
    struct stat slots_st;
    const char* active_root =
        stat(slots_root, &slots_st) == 0 && S_ISDIR(slots_st.st_mode)
        ? slots_root : payload_dir;
    size_t planned_count = 0;
    if (!preflight_plain_target_children(active_root, user_uid, title_id,
                                         target_title_dir, selected_slots,
                                         selected_count, &planned_count,
                                         err, err_sz) || planned_count == 0) {
        if (planned_count == 0 && (!err || !err[0]))
            set_err(err, err_sz, "No portable save slots found in backup");
        return false;
    }
    if (selected_slots && planned_count != selected_count)
        return set_err(err, err_sz,
                       "Selected portable slot inventory differs (%zu/%zu)",
                       planned_count, selected_count);
    log_info("restore[title=%s]: phase=preflight_complete slots=%zu "
             "target_containers=preserved db=read_only",
             title_id, planned_count);
    if (!fs_title_is_closed(title_id))
        return set_err(err, err_sz,
                       "Game must be closed and its state readable before restoring this save");

    char rollback_dir[SDIMG_PATH_MAX];
    snprintf(rollback_dir, sizeof(rollback_dir), "%s_sdimg_rollback",
             stage_base);
    char old_names[SDIMG_MAX_ITEMS][SDIMG_NAME_MAX];
    size_t old_count = 0;
    portable_transaction_t* transaction = NULL;
    portable_authority_t authority = {scope, canonical_zip_path};
    if (scope) {
        if (!portable_authority_current(&authority))
            return set_err(err, err_sz, "Portable durable claim/source hash no longer valid");
        char parent[SDIMG_PATH_MAX], workspace[SDIMG_PATH_MAX];
        int len = snprintf(parent, sizeof(parent), "%s.portable.XXXXXX", stage_base);
        if (len < 0 || (size_t)len >= sizeof(parent) || !mkdtemp(parent))
            return set_err(err, err_sz, "Could not allocate new Portable transaction workspace");
        len = snprintf(workspace, sizeof(workspace), "%s/transaction", parent);
        if (len < 0 || (size_t)len >= sizeof(workspace))
            return set_err(err, err_sz, "Portable transaction workspace too long");
        if (!rollback_snapshot_space(target_title_dir, workspace, err, err_sz)) return false;
        transaction = portable_transaction_begin(scope, target_title_dir, workspace, err, err_sz);
        if (!transaction) {
            if (transaction_report) {
                snprintf(transaction_report->workspace, sizeof(transaction_report->workspace), "%s", workspace);
                snprintf(transaction_report->result, sizeof(transaction_report->result), "RECOVERY_REQUIRED");
                transaction_report->recovery_required = transaction_report->barrier_retained = true;
            }
            return false;
        }
        if (!portable_transaction_set_authority(transaction, portable_authority_current, &authority)) {
            portable_transaction_failed(transaction, "Portable claim/source authority unavailable", false);
            portable_transaction_report(transaction, transaction_report);
            portable_transaction_free(transaction);
            return set_err(err, err_sz, "Portable claim/source authority unavailable; evidence retained");
        }
    } else if (!prepare_restore_snapshot(target_title_dir, old_names, &old_count,
                                        rollback_dir, err, err_sz)) return false;
    sync();
    log_info("restore[title=%s]: phase=rollback_created images=%zu",
             title_id, old_count);

    sdimg_item_t items[SDIMG_MAX_ITEMS];
    memset(items, 0, sizeof(items));
    size_t count = 0;
    size_t ordinal = 0;
    size_t verified_writes = 0;
    bool recovery_required = false;
    bool ok = import_plain_children(active_root, user_uid, target_title_dir,
                                    title_id, stage_base, &ordinal, false,
                                    items, &count, selected_slots, selected_count,
                                    &verified_writes, &recovery_required, transaction, originals, err, err_sz);
    if (written_count) *written_count = verified_writes;
    if (transaction) {
        if (ok && count == planned_count) ok = portable_transaction_finish(transaction, err, err_sz);
        else {
            ok = false;
            portable_transaction_failed(transaction,
                err && err[0] ? err : "Portable native verification incomplete", false);
            if (err && err_sz && !err[0])
                set_err(err, err_sz, "Portable selected verification incomplete; preserve transaction and barrier");
        }
        portable_transaction_report(transaction, transaction_report);
        log_info("restore[title=%s]: scope=portable_selected authorized=%zu attempted=%zu written=%zu verified=%zu uncertain=%s workspace=%s",
            title_id, scope->selection.count,
            transaction_report ? transaction_report->attempted_images : 0,
            transaction_report ? transaction_report->written_images : 0,
            transaction_report ? transaction_report->verified_images : 0,
            transaction_report && transaction_report->publication_uncertain ? "yes" : "no",
            transaction_report ? transaction_report->workspace : "(retained)");
        portable_transaction_free(transaction);
        return ok;
    }
    if (!ok || count != planned_count) {
        // Native mode/content/publication failures retain the candidate,
        // title snapshot and .pending guard. Never auto-rollback or continue.
        if (recovery_required) return false;
        if (ok)
            set_err(err, err_sz,
                    "Portable slot count changed after preflight (%zu/%zu)",
                    count, planned_count);
        rollback_plain_transfer_after_failure(target_title_dir, old_names,
                                              old_count, rollback_dir,
                                              err, err_sz);
        return false;
    }

    // Every imported item reached this point only after private copies of its
    // closed candidate and permanent image passed native modes, complete
    // payload/keystone hashes and target param.sfo identity validation.
    log_info("restore[title=%s]: phase=filesystem_content_verified slots=%zu",
             title_id, count);
    log_info("restore[title=%s]: phase=metadata_verified slots=%zu",
             title_id, count);

    // Every target row and container was created by this PS5 and validated
    // before the first write. Preserve the database and any extra/service
    // images exactly as the destination firmware left them.
    log_info("restore[title=%s]: phase=database_preserved slots=%zu",
             title_id, count);

    // Keep one rolling pre-transfer image set until the next transfer attempt.
    // This is outside restore_stage, so the worker's normal staging cleanup
    // does not erase the last known target state after a successful commit.
    log_info("restore[title=%s]: rollback retained at %s", title_id,
             rollback_dir);
    if (!finish_restore_snapshot(rollback_dir, err, err_sz)) return false;
    log_info("restore[title=%s]: phase=complete slots=%zu", title_id, count);
    log_info("sdimg: plain-sdimg transfer verified for %s/%s (%zu slot(s))",
             user_uid, title_id, count);
    return true;
}

bool sdimg_restore_plain_set_selected_from_payload(const char* payload_dir,
    const char* uid, const char* title, const char* target, const char* stage,
    const char slots[][64], size_t count, size_t* written, const restore_sources_t* originals, char* err, size_t n) {
    return restore_plain_set_impl(payload_dir, uid, title, target, stage,
        slots, count, written, NULL, NULL, NULL, originals, err, n);
}

bool sdimg_restore_portable_scope_from_payload(const char* payload_dir,
    const char* uid, const char* title, const char* target, const char* stage,
    const restore_scope_t* scope, const char* canonical_zip_path,
    portable_transaction_report_t* report, const restore_sources_t* originals,
    size_t* written, char* err, size_t n) {
    if (report) memset(report, 0, sizeof(*report));
    if (!scope || !report) return set_err(err, n, "Portable authority/report required");
    return restore_plain_set_impl(payload_dir, uid, title, target, stage,
        scope->selection.slots, scope->selection.count, written, scope, canonical_zip_path, report, originals, err, n);
}

bool sdimg_restore_plain_set_from_payload(const char* payload_dir,
                                          const char* user_uid,
                                          const char* title_id,
                                          const char* target_title_dir,
                                          const char* stage_base,
                                          const restore_sources_t* originals,
                                          char* err,
                                          size_t err_sz) {
    // Historical callers restore every active portable slot; no selection
    // can be silently inferred from source provenance or a prior HTTP check.
    return sdimg_restore_plain_set_selected_from_payload(
        payload_dir, user_uid, title_id, target_title_dir, stage_base,
        NULL, 0, NULL, originals, err, err_sz);
}

static bool merge_promoted_item(sdimg_item_t* items,
                                size_t* count,
                                size_t max_items,
                                const char* target_title_dir,
                                const char* dir_name,
                                uint64_t bytes,
                                const sfo_info_t* sfo,
                                char* err,
                                size_t err_sz) {
    char image_name[SDIMG_NAME_MAX];
    snprintf(image_name, sizeof(image_name), "sdimg_%s", dir_name);

    size_t idx = *count;
    for (size_t i = 0; i < *count; i++) {
        if (strcmp(items[i].dir_name, dir_name) == 0 ||
            strcmp(items[i].name, image_name) == 0) {
            idx = i;
            break;
        }
    }
    if (idx == *count) {
        if (*count >= max_items)
            return set_err(err, err_sz,
                           "Too many sdimg slots after service-backup promotion");
        memset(&items[idx], 0, sizeof(items[idx]));
        (*count)++;
    }

    snprintf(items[idx].name, sizeof(items[idx].name), "%s", image_name);
    snprintf(items[idx].dir_name, sizeof(items[idx].dir_name), "%s", dir_name);
    snprintf(items[idx].dst, sizeof(items[idx].dst), "%s/%s",
             target_title_dir, image_name);
    items[idx].bytes = bytes;
    if (sfo) {
        items[idx].have_sfo = true;
        items[idx].sfo = *sfo;
    }
    return true;
}

static bool promote_service_backup_images(const char* payload_dir,
                                          const char* user_uid,
                                          const char* target_title_dir,
                                          const char* stage_base,
                                          const char* title_id,
                                          char service_names[][SDIMG_NAME_MAX],
                                          size_t service_count,
                                          sdimg_item_t* items,
                                          size_t* count,
                                          size_t max_items,
                                          char* err,
                                          size_t err_sz) {
    for (size_t i = 0; i < service_count; i++) {
        char src[SDIMG_PATH_MAX], plain_dir[SDIMG_PATH_MAX];
        char snap_dir[SDIMG_PATH_MAX], target_img[SDIMG_PATH_MAX];
        snprintf(src, sizeof(src), "%s/%s", payload_dir, service_names[i]);
        snprintf(plain_dir, sizeof(plain_dir), "%s_scebu_%zu_plain",
                 stage_base, i);
        snprintf(snap_dir, sizeof(snap_dir), "%s_scebu_%zu_snap",
                 stage_base, i);

        pfs_fs_rmrf(plain_dir);
        pfs_fs_rmrf(snap_dir);
        log_info("sdimg: promoting service backup %s", service_names[i]);
        if (!pfs_resign_dump_image_to_dir(src, plain_dir)) {
            pfs_fs_rmrf(plain_dir);
            return set_err(err, err_sz,
                           "Could not mount service backup %s",
                           service_names[i]);
        }

        sfo_info_t sfo;
        if (!plain_slot_info_from_dir(plain_dir, title_id, &sfo,
                                      err, err_sz)) {
            pfs_fs_rmrf(plain_dir);
            return false;
        }
        snprintf(target_img, sizeof(target_img), "%s/sdimg_%s",
                 target_title_dir, sfo.dir_name);

        bool active_present = false;
        for (size_t j = 0; j < *count; j++) {
            if (strcmp(items[j].dir_name, sfo.dir_name) == 0) {
                active_present = true;
                break;
            }
        }
        if (active_present) {
            // The backup carries BOTH the active slot and this service backup
            // for the same dir. Promote the snapshot OVER the active slot only
            // when it is genuinely NEWER — a service backup is usually the
            // older copy, so blindly promoting would revert the save. We
            // compare the newest internal file mtime of each sealed image.
            char active_img[SDIMG_PATH_MAX];
            snprintf(active_img, sizeof(active_img), "%s/sdimg_%s",
                     payload_dir, sfo.dir_name);
            int64_t t_active = 0, t_scebu = 0;
            bool have_a = pfs_image_newest_mtime(active_img, &t_active);
            bool have_s = pfs_image_newest_mtime(src, &t_scebu);
            if (!have_a || !have_s) {
                log_warn("sdimg: cannot compare dates for %s vs active %s "
                         "(mtime unavailable) — keeping active, not promoting",
                         service_names[i], sfo.dir_name);
                pfs_fs_rmrf(plain_dir);
                continue;
            }
            if (t_scebu <= t_active) {
                log_info("sdimg: service backup %s (%lld) not newer than active "
                         "%s (%lld) — keeping active slot",
                         service_names[i], (long long)t_scebu, sfo.dir_name,
                         (long long)t_active);
                pfs_fs_rmrf(plain_dir);
                continue;
            }
            log_info("sdimg: service backup %s is NEWER (%lld > %lld) — "
                     "promoting over active slot %s", service_names[i],
                     (long long)t_scebu, (long long)t_active, sfo.dir_name);
        }

        struct stat st;

        uint64_t local_account_id = 0;
        uint32_t local_user_id = 0;
        if (!local_owner_for_slot(user_uid, title_id, sfo.dir_name,
                                  &local_account_id, &local_user_id)) {
            pfs_fs_rmrf(plain_dir);
            pfs_fs_rmrf(snap_dir);
            return set_err(err, err_sz,
                           "Could not detect the local PS5 account. Create "
                           "any save once for this user, then retry.");
        }
        sfo_info_t db_sfo = sfo_with_local_identity(&sfo, local_account_id,
                                                    local_user_id);
        if (!fs_mkdir_p(snap_dir) ||
            !restore_plain_dir_to_slot_image(plain_dir, target_img, snap_dir,
                                             title_id, sfo.dir_name,
                                             local_account_id,
                                             local_user_id, false, NULL, NULL, NULL, err, err_sz)) {
            pfs_fs_rmrf(plain_dir);
            pfs_fs_rmrf(snap_dir);
            if (err && err_sz && !err[0])
                set_err(err, err_sz, "Could not promote %s into sdimg_%s",
                        service_names[i], sfo.dir_name);
            return false;
        }
        pfs_fs_rmrf(snap_dir);

        if (stat(target_img, &st) != 0) st.st_size = 0;
        if (!merge_promoted_item(items, count, max_items, target_title_dir,
                                 sfo.dir_name, (uint64_t)st.st_size,
                                 &db_sfo, err, err_sz)) {
            pfs_fs_rmrf(plain_dir);
            return false;
        }
        log_info("sdimg: promoted %s -> sdimg_%s",
                 service_names[i], sfo.dir_name);
        pfs_fs_rmrf(plain_dir);
    }
    return true;
}

// This console's PSN account id, read from any existing row in its
// savedata.db. Returns 0 when it cannot be determined (no DB, no rows, or no
// non-zero account) — callers then SKIP the cross-console check rather than
// guess, so a same-console restore is never blocked by a false positive.
static int64_t console_account_id(const char* uid) {
    if (!uid || !uid[0]) return 0;
    char db_path[SDIMG_PATH_MAX];
    snprintf(db_path, sizeof(db_path),
             "/system_data/savedata_prospero/%s/db/user/savedata.db", uid);
    sqlite3* db = NULL;
    if (sqlite3_open_v2(db_path, &db,
                        SQLITE_OPEN_READONLY | SQLITE_OPEN_NOMUTEX, NULL)
        != SQLITE_OK) {
        if (db) sqlite3_close(db);
        return 0;
    }
    int64_t aid = 0;
    sqlite3_stmt* st = NULL;
    if (sqlite3_prepare_v2(db,
            "SELECT account_id FROM savedata WHERE account_id != 0 LIMIT 1",
            -1, &st, NULL) == SQLITE_OK) {
        if (sqlite3_step(st) == SQLITE_ROW) aid = sqlite3_column_int64(st, 0);
        sqlite3_finalize(st);
    }
    sqlite3_close(db);
    return aid;
}

// Refuse a raw restore whose backup provably belongs to a DIFFERENT PSN
// account than this console (audit #1/#49): a byte-copy of an image sealed for
// another console will mount-fail and look corrupt. We only refuse on a
// POSITIVE mismatch (both account ids known and different); when either side is
// unknown we proceed exactly as before, so same-console restores are untouched.
static bool raw_set_provenance_ok(const char* uid, const sdimg_item_t* items,
                                  size_t count, char* err, size_t err_sz) {
    int64_t console_aid = console_account_id(uid);
    if (console_aid == 0) return true;        // console identity unknown → skip
    for (size_t i = 0; i < count; i++) {
        if (!items[i].have_sfo || items[i].sfo.account_id == 0) continue;
        if ((int64_t)items[i].sfo.account_id != console_aid)
            return set_err(err, err_sz,
                "This backup belongs to a different PS5 account (made on another "
                "console). Restoring it raw would corrupt the save. Only an "
                "exact backup of the current slot on THIS console is supported.");
    }
    return true;
}

static bool raw_item_identity_verified(const sdimg_item_t* item,
                                       const char* title_id,
                                       char* err,
                                       size_t err_sz) {
    if (!item->have_sfo)
        return set_err(err, err_sz,
                       "Cannot verify %s: its param.sfo is not readable",
                       item->name);
    if (!sfo_title_matches(&item->sfo, title_id))
        return set_err(err, err_sz,
                       "%s belongs to a different TITLE ID", item->name);
    if (!item->sfo.dir_name[0] ||
        strcmp(item->sfo.dir_name, item->dir_name) != 0)
        return set_err(err, err_sz,
                       "%s slot name does not match SAVEDATA_DIRECTORY",
                       item->name);
    struct stat st;
    if (stat(item->dst, &st) != 0 || !S_ISREG(st.st_mode))
        return set_err(err, err_sz,
                       "Cannot restore %s: the original slot does not exist on "
                       "this PS5. Open the game and create it first.",
                       item->dir_name);
    if (!pfs_save_images_share_sealed_key(item->src, item->dst))
        return set_err(err, err_sz,
                       "Cannot restore %s safely: its encrypted key does not "
                       "match the current slot. This backup may come from "
                       "another PS5 or from a save that was recreated.",
                       item->dir_name);
    return true;
}

static bool raw_db_rows_exist(const char* uid, const char* title_id,
                              const sdimg_item_t* items, size_t count,
                              char* err, size_t err_sz) {
    char db_path[SDIMG_PATH_MAX];
    snprintf(db_path, sizeof(db_path),
             "/system_data/savedata_prospero/%s/db/user/savedata.db", uid);
    sqlite3* db = NULL;
    if (sqlite3_open_v2(db_path, &db,
                        SQLITE_OPEN_READONLY | SQLITE_OPEN_NOMUTEX, NULL)
        != SQLITE_OK) {
        if (db) sqlite3_close(db);
        return set_err(err, err_sz,
                       "Cannot verify savedata.db; raw restore was not started");
    }
    bool ok = true;
    for (size_t i = 0; i < count; i++) {
        if (row_exists(db, title_id, items[i].dir_name)) continue;
        set_err(err, err_sz,
                "Cannot restore %s: the slot is not registered on this PS5. "
                "Open the game and create it first.", items[i].dir_name);
        ok = false;
        break;
    }
    sqlite3_close(db);
    return ok;
}

static bool raw_service_backups_verified(
        const char* payload_dir, const char* target_title_dir,
        char names[][SDIMG_NAME_MAX], size_t count,
        char* err, size_t err_sz) {
    for (size_t i = 0; i < count; i++) {
        char src[SDIMG_PATH_MAX], dst[SDIMG_PATH_MAX];
        snprintf(src, sizeof(src), "%s/%s", payload_dir, names[i]);
        snprintf(dst, sizeof(dst), "%s/%s", target_title_dir, names[i]);
        struct stat st;
        if (stat(dst, &st) == 0 && S_ISREG(st.st_mode) &&
            pfs_save_images_share_sealed_key(src, dst))
            continue;

        // Do not pass an untrusted auxiliary image to /dev/pfsmgr merely to
        // discover whether it belongs here. Prove lineage using the matching
        // active image in the same backup instead. That active image has
        // already been checked against the live destination slot above.
        const char* suffix = names[i] + strlen("sdimg_sce_bu_");
        char active[SDIMG_PATH_MAX];
        snprintf(active, sizeof(active), "%s/sdimg_%s", payload_dir, suffix);
        if (stat(active, &st) == 0 && S_ISREG(st.st_mode) &&
            pfs_save_images_share_sealed_key(src, active))
            continue;

        return set_err(err, err_sz,
                       "Cannot verify service backup %s against its existing "
                       "or active slot; restore was not started", names[i]);
    }
    return true;
}

static bool reseal_raw_item_to_current_slot(sdimg_item_t* item,
                                            const char* user_uid,
                                            const char* title_id,
                                            const char* target_title_dir,
                                            const char* stage_base,
                                            size_t ordinal,
                                            char* err,
                                            size_t err_sz) {
    char plain_dir[SDIMG_PATH_MAX], snap_dir[SDIMG_PATH_MAX];
    snprintf(plain_dir, sizeof(plain_dir), "%s_raw_%zu_plain",
             stage_base, ordinal);
    snprintf(snap_dir, sizeof(snap_dir), "%s_raw_%zu_snap",
             stage_base, ordinal);
    pfs_fs_rmrf(plain_dir);
    pfs_fs_rmrf(snap_dir);

    if (!pfs_resign_dump_image_to_dir(item->src, plain_dir)) {
        pfs_fs_rmrf(plain_dir);
        return set_err(err, err_sz, "Could not decrypt %s", item->name);
    }

    sfo_info_t sfo;
    if (!plain_slot_info_from_dir(plain_dir, title_id, &sfo, err, err_sz)) {
        pfs_fs_rmrf(plain_dir);
        return false;
    }
    if (strcmp(sfo.dir_name, item->dir_name) != 0) {
        pfs_fs_rmrf(plain_dir);
        return set_err(err, err_sz,
                       "%s decrypted slot name changed unexpectedly",
                       item->name);
    }

    uint64_t local_account_id = 0;
    uint32_t local_user_id = 0;
    if (!local_owner_for_slot(user_uid, title_id, sfo.dir_name,
                              &local_account_id, &local_user_id)) {
        pfs_fs_rmrf(plain_dir);
        pfs_fs_rmrf(snap_dir);
        return set_err(err, err_sz,
                       "Could not detect the local PS5 account. Create any "
                       "save once for this user, then retry.");
    }
    sfo_info_t db_sfo = sfo_with_local_identity(&sfo, local_account_id,
                                                local_user_id);
    if (!fs_mkdir_p(snap_dir) ||
        !restore_plain_dir_to_slot_image(plain_dir, item->dst, snap_dir,
                                         title_id, sfo.dir_name,
                                         local_account_id,
                                         local_user_id, false, NULL, NULL, NULL, err, err_sz)) {
        pfs_fs_rmrf(plain_dir);
        pfs_fs_rmrf(snap_dir);
        return false;
    }

    struct stat st;
    if (stat(item->dst, &st) != 0 || !S_ISREG(st.st_mode)) {
        pfs_fs_rmrf(plain_dir);
        pfs_fs_rmrf(snap_dir);
        return set_err(err, err_sz,
                       "Re-sealed image is missing for %s", item->dir_name);
    }
    item->bytes = (uint64_t)st.st_size;
    item->have_sfo = true;
    item->sfo = db_sfo;
    snprintf(item->name, sizeof(item->name), "sdimg_%s", sfo.dir_name);
    snprintf(item->dst, sizeof(item->dst), "%s/sdimg_%s",
             target_title_dir, sfo.dir_name);

    pfs_fs_rmrf(plain_dir);
    pfs_fs_rmrf(snap_dir);
    log_info("sdimg: smart re-sealed raw backup into %s", item->dst);
    return true;
}

static bool raw_published_image_verified(const restore_sources_t* originals,
                                          const char* src, const char* dst,
                                          const char* name, char* err, size_t err_sz) {
    const restore_source_entry_t* expected = restore_sources_find(originals, src);
    char observed[65]; struct stat st;
    if (!expected || expected->directory)
        return set_err(err, err_sz, "Original RAW checksum unavailable: %s", name);
    errno = 0;
    if (lstat(dst, &st) || !S_ISREG(st.st_mode) || !sha256_file_hex(dst, observed)) {
        int saved = errno;
        log_warn("sdimg: result=failed phase=readback_published image=%s errno=%d", name, saved);
        return set_err(err, err_sz, "RAW published image unreadable: %s (errno %d)", name, saved);
    }
    if (st.st_size < 0 || (uint64_t)st.st_size != expected->bytes || strcmp(expected->sha256, observed)) {
        log_warn("sdimg: result=failed phase=readback_sha256 image=%s", name);
        return set_err(err, err_sz, "RAW published image SHA-256 mismatch: %s", name);
    }
    log_info("sdimg: readback image=%s result=verified sha256=%s", name, observed);
    return true;
}

bool sdimg_restore_from_payload(const char* payload_dir,
                                const char* user_uid,
                                const char* title_id,
                                const char* target_title_dir,
                                const char* stage_base,
                                const restore_sources_t* originals,
                                bool promote_service_backups,
                                bool fix_zeroed_sfo,
                                char* err,
                                size_t err_sz) {
    if (!payload_dir || !target_title_dir || !stage_base)
        return set_err(err, err_sz, "Internal sdimg restore path is missing");
    if (!uid_ok(user_uid))
        return set_err(err, err_sz, "Missing PS5 user for sdimg restore");
    if (!title_ok(title_id))
        return set_err(err, err_sz, "Invalid TITLE ID for sdimg restore");

    if (!originals || !originals->count)
        return set_err(err, err_sz, "Original backup checksums are required; no saves changed");

    sdimg_item_t items[SDIMG_MAX_ITEMS];
    bool item_overflow = false, service_overflow = false;
    bool unmount_uncertain = false;
    size_t count = collect_sdimg_items(payload_dir, target_title_dir,
                                       items, SDIMG_MAX_ITEMS,
                                       &item_overflow, &unmount_uncertain);
    if (unmount_uncertain)
        return set_err(err, err_sz,
                       "RAW metadata mount cleanup is uncertain; retained "
                       "evidence requires inspection before retrying");
    char service_names[SDIMG_MAX_ITEMS][SDIMG_NAME_MAX];
    size_t service_count = collect_service_backup_names(payload_dir,
                                                        service_names,
                                                        SDIMG_MAX_ITEMS,
                                                        &service_overflow);
    if (item_overflow || service_overflow)
        return set_err(err, err_sz,
                       "Backup contains more than %d sdimg images; refusing partial restore",
                       SDIMG_MAX_ITEMS);
    if (count == 0 && service_count == 0)
        return set_err(err, err_sz, "No sdimg_* files found in backup");
    if (count == 0 && service_count > 0 && !promote_service_backups)
        return set_err(err, err_sz,
                       "Backup only contains service snapshots; no active save image can be restored safely");
    if (service_count && promote_service_backups)
        log_info("sdimg: %zu service backup image(s) will be considered for "
                 "missing active slots only",
                 service_count);
    else if (service_count)
        log_warn("sdimg: %zu service backup image(s) copied only; they cannot "
                 "replace a missing active save image safely",
                 service_count);

    size_t raw_count = count;
    log_info("sdimg: restoring %zu active image(s), %zu service backup(s) into %s",
             raw_count, service_count, target_title_dir);
    struct stat target_st;
    if (stat(target_title_dir, &target_st) != 0 || !S_ISDIR(target_st.st_mode))
        return set_err(err, err_sz,
                       "The save does not exist on this PS5. Open the game and "
                       "create it before restoring a raw backup.");

    // Cross-console provenance gate (audit #1/#49): refuse BEFORE touching any
    // file when the backup provably belongs to another PSN account. Nothing has
    // been copied yet, so there is nothing to roll back.
    if (!raw_set_provenance_ok(user_uid, items, count, err, err_sz))
        return false;

    // A raw image is safe only for the exact registered slot lineage. Validate
    // every active image and DB row before creating a rollback snapshot or
    // changing any live file.
    for (size_t i = 0; i < count; i++)
        if (!raw_item_identity_verified(&items[i], title_id, err, err_sz))
            return false;
    if (!raw_db_rows_exist(user_uid, title_id, items, count, err, err_sz))
        return false;
    if (!raw_service_backups_verified(payload_dir, target_title_dir,
                                      service_names, service_count,
                                      err, err_sz))
        return false;

    size_t expected_images = 0, prefix_size = strlen(payload_dir);
    for (size_t i = 0; i < originals->count; i++) {
        const restore_source_entry_t* entry = &originals->entries[i];
        if (entry->directory || strncmp(entry->path, payload_dir, prefix_size) ||
            entry->path[prefix_size] != '/') continue;
        const char* name = entry->path + prefix_size + 1;
        if (sdimg_any_name_ok(name)) expected_images++;
    }
    if (expected_images != count + service_count)
        return set_err(err, err_sz, "Original backup image inventory changed; no saves changed");

    for (size_t i = 0; i < count; i++)
        if (!restore_sources_file_matches(originals, items[i].src, items[i].src))
            return set_err(err, err_sz, "Original backup image changed: %s; no saves changed", items[i].name);
    for (size_t i = 0; i < service_count; i++) {
        char source[SDIMG_PATH_MAX];
        int n = snprintf(source, sizeof(source), "%s/%s", payload_dir, service_names[i]);
        if (n < 0 || n >= (int)sizeof(source) || !restore_sources_file_matches(originals, source, source))
            return set_err(err, err_sz, "Original service image changed: %s; no saves changed", service_names[i]);
    }

    char rollback_dir[SDIMG_PATH_MAX];
    snprintf(rollback_dir, sizeof(rollback_dir), "%s_sdimg_rollback",
             stage_base);
    char old_names[SDIMG_MAX_ITEMS][SDIMG_NAME_MAX];
    size_t old_count = 0;
    if (!prepare_restore_snapshot(target_title_dir, old_names, &old_count,
                                   rollback_dir, err, err_sz))
        return false;
    if (!log_durable("sdimg: rollback_created images=%zu", old_count))
        return set_err(err, err_sz, "RAW rollback log could not be persisted; no image copied");

    for (size_t i = 0; i < count; i++) {
        // SAME-CONSOLE RESTORE = byte-for-byte copy of the encrypted image,
        // exactly like PS5 Payload Manager. We do NOT decrypt + re-seal here.
        // The re-seal rewrites the PFS header/hash-tree; the game then reads
        // the save as CORRUPT even though the decrypted data body is intact
        // (confirmed on hardware: a TostónSync re-sealed image differs from a raw
        // PS5Upload image ONLY in bytes 185..0x240000, the header/hash region,
        // and that breaks the save). A byte-copy of any image this console
        // produced always re-mounts, because the per-console master key unwraps
        // its own sealed keys regardless of per-save "lineage". Re-seal is only
        // meaningful for CROSS-console transfer, which stays behind the
        // experimental path — never on a normal restore.
        (void)reseal_raw_item_to_current_slot;
        if (!copy_file_atomic(items[i].src, items[i].dst)) {
            log_warn("sdimg: copy failed for %s — rolling back",
                     items[i].name);
            set_err(err, err_sz, "Could not copy %s", items[i].name);
            rollback_sdimg_set_after_failure(target_title_dir, old_names,
                                             old_count, rollback_dir,
                                             err, err_sz);
            return false;
        }
        log_info("sdimg: copied %s (%llu B, raw byte-for-byte)", items[i].name,
                 (unsigned long long)items[i].bytes);
    }

    // Copy the backup's service-backup (sce_bu_) images too, so the on-disk set
    // matches the backup exactly — and remove any stale sce_bu_ left from a
    // previous restore that the new backup doesn't carry.
    if (!copy_service_backup_images(payload_dir, target_title_dir,
                                    service_names, service_count, err, err_sz)) {
        log_warn("sdimg: service-backup copy failed — rolling back files");
        rollback_sdimg_set_after_failure(target_title_dir, old_names,
                                         old_count, rollback_dir,
                                         err, err_sz);
        return false;
    }

    if (promote_service_backups) {
        if (!promote_service_backup_images(payload_dir, user_uid,
                                           target_title_dir,
                                           stage_base, title_id,
                                           service_names, service_count,
                                           items, &count, SDIMG_MAX_ITEMS,
                                           err, err_sz)) {
            log_warn("sdimg: service-backup promotion failed — rolling back");
            rollback_sdimg_set_after_failure(target_title_dir, old_names,
                                             old_count, rollback_dir,
                                             err, err_sz);
            return false;
        }
    }

    // CONSERVATIVE RESTORE: never delete on-disk slots or service-backup
    // images just because the backup being restored doesn't contain them.
    // A backup can legitimately be a single slot (or a partial set), and the
    // old behaviour treated any restore as a full set — restoring one slot
    // would wipe the others. Restore now only adds/overwrites what is in the
    // backup; extra existing slots are left untouched (the user can remove a
    // save from the PS5 menu if they want). PS5 Payload Manager behaves the
    // same way. (Pruning helpers kept for a future explicit "mirror" mode.)
    (void)raw_count;
    (void)remove_sdimg_not_in_backup;
    (void)remove_service_backups_not_in_payload;

    // Raw restore deliberately leaves savedata.db untouched. Every row was
    // verified above, and the PS5 already owns the correct metadata.

    sync();

    // EXPERIMENTAL, opt-in: re-seal any slot whose param.sfo was zeroed,
    // rebuilding it from sibling metadata + a reused PARAMS HMAC. The raw
    // restore above already succeeded and the DB is committed; this only
    // touches images flagged as having a corrupt SFO, and rolls each one back
    // internally on failure. A failure here does NOT fail the whole restore.
    if (fix_zeroed_sfo) {
        size_t fixed = 0, zeroed = 0;
        for (size_t i = 0; i < count; i++) {
            if (!items[i].sfo_zeroed) continue;
            zeroed++;
            sfo_info_t meta;
            const uint8_t* hmac = NULL;
            build_fix_meta(title_id, &items[i], items, count, &meta, &hmac);
            if (!hmac)
                log_warn("sdimg: fix_zeroed_sfo on for %s but no sibling HMAC "
                         "available — rebuilding param.sfo without HMAC",
                         items[i].name);
            int r = pfs_resign_fix_zeroed_sfo(items[i].dst, &meta, hmac,
                                              rollback_dir);
            if (r == 1) fixed++;
            else if (r < 0)
                log_warn("sdimg: could not repair zeroed param.sfo for %s "
                         "(left as restored)", items[i].name);
        }
        if (zeroed)
            log_info("sdimg: param.sfo repair pass — %zu/%zu zeroed slot(s) "
                     "re-sealed", fixed, zeroed);
    }

    if (!promote_service_backups && !fix_zeroed_sfo) {
        bool verified = true;
        for (size_t i = 0; i < count && verified; i++)
            verified = raw_published_image_verified(originals, items[i].src, items[i].dst,
                                                    items[i].name, err, err_sz);
        for (size_t i = 0; i < service_count && verified; i++) {
            char src[SDIMG_PATH_MAX], dst[SDIMG_PATH_MAX];
            int a = snprintf(src, sizeof(src), "%s/%s", payload_dir, service_names[i]);
            int b = snprintf(dst, sizeof(dst), "%s/%s", target_title_dir, service_names[i]);
            if (a < 0 || a >= (int)sizeof(src) || b < 0 || b >= (int)sizeof(dst))
                verified = set_err(err, err_sz, "RAW readback path exceeds its limit");
            else verified = raw_published_image_verified(originals, src, dst, service_names[i], err, err_sz);
        }
        if (!verified) {
            log_warn("sdimg: original backup verification failed — rolling back entire image set");
            if (rollback_sdimg_set_after_failure(target_title_dir, old_names,
                                                 old_count, rollback_dir, err, err_sz)) {
                log_info("sdimg: result=failed original_save_restored images=%zu", old_count);
                set_err(err, err_sz, "Backup verification failed; your previous save was restored");
            }
            return false;
        }
    }
    if (!finish_restore_snapshot(rollback_dir, err, err_sz)) {
        log_warn("sdimg: result=failed phase=finish_snapshot");
        return false;
    }
    if (!promote_service_backups && !fix_zeroed_sfo)
        log_info("sdimg: result=verified images=%zu", count + service_count);
    log_info("sdimg: rollback retained at %s", rollback_dir);
    log_info("sdimg: restore complete for %s/%s (%zu image(s))",
             user_uid, title_id, count);
    return true;
}
