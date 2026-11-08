#define _FILE_OFFSET_BITS 64

#include "import_session.h"
#include "fs.h"
#include "log.h"
#include "pfs_resign.h"
#include "sha256.h"
#include "usb.h"
#include "zip.h"
#include "version.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <time.h>
#include <unistd.h>

static pthread_mutex_t s_lock = PTHREAD_MUTEX_INITIALIZER;
static import_session_info_t s_session;
// Separate from the historical receipt ABI; only v4 checkpoints carry this authority.
static char s_raw_target_uid[16];
static unsigned long s_seq = 1;
static char s_state_path[512];
static bool sha_text_ok(const char* s);
static bool s_checkpoint_uncertain;
static char s_preserved_dir[512];
static bool s_preserved_uncertain;
static bool s_observation_only;
static bool s_observed_checkpoint_present;
static bool s_observed_historical_receipt_present;
static bool file_matches_sha(const char* path, const char* expected,
                             uint64_t expected_size);

// Separate, non-authorizing incarnation evidence. This is not a checkpoint
// schema change and is never loaded as a receipt or work session.
typedef struct {
    char magic[16];
    uint32_t schema, size;
    char id[48], path[512], canonical_sha256[65], container[64];
    individual_backup_t item;
    char sha256[65];
} individual_import_record_t;

// Schema 1 retains the complete original work checkpoint as evidence. It is
// deliberately not fed back into the work-session loader or receipt APIs.
// Unknown schemas/sizes block registry operations instead of being forgotten.
#define PRESERVED_CHECKPOINT_MAX 16384
typedef struct {
    char magic[16];
    uint32_t schema;
    uint32_t size;
    import_preserved_info_t info;
    uint32_t checkpoint_size;
    unsigned char checkpoint[PRESERVED_CHECKPOINT_MAX];
    char sha256[65];
} preserved_record_t;

// Historical schema 1 predates Portable target-state approvals. Read its exact
// previous ABI into a dedicated representation; never feed it into work-session
// loaders or manufacture current authority from its receipt evidence.
typedef struct {
    restore_selection_t selection;
    char import_id[48], title_id[16], target_uid[16];
    char source_sha256[65], portable_sha256[65], receipt[65];
    size_t available_slots;
} preserved_scope_v1_t;
typedef struct {
    unsigned char prefix[offsetof(import_session_info_t, restore_scope)];
    preserved_scope_v1_t scope;
} preserved_session_v1_t;
typedef struct {
    preserved_session_v1_t historical;
    unsigned char suffix[sizeof(import_preserved_info_t) -
                         offsetof(import_preserved_info_t, metadata)];
} preserved_info_v1_t;
typedef struct {
    char magic[16];
    uint32_t schema, size;
    preserved_info_v1_t info;
    uint32_t checkpoint_size;
    unsigned char checkpoint[PRESERVED_CHECKPOINT_MAX];
    char sha256[65];
} preserved_record_v1_t;
_Static_assert(offsetof(preserved_session_v1_t, scope) ==
               offsetof(import_session_info_t, restore_scope), "Historical prefix ABI");
_Static_assert(sizeof(preserved_session_v1_t) % 8 == 0, "Historical suffix ABI");

#ifdef IMPORT_SESSION_TEST
static import_preserve_fault_fn s_preserve_fault;
void import_session_preserve_test_fault(import_preserve_fault_fn fault) {
    s_preserve_fault = fault;
}
#define PRESERVE_BOUNDARY(n) (!s_preserve_fault || !s_preserve_fault(n))
#else
#define PRESERVE_BOUNDARY(n) true
#endif

static void hash_bytes(const void* bytes, size_t size, char out[65]) {
    sha256_ctx_t hash;
    unsigned char digest[32];
    sha256_init(&hash); sha256_update(&hash, bytes, size); sha256_final(&hash, digest);
    for (size_t i = 0; i < 32; i++) snprintf(out + i * 2, 3, "%02x", digest[i]);
}

static bool preserved_id_valid(const char* id) {
    return id && id[0] && strlen(id) < sizeof(s_session.id) &&
        strspn(id, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_") == strlen(id);
}

static bool preserved_record_path(const char* id, char path[512]) {
    if (!s_preserved_dir[0] || !preserved_id_valid(id)) return false;
    int n = snprintf(path, 512, "%s/import_%s.record", s_preserved_dir, id);
    return n > 0 && n < 512;
}

static bool stable_regular_read(const char* path, void* bytes, size_t size,
                                bool exact, size_t* actual) {
    struct stat before, opened, after;
    if (lstat(path, &before) || !S_ISREG(before.st_mode) ||
        before.st_size < 1 || (uint64_t)before.st_size > size ||
        (exact && (uint64_t)before.st_size != size)) return false;
    int fd = open(path, O_RDONLY | O_NOFOLLOW | O_NONBLOCK);
    if (fd < 0) return false;
    bool ok = !fstat(fd, &opened) && S_ISREG(opened.st_mode) &&
        before.st_dev == opened.st_dev && before.st_ino == opened.st_ino &&
        before.st_size == opened.st_size;
    size_t got = 0;
    while (ok && got < (size_t)before.st_size) {
        ssize_t n = read(fd, (char*)bytes + got, (size_t)before.st_size - got);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) ok = false; else got += (size_t)n;
    }
    unsigned char extra;
    if (ok) ok = read(fd, &extra, 1) == 0 && !fstat(fd, &after) &&
        before.st_dev == after.st_dev && before.st_ino == after.st_ino &&
        before.st_size == after.st_size && before.st_mtime == after.st_mtime &&
        before.st_ctime == after.st_ctime && !lstat(path, &opened) &&
        before.st_dev == opened.st_dev && before.st_ino == opened.st_ino;
    if (close(fd)) ok = false;
    if (ok && actual) *actual = got;
    return ok;
}

static bool terminated(const char* s, size_t n) { return memchr(s, 0, n) != NULL; }
#define FIELD_TERMINATED(s, f) terminated((s)->f, sizeof((s)->f))

static bool preserved_record_read(const char* path, preserved_record_t* record) {
    char sha[65], checkpoint_sha[65];
    size_t wire_size = sizeof(*record), checkpoint_offset = offsetof(preserved_record_t, checkpoint);
    struct stat st;
    if (lstat(path, &st) || !S_ISREG(st.st_mode)) return false;
    if ((uint64_t)st.st_size == sizeof(preserved_record_v1_t)) {
        preserved_record_v1_t old;
        if (!stable_regular_read(path, &old, sizeof(old), true, NULL)) return false;
        hash_bytes(&old, offsetof(preserved_record_v1_t, sha256), sha);
        memset(record, 0, sizeof(*record));
        memcpy(record->magic, old.magic, sizeof(old.magic));
        record->schema = old.schema; record->size = old.size;
        memcpy(&record->info.historical, old.info.historical.prefix,
               sizeof(old.info.historical.prefix));
        const preserved_scope_v1_t* source = &old.info.historical.scope;
        restore_scope_t* scope = &record->info.historical.restore_scope;
        memcpy(&scope->selection, &source->selection, sizeof(scope->selection));
        memcpy(scope->import_id, source->import_id, sizeof(scope->import_id));
        memcpy(scope->title_id, source->title_id, sizeof(scope->title_id));
        memcpy(scope->target_uid, source->target_uid, sizeof(scope->target_uid));
        memcpy(scope->source_sha256, source->source_sha256, sizeof(scope->source_sha256));
        memcpy(scope->portable_sha256, source->portable_sha256, sizeof(scope->portable_sha256));
        memcpy(scope->receipt, source->receipt, sizeof(scope->receipt));
        scope->available_slots = source->available_slots;
        memcpy(&record->info.metadata, old.info.suffix, sizeof(old.info.suffix));
        record->checkpoint_size = old.checkpoint_size;
        memcpy(record->checkpoint, old.checkpoint, sizeof(old.checkpoint));
        memcpy(record->sha256, old.sha256, sizeof(old.sha256));
        wire_size = sizeof(old); checkpoint_offset = offsetof(preserved_record_v1_t, checkpoint);
    } else {
        if (!stable_regular_read(path, record, sizeof(*record), true, NULL)) return false;
        hash_bytes(record, offsetof(preserved_record_t, sha256), sha);
    }
    if (memcmp(record->magic, "TOSTON-PRESERVE1", 16) || record->schema != 1 ||
        record->size != wire_size || !FIELD_TERMINATED(record, sha256) ||
        strcmp(record->sha256, sha) || !record->checkpoint_size ||
        record->checkpoint_size > PRESERVED_CHECKPOINT_MAX) return false;
    import_preserved_info_t* info = &record->info;
    import_session_info_t* historical = &info->historical;
    const import_preserve_metadata_t* meta = &info->metadata;
    const restore_scope_t* scope = &historical->restore_scope;
    // Reject malformed wire bool representations before any typed bool read.
    const unsigned char* bytes = (const unsigned char*)info;
    if (bytes[offsetof(import_preserved_info_t, operational_authority)] != 0 ||
        bytes[offsetof(import_preserved_info_t, historical) +
              offsetof(import_session_info_t, restore_selection_required)] > 1 ||
        ((const unsigned char*)&scope->selection)[offsetof(restore_selection_t, specified)] > 1) return false;
    if (!FIELD_TERMINATED(historical, id) || !preserved_id_valid(historical->id) ||
        !FIELD_TERMINATED(historical, name) || !FIELD_TERMINATED(historical, location) ||
        !FIELD_TERMINATED(historical, source) || !FIELD_TERMINATED(historical, title_hint) ||
        !FIELD_TERMINATED(historical, user_hint) || !FIELD_TERMINATED(historical, error) ||
        !FIELD_TERMINATED(historical, path) || historical->path[0] != '/' ||
        !FIELD_TERMINATED(historical, sha256) || !historical->sha256[0] || !sha_text_ok(historical->sha256) ||
        !FIELD_TERMINATED(historical, portable_path) ||
        !FIELD_TERMINATED(historical, portable_sha256) ||
        !FIELD_TERMINATED(info, record_path) || strcmp(info->record_path, path) ||
        !FIELD_TERMINATED(info, preserved_version) || !info->preserved_version[0] ||
        !FIELD_TERMINATED(info, checkpoint_sha256) || !sha_text_ok(info->checkpoint_sha256) ||
        !FIELD_TERMINATED(info, record_sha256) ||
        !FIELD_TERMINATED(scope, import_id) || !FIELD_TERMINATED(scope, title_id) ||
        !FIELD_TERMINATED(scope, target_uid) || !FIELD_TERMINATED(scope, source_sha256) ||
        !FIELD_TERMINATED(scope, portable_sha256) || !FIELD_TERMINATED(scope, receipt) ||
        !FIELD_TERMINATED(scope, restore_mode) || !FIELD_TERMINATED(scope, target_state_sha256) ||
        scope->available_slots > RESTORE_SELECTION_MAX || scope->selection.count > RESTORE_SELECTION_MAX ||
        info->checkpoint_offset != checkpoint_offset ||
        info->checkpoint_size != record->checkpoint_size ||
        !FIELD_TERMINATED(info, receipt_domain) || strcmp(info->receipt_domain, "HISTORICAL_NON_AUTHORIZING") ||
        !FIELD_TERMINATED(info, inventory_fingerprint_scope) || strcmp(info->inventory_fingerprint_scope, "inspector-container-inventory") ||
        !FIELD_TERMINATED(meta, source_format) || !meta->source_format[0] ||
        !FIELD_TERMINATED(meta, title_id) || !meta->title_id[0] ||
        !FIELD_TERMINATED(meta, source_uid) ||
        !FIELD_TERMINATED(meta, raw_manifest_sha256) ||
        !FIELD_TERMINATED(meta, raw_inventory_sha256) ||
        !FIELD_TERMINATED(meta, portable_manifest_sha256) ||
        !FIELD_TERMINATED(meta, portable_inventory_sha256) ||
        !sha_text_ok(meta->raw_manifest_sha256) || !sha_text_ok(meta->raw_inventory_sha256) ||
        !sha_text_ok(meta->portable_manifest_sha256) || !sha_text_ok(meta->portable_inventory_sha256) ||
        historical->state != IMPORT_READY || info->operational_authority ||
        info->raw_size != historical->expected || info->raw_size < 22 || info->raw_size > IMPORT_MAX_BYTES ||
        historical->received != historical->expected ||
        !!historical->portable_path[0] != !!historical->portable_sha256[0] ||
        (historical->portable_path[0] && (historical->portable_path[0] != '/' ||
         !sha_text_ok(historical->portable_sha256) || info->portable_size < 22))) return false;
    char expected_path[512];
    if (!preserved_record_path(historical->id, expected_path) || strcmp(path, expected_path)) return false;
    hash_bytes(record->checkpoint, record->checkpoint_size, checkpoint_sha);
    if (strcmp(info->checkpoint_sha256, checkpoint_sha)) return false;
    // Receipt evidence is retained solely inside historical checkpoint bytes.
    for (size_t i = 0; i < RESTORE_SELECTION_MAX; i++)
        if (!terminated(scope->selection.slots[i], sizeof(scope->selection.slots[i]))) return false;
    for (size_t i = 0; i < sizeof(scope->receipt); i++)
        if (scope->receipt[i]) return false;
    snprintf(info->record_sha256, sizeof(info->record_sha256), "%s", sha);
    return true;
}

static bool preserved_artifacts_match(const import_preserved_info_t* info) {
    return file_matches_sha(info->historical.path, info->historical.sha256, info->raw_size) &&
        (!info->historical.portable_path[0] ||
         file_matches_sha(info->historical.portable_path, info->historical.portable_sha256, info->portable_size));
}

// A single scan avoids a second mutable index. Historical records have no
// session ownership. A malformed registry is uncertainty, never "zero imports".
static bool preserved_scan_readonly_locked(const char* wanted_id, const char* candidate,
                                  import_preserved_info_t* found, size_t* count,
                                  bool validate_artifacts, bool* blocked) {
    if (count) *count = 0;
    if (blocked) *blocked = false;
    if (s_preserved_uncertain || !s_preserved_dir[0]) return false;
    struct stat dir_st;
    if (lstat(s_preserved_dir, &dir_st)) {
        if (errno == ENOENT) return true;
        return false;
    }
    if (!S_ISDIR(dir_st.st_mode)) return false;
    DIR* dir = opendir(s_preserved_dir);
    if (!dir) return false;
    bool ok = true;
    struct dirent* entry;
    while (ok) {
        errno = 0;
        entry = readdir(dir);
        if (!entry) { if (errno) ok = false; break; }
        if (!strcmp(entry->d_name, ".") || !strcmp(entry->d_name, "..") ||
            !strncmp(entry->d_name, ".pending.", 9)) continue;
        size_t len = strlen(entry->d_name);
        if (len < 15 || strncmp(entry->d_name, "import_", 7) || strcmp(entry->d_name + len - 7, ".record")) { ok = false; break; }
        char path[512];
        int n = snprintf(path, sizeof(path), "%s/%s", s_preserved_dir, entry->d_name);
        preserved_record_t record;
        if (n < 0 || (size_t)n >= sizeof(path) || !preserved_record_read(path, &record) ||
            (validate_artifacts && !preserved_artifacts_match(&record.info))) { ok = false; break; }
        if (count) (*count)++;
        if (wanted_id && !strcmp(wanted_id, record.info.historical.id) && found) *found = record.info;
        if (!candidate || !blocked) continue;
        struct stat supplied;
        bool have_supplied = stat(candidate, &supplied) == 0;
        const char* protected_paths[] = {record.info.historical.path, record.info.historical.portable_path,
                                        record.info.record_path};
        for (size_t i = 0; i < 3; i++) {
            if (!protected_paths[i][0]) continue;
            struct stat protected_st;
            if (!strcmp(candidate, protected_paths[i])) { *blocked = true; continue; }
            if (stat(protected_paths[i], &protected_st) || !S_ISREG(protected_st.st_mode)) {
                ok = false; break;
            }
            if (have_supplied && supplied.st_dev == protected_st.st_dev && supplied.st_ino == protected_st.st_ino) *blocked = true;
            // Nonexistent candidate paths still cannot alias a retained file
            // via a symlinked parent once they are later created/finalized.
            char protected_real[512], supplied_real[512];
            if (realpath(protected_paths[i], protected_real) && realpath(candidate, supplied_real) &&
                !strcmp(protected_real, supplied_real)) *blocked = true;
        }
        if (!ok) break;
    }
    if (closedir(dir)) ok = false;
    return ok;
}

static bool preserved_scan_locked(const char* wanted_id, const char* candidate,
                                  import_preserved_info_t* found, size_t* count,
                                  bool validate_artifacts, bool* blocked) {
    bool ok = preserved_scan_readonly_locked(wanted_id, candidate, found, count,
                                             validate_artifacts, blocked);
    // Mutating operations retain uncertainty; observations only report it.
    if (!ok && s_preserved_dir[0]) s_preserved_uncertain = true;
    return ok;
}

static bool preserved_path_blocked_locked(const char* path) {
    bool blocked = false;
    return !preserved_scan_locked(NULL, path, NULL, NULL, false, &blocked) || blocked;
}

static bool checkpoint_uncertain_locked(void) {
    // Do not trust identifiers/paths from a damaged present checkpoint. Keep
    // the evidence untouched and refuse replacement, cleanup or local restores
    // until an explicit inspection outside this import workflow resolves it.
    s_checkpoint_uncertain = true;
    memset(&s_session, 0, sizeof(s_session)); s_raw_target_uid[0] = '\0';
    s_session.state = IMPORT_FAILED;
    s_session.restore_selection_required = true;
    snprintf(s_session.error, sizeof(s_session.error),
             "Import checkpoint is unreadable or invalid; evidence retained. Explicit inspection required.");
    if (!s_observation_only) log_warn("%s", s_session.error);
    return false;
}

static bool fsync_parent(const char* path) {
    char parent[512];
    int n = snprintf(parent, sizeof(parent), "%s", path);
    if (n < 0 || (size_t)n >= sizeof(parent)) return false;
    char* slash = strrchr(parent, '/');
    if (!slash) return false;
    if (slash == parent) slash[1] = '\0'; else *slash = '\0';
    int fd = open(parent, O_RDONLY | O_DIRECTORY | O_NOFOLLOW);
    bool ok = fd >= 0 && fsync(fd) == 0;
    if (fd >= 0 && close(fd) != 0) ok = false;
    return ok;
}

static bool sidecar_path(const import_session_info_t* info, const char* suffix,
                         char* out, size_t out_sz) {
    if (!info || !info->path[0] || !out || !out_sz) return false;
    int n = snprintf(out, out_sz, "%s%s", info->path, suffix);
    if (n < 0 || (size_t)n >= out_sz) { out[0] = '\0'; return false; }
    return true;
}

bool import_session_recovery_candidate(const import_session_info_t* info,
                                       char* out, size_t out_sz) {
    return sidecar_path(info, ".portable.tmp", out, out_sz);
}

const char* import_session_selected_path(const import_session_info_t* info) {
    if (!info) return "";
    return info->portable_path[0] ? info->portable_path : info->path;
}

static bool file_matches_sha(const char* path, const char* expected,
                              uint64_t expected_size) {
    struct stat before, after;
    char actual[65];
    return expected && expected[0] && sha_text_ok(expected) &&
           lstat(path, &before) == 0 && S_ISREG(before.st_mode) &&
           before.st_size >= 22 &&
           (!expected_size || (uint64_t)before.st_size == expected_size) &&
           sha256_file_hex(path, actual) && strcasecmp(actual, expected) == 0 &&
           lstat(path, &after) == 0 && S_ISREG(after.st_mode) &&
           before.st_dev == after.st_dev && before.st_ino == after.st_ino &&
           before.st_size == after.st_size && before.st_mtime == after.st_mtime &&
           before.st_ctime == after.st_ctime;
}

bool import_session_validate_selected(const import_session_info_t* info) {
    if (s_observation_only || !info || !file_matches_sha(info->path, info->sha256, info->expected))
        return false;
    if (!info->portable_path[0] && !info->portable_sha256[0]) return true;
    char expected[512];
    return sidecar_path(info, ".portable.zip", expected, sizeof(expected)) &&
           strcmp(info->portable_path, expected) == 0 &&
           file_matches_sha(info->portable_path, info->portable_sha256, 0);
}

const char* import_state_name(import_state_t state) {
    switch (state) {
        case IMPORT_RECEIVING: return "receiving";
        case IMPORT_VERIFYING: return "verifying";
        case IMPORT_READY: return "ready";
        case IMPORT_COMMITTED: return "committed";
        case IMPORT_FAILED: return "failed";
        case IMPORT_RECOVERING: return "recovering";
        default: return "idle";
    }
}

static bool id_ok(const char* id) {
    return !s_observation_only && !s_checkpoint_uncertain && preserved_scan_locked(NULL, NULL, NULL, NULL, false, NULL) &&
        id && id[0] && strcmp(id, s_session.id) == 0;
}

static bool clear_session_locked(bool delete_file) {
    if (s_observation_only || s_checkpoint_uncertain || s_preserved_uncertain) return false;
    if (delete_file && s_session.path[0]) {
        char sidecar[512];
        if (preserved_path_blocked_locked(s_session.path) ||
            !sidecar_path(&s_session, ".portable.zip", sidecar, sizeof(sidecar)) ||
            preserved_path_blocked_locked(sidecar) ||
            !import_session_recovery_candidate(&s_session, sidecar, sizeof(sidecar)) ||
            preserved_path_blocked_locked(sidecar)) return false;
        if (sidecar_path(&s_session, ".portable.zip", sidecar, sizeof(sidecar)))
            unlink(sidecar);
        if (import_session_recovery_candidate(&s_session, sidecar, sizeof(sidecar)))
            unlink(sidecar);
        unlink(s_session.path);
    }
    if (s_state_path[0]) unlink(s_state_path);
    memset(&s_session, 0, sizeof(s_session)); s_raw_target_uid[0] = '\0';
    return true;
}

static bool persist_session_locked(void) {
    if (s_observation_only || s_checkpoint_uncertain || s_preserved_uncertain) return false;
    if (!s_state_path[0]) return false;
    if (s_session.state == IMPORT_IDLE) {
        unlink(s_state_path);
        return true;
    }
    char tmp[560];
    int n = snprintf(tmp, sizeof(tmp), "%s.tmp.%ld", s_state_path,
                     (long)getpid());
    if (n < 0 || (size_t)n >= sizeof(tmp)) return false;
    FILE* f = fopen(tmp, "wb");
    if (!f) return false;
    chmod(tmp, 0600);
    fprintf(f,
            "version=%d\nid=%s\nname=%s\npath=%s\nlocation=%s\nsource=%s\n"
            "title_hint=%s\nuser_hint=%s\nsha256=%s\nerror=%s\n"
            "portable_path=%s\nportable_sha256=%s\n"
            "expected=%llu\nreceived=%llu\nupdated=%lld\nstate=%d\n",
            s_raw_target_uid[0] ? 4 : 3, s_session.id, s_session.name, s_session.path, s_session.location,
            s_session.source, s_session.title_hint, s_session.user_hint,
            s_session.sha256, s_session.error,
            s_session.portable_path, s_session.portable_sha256,
            (unsigned long long)s_session.expected,
            (unsigned long long)s_session.received,
            (long long)s_session.updated_unix, (int)s_session.state);
    if (s_raw_target_uid[0]) fprintf(f, "raw_target_uid=%s\n", s_raw_target_uid);
    const restore_scope_t* scope = &s_session.restore_scope;
    fprintf(f, "restore_selection_required=%d\nrestore_scope_id=%s\n"
            "restore_scope_title=%s\nrestore_scope_uid=%s\n"
            "restore_scope_source_sha256=%s\nrestore_scope_portable_sha256=%s\n"
            "restore_scope_mode=%s\nrestore_scope_target_state_sha256=%s\n"
            "restore_scope_receipt=%s\nrestore_scope_available=%zu\nrestore_scope_count=%zu\n",
            s_session.restore_selection_required ? 1 : 0, scope->import_id,
            scope->title_id, scope->target_uid, scope->source_sha256,
            scope->portable_sha256, scope->restore_mode, scope->target_state_sha256,
            scope->receipt, scope->available_slots,
            scope->selection.count);
    for (size_t i = 0; i < scope->selection.count && i < RESTORE_SELECTION_MAX; i++)
        fprintf(f, "restore_scope_slot_%zu=%s\n", i, scope->selection.slots[i]);
    bool ok = !ferror(f) && fflush(f) == 0 && fsync(fileno(f)) == 0;
    if (fclose(f) != 0) ok = false;
    if (ok) ok = rename(tmp, s_state_path) == 0 && fsync_parent(s_state_path);
    if (!ok) unlink(tmp);
    return ok;
}

static void expire_abandoned_session_locked(void) {
    if (s_observation_only || s_checkpoint_uncertain || s_preserved_uncertain) return;
    time_t now = time(NULL);
    bool stale = s_session.state == IMPORT_FAILED ||
        (s_session.state == IMPORT_RECEIVING && s_session.updated_unix > 0 &&
         now - s_session.updated_unix > 15 * 60);
    if (!stale) return;
    if (!clear_session_locked(true)) return;
    log_info("Abandoned ZIP import session was released.");
}

void import_session_maintenance(void) {
    if (!lifecycle_operation_begin()) return;
    pthread_mutex_lock(&s_lock);
    expire_abandoned_session_locked();
    pthread_mutex_unlock(&s_lock);
    lifecycle_operation_end();
}

static void safe_name(const char* in, char out[96]) {
    size_t n = 0;
    const char* p = (in && in[0]) ? in : "backup.zip";
    for (; *p && n + 1 < 96; p++) {
        unsigned char c = (unsigned char)*p;
        out[n++] = ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
                    (c >= '0' && c <= '9') || c == '_' || c == '-' || c == '.')
                   ? (char)c : '_';
    }
    out[n] = '\0';
    if (!strstr(out, ".zip")) {
        size_t left = 95 - strlen(out);
        if (left >= 4) strncat(out, ".zip", left);
    }
}

static uint64_t free_bytes(const char* path) {
    struct statvfs v;
    if (!path || statvfs(path, &v) != 0) return 0;
    return (uint64_t)v.f_bavail * (uint64_t)v.f_frsize;
}

static int64_t monotonic_ms(void) {
    struct timespec ts;
    return clock_gettime(CLOCK_MONOTONIC, &ts) == 0
           ? (int64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000 : 0;
}

static bool cleanup_tree_unprotected_locked(const char* path, unsigned depth) {
    if (s_observation_only || depth > 64 || preserved_path_blocked_locked(path)) return false;
    struct stat st;
    if (lstat(path, &st)) return false;
    if (S_ISLNK(st.st_mode)) return false;
    if (!S_ISDIR(st.st_mode)) return true;
    DIR* dir = opendir(path);
    if (!dir) return false;
    bool ok = true;
    struct dirent* entry;
    while (ok) {
        errno = 0;
        entry = readdir(dir);
        if (!entry) { if (errno) ok = false; break; }
        if (!strcmp(entry->d_name, ".") || !strcmp(entry->d_name, "..")) continue;
        char child[512];
        int n = snprintf(child, sizeof(child), "%s/%s", path, entry->d_name);
        ok = n >= 0 && (size_t)n < sizeof(child) &&
            cleanup_tree_unprotected_locked(child, depth + 1);
    }
    if (closedir(dir)) ok = false;
    return ok;
}

static void cleanup_dir(const char* dir) {
    DIR* d = opendir(dir);
    if (!d) return;
    time_t cutoff = time(NULL) - 24 * 60 * 60;
    struct dirent* e;
    while ((e = readdir(d)) != NULL) {
        size_t n = strlen(e->d_name);
        bool partial = n >= 5 && strcmp(e->d_name + n - 5, ".part") == 0;
        bool inspect = n >= 8 && strcmp(e->d_name + n - 8, ".inspect") == 0;
        if (!partial && !inspect) continue;
        char path[512];
        snprintf(path, sizeof(path), "%s/%s", dir, e->d_name);
        struct stat st;
        if (stat(path, &st) == 0 && st.st_mtime < cutoff) {
            pthread_mutex_lock(&s_lock);
            if (cleanup_tree_unprotected_locked(path, 0)) {
                if (S_ISDIR(st.st_mode)) pfs_fs_rmrf(path);
                else unlink(path);
                log_info("Previous ZIP import staging was cleaned up.");
            }
            pthread_mutex_unlock(&s_lock);
        }
    }
    closedir(d);
}

static void cleanup_stale(const config_t* cfg) {
    if (!cfg) return;
    char dir[512];
    snprintf(dir, sizeof(dir), "%s/imports", cfg->paths.state_dir);
    cleanup_dir(dir);
    usb_mount_t mounts[8];
    size_t count = usb_list_mounts(mounts, 8);
    for (size_t i = 0; i < count; i++) {
        snprintf(dir, sizeof(dir), "%s/%s/.imports", mounts[i].path,
                 cfg->usb.folder[0] ? cfg->usb.folder : "TostónSync");
        cleanup_dir(dir);
    }
}

static void copy_field(char* out, size_t out_sz, const char* value) {
    if (out && out_sz) snprintf(out, out_sz, "%s", value ? value : "");
}

static bool staging_path_allowed(const config_t* cfg, const char* path) {
    if (!cfg || !path || !path[0] || strstr(path, "..")) return false;
    char prefix[512];
    snprintf(prefix, sizeof(prefix), "%s/imports/import_", cfg->paths.state_dir);
    if (strncmp(path, prefix, strlen(prefix)) == 0) return true;
    usb_mount_t mounts[8];
    size_t count = usb_list_mounts(mounts, 8);
    for (size_t i = 0; i < count; i++) {
        snprintf(prefix, sizeof(prefix), "%s/%s/.imports/import_",
                 mounts[i].path,
                 cfg->usb.folder[0] ? cfg->usb.folder : "TostónSync");
        if (strncmp(path, prefix, strlen(prefix)) == 0) return true;
    }
    return false;
}

static bool checkpoint_stat_same(const struct stat* a, const struct stat* b) {
#ifdef __APPLE__
    bool times = a->st_mtimespec.tv_nsec == b->st_mtimespec.tv_nsec &&
                 a->st_ctimespec.tv_nsec == b->st_ctimespec.tv_nsec;
#else
    bool times = a->st_mtim.tv_nsec == b->st_mtim.tv_nsec &&
                 a->st_ctim.tv_nsec == b->st_ctim.tv_nsec;
#endif
    return S_ISREG(b->st_mode) && a->st_dev == b->st_dev && a->st_ino == b->st_ino &&
        a->st_size == b->st_size && a->st_mtime == b->st_mtime && a->st_ctime == b->st_ctime && times;
}

static bool load_session_locked(const config_t* cfg, bool observation) {
    struct stat checkpoint, opened, after;
    // A non-directory ancestor cannot contain an existing checkpoint either;
    // unavailable internal storage may still permit a new USB import.
    if (lstat(s_state_path, &checkpoint) != 0)
        return (errno == ENOENT || (!observation && errno == ENOTDIR)) ? false : checkpoint_uncertain_locked();
    if (observation) s_observed_checkpoint_present = true;
    if (!S_ISREG(checkpoint.st_mode)) return checkpoint_uncertain_locked();
    if (observation && (checkpoint.st_size < 1 ||
        (uint64_t)checkpoint.st_size > PRESERVED_CHECKPOINT_MAX)) return checkpoint_uncertain_locked();
    int fd = open(s_state_path, O_RDONLY | O_NOFOLLOW | O_NONBLOCK);
    if (fd < 0) return checkpoint_uncertain_locked();
    if (fstat(fd, &opened) != 0 || !S_ISREG(opened.st_mode) ||
        opened.st_dev != checkpoint.st_dev || opened.st_ino != checkpoint.st_ino ||
        (observation && !checkpoint_stat_same(&checkpoint, &opened))) {
        close(fd);
        return checkpoint_uncertain_locked();
    }
    FILE* f = fdopen(fd, "rb");
    if (!f) { close(fd); return checkpoint_uncertain_locked(); }
    import_session_info_t loaded;
    memset(&loaded, 0, sizeof(loaded));
    int version = 0, state = 0;
    char raw_target_uid[16] = {0}; bool raw_uid_seen = false;
    bool scope_seen = false, selection_flag_seen = false, scope_bad = false;
    unsigned long long scope_fields = 0, slot_fields = 0;
    unsigned scalar_fields = 0; bool checkpoint_bad = false;
    char line[1024];
    while (fgets(line, sizeof(line), f)) {
        char* nl = strpbrk(line, "\r\n");
        if (!nl) checkpoint_bad = true;
        if (nl) *nl = '\0';
        char* eq = strchr(line, '=');
        if (!eq) { checkpoint_bad = true; continue; }
        *eq++ = '\0';
        if (!strcmp(line, "raw_target_uid")) {
            if (raw_uid_seen || !restore_uid_valid(eq)) scope_bad = true;
            else snprintf(raw_target_uid, sizeof(raw_target_uid), "%s", eq);
            raw_uid_seen = true;
            continue;
        }
        {
            const char* keys[] = {"version", "id", "name", "path", "location", "source",
                "title_hint", "user_hint", "sha256", "portable_path", "portable_sha256",
                "error", "expected", "received", "updated", "state"};
            const size_t caps[] = {0, sizeof(loaded.id), sizeof(loaded.name), sizeof(loaded.path),
                sizeof(loaded.location), sizeof(loaded.source), sizeof(loaded.title_hint),
                sizeof(loaded.user_hint), sizeof(loaded.sha256), sizeof(loaded.portable_path),
                sizeof(loaded.portable_sha256), sizeof(loaded.error), 0, 0, 0, 0};
            for (unsigned i = 0; i < sizeof(keys) / sizeof(*keys); i++) {
                if (strcmp(line, keys[i])) continue;
                if (scalar_fields & (1U << i)) checkpoint_bad = true;
                scalar_fields |= 1U << i;
                if (caps[i]) { if (strlen(eq) >= caps[i]) checkpoint_bad = true; }
                else {
                    char* tail; errno = 0;
                    unsigned long long number = 0;
                    if (i == 14) (void)strtoll(eq, &tail, 10);
                    else number = strtoull(eq, &tail, 10);
                    if (!eq[0] || *tail || errno || (i != 14 && eq[0] == '-')) checkpoint_bad = true;
                    if ((i == 0 && (number < 1 || number > 4)) ||
                        (i == 15 && number > IMPORT_RECOVERING)) checkpoint_bad = true;
                }
                break;
            }
            if (checkpoint_bad && observation) continue;
        }
        if (strcmp(line, "version") == 0) version = atoi(eq);
        else if (strcmp(line, "id") == 0)
            copy_field(loaded.id, sizeof(loaded.id), eq);
        else if (strcmp(line, "name") == 0)
            copy_field(loaded.name, sizeof(loaded.name), eq);
        else if (strcmp(line, "path") == 0)
            copy_field(loaded.path, sizeof(loaded.path), eq);
        else if (strcmp(line, "location") == 0)
            copy_field(loaded.location, sizeof(loaded.location), eq);
        else if (strcmp(line, "source") == 0)
            copy_field(loaded.source, sizeof(loaded.source), eq);
        else if (strcmp(line, "title_hint") == 0)
            copy_field(loaded.title_hint, sizeof(loaded.title_hint), eq);
        else if (strcmp(line, "user_hint") == 0)
            copy_field(loaded.user_hint, sizeof(loaded.user_hint), eq);
        else if (strcmp(line, "sha256") == 0)
            copy_field(loaded.sha256, sizeof(loaded.sha256), eq);
        else if (strcmp(line, "portable_path") == 0)
            copy_field(loaded.portable_path, sizeof(loaded.portable_path), eq);
        else if (strcmp(line, "portable_sha256") == 0)
            copy_field(loaded.portable_sha256, sizeof(loaded.portable_sha256), eq);
        else if (strcmp(line, "error") == 0)
            copy_field(loaded.error, sizeof(loaded.error), eq);
        else if (strcmp(line, "expected") == 0)
            loaded.expected = strtoull(eq, NULL, 10);
        else if (strcmp(line, "received") == 0)
            loaded.received = strtoull(eq, NULL, 10);
        else if (strcmp(line, "updated") == 0)
            loaded.updated_unix = strtoll(eq, NULL, 10);
        else if (strcmp(line, "state") == 0) state = atoi(eq);
        else if (strcmp(line, "restore_selection_required") == 0) {
            if (selection_flag_seen || (strcmp(eq, "0") && strcmp(eq, "1"))) scope_bad = true;
            selection_flag_seen = true;
            loaded.restore_selection_required = strcmp(eq, "0") != 0;
        } else if (!strncmp(line, "restore_scope_", 14)) {
            scope_seen = true;
            restore_scope_t* scope = &loaded.restore_scope;
            const char* key = line + 14;
            char* output = NULL; size_t cap = 0; unsigned bit = 0;
            if (!strcmp(key, "id")) { output = scope->import_id; cap = sizeof(scope->import_id); bit = 0; }
            else if (!strcmp(key, "title")) { output = scope->title_id; cap = sizeof(scope->title_id); bit = 1; }
            else if (!strcmp(key, "uid")) { output = scope->target_uid; cap = sizeof(scope->target_uid); bit = 2; }
            else if (!strcmp(key, "source_sha256")) { output = scope->source_sha256; cap = sizeof(scope->source_sha256); bit = 3; }
            else if (!strcmp(key, "portable_sha256")) { output = scope->portable_sha256; cap = sizeof(scope->portable_sha256); bit = 4; }
            else if (!strcmp(key, "receipt")) { output = scope->receipt; cap = sizeof(scope->receipt); bit = 5; }
            else if (!strcmp(key, "mode")) { output = scope->restore_mode; cap = sizeof(scope->restore_mode); bit = 8; }
            else if (!strcmp(key, "target_state_sha256")) { output = scope->target_state_sha256; cap = sizeof(scope->target_state_sha256); bit = 9; }
            else if (!strcmp(key, "available") || !strcmp(key, "count")) {
                bit = !strcmp(key, "available") ? 6 : 7;
                char* tail; unsigned long long n = strtoull(eq, &tail, 10);
                if (!eq[0] || *tail || n > RESTORE_SELECTION_MAX) scope_bad = true;
                if (bit == 6) scope->available_slots = (size_t)n;
                else scope->selection.count = (size_t)n;
            } else if (!strncmp(key, "slot_", 5)) {
                char* tail; unsigned long long i = strtoull(key + 5, &tail, 10);
                if (!key[5] || *tail || i >= RESTORE_SELECTION_MAX ||
                    (slot_fields & (1ULL << i)) || strlen(eq) >= 64) scope_bad = true;
                else { slot_fields |= 1ULL << i; copy_field(scope->selection.slots[i], 64, eq); }
                continue;
            } else { scope_bad = true; continue; }
            if (scope_fields & (1ULL << bit)) scope_bad = true;
            scope_fields |= 1ULL << bit;
            if (output) {
                if (strlen(eq) >= cap) scope_bad = true;
                copy_field(output, cap, eq);
            }
        }
    }
    bool read_ok = !ferror(f);
    if (observation) {
        read_ok = read_ok && !fstat(fd, &after) && checkpoint_stat_same(&checkpoint, &after) &&
            !lstat(s_state_path, &opened) && checkpoint_stat_same(&after, &opened);
        // Required scalar fields cannot be supplied by a truncated checkpoint.
        if ((scalar_fields & 0xf00fU) != 0xf00fU) read_ok = false;
    }
    if (version == 4 && (scalar_fields != 0xffffU ||
        (import_session_rejected_uid(&loaded) && !restore_uid_valid(import_session_rejected_uid(&loaded))))) read_ok = false;
    if (fclose(f) && (observation || version == 4)) read_ok = false;
    loaded.state = (import_state_t)state;
    struct stat st;
    bool have_file = lstat(loaded.path, &st) == 0;
    if (!observation && !have_file && loaded.state == IMPORT_VERIFYING) {
        char finalized[512];
        snprintf(finalized, sizeof(finalized), "%s", loaded.path);
        char* ext = strrchr(finalized, '.');
        if (ext) snprintf(ext, (size_t)(finalized + sizeof(finalized) - ext),
                          ".zip");
        if (lstat(finalized, &st) == 0) {
            snprintf(loaded.path, sizeof(loaded.path), "%s", finalized);
            have_file = true;
        }
    }
    bool file_ok = have_file && S_ISREG(st.st_mode) &&
                   (uint64_t)st.st_size <= loaded.expected;
    bool state_ok = (loaded.state >= IMPORT_RECEIVING &&
                     loaded.state <= IMPORT_COMMITTED) ||
                    loaded.state == IMPORT_RECOVERING || (observation && loaded.state == IMPORT_FAILED);
    if (!read_ok || (version != 1 && version != 2 && version != 3 && version != 4) || !loaded.id[0] || !loaded.name[0] ||
        loaded.expected < 22 || loaded.expected > IMPORT_MAX_BYTES ||
        !state_ok || !file_ok || !staging_path_allowed(cfg, loaded.path)) {
        return checkpoint_uncertain_locked();
    }
    if ((loaded.state == IMPORT_READY || loaded.state == IMPORT_COMMITTED ||
         loaded.state == IMPORT_RECOVERING) &&
        (uint64_t)st.st_size != loaded.expected) {
        return checkpoint_uncertain_locked();
    }
    // Old sessions have no scope. A damaged new checkpoint must never acquire
    // restore-all semantics or trigger interrupted-recovery cleanup.
    if (version == 2 && (!selection_flag_seen || scope_fields != 255)) scope_bad = true;
    if ((version == 3 || version == 4) && (!selection_flag_seen || scope_fields != 1023)) scope_bad = true;
    if (version == 4 ? (!raw_uid_seen || !restore_uid_valid(raw_target_uid)) : raw_uid_seen) scope_bad = true;
    if (scope_seen && loaded.restore_scope.receipt[0]) {
        if (!observation) loaded.restore_selection_required = true;
        loaded.restore_scope.selection.specified = true;
        size_t n = loaded.restore_scope.selection.count;
        // v2 approval fields are historical metadata, never current receipts.
        bool historical_v2 = observation && version == 2 && scope_fields == 255 &&
            sha_text_ok(loaded.restore_scope.receipt) &&
            loaded.restore_scope.title_id[0] && loaded.restore_scope.target_uid[0] &&
            loaded.restore_scope.available_slots >= n;
        for (size_t i = 0; historical_v2 && i < n && i < RESTORE_SELECTION_MAX; i++)
            historical_v2 = loaded.restore_scope.selection.slots[i][0] &&
                (!i || strcmp(loaded.restore_scope.selection.slots[i - 1],
                              loaded.restore_scope.selection.slots[i]) < 0);
        if ((loaded.state != IMPORT_READY && loaded.state != IMPORT_COMMITTED) ||
            (!historical_v2 && ((version != 3 && version != 4) || scope_fields != 1023)) || !n || n > RESTORE_SELECTION_MAX ||
            slot_fields != ((1ULL << n) - 1) ||
            (!historical_v2 && !restore_scope_valid(&loaded.restore_scope)) ||
            strcmp(loaded.restore_scope.import_id, loaded.id) ||
            strcmp(loaded.restore_scope.source_sha256, loaded.sha256) ||
            strcmp(loaded.restore_scope.portable_sha256, loaded.portable_sha256)) scope_bad = true;
    } else if (slot_fields || loaded.restore_scope.selection.count) scope_bad = true;
    if ((observation || version == 4 || raw_uid_seen) && checkpoint_bad) scope_bad = true;
    if (scope_bad) {
        return checkpoint_uncertain_locked();
    }
    if (observation) {
        if (loaded.received > loaded.expected || !preserved_id_valid(loaded.id) ||
            !sha_text_ok(loaded.sha256) || !sha_text_ok(loaded.portable_sha256) ||
            ((loaded.state == IMPORT_READY || loaded.state == IMPORT_COMMITTED ||
              loaded.state == IMPORT_RECOVERING) &&
             (!loaded.sha256[0] || loaded.received != loaded.expected)) ||
            (!!loaded.portable_path[0] != !!loaded.portable_sha256[0])) return checkpoint_uncertain_locked();
        if (loaded.portable_path[0]) {
            char portable[512]; struct stat portable_st;
            if (!sidecar_path(&loaded, ".portable.zip", portable, sizeof(portable)) ||
                strcmp(portable, loaded.portable_path) || lstat(portable, &portable_st) ||
                !S_ISREG(portable_st.st_mode) || portable_st.st_size < 22) return checkpoint_uncertain_locked();
        }
        s_observed_historical_receipt_present = loaded.restore_scope.receipt[0] != '\0';
        memset(loaded.restore_scope.receipt, 0, sizeof(loaded.restore_scope.receipt));
        s_session = loaded;
        snprintf(s_raw_target_uid, sizeof(s_raw_target_uid), "%s", raw_target_uid);
        return true;
    }
    loaded.received = (uint64_t)st.st_size;
    if (!loaded.source[0]) snprintf(loaded.source, sizeof(loaded.source), "browser");
    if (loaded.state == IMPORT_VERIFYING) loaded.state = IMPORT_RECEIVING;
    if (loaded.state == IMPORT_COMMITTED && loaded.restore_selection_required) {
        // A restart cannot tell whether a queued selected writer published.
        // Retain the exact checkpoint and all ZIP evidence, but never revive
        // its receipt or automatically release/clean the interrupted claim.
        memset(&loaded.restore_scope, 0, sizeof(loaded.restore_scope));
        snprintf(loaded.error, sizeof(loaded.error),
                 "Selected Portable restore was interrupted; evidence retained. Inspect recovery before a new approval.");
        s_session = loaded;
        snprintf(s_raw_target_uid, sizeof(s_raw_target_uid), "%s", raw_target_uid);
        s_checkpoint_uncertain = true;
        log_warn("%s", s_session.error);
        return true;
    }
    if (loaded.state == IMPORT_COMMITTED) loaded.state = IMPORT_READY;
    if (loaded.state == IMPORT_RECOVERING) {
        loaded.state = IMPORT_READY;
        snprintf(loaded.error, sizeof(loaded.error),
                 "RAW recovery was interrupted; original ZIP retained. Retry recovery.");
        char candidate[512];
        if (import_session_recovery_candidate(&loaded, candidate, sizeof(candidate)) &&
            !preserved_path_blocked_locked(candidate))
            unlink(candidate);
    }
    if ((loaded.portable_path[0] || loaded.portable_sha256[0]) &&
        !import_session_validate_selected(&loaded)) {
        if (loaded.restore_scope.receipt[0]) return checkpoint_uncertain_locked();
        loaded.portable_path[0] = loaded.portable_sha256[0] = '\0';
        snprintf(loaded.error, sizeof(loaded.error),
                 "Recovered portable ZIP or original source changed; recovery must be repeated.");
    }
    s_session = loaded;
    snprintf(s_raw_target_uid, sizeof(s_raw_target_uid), "%s", raw_target_uid);
    if (s_session.state == IMPORT_IDLE) return false;
    persist_session_locked();
    log_info("Previous ZIP import recovered: %s (%llu/%llu bytes, %s)",
             s_session.name, (unsigned long long)s_session.received,
             (unsigned long long)s_session.expected,
             import_state_name(s_session.state));
    return true;
}

void import_session_init(const config_t* cfg) {
    if (!cfg) return;
    pthread_mutex_lock(&s_lock);
    if (s_observation_only) { pthread_mutex_unlock(&s_lock); return; }
    char wanted[512];
    snprintf(wanted, sizeof(wanted), "%s/import.session",
             cfg->paths.state_dir);
    if (s_state_path[0] && strcmp(s_state_path, wanted) == 0 &&
        s_session.state != IMPORT_IDLE) {
        (void)preserved_scan_locked(NULL, NULL, NULL, NULL, false, NULL);
        bool cleanup_allowed = !s_checkpoint_uncertain && !s_preserved_uncertain;
        pthread_mutex_unlock(&s_lock);
        if (cleanup_allowed) cleanup_stale(cfg);
        return;
    }
    snprintf(s_state_path, sizeof(s_state_path), "%s", wanted);
    int n = snprintf(s_preserved_dir, sizeof(s_preserved_dir), "%s/preserved", cfg->paths.state_dir);
    s_preserved_uncertain = n < 0 || (size_t)n >= sizeof(s_preserved_dir);
    memset(&s_session, 0, sizeof(s_session)); s_raw_target_uid[0] = '\0';
    s_checkpoint_uncertain = false;
    (void)preserved_scan_locked(NULL, NULL, NULL, NULL, true, NULL);
    (void)load_session_locked(cfg, false);
    bool cleanup_allowed = !s_checkpoint_uncertain && !s_preserved_uncertain;
    pthread_mutex_unlock(&s_lock);
    if (cleanup_allowed) cleanup_stale(cfg);
}

void import_session_observe_init(const config_t* cfg) {
    pthread_mutex_lock(&s_lock);
    s_observation_only = true;
    s_observed_checkpoint_present = s_observed_historical_receipt_present = false;
    memset(&s_session, 0, sizeof(s_session)); s_raw_target_uid[0] = '\0';
    s_checkpoint_uncertain = s_preserved_uncertain = false;
    int n = cfg ? snprintf(s_state_path, sizeof(s_state_path), "%s/import.session", cfg->paths.state_dir) : -1;
    if (n < 0 || (size_t)n >= sizeof(s_state_path)) {
        s_state_path[0] = s_preserved_dir[0] = '\0';
        (void)checkpoint_uncertain_locked();
    } else {
        n = snprintf(s_preserved_dir, sizeof(s_preserved_dir), "%s/preserved", cfg->paths.state_dir);
        s_preserved_uncertain = n < 0 || (size_t)n >= sizeof(s_preserved_dir);
        (void)preserved_scan_locked(NULL, NULL, NULL, NULL, false, NULL);
        (void)load_session_locked(cfg, true);
    }
    pthread_mutex_unlock(&s_lock);
}

bool import_session_observe_snapshot(import_session_observation_t* out) {
    if (!out) return false;
    pthread_mutex_lock(&s_lock);
    bool ok = s_observation_only;
    if (ok) {
        memset(out, 0, sizeof(*out));
        out->info = s_session;
        out->checkpoint_present = s_observed_checkpoint_present;
        out->checkpoint_valid = s_state_path[0] && !s_checkpoint_uncertain;
        out->historical_receipt_present = s_observed_historical_receipt_present;
        out->result = LIFE_UNKNOWN;
        if (s_state_path[0] && !s_checkpoint_uncertain && !s_preserved_uncertain) {
            switch (s_session.state) {
                case IMPORT_IDLE: case IMPORT_READY: out->result = LIFE_CLEAR; break;
                case IMPORT_RECEIVING: case IMPORT_VERIFYING:
                case IMPORT_COMMITTED: case IMPORT_RECOVERING: out->result = LIFE_BUSY; break;
                default: break;
            }
        }
        snprintf(out->detail, sizeof(out->detail), "%s", s_checkpoint_uncertain ? s_session.error :
            s_preserved_uncertain ? "Preserved registry is uncertain; observation grants no authority." :
            s_observed_checkpoint_present ? "Checkpoint observed unchanged; no operational or receipt authority." :
            "No checkpoint present; observation grants no operational authority.");
    }
    pthread_mutex_unlock(&s_lock);
    return ok;
}

static bool choose_staging(const config_t* cfg, uint64_t need,
                           char out[512], char location[32],
                           uint64_t* internal_free, uint64_t* best_usb_free) {
    char dir[512];
    snprintf(dir, sizeof(dir), "%s/imports", cfg->paths.state_dir);
    uint64_t inside = fs_mkdir_p(dir) ? free_bytes(dir) : 0;
    if (internal_free) *internal_free = inside;
    if (inside >= need) {
        snprintf(out, 512, "%s", dir);
        snprintf(location, 32, "Internal SSD");
        if (best_usb_free) *best_usb_free = 0;
        return true;
    }

    usb_mount_t mounts[8];
    size_t count = usb_list_mounts(mounts, 8);
    size_t best = count;
    uint64_t usb_free = 0;
    for (size_t i = 0; i < count; i++) {
        if (!mounts[i].writable) continue;
        if (mounts[i].free_bytes > usb_free) usb_free = mounts[i].free_bytes;
        if (mounts[i].free_bytes < need) continue;
        if (best == count || mounts[i].free_bytes > mounts[best].free_bytes) best = i;
    }
    if (best_usb_free) *best_usb_free = usb_free;
    if (best < count) {
        snprintf(dir, sizeof(dir), "%s/%s/.imports", mounts[best].path,
                 cfg->usb.folder[0] ? cfg->usb.folder : "TostónSync");
        if (fs_mkdir_p(dir)) {
            snprintf(out, 512, "%s", dir);
            snprintf(location, 32, "USB Drive");
            return true;
        }
    }
    return false;
}

static bool import_session_start_identity(const config_t* cfg, const char* name,
                          uint64_t expected, uint64_t reserve_bytes,
                          const char* title_hint, const char* user_hint,
                          const char* source, const char* resume_id,
                          import_session_info_t* out, const char* raw_uid) {
    if (out) memset(out, 0, sizeof(*out));
    if (raw_uid && !restore_uid_valid(raw_uid)) return false;
    if (!cfg || expected < 22 || expected > IMPORT_MAX_BYTES) return false;
    char normalized_name[96];
    safe_name(name, normalized_name);
    pthread_mutex_lock(&s_lock);
    if (s_observation_only) { pthread_mutex_unlock(&s_lock); return false; }
    if (!preserved_scan_locked(NULL, NULL, NULL, NULL, false, NULL)) {
        if (out) snprintf(out->error, sizeof(out->error), "Preserved import registry is uncertain; evidence retained.");
        pthread_mutex_unlock(&s_lock); return false;
    }
    if (s_session.state != IMPORT_IDLE) {
        bool resume = s_session.state == IMPORT_RECEIVING &&
                      resume_id && resume_id[0] && id_ok(resume_id) &&
                      s_session.expected == expected &&
                      strcmp(s_session.name, normalized_name) == 0 &&
                      ((!raw_uid && !s_raw_target_uid[0]) ||
                       (raw_uid && !strcmp(raw_uid, s_raw_target_uid) && !strcmp(resume_id, s_session.id)));
        if (resume && out) *out = s_session;
        pthread_mutex_unlock(&s_lock);
        return resume;
    }
    uint64_t margin = 512ULL * 1024ULL * 1024ULL;
    uint64_t need = expected;
    if (UINT64_MAX - need < reserve_bytes ||
        UINT64_MAX - need - reserve_bytes < margin) {
        pthread_mutex_unlock(&s_lock);
        return false;
    }
    need += reserve_bytes + margin;
    char dir[512], location[32];
    uint64_t internal_free = 0, usb_free = 0;
    if (!choose_staging(cfg, need, dir, location,
                        &internal_free, &usb_free)) {
        if (out) {
            uint64_t available = internal_free > usb_free
                                 ? internal_free : usb_free;
            snprintf(out->error, sizeof(out->error),
                     "Not enough free space. Need %llu MiB; available %llu MiB. "
                     "Free internal storage or connect a USB drive.",
                     (unsigned long long)((need + 1048575) / 1048576),
                     (unsigned long long)(available / 1048576));
        }
        pthread_mutex_unlock(&s_lock);
        return false;
    }
    memset(&s_session, 0, sizeof(s_session)); s_raw_target_uid[0] = '\0';
    snprintf(s_session.name, sizeof(s_session.name), "%s", normalized_name);
    snprintf(s_session.id, sizeof(s_session.id), "%llx-%ld-%lu",
             (unsigned long long)time(NULL), (long)getpid(), s_seq++);
    snprintf(s_session.path, sizeof(s_session.path), "%s/import_%s.part",
             dir, s_session.id);
    char prospective[512], historical_path[512];
    struct stat collision;
    bool independent = preserved_record_path(s_session.id, historical_path) &&
        lstat(historical_path, &collision) != 0 && (errno == ENOENT || errno == ENOTDIR) &&
        !preserved_path_blocked_locked(s_session.path);
    const char* suffixes[] = {".zip", ".zip.portable.zip", ".zip.portable.tmp"};
    for (size_t i = 0; independent && i < 3; i++) {
        int written = snprintf(prospective, sizeof(prospective), "%s/import_%s%s", dir, s_session.id, suffixes[i]);
        independent = written >= 0 && (size_t)written < sizeof(prospective) &&
            !preserved_path_blocked_locked(prospective) && lstat(prospective, &collision) != 0 && errno == ENOENT;
    }
    if (!independent) { memset(&s_session, 0, sizeof(s_session)); s_raw_target_uid[0] = '\0'; pthread_mutex_unlock(&s_lock); return false; }
    snprintf(s_session.location, sizeof(s_session.location), "%s", location);
    snprintf(s_session.source, sizeof(s_session.source), "%s",
             source && strcmp(source, "google_drive") == 0
             ? "google_drive" : "browser");
    snprintf(s_session.title_hint, sizeof(s_session.title_hint), "%s",
             title_hint ? title_hint : "");
    snprintf(s_session.user_hint, sizeof(s_session.user_hint), "%s",
             user_hint ? user_hint : "");
    if (raw_uid) snprintf(s_raw_target_uid, sizeof(s_raw_target_uid), "%s", raw_uid);
    s_session.expected = expected;
    s_session.updated_unix = time(NULL);
    s_session.state = IMPORT_RECEIVING;
    int fd = open(s_session.path, O_CREAT | O_EXCL | O_WRONLY, 0600);
    if (fd < 0) {
        memset(&s_session, 0, sizeof(s_session)); s_raw_target_uid[0] = '\0';
        pthread_mutex_unlock(&s_lock);
        return false;
    }
    close(fd);
    if (!persist_session_locked()) {
        log_warn("ZIP import session state could not be persisted.");
        if (raw_uid) {
            s_checkpoint_uncertain = true;
            if (out) *out = s_session;
            pthread_mutex_unlock(&s_lock); return false;
        }
    }
    if (out) *out = s_session;
    log_info("ZIP import started: %s (%llu bytes, %s)", s_session.name,
             (unsigned long long)expected, s_session.location);
    pthread_mutex_unlock(&s_lock);
    return true;
}
bool import_session_start(const config_t* cfg, const char* name,
                          uint64_t expected, uint64_t reserve_bytes,
                          const char* title_hint, const char* user_hint,
                          const char* source, const char* resume_id,
                          import_session_info_t* out) {
    return import_session_start_identity(cfg,name,expected,reserve_bytes,title_hint,user_hint,source,resume_id,out,NULL);
}

bool import_session_start_uid(const config_t* cfg, const char* name,
                              uint64_t expected, uint64_t reserve_bytes,
                              const char* title_hint, const char* uid,
                              const char* source, const char* resume_id,
                              import_session_info_t* out) {
    if (!restore_uid_valid(uid)) return false;
    return import_session_start_identity(cfg,name,expected,reserve_bytes,title_hint,uid,source,resume_id,out,uid);
}

int import_session_restore_uid(const char* id, char uid[16]) {
    if (!uid) return -1;
    uid[0] = '\0';
    pthread_mutex_lock(&s_lock);
    int result = -1;
    if (id && !strcmp(id,s_session.id) && s_session.state != IMPORT_IDLE &&
        !s_checkpoint_uncertain && !s_preserved_uncertain) {
        result = s_raw_target_uid[0] ? 1 : 0;
        if (result) snprintf(uid,16,"%s",s_raw_target_uid);
    }
    pthread_mutex_unlock(&s_lock);
    return result;
}

const char* import_session_rejected_uid(const import_session_info_t* info) {
    const char prefix[] = "restore_target_uid_missing:";
    if (!info || strncmp(info->error,prefix,sizeof(prefix)-1)) return NULL;
    const char* uid = info->error + sizeof(prefix)-1;
    return uid;
}

bool import_session_restore_target_allowed(const char* path, const char* uid, bool explicit_uid) {
    if (!path) return true;
    pthread_mutex_lock(&s_lock);
    bool ok = !s_checkpoint_uncertain && !s_preserved_uncertain;
    if (ok && (import_session_rejected_uid(&s_session) ||
        (s_raw_target_uid[0] && (!explicit_uid || !uid || strcmp(uid,s_raw_target_uid))))) {
        struct stat candidate, bound;
        ok = stat(path,&candidate) == 0 && S_ISREG(candidate.st_mode);
        const char* paths[] = {s_session.path,s_session.portable_path};
        for (size_t i=0; ok && i<2; i++) if (paths[i][0]) {
            ok = strcmp(path,paths[i]) && stat(paths[i],&bound) == 0 && S_ISREG(bound.st_mode) &&
                (candidate.st_dev != bound.st_dev || candidate.st_ino != bound.st_ino);
        }
    }
    pthread_mutex_unlock(&s_lock);
    return ok;
}


bool import_session_write(const char* id, uint64_t offset,
                          const void* data, size_t len,
                          import_session_info_t* out) {
    if (!data || len == 0 || len > IMPORT_CHUNK_BYTES) return false;
    pthread_mutex_lock(&s_lock);
    if (!id_ok(id) || s_session.state != IMPORT_RECEIVING ||
        offset != s_session.received || len > s_session.expected - offset) {
        if (out) *out = s_session;
        pthread_mutex_unlock(&s_lock);
        return false;
    }
    int64_t started_ms = monotonic_ms();
    if (preserved_path_blocked_locked(s_session.path)) {
        pthread_mutex_unlock(&s_lock); return false;
    }
    int fd = open(s_session.path, O_WRONLY | O_NOFOLLOW);
    bool ok = fd >= 0 && pwrite(fd, data, len, (off_t)offset) == (ssize_t)len;
    if (fd >= 0) { if (ok) ok = fsync(fd) == 0; close(fd); }
    if (ok) {
        s_session.received += len;
        s_session.updated_unix = time(NULL);
    } else {
        s_session.state = IMPORT_FAILED;
        snprintf(s_session.error, sizeof(s_session.error), "Could not write upload chunk");
    }
    (void)persist_session_locked();
    log_info("ZIP import chunk: offset=%llu bytes=%zu stored=%s duration_ms=%lld location=%s",
             (unsigned long long)offset, len, ok ? "yes" : "no",
             (long long)(monotonic_ms() - started_ms), s_session.location);
    if (out) *out = s_session;
    pthread_mutex_unlock(&s_lock);
    return ok;
}

static bool sha_text_ok(const char* s) {
    if (!s || !s[0]) return true;
    if (strlen(s) != 64) return false;
    for (int i = 0; i < 64; i++) {
        char c = s[i];
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') ||
              (c >= 'A' && c <= 'F'))) return false;
    }
    return true;
}

bool import_session_finish(const char* id, const char* expected_sha256,
                           import_session_info_t* out) {
    if (!sha_text_ok(expected_sha256)) return false;
    char path[512], expected[65], actual[65] = {0};
    pthread_mutex_lock(&s_lock);
    if (!id_ok(id) || s_session.state != IMPORT_RECEIVING ||
        s_session.received != s_session.expected) {
        if (out) *out = s_session;
        pthread_mutex_unlock(&s_lock);
        return false;
    }
    s_session.state = IMPORT_VERIFYING;
    (void)persist_session_locked();
    snprintf(path, sizeof(path), "%s", s_session.path);
    snprintf(expected, sizeof(expected), "%s",
             expected_sha256 ? expected_sha256 : "");
    if (out) *out = s_session;
    pthread_mutex_unlock(&s_lock);

    int64_t verify_started_ms = monotonic_ms();
    bool hash_ok = sha256_file_hex(path, actual);
    bool checksum_ok = hash_ok &&
        (!expected[0] || strcasecmp(expected, actual) == 0);
    bool zip_ok = checksum_ok && zip_entry_count(path) > 0;

    pthread_mutex_lock(&s_lock);
    if (!id_ok(id) || s_session.state != IMPORT_VERIFYING ||
        strcmp(s_session.path, path) != 0) {
        pthread_mutex_unlock(&s_lock);
        return false;
    }
    if (!hash_ok) {
        s_session.state = IMPORT_FAILED;
        snprintf(s_session.error, sizeof(s_session.error), "Could not calculate ZIP checksum");
    } else if (!checksum_ok) {
        s_session.state = IMPORT_FAILED;
        snprintf(s_session.error, sizeof(s_session.error), "ZIP checksum does not match");
    } else if (!zip_ok) {
        s_session.state = IMPORT_FAILED;
        snprintf(s_session.error, sizeof(s_session.error), "ZIP is invalid or empty");
    } else {
        snprintf(s_session.sha256, sizeof(s_session.sha256), "%s", actual);
        char final_path[512];
        snprintf(final_path, sizeof(final_path), "%s", s_session.path);
        char* ext = strrchr(final_path, '.');
        if (ext) snprintf(ext, (size_t)(final_path + sizeof(final_path) - ext), ".zip");
        struct stat collision;
        if (preserved_path_blocked_locked(s_session.path) || preserved_path_blocked_locked(final_path) ||
            lstat(final_path, &collision) == 0 || errno != ENOENT || rename(s_session.path, final_path) != 0) {
            s_session.state = IMPORT_FAILED;
            snprintf(s_session.error, sizeof(s_session.error), "Could not finalize ZIP upload");
        } else {
            snprintf(s_session.path, sizeof(s_session.path), "%s", final_path);
            s_session.state = IMPORT_READY;
            s_session.updated_unix = time(NULL);
            log_info("ZIP upload complete: %s (%llu bytes, SHA-256 %s)",
                     s_session.name, (unsigned long long)s_session.received,
                     s_session.sha256);
        }
    }
    if (out) *out = s_session;
    bool ok = s_session.state == IMPORT_READY;
    (void)persist_session_locked();
    log_info("ZIP import verification: result=%s duration_ms=%lld",
             ok ? "ready" : "failed",
             (long long)(monotonic_ms() - verify_started_ms));
    pthread_mutex_unlock(&s_lock);
    return ok;
}

life_check_t import_session_lifecycle_snapshot(void) {
    int locked = pthread_mutex_trylock(&s_lock);
    if (locked) return locked == EBUSY ? LIFE_BUSY : LIFE_UNKNOWN;
    life_check_t result = LIFE_UNKNOWN;
    if (s_state_path[0] && !s_checkpoint_uncertain && !s_preserved_uncertain) {
        switch (s_session.state) {
            case IMPORT_IDLE: case IMPORT_READY: result = LIFE_CLEAR; break;
            case IMPORT_RECEIVING: case IMPORT_VERIFYING:
            case IMPORT_COMMITTED: case IMPORT_RECOVERING: result = LIFE_BUSY; break;
            default: break;
        }
    }
    pthread_mutex_unlock(&s_lock);
    return result;
}

import_jobs_observation_t import_session_jobs_snapshot(import_jobs_snapshot_t* out) {
    if (!out) return IMPORT_JOBS_UNKNOWN;
    int saved_errno = errno;
    memset(out, 0, sizeof(*out));
    out->uncertain = true;
    int locked = pthread_mutex_trylock(&s_lock);
    if (locked) {
        errno = saved_errno;
        return locked == EBUSY ? IMPORT_JOBS_BUSY : IMPORT_JOBS_UNKNOWN;
    }
    out->state = s_session.state;
    out->current_present = s_session.id[0] || s_session.state != IMPORT_IDLE;
    out->uncertain = !s_state_path[0] || s_checkpoint_uncertain || s_preserved_uncertain ||
        s_session.state < IMPORT_IDLE || s_session.state > IMPORT_RECOVERING ||
        strnlen(s_session.id, sizeof(s_session.id)) == sizeof(s_session.id) ||
        (out->current_present && (!s_session.id[0] || s_session.received > s_session.expected));
    out->observation_only = s_observation_only;
    memcpy(out->native_id, s_session.id, sizeof(out->native_id));
    out->native_id[sizeof(out->native_id) - 1] = 0;
    out->received = s_session.received;
    out->expected = s_session.expected;
    out->updated_unix = s_session.updated_unix;
    const restore_scope_t* scope = &s_session.restore_scope;
    bool scoped = scope->selection.specified &&
        strnlen(scope->import_id, sizeof(scope->import_id)) < sizeof(scope->import_id) &&
        strnlen(s_session.id, sizeof(s_session.id)) < sizeof(s_session.id) &&
        !strcmp(scope->import_id, s_session.id);
    const char* title = scoped ? scope->title_id : s_session.title_hint;
    const char* uid = scoped ? scope->target_uid : s_session.user_hint;
    if (strnlen(title, 16) == 9 && (!strncmp(title, "PPSA", 4) || !strncmp(title, "CUSA", 4)) &&
        strspn(title + 4, "0123456789") == 5)
        memcpy(out->title_id, title, 10);
    if (strnlen(uid, 16) == 8 && strspn(uid, "0123456789abcdefABCDEF") == 8)
        memcpy(out->user_uid, uid, 9);
    if (scoped && scope->selection.count == 1 &&
        strnlen(scope->selection.slots[0], sizeof(out->container)) < sizeof(out->container)) {
        memcpy(out->container, scope->selection.slots[0], sizeof(out->container));
        out->container[sizeof(out->container) - 1] = 0;
    }
    if (pthread_mutex_unlock(&s_lock)) out->uncertain = true;
    errno = saved_errno;
    return out->uncertain ? IMPORT_JOBS_UNKNOWN : IMPORT_JOBS_OBSERVED;
}

bool import_session_current(import_session_info_t* out) {
    pthread_mutex_lock(&s_lock);
    bool ok = s_session.state != IMPORT_IDLE;
    if (ok && out) *out = s_session;
    pthread_mutex_unlock(&s_lock);
    return ok;
}

bool import_session_status(const char* id, import_session_info_t* out) {
    pthread_mutex_lock(&s_lock);
    bool ok = s_observation_only ? !s_checkpoint_uncertain && !s_preserved_uncertain &&
        id && id[0] && !strcmp(id, s_session.id) : id_ok(id);
    if (ok && out) *out = s_session;
    pthread_mutex_unlock(&s_lock);
    return ok;
}

bool import_session_status_observe(const char* id, import_session_info_t* out) {
    pthread_mutex_lock(&s_lock);
    bool ok = !s_checkpoint_uncertain && !s_preserved_uncertain &&
        (s_observation_only || preserved_scan_readonly_locked(NULL, NULL, NULL, NULL, false, NULL)) &&
        id && id[0] && !strcmp(id, s_session.id);
    if (ok && out) *out = s_session;
    pthread_mutex_unlock(&s_lock);
    return ok;
}

bool import_session_set_title_hint(const char* id, const char* title_hint) {
    pthread_mutex_lock(&s_lock);
    bool ok = id_ok(id) && title_hint && title_hint[0] &&
              (s_session.state == IMPORT_RECEIVING ||
               s_session.state == IMPORT_READY);
    if (ok) {
        memset(&s_session.restore_scope, 0, sizeof(s_session.restore_scope));
        snprintf(s_session.title_hint, sizeof(s_session.title_hint), "%s",
                 title_hint);
    }
    if (ok) (void)persist_session_locked();
    pthread_mutex_unlock(&s_lock);
    return ok;
}

bool import_session_begin_recovery(const char* id, import_session_info_t* out) {
    pthread_mutex_lock(&s_lock);
    bool ok = id_ok(id) && s_session.state == IMPORT_READY &&
              !import_session_rejected_uid(&s_session) &&
              !s_session.portable_path[0] && !s_session.portable_sha256[0] &&
              s_session.sha256[0] && sha_text_ok(s_session.sha256) &&
              !preserved_path_blocked_locked(s_session.path);
    if (ok) {
        import_session_info_t previous = s_session;
        memset(&s_session.restore_scope, 0, sizeof(s_session.restore_scope));
        s_session.state = IMPORT_RECOVERING;
        s_session.error[0] = '\0';
        s_session.updated_unix = time(NULL);
        if (!persist_session_locked()) {
            s_session = previous;
            snprintf(s_session.error, sizeof(s_session.error),
                     "Could not persist RAW recovery state; original ZIP retained.");
            ok = false;
        }
    }
    if (out) *out = s_session;
    pthread_mutex_unlock(&s_lock);
    return ok;
}

static void recovery_error_locked(const char* error) {
    s_session.state = IMPORT_READY;
    s_session.portable_path[0] = s_session.portable_sha256[0] = '\0';
    snprintf(s_session.error, sizeof(s_session.error), "%s",
             error && error[0] ? error : "RAW recovery failed; original ZIP retained.");
    for (char* p = s_session.error; *p; p++)
        if (*p == '\r' || *p == '\n') *p = ' ';
    s_session.updated_unix = time(NULL);
}

bool import_session_finish_recovery(const char* id, const char* candidate_path,
                                    const char* title_hint, const char* error,
                                    import_session_info_t* out) {
    pthread_mutex_lock(&s_lock);
    if (!id_ok(id) || s_session.state != IMPORT_RECOVERING) {
        if (out) *out = s_session;
        pthread_mutex_unlock(&s_lock);
        return false;
    }
    import_session_info_t original = s_session;
    pthread_mutex_unlock(&s_lock);

    char candidate[512], final[512], candidate_sha[65] = {0};
    bool paths_ok = import_session_recovery_candidate(&original, candidate,
                                                       sizeof(candidate)) &&
                    sidecar_path(&original, ".portable.zip", final, sizeof(final));
    bool ok = paths_ok && candidate_path && !strcmp(candidate_path, candidate) &&
              !(error && error[0]) && title_hint && title_hint[0] &&
              strlen(title_hint) < sizeof(original.title_hint) &&
              strspn(title_hint, "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789") == strlen(title_hint);
    pthread_mutex_lock(&s_lock);
    if (paths_ok && (preserved_path_blocked_locked(original.path) ||
        preserved_path_blocked_locked(candidate) || preserved_path_blocked_locked(final))) {
        pthread_mutex_unlock(&s_lock);
        return false;
    }
    pthread_mutex_unlock(&s_lock);
    struct stat st;
    const char* failure = error;
    if (ok) {
        ok = lstat(candidate, &st) == 0 && S_ISREG(st.st_mode) &&
             st.st_size >= 22 && (uint64_t)st.st_size <= IMPORT_MAX_BYTES &&
             sha256_file_hex(candidate, candidate_sha) &&
             file_matches_sha(candidate, candidate_sha, (uint64_t)st.st_size);
        if (ok) {
            int fd = open(candidate, O_RDONLY | O_NOFOLLOW);
            ok = fd >= 0 && fsync(fd) == 0;
            if (fd >= 0 && close(fd) != 0) ok = false;
        }
        if (!ok) failure = "Could not verify recovered portable ZIP; original retained.";
    }
    if (ok && !import_session_validate_selected(&original)) {
        ok = false;
        failure = "Original RAW ZIP changed; recovery was not published.";
    }

    pthread_mutex_lock(&s_lock);
    if (!id_ok(id) || s_session.state != IMPORT_RECOVERING ||
        strcmp(s_session.path, original.path) != 0 ||
        strcmp(s_session.sha256, original.sha256) != 0) {
        pthread_mutex_unlock(&s_lock);
        return false;
    }
    if (ok && (rename(candidate, final) != 0 || !fsync_parent(final))) {
        ok = false;
        failure = "Could not finalize recovered portable ZIP; original retained.";
    }
    if (ok) {
        s_session.state = IMPORT_READY;
        snprintf(s_session.portable_path, sizeof(s_session.portable_path), "%s", final);
        snprintf(s_session.portable_sha256, sizeof(s_session.portable_sha256), "%s", candidate_sha);
        snprintf(s_session.title_hint, sizeof(s_session.title_hint), "%s", title_hint);
        s_session.user_hint[0] = s_session.error[0] = '\0';
        s_session.updated_unix = time(NULL);
        if (!persist_session_locked()) {
            ok = false;
            failure = "Could not persist recovered portable ZIP; original retained.";
        }
    }
    if (!ok) {
        // Only fixed session-owned sidecars are touched on failure.
        if (paths_ok && !preserved_path_blocked_locked(candidate) &&
            !preserved_path_blocked_locked(final)) { unlink(candidate); unlink(final); }
        recovery_error_locked(failure);
        (void)persist_session_locked();
    }
    if (out) *out = s_session;
    pthread_mutex_unlock(&s_lock);
    return ok;
}

bool import_session_owns_ready_path(const char* path) {
    pthread_mutex_lock(&s_lock);
    bool ok = !s_observation_only && path && path[0] && !preserved_path_blocked_locked(path) &&
              (s_session.state == IMPORT_READY ||
               s_session.state == IMPORT_COMMITTED) &&
              (strcmp(path, s_session.path) == 0 ||
               (strcmp(path, s_session.portable_path) == 0 &&
                import_session_validate_selected(&s_session)));
    pthread_mutex_unlock(&s_lock);
    return ok;
}

bool import_session_claim(const char* id, import_session_info_t* out) {
    if (!lifecycle_operation_begin()) return false;
    pthread_mutex_lock(&s_lock);
    bool ok = id_ok(id) && s_session.state == IMPORT_READY &&
              !s_session.restore_selection_required &&
              !preserved_path_blocked_locked(import_session_selected_path(&s_session)) &&
              (!s_session.portable_path[0] ||
               import_session_validate_selected(&s_session));
    if (ok) {
        s_session.state = IMPORT_COMMITTED;
        s_session.updated_unix = time(NULL);
        if (!persist_session_locked()) { s_session.state = IMPORT_READY; ok = false; }
        if (out) *out = s_session;
    }
    pthread_mutex_unlock(&s_lock);
    lifecycle_operation_end();
    return ok;
}

static bool scope_matches_session(const restore_scope_t* scope) {
    return restore_scope_valid(scope) &&
        !strcmp(scope->import_id, s_session.id) &&
        !strcmp(scope->source_sha256, s_session.sha256) &&
        !strcmp(scope->portable_sha256, s_session.portable_sha256) &&
        (!s_session.title_hint[0] || !strcmp(s_session.title_hint, "auto") ||
         !strcmp(scope->title_id, s_session.title_hint));
}

bool import_session_invalidate_restore_scope(const char* id, bool require_selection) {
    if (!lifecycle_operation_begin()) return false;
    pthread_mutex_lock(&s_lock);
    bool ok = id_ok(id) && s_session.state == IMPORT_READY &&
        !s_checkpoint_uncertain && !s_preserved_uncertain;
    if (ok) {
        // Keep this conservative state in memory even if its checkpoint fails.
        s_session.restore_selection_required |= require_selection;
        memset(&s_session.restore_scope, 0, sizeof(s_session.restore_scope));
        ok = persist_session_locked();
        if (!ok) s_checkpoint_uncertain = true;
    }
    pthread_mutex_unlock(&s_lock);
    lifecycle_operation_end();
    return ok;
}

bool import_session_bind_restore_scope(const import_session_info_t* reviewed,
                                      const restore_scope_t* scope) {
    if (!lifecycle_operation_begin()) return false;
    pthread_mutex_lock(&s_lock);
    bool ok = reviewed && scope && id_ok(reviewed->id) &&
        s_session.state == IMPORT_READY && !s_checkpoint_uncertain && !s_preserved_uncertain &&
        !strcmp(reviewed->path, s_session.path) &&
        !strcmp(reviewed->portable_path, s_session.portable_path) &&
        !strcmp(reviewed->title_hint, s_session.title_hint) &&
        reviewed->expected == s_session.expected && scope_matches_session(scope) &&
        import_session_validate_selected(&s_session);
    if (ok) {
        s_session.restore_selection_required = true;
        s_session.restore_scope = *scope;
        char rejected[sizeof(s_session.error)];
        snprintf(rejected,sizeof(rejected),"%s",s_session.error);
        if (import_session_rejected_uid(&s_session)) s_session.error[0] = '\0';
        if (!persist_session_locked()) {
            snprintf(s_session.error,sizeof(s_session.error),"%s",rejected);
            memset(&s_session.restore_scope, 0, sizeof(s_session.restore_scope));
            s_checkpoint_uncertain = true;
            ok = false;
        }
    }
    pthread_mutex_unlock(&s_lock);
    lifecycle_operation_end();
    return ok;
}

bool import_session_get_restore_scope(const char* id, restore_scope_t* out) {
    pthread_mutex_lock(&s_lock);
    bool ok = id_ok(id) && !s_checkpoint_uncertain && !s_preserved_uncertain && (s_session.state == IMPORT_READY ||
        s_session.state == IMPORT_COMMITTED) && s_session.restore_selection_required &&
        scope_matches_session(&s_session.restore_scope);
    if (ok && out) *out = s_session.restore_scope;
    pthread_mutex_unlock(&s_lock);
    return ok;
}

bool import_session_claim_restore_scope(const restore_scope_t* scope,
                                       import_session_info_t* out) {
    if (!lifecycle_operation_begin()) return false;
    pthread_mutex_lock(&s_lock);
    bool ok = scope && id_ok(scope->import_id) && s_session.state == IMPORT_READY &&
        !s_checkpoint_uncertain && !s_preserved_uncertain &&
        s_session.restore_selection_required && scope_matches_session(scope) &&
        restore_scope_equal(scope, &s_session.restore_scope) &&
        !preserved_path_blocked_locked(import_session_selected_path(&s_session)) &&
        import_session_validate_selected(&s_session);
    if (ok) {
        s_session.state = IMPORT_COMMITTED;
        s_session.updated_unix = time(NULL);
        if (!persist_session_locked()) {
            // Rename may have succeeded before directory fsync failed. Do not
            // pretend this ambiguous durable claim is READY or queue a writer.
            s_checkpoint_uncertain = true;
            memset(&s_session.restore_scope, 0, sizeof(s_session.restore_scope));
            ok = false;
        }
        if (out) *out = s_session;
    }
    pthread_mutex_unlock(&s_lock);
    lifecycle_operation_end();
    return ok;
}

bool import_session_validate_restore_scope(const restore_scope_t* scope,
                                          const char* path) {
    pthread_mutex_lock(&s_lock);
    bool ok = scope && path && id_ok(scope->import_id) && s_session.state == IMPORT_COMMITTED &&
        !s_checkpoint_uncertain && !s_preserved_uncertain &&
        s_session.restore_selection_required && scope_matches_session(scope) &&
        restore_scope_equal(scope, &s_session.restore_scope) &&
        !strcmp(path, import_session_selected_path(&s_session)) &&
        !preserved_path_blocked_locked(path) &&
        import_session_validate_selected(&s_session);
    pthread_mutex_unlock(&s_lock);
    return ok;
}

bool import_session_legacy_restore_allowed(const char* path) {
    pthread_mutex_lock(&s_lock);
    bool ok = !s_observation_only && !s_checkpoint_uncertain && path && !preserved_path_blocked_locked(path) && !strcmp(path, import_session_selected_path(&s_session)) &&
        !s_session.restore_selection_required;
    pthread_mutex_unlock(&s_lock);
    return ok;
}

bool import_session_path_requires_selection(const char* path) {
    pthread_mutex_lock(&s_lock);
    if (s_observation_only) { pthread_mutex_unlock(&s_lock); return true; }
    if (preserved_path_blocked_locked(path)) {
        pthread_mutex_unlock(&s_lock); return true;
    }
    bool required = s_session.restore_selection_required;
    if (!required || (path && path[0] != '/')) {
        pthread_mutex_unlock(&s_lock);
        return false;
    }
    if (s_checkpoint_uncertain) {
        pthread_mutex_unlock(&s_lock);
        return true;
    }
    if (!path || !strcmp(path, s_session.path) ||
        (s_session.portable_path[0] && !strcmp(path, s_session.portable_path))) {
        pthread_mutex_unlock(&s_lock);
        return true;
    }
    struct stat candidate, protected;
    // stat intentionally follows aliases, using only filesystem metadata.
    // If a protected USB volume disappeared, different textual paths cannot
    // establish independence; defer rather than grant restore-all permission.
    bool blocked = stat(path, &candidate) != 0 || !S_ISREG(candidate.st_mode);
    const char* paths[] = {s_session.path, s_session.portable_path};
    for (size_t i = 0; !blocked && i < 2; i++) {
        if (!paths[i][0]) continue;
        if (stat(paths[i], &protected) != 0 || !S_ISREG(protected.st_mode) ||
            (candidate.st_dev == protected.st_dev && candidate.st_ino == protected.st_ino)) blocked = true;
    }
    char fixed_portable[512];
    if (!blocked) {
        if (!sidecar_path(&s_session, ".portable.zip", fixed_portable, sizeof(fixed_portable))) blocked = true;
        else if (!strcmp(path, fixed_portable)) blocked = true;
        else if (stat(fixed_portable, &protected) == 0)
            blocked = !S_ISREG(protected.st_mode) ||
                (candidate.st_dev == protected.st_dev && candidate.st_ino == protected.st_ino);
        else if (errno != ENOENT) blocked = true;
    }
    pthread_mutex_unlock(&s_lock);
    return blocked;
}

static bool import_session_unclaim_internal(const char* id, const char* target_rejected) {
    if (!lifecycle_operation_begin()) return false;
    pthread_mutex_lock(&s_lock);
    bool ok = id_ok(id) && s_session.state == IMPORT_COMMITTED;
    if (ok) {
        bool selected = s_session.restore_selection_required;
        // A Portable approval authorizes one attempt, including queue failure.
        // Leave the sticky selection guard; another attempt needs new preflight.
        if (selected || target_rejected) memset(&s_session.restore_scope, 0, sizeof(s_session.restore_scope));
        if (target_rejected) {
            snprintf(s_session.error, sizeof(s_session.error), "restore_target_uid_missing:%s", target_rejected);
            if (!s_raw_target_uid[0]) snprintf(s_raw_target_uid,sizeof(s_raw_target_uid),"%s",target_rejected);
        }
        s_session.state = IMPORT_READY;
        s_session.updated_unix = time(NULL);
        bool durable = persist_session_locked();
        if ((selected || target_rejected) && !durable) {
            s_session.state = IMPORT_COMMITTED;
            s_checkpoint_uncertain = true;
            ok = false;
        }
    }
    pthread_mutex_unlock(&s_lock);
    lifecycle_operation_end();
    return ok;
}

bool import_session_unclaim(const char* id) {
    return import_session_unclaim_internal(id, NULL);
}

bool import_session_release_target_rejected(const char* id, const char* uid) {
    return restore_uid_valid(uid) && import_session_unclaim_internal(id, uid);
}

// Only a new explicit review may clear the failed destination's approval barrier.
bool import_session_target_reviewed(const char* id, const char* uid) {
    if (!lifecycle_operation_begin()) return false;
    pthread_mutex_lock(&s_lock);
    bool ok = id_ok(id) && s_session.state == IMPORT_READY &&
        import_session_rejected_uid(&s_session) && uid &&
        !strcmp(import_session_rejected_uid(&s_session),uid);
    if (ok) {
        s_session.error[0] = '\0';
        ok = persist_session_locked();
        if (!ok) {
            snprintf(s_session.error, sizeof(s_session.error), "restore_target_uid_missing:%s", uid);
            s_checkpoint_uncertain = true;
        }
    }
    pthread_mutex_unlock(&s_lock);
    lifecycle_operation_end();
    return ok;
}

bool import_session_unclaim_raw_durable(const char* id) {
    if (!lifecycle_operation_begin()) return false;
    pthread_mutex_lock(&s_lock);
    bool ok = id_ok(id) && s_session.state == IMPORT_COMMITTED &&
        !s_session.portable_path[0] && !s_session.restore_selection_required &&
        !s_checkpoint_uncertain && !s_preserved_uncertain;
    if (ok) {
        s_session.state = IMPORT_READY; s_session.updated_unix = time(NULL);
        ok = persist_session_locked();
        if (!ok) { s_session.state = IMPORT_COMMITTED; s_checkpoint_uncertain = true; }
    }
    pthread_mutex_unlock(&s_lock); lifecycle_operation_end(); return ok;
}

bool import_session_cancel(const char* id) {
    pthread_mutex_lock(&s_lock);
    if (!id_ok(id) || s_session.state == IMPORT_VERIFYING ||
        s_session.state == IMPORT_COMMITTED ||
        s_session.state == IMPORT_RECOVERING) {
        pthread_mutex_unlock(&s_lock);
        return false;
    }
    log_info("ZIP import canceled: %s", s_session.name);
    bool ok = clear_session_locked(true);
    pthread_mutex_unlock(&s_lock);
    return ok;
}

static bool individual_import_item_valid(const individual_backup_t* item) {
    if (!item || !memchr(item->source, 0, sizeof(item->source)) ||
        (strcmp(item->source, "usb") && strcmp(item->source, "ftp") &&
         strcmp(item->source, "drive") && strcmp(item->source, "browser")) ||
        !individual_catalog_item_valid(item, item->source) ||
        !memchr(item->container, 0, sizeof(item->container))) return false;
    size_t title_size = strlen(item->title_id);
    return strlen(item->user) == 8 && strspn(item->user, "0123456789abcdef") == 8 &&
        title_size >= 5 && title_size < sizeof(s_session.title_hint) &&
        strspn(item->title_id, "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789") == title_size &&
        (!strncmp(item->title_id, "PPSA", 4) || !strncmp(item->title_id, "CUSA", 4) ||
         !strncmp(item->title_id, "PCSA", 4) || !strncmp(item->title_id, "NPXS", 4)) &&
        strspn(item->destination_identity, "0123456789abcdef") == 64 &&
        strspn(item->file_stamp, "0123456789abcdef") == 64;
}

static bool individual_import_container_valid(const char* container) {
    if (!container || !container[0] || strlen(container) >= 64 ||
        container[0] == '.' || strstr(container, "..")) return false;
    for (const unsigned char* p = (const unsigned char*)container; *p; p++)
        if (*p < 32 || *p == 127 || strchr("/\\\"", *p)) return false;
    return true;
}

static bool individual_import_checkpoint_locked(void) {
    bool ok = fsync_parent(s_session.path) && persist_session_locked();
    if (!ok) {
        s_checkpoint_uncertain = true;
        s_session.restore_selection_required = true;
        memset(&s_session.restore_scope, 0, sizeof(s_session.restore_scope));
        snprintf(s_session.error, sizeof(s_session.error),
                 "Individual import checkpoint is uncertain; evidence retained. No Restore is authorized.");
    }
    return ok;
}

static bool individual_import_source_valid(const char* source) {
    return !strcmp(source, "individual") || !strcmp(source, "individual-browser");
}

static bool individual_import_mark_source(const char* id, const char* source,
                                          import_session_info_t* out) {
    pthread_mutex_lock(&s_lock);
    bool ok = id_ok(id) && !s_preserved_uncertain &&
        !s_session.restore_scope.receipt[0] &&
        (s_session.state == IMPORT_RECEIVING ||
         (s_session.state == IMPORT_READY && individual_import_source_valid(s_session.source))) &&
        (!individual_import_source_valid(s_session.source) || !strcmp(s_session.source, source));
    if (ok) {
        snprintf(s_session.source, sizeof(s_session.source), "%s", source);
        s_session.restore_selection_required = true;
        memset(&s_session.restore_scope, 0, sizeof(s_session.restore_scope));
        ok = individual_import_checkpoint_locked();
    }
    if (out) *out = s_session;
    pthread_mutex_unlock(&s_lock);
    return ok;
}

bool import_session_individual_mark(const char* id, import_session_info_t* out) {
    return individual_import_mark_source(id, "individual", out);
}

bool import_session_individual_browser_mark(const char* id, import_session_info_t* out) {
    return individual_import_mark_source(id, "individual-browser", out);
}

bool import_session_individual_checkpoint(const char* id, import_session_info_t* out) {
    pthread_mutex_lock(&s_lock);
    bool ok = id_ok(id) && !s_preserved_uncertain &&
        individual_import_source_valid(s_session.source) && s_session.restore_selection_required &&
        !s_session.restore_scope.receipt[0] &&
        (s_session.state == IMPORT_RECEIVING || s_session.state == IMPORT_READY);
    if (ok) ok = individual_import_checkpoint_locked();
    if (out) *out = s_session;
    pthread_mutex_unlock(&s_lock);
    return ok;
}

static bool individual_import_record_read(const char* path, individual_import_record_t* record) {
    struct stat before, opened, after;
    if (lstat(path, &before) || !S_ISREG(before.st_mode) ||
        (before.st_mode & 0777) != 0600 || before.st_uid != getuid() ||
        (uint64_t)before.st_size != sizeof(*record)) return false;
    int fd = open(path, O_RDONLY | O_NOFOLLOW | O_NONBLOCK);
    if (fd < 0) return false;
    bool ok = !fstat(fd, &opened) && checkpoint_stat_same(&before, &opened) &&
        (opened.st_mode & 0777) == 0600 && opened.st_uid == getuid();
    size_t got = 0;
    while (ok && got < sizeof(*record)) {
        ssize_t count = read(fd, (char*)record + got, sizeof(*record) - got);
        if (count < 0 && errno == EINTR) continue;
        if (count <= 0) ok = false; else got += (size_t)count;
    }
    unsigned char extra;
    if (ok) ok = read(fd, &extra, 1) == 0 && !fstat(fd, &after) &&
        checkpoint_stat_same(&before, &after) && !lstat(path, &opened) &&
        checkpoint_stat_same(&after, &opened) && (opened.st_mode & 0777) == 0600 &&
        opened.st_uid == getuid();
    if (close(fd)) ok = false;
    char sha[65];
    if (ok) {
        hash_bytes(record, offsetof(individual_import_record_t, sha256), sha);
        ok = !memcmp(record->magic, "TOSTON-INDIV-1", 14) &&
            record->schema == 1 && record->size == sizeof(*record) &&
            FIELD_TERMINATED(record, id) && preserved_id_valid(record->id) &&
            FIELD_TERMINATED(record, path) && record->path[0] == '/' &&
            FIELD_TERMINATED(record, canonical_sha256) && record->canonical_sha256[0] &&
            sha_text_ok(record->canonical_sha256) && FIELD_TERMINATED(record, container) &&
            individual_import_container_valid(record->container) &&
            individual_import_item_valid(&record->item) &&
            FIELD_TERMINATED(record, sha256) && !strcmp(record->sha256, sha);
    }
    return ok;
}

static bool individual_import_record_matches_locked(const individual_import_record_t* record) {
    struct stat owned;
    return !lstat(s_session.path, &owned) && S_ISREG(owned.st_mode) &&
        (owned.st_mode & 0777) == 0600 && owned.st_uid == getuid() &&
        !s_session.portable_path[0] && !s_session.portable_sha256[0] &&
        individual_import_source_valid(s_session.source) && s_session.restore_selection_required &&
        (!strcmp(record->item.source, "browser") == !strcmp(s_session.source, "individual-browser")) &&
        !strcmp(record->id, s_session.id) && !strcmp(record->path, s_session.path) &&
        !strcmp(record->canonical_sha256, s_session.sha256) &&
        !strcmp(record->item.user, s_session.user_hint) &&
        !strcmp(record->item.title_id, s_session.title_hint) &&
        record->item.size_bytes == s_session.expected &&
        (!record->item.checksum[0] || !strcmp(record->item.checksum, s_session.sha256)) &&
        s_session.received == s_session.expected &&
        !preserved_path_blocked_locked(s_session.path) &&
        import_session_validate_selected(&s_session);
}

bool import_session_individual_bind(const char* id, const individual_backup_t* item,
                                    const char* container, import_session_info_t* out) {
    pthread_mutex_lock(&s_lock);
    char path[512];
    bool ok = id_ok(id) && !s_preserved_uncertain && s_session.state == IMPORT_READY &&
        individual_import_source_valid(s_session.source) && s_session.restore_selection_required &&
        !s_session.restore_scope.receipt[0] && individual_import_item_valid(item) &&
        individual_import_container_valid(container) &&
        sidecar_path(&s_session, ".individual", path, sizeof(path));
    individual_import_record_t record;
    memset(&record, 0, sizeof(record));
    if (ok) {
        memcpy(record.magic, "TOSTON-INDIV-1", 14);
        record.schema = 1; record.size = sizeof(record);
        snprintf(record.id, sizeof(record.id), "%s", s_session.id);
        snprintf(record.path, sizeof(record.path), "%s", s_session.path);
        snprintf(record.canonical_sha256, sizeof(record.canonical_sha256), "%s", s_session.sha256);
        snprintf(record.container, sizeof(record.container), "%s", container);
        record.item = *item;
        ok = individual_import_record_matches_locked(&record) &&
            individual_import_checkpoint_locked();
    }
    bool published = false;
    if (ok) {
        hash_bytes(&record, offsetof(individual_import_record_t, sha256), record.sha256);
        int fd = open(path, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW, 0600);
        ok = fd >= 0;
        if (ok) published = true;
        size_t written = 0;
        while (ok && written < sizeof(record)) {
            ssize_t count = write(fd, (const char*)&record + written, sizeof(record) - written);
            if (count < 0 && errno == EINTR) continue;
            if (count <= 0) ok = false; else written += (size_t)count;
        }
        if (ok) ok = fsync(fd) == 0;
        if (fd >= 0 && close(fd)) ok = false;
        if (ok) ok = fsync_parent(path);
        individual_import_record_t verified;
        if (ok) ok = individual_import_record_read(path, &verified) &&
            !memcmp(&record, &verified, sizeof(record)) &&
            individual_import_record_matches_locked(&verified);
    }
    if (published && !ok) {
        // A partial or uncertain publication is evidence, never permission.
        s_checkpoint_uncertain = true;
        memset(&s_session.restore_scope, 0, sizeof(s_session.restore_scope));
        snprintf(s_session.error, sizeof(s_session.error),
                 "Individual import binding is uncertain; evidence retained. No Restore is authorized.");
    }
    if (out) *out = s_session;
    pthread_mutex_unlock(&s_lock);
    return ok;
}

bool import_session_individual_get(const char* id, individual_backup_t* item,
                                   char container[64]) {
    if (item) memset(item, 0, sizeof(*item));
    if (container) container[0] = '\0';
    pthread_mutex_lock(&s_lock);
    char path[512]; individual_import_record_t record;
    bool ok = id_ok(id) && !s_preserved_uncertain &&
        (s_session.state == IMPORT_READY || s_session.state == IMPORT_COMMITTED) &&
        sidecar_path(&s_session, ".individual", path, sizeof(path)) &&
        individual_import_record_read(path, &record) &&
        individual_import_record_matches_locked(&record);
    if (ok && item) *item = record.item;
    if (ok && container) snprintf(container, 64, "%s", record.container);
    pthread_mutex_unlock(&s_lock);
    return ok;
}

bool import_session_preserved_path_blocked(const char* path) {
    pthread_mutex_lock(&s_lock);
    bool blocked = preserved_path_blocked_locked(path);
    pthread_mutex_unlock(&s_lock);
    return blocked;
}

bool import_session_preserved_status(const char* id, import_preserved_info_t* out) {
    if (out) memset(out, 0, sizeof(*out));
    if (!preserved_id_valid(id)) return false;
    pthread_mutex_lock(&s_lock);
    import_preserved_info_t found;
    memset(&found, 0, sizeof(found));
    bool ok = preserved_scan_locked(id, NULL, &found, NULL, !s_observation_only, NULL) && found.historical.id[0];
    if (ok && out) *out = found;
    pthread_mutex_unlock(&s_lock);
    return ok;
}

bool import_session_preserved_count(size_t* out) {
    pthread_mutex_lock(&s_lock);
    bool ok = preserved_scan_locked(NULL, NULL, NULL, out, !s_observation_only, NULL);
    pthread_mutex_unlock(&s_lock);
    return ok;
}

bool import_session_preserved_status_observe(const char* id, import_preserved_info_t* out) {
    if (out) memset(out, 0, sizeof(*out));
    if (!preserved_id_valid(id)) return false;
    pthread_mutex_lock(&s_lock);
    import_preserved_info_t found;
    memset(&found, 0, sizeof(found));
    bool ok = preserved_scan_readonly_locked(id, NULL, &found, NULL, !s_observation_only, NULL) && found.historical.id[0];
    if (ok && out) *out = found;
    pthread_mutex_unlock(&s_lock);
    return ok;
}

static bool preserve_metadata_valid(const import_preserve_metadata_t* meta) {
    return meta && FIELD_TERMINATED(meta, source_format) && meta->source_format[0] &&
        FIELD_TERMINATED(meta, title_id) && meta->title_id[0] &&
        strspn(meta->title_id, "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789") == strlen(meta->title_id) &&
        FIELD_TERMINATED(meta, source_uid) && FIELD_TERMINATED(meta, raw_manifest_sha256) &&
        FIELD_TERMINATED(meta, raw_inventory_sha256) && FIELD_TERMINATED(meta, portable_manifest_sha256) &&
        FIELD_TERMINATED(meta, portable_inventory_sha256) && sha_text_ok(meta->raw_manifest_sha256) &&
        sha_text_ok(meta->raw_inventory_sha256) && sha_text_ok(meta->portable_manifest_sha256) &&
        sha_text_ok(meta->portable_inventory_sha256);
}

static bool preserved_same_source(const import_preserved_info_t* record,
                                  const import_session_info_t* current,
                                  const import_preserve_metadata_t* meta) {
    const import_session_info_t* old = &record->historical;
    return !strcmp(old->id, current->id) && !strcmp(old->path, current->path) &&
        !strcmp(old->sha256, current->sha256) && old->expected == current->expected &&
        !strcmp(old->portable_path, current->portable_path) &&
        !strcmp(old->portable_sha256, current->portable_sha256) &&
        old->restore_selection_required == current->restore_selection_required &&
        old->restore_scope.selection.count == current->restore_scope.selection.count &&
        !memcmp(old->restore_scope.selection.slots, current->restore_scope.selection.slots,
                sizeof(old->restore_scope.selection.slots)) &&
        !memcmp(&record->metadata, meta, sizeof(*meta));
}

bool import_session_preserve(const char* id,
                             const import_preserve_metadata_t* metadata,
                             import_preserved_info_t* out,
                             char* error, size_t error_cap) {
    if (out) memset(out, 0, sizeof(*out));
    if (error && error_cap) error[0] = '\0';
    pthread_mutex_lock(&s_lock);
    const char* failure = "Preserve requires the exact active READY session, with no claim or uncertain checkpoint.";
    bool ok = id_ok(id) && s_session.state == IMPORT_READY && preserve_metadata_valid(metadata) &&
        s_session.received == s_session.expected;
    import_session_info_t original = s_session;
    preserved_record_t record;
    memset(&record, 0, sizeof(record));
    char final[512] = {0}, temporary[512] = {0};
    bool published = false, released = false;
    if (ok) {
        failure = "Original RAW/portable integrity or filesystem identity is uncertain; session retained.";
        ok = import_session_validate_selected(&original) && preserved_record_path(id, final);
    }
    if (ok) {
        failure = "Could not create/validate preserved directory; session retained.";
        struct stat st;
        ok = (mkdir(s_preserved_dir, 0700) == 0 || errno == EEXIST) &&
            !lstat(s_preserved_dir, &st) && S_ISDIR(st.st_mode) && fsync_parent(s_preserved_dir);
    }
    if (ok) {
        struct stat existing;
        if (!lstat(final, &existing)) {
            // A crash may leave a safe historical duplicate while READY still
            // owns authority. Continue only if its exact source/scope agrees.
            failure = "Existing preserved record does not match the active source; evidence retained.";
            ok = preserved_record_read(final, &record) &&
                preserved_same_source(&record.info, &original, metadata) &&
                preserved_artifacts_match(&record.info);
            published = ok;
        } else if (errno != ENOENT) ok = false;
        else {
            failure = "Could not retain the original checkpoint; session retained.";
            size_t checkpoint_size = 0;
            ok = stable_regular_read(s_state_path, record.checkpoint,
                                     sizeof(record.checkpoint), false, &checkpoint_size);
            if (ok) {
                memcpy(record.magic, "TOSTON-PRESERVE1", 16);
                record.schema = 1; record.size = sizeof(record);
                record.checkpoint_size = (uint32_t)checkpoint_size;
                record.info.checkpoint_offset = offsetof(preserved_record_t, checkpoint);
                record.info.checkpoint_size = checkpoint_size;
                snprintf(record.info.receipt_domain, sizeof(record.info.receipt_domain), "HISTORICAL_NON_AUTHORIZING");
                snprintf(record.info.inventory_fingerprint_scope, sizeof(record.info.inventory_fingerprint_scope), "inspector-container-inventory");
                record.info.historical = original;
                // Full receipts remain in exact checkpoint evidence only.
                // Exported historical metadata cannot masquerade as approval.
                memset(record.info.historical.restore_scope.receipt, 0,
                       sizeof(record.info.historical.restore_scope.receipt));
                record.info.metadata = *metadata;
                record.info.raw_size = original.expected;
                struct stat portable;
                ok = !original.portable_path[0] ||
                    (!lstat(original.portable_path, &portable) && S_ISREG(portable.st_mode));
                if (ok && original.portable_path[0]) record.info.portable_size = (uint64_t)portable.st_size;
                record.info.preserved_unix = (int64_t)time(NULL);
                snprintf(record.info.preserved_version, sizeof(record.info.preserved_version), "%s", TOSTONSYNC_VERSION);
                snprintf(record.info.record_path, sizeof(record.info.record_path), "%s", final);
                hash_bytes(record.checkpoint, checkpoint_size, record.info.checkpoint_sha256);
                hash_bytes(&record, offsetof(preserved_record_t, sha256), record.sha256);
            }
            int fd = -1;
            if (ok) {
                failure = "Could not write preserved temporary; session retained.";
                int n = snprintf(temporary, sizeof(temporary), "%s/.pending.XXXXXX", s_preserved_dir);
                ok = n > 0 && (size_t)n < sizeof(temporary) && (fd = mkstemp(temporary)) >= 0;
            }
            if (ok) {
                size_t written = 0;
                while (ok && written < sizeof(record)) {
                    ssize_t n = write(fd, (char*)&record + written, sizeof(record) - written);
                    if (n < 0 && errno == EINTR) continue;
                    if (n <= 0) ok = false; else written += (size_t)n;
                }
                ok = ok && PRESERVE_BOUNDARY(IMPORT_PRESERVE_AFTER_TEMP_WRITE);
            }
            if (ok) {
                failure = "Could not synchronize preserved record; session retained.";
                ok = fsync(fd) == 0 && PRESERVE_BOUNDARY(IMPORT_PRESERVE_AFTER_TEMP_FSYNC);
            }
            if (fd >= 0 && close(fd)) ok = false;
            if (ok) {
                failure = "Could not publish preserved record without replacement; session retained.";
                // link is an atomic, no-overwrite publication. A crash before
                // removing the temporary link leaves the same valid evidence.
                ok = link(temporary, final) == 0;
                published = ok;
                if (ok) ok = PRESERVE_BOUNDARY(IMPORT_PRESERVE_AFTER_PUBLISH);
                if (ok) ok = unlink(temporary) == 0;
            }
        }
    }
    if (ok) {
        failure = "Preserved directory durability is uncertain; session retained.";
        ok = fsync_parent(final) && PRESERVE_BOUNDARY(IMPORT_PRESERVE_AFTER_DIRECTORY_FSYNC);
    }
    if (ok) {
        failure = "Published preserved record or original files failed revalidation; session retained.";
        ok = preserved_record_read(final, &record) && preserved_same_source(&record.info, &original, metadata) &&
            preserved_artifacts_match(&record.info) && PRESERVE_BOUNDARY(IMPORT_PRESERVE_AFTER_RELOAD);
    }
    if (ok) {
        // No work may change the checkpoint while this mutex and the caller's
        // exclusive gate are held. Verify it again immediately before unlink.
        unsigned char checkpoint[PRESERVED_CHECKPOINT_MAX];
        size_t checkpoint_size = 0;
        char checkpoint_sha[65] = {0};
        failure = "Work checkpoint changed before release; session retained.";
        ok = s_session.state == IMPORT_READY && !memcmp(&s_session, &original, sizeof(original)) &&
            stable_regular_read(s_state_path, checkpoint, sizeof(checkpoint), false, &checkpoint_size);
        if (ok) {
            hash_bytes(checkpoint, checkpoint_size, checkpoint_sha);
            ok = !strcmp(checkpoint_sha, record.info.checkpoint_sha256) &&
                PRESERVE_BOUNDARY(IMPORT_PRESERVE_BEFORE_RELEASE);
        }
    }
    if (ok) {
        failure = "Work checkpoint release durability is uncertain; preserved evidence retained.";
        ok = unlink(s_state_path) == 0;
        if (ok) {
            released = true;
            memset(&s_session, 0, sizeof(s_session)); s_raw_target_uid[0] = '\0';
            ok = fsync_parent(s_state_path) && PRESERVE_BOUNDARY(IMPORT_PRESERVE_AFTER_RELEASE);
        }
    }
    if (ok) {
        failure = "Original files changed after release; preserved evidence retained and workflow blocked.";
        ok = preserved_artifacts_match(&record.info) &&
            PRESERVE_BOUNDARY(IMPORT_PRESERVE_AFTER_POST_VERIFY);
    }
    if (!ok) {
        // Retain temporary/public record evidence. Never cancel, unlink or
        // reactivate a historical import to "repair" a failed transition.
        if (released) { s_preserved_uncertain = true; s_checkpoint_uncertain = true; }
        if (error && error_cap) snprintf(error, error_cap, "%s", failure);
    }
    if (published && out) *out = record.info;
    pthread_mutex_unlock(&s_lock);
    return ok;
}
