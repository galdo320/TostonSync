#include "portable_transaction.h"
#include "raw_selected.h"
#include "savemount.h"
#include "sha256.h"

#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define PT_MAGIC 0x50535458u
#define PT_VERSION 1u
enum { PT_READY = 1, PT_INTENT, PT_PUBLISHED, PT_VERIFIED, PT_COMPLETE };
typedef struct {
    char slot[64], target[512], preimage[512], pre_sha256[65];
    raw_selected_stat_t target_stat, preimage_stat;
    raw_selected_row_t row;
} pt_entry_t;
typedef struct {
    uint32_t magic, version, size;
    restore_scope_t scope;
    char target_root[512], workspace[512], sha256[65];
    size_t count;
    pt_entry_t entries[RESTORE_SELECTION_MAX];
} pt_plan_t;
typedef struct {
    uint32_t magic, version, size, sequence, action, entry;
    char candidate[512], candidate_sha256[65], previous_sha256[65], sha256[65];
    raw_selected_stat_t candidate_stat, target_stat;
} pt_record_t;
struct portable_transaction {
    pt_plan_t plan;
    pt_record_t latest[RESTORE_SELECTION_MAX];
    size_t sequence;
    bool complete;
    bool stopped;
    bool (*authority_check)(void* context);
    void* authority_context;
    char last_sha256[65];
    portable_transaction_report_t report;
};
#ifdef PORTABLE_TRANSACTION_TESTING
#if !defined(__APPLE__) && !defined(__linux__)
#error "Portable transaction synthetic faults are host-only"
#endif
static const char* fault_point;
static size_t fault_entry;
void portable_transaction_test_fault(const char* point, size_t entry) {
    fault_point = point; fault_entry = entry;
}
static bool fault(const char* point, size_t entry) {
    return fault_point && !strcmp(fault_point, point) && fault_entry == entry;
}
#else
#define fault(point, entry) false
#endif
static bool fail(char* err, size_t n, const char* detail) {
    if (err && n) snprintf(err, n, "%s", detail);
    return false;
}
static bool bounded(const char* text, size_t n) { return memchr(text, 0, n) != NULL; }
static bool scope_bytes_ok(const restore_scope_t* scope) {
    return scope && ((const unsigned char*)&scope->selection)[offsetof(restore_selection_t, specified)] <= 1;
}
static bool hex64(const char* text) {
    if (!text || strlen(text) != 64) return false;
    return strspn(text, "0123456789abcdef") == 64;
}
static bool component(const char* text, size_t n) {
    if (!bounded(text, n) || !text[0] || !strcmp(text, ".") || !strcmp(text, "..") ||
        strchr(text, '/') || strchr(text, '\\')) return false;
    for (const unsigned char* p = (const unsigned char*)text; *p; p++)
        if (*p < 32 || *p == 127) return false;
    return true;
}
static bool stat_equal(const raw_selected_stat_t* a, const raw_selected_stat_t* b) {
    return a->dev == b->dev && a->ino == b->ino && a->size == b->size &&
        a->mode == b->mode && a->uid == b->uid && a->gid == b->gid && a->nlink == b->nlink &&
        a->mtime == b->mtime && a->mtime_nsec == b->mtime_nsec &&
        a->ctime == b->ctime && a->ctime_nsec == b->ctime_nsec && a->flags == b->flags;
}
static bool join(char out[512], const char* root, const char* leaf) {
    int n = snprintf(out, 512, "%s/%s", root, leaf);
    return n > 0 && n < 512;
}
static bool nested(const char* path, const char* root) {
    size_t n = strlen(root); return !strncmp(path, root, n) && path[n] == '/';
}
static bool canonical_directory(const char* path, bool private) {
    struct stat st; char* resolved = realpath(path, NULL);
    bool ok = resolved && !strcmp(path, resolved) && lstat(path, &st) == 0 &&
        S_ISDIR(st.st_mode) && (!private || (st.st_uid == geteuid() && (st.st_mode & 0777) == 0700));
    free(resolved); return ok;
}
static bool target_root_ok(const restore_scope_t* scope, const char* root) {
    if (!scope_bytes_ok(scope) || !root || !bounded(scope->target_uid, 16) || strlen(scope->target_uid) != 8 ||
        strspn(scope->target_uid, "0123456789abcdef") != 8 || !bounded(scope->title_id, 16) ||
        strlen(scope->title_id) != 9 || strncmp(scope->title_id, "PPSA", 4) ||
        strspn(scope->title_id + 4, "0123456789") != 5 || !scope->selection.specified ||
        !scope->selection.count || scope->selection.count > RESTORE_SELECTION_MAX ||
        !bounded(scope->restore_mode, sizeof(scope->restore_mode)) ||
        strcmp(scope->restore_mode, "portable_selected")) return false;
    char suffix[128];
    int n = snprintf(suffix, sizeof(suffix), "/user/home/%s/savedata_prospero/%s",
        scope->target_uid, scope->title_id);
    size_t length = strlen(root);
    if (n <= 0 || n >= (int)sizeof(suffix) || length < (size_t)n ||
        strcmp(root + length - (size_t)n, suffix) || !canonical_directory(root, false)) return false;
    for (size_t i = 0; i < scope->selection.count; i++)
        if (!component(scope->selection.slots[i], 64) ||
            !strcmp(scope->selection.slots[i], ".capture") ||
            !strncmp(scope->selection.slots[i], "sdimg_", 6) ||
            !strncmp(scope->selection.slots[i], "sce_bu_", 7) ||
            (i && strcmp(scope->selection.slots[i - 1], scope->selection.slots[i]) >= 0)) return false;
    return true;
}
static bool observe(const char* path, const char* expected,
    const raw_selected_stat_t* expected_stat, raw_selected_stat_t* stat) {
    raw_selected_stat_t local; char sha[65];
    bool ok = raw_selected_file_observe(path, &local, sha, NULL, 0) &&
        (!expected || !strcmp(expected, sha)) && (!expected_stat || stat_equal(&local, expected_stat));
    if (ok && stat) *stat = local;
    return ok;
}
static void hash_bytes(const void* bytes, size_t size, char out[65]) {
    sha256_ctx_t c; unsigned char digest[32]; sha256_init(&c);
    sha256_update(&c, bytes, size); sha256_final(&c, digest);
    for (size_t i = 0; i < 32; i++) snprintf(out + i * 2, 3, "%02x", digest[i]);
}
static void hash_string(sha256_ctx_t* c, const char* text) {
    uint64_t size = strlen(text); unsigned char bytes[8];
    for (size_t i = 0; i < 8; i++) bytes[i] = (unsigned char)(size >> (8 * i));
    sha256_update(c, bytes, sizeof(bytes)); sha256_update(c, text, (size_t)size);
}
static void hash_number(sha256_ctx_t* c, uint64_t number) {
    unsigned char bytes[8]; for (size_t i = 0; i < 8; i++) bytes[i] = (unsigned char)(number >> (8 * i));
    sha256_update(c, bytes, sizeof(bytes));
}
static void hash_stat(sha256_ctx_t* c, const raw_selected_stat_t* s) {
    hash_number(c, s->dev); hash_number(c, s->ino); hash_number(c, s->size);
    hash_number(c, s->mode); hash_number(c, s->uid); hash_number(c, s->gid); hash_number(c, s->nlink);
    hash_number(c, (uint64_t)s->mtime); hash_number(c, (uint64_t)s->mtime_nsec);
    hash_number(c, (uint64_t)s->ctime); hash_number(c, (uint64_t)s->ctime_nsec); hash_number(c, s->flags);
}
static void hash_row(sha256_ctx_t* c, const raw_selected_row_t* r) {
    hash_number(c, r->status); hash_number(c, (uint64_t)r->rowid);
    hash_number(c, r->account_id); hash_number(c, r->user_id);
    hash_number(c, (uint64_t)r->sqlite_code); hash_number(c, (uint64_t)r->sqlite_extended_code);
    hash_number(c, r->owner_verified ? 1 : 0);
}
static bool row_equal(const raw_selected_row_t* a, const raw_selected_row_t* b) {
    return a->status == b->status && a->rowid == b->rowid && a->account_id == b->account_id &&
        a->user_id == b->user_id && a->sqlite_code == b->sqlite_code &&
        a->sqlite_extended_code == b->sqlite_extended_code && a->owner_verified == b->owner_verified;
}
static bool observe_row(const restore_scope_t* scope, const char* slot,
    const raw_selected_row_t* expected, raw_selected_row_t* observed) {
    raw_selected_row_t row;
    bool ok = raw_selected_read_exact_row(scope->target_uid, scope->title_id, slot, &row, NULL, 0) &&
        row.status == RAW_SELECTED_ROW_FOUND && row.owner_verified && row.rowid > 0 &&
        !row.sqlite_code && !row.sqlite_extended_code && row.user_id &&
        row.user_id == (uint32_t)strtoul(scope->target_uid, NULL, 16) &&
        (!expected || row_equal(&row, expected));
    if (ok && observed) *observed = row;
    return ok;
}
bool portable_transaction_target_digest(const restore_scope_t* scope,
    const char* root, char out[65], char* err, size_t n) {
    if (!out || !target_root_ok(scope, root)) return fail(err, n, "Portable literal target scope unavailable");
    sha256_ctx_t c; sha256_init(&c); hash_string(&c, "TostonSync portable_selected target state v1");
    hash_string(&c, scope->target_uid); hash_string(&c, scope->title_id); hash_string(&c, root);
    hash_number(&c, scope->selection.count);
    for (size_t i = 0; i < scope->selection.count; i++) {
        char leaf[128], path[512], sha[65]; raw_selected_stat_t st; raw_selected_row_t row;
        int l = snprintf(leaf, sizeof(leaf), "sdimg_%s", scope->selection.slots[i]);
        if (l <= 0 || l >= (int)sizeof(leaf) || !join(path, root, leaf) ||
            !raw_selected_file_observe(path, &st, sha, err, n)) return false;
        if (!observe_row(scope, scope->selection.slots[i], NULL, &row))
            return fail(err, n, "Portable exact target row/owner is UNKNOWN or inconsistent");
        hash_string(&c, scope->selection.slots[i]); hash_string(&c, path); hash_string(&c, sha); hash_stat(&c, &st); hash_row(&c, &row);
    }
    unsigned char digest[32]; sha256_final(&c, digest);
    for (size_t i = 0; i < 32; i++) snprintf(out + i * 2, 3, "%02x", digest[i]);
    return true;
}
static bool sync_dir(const char* path) {
    int fd = open(path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW);
    if (fd < 0) return false;
    bool ok = fsync(fd) == 0; if (close(fd) != 0) ok = false; return ok;
}
static bool write_all(int fd, const void* bytes, size_t n) {
    const unsigned char* p = bytes;
    while (n) { ssize_t size = write(fd, p, n); if (size <= 0) return false; p += size; n -= (size_t)size; }
    return true;
}
static bool create_file(const char* path, const void* bytes, size_t n) {
    int fd = open(path, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW, 0600);
    if (fd < 0) return false;
    bool ok = write_all(fd, bytes, n) && fsync(fd) == 0;
    if (close(fd) != 0) ok = false; return ok; // Partial evidence is never removed.
}
static bool read_exact(const char* path, void* bytes, size_t n) {
    struct stat st; int fd = open(path, O_RDONLY | O_NOFOLLOW);
    if (fd < 0) return false;
    bool ok = fstat(fd, &st) == 0 && S_ISREG(st.st_mode) && st.st_size == (off_t)n;
    unsigned char* p = bytes; size_t left = n;
    while (ok && left) { ssize_t size = read(fd, p, left); if (size <= 0) { ok = false; break; } p += size; left -= (size_t)size; }
    unsigned char extra; if (ok && read(fd, &extra, 1) != 0) ok = false;
    if (close(fd) != 0) ok = false; return ok;
}
static void plan_hash(pt_plan_t* plan, char out[65]) {
    char saved[65], hash[65]; memcpy(saved, plan->sha256, sizeof(saved)); memset(plan->sha256, 0, sizeof(plan->sha256));
    hash_bytes(plan, sizeof(*plan), hash); memcpy(plan->sha256, saved, sizeof(saved)); memcpy(out, hash, sizeof(hash));
}
static void record_hash(pt_record_t* record, char out[65]) {
    char saved[65], hash[65]; memcpy(saved, record->sha256, sizeof(saved)); memset(record->sha256, 0, sizeof(record->sha256));
    hash_bytes(record, sizeof(*record), hash); memcpy(record->sha256, saved, sizeof(saved)); memcpy(out, hash, sizeof(hash));
}
static void blocked(portable_transaction_t* tx, const char* detail, bool uncertain) {
    tx->stopped = true;
    snprintf(tx->report.result, sizeof(tx->report.result), "RECOVERY_REQUIRED");
    snprintf(tx->report.detail, sizeof(tx->report.detail), "%s", detail);
    tx->report.recovery_required = true; tx->report.barrier_retained = true;
    tx->report.publication_uncertain |= uncertain;
}
static bool target_index(const portable_transaction_t* tx, const char* target, size_t* index) {
    if (!target) return false;
    for (size_t i = 0; i < tx->plan.count; i++) if (!strcmp(target, tx->plan.entries[i].target)) {
        if (index) *index = i; return true;
    }
    return false;
}
static bool append(portable_transaction_t* tx, unsigned action, size_t i,
    const char* candidate, const char* sha, const raw_selected_stat_t* source_stat,
    const raw_selected_stat_t* target_stat) {
    pt_record_t record = {0}; char path[512];
    if (i < tx->plan.count) record = tx->latest[i];
    record.magic = PT_MAGIC; record.version = PT_VERSION; record.size = sizeof(record);
    record.sequence = (uint32_t)tx->sequence + 1; record.action = action; record.entry = (uint32_t)i;
    if (candidate) snprintf(record.candidate, sizeof(record.candidate), "%s", candidate);
    if (sha) snprintf(record.candidate_sha256, sizeof(record.candidate_sha256), "%s", sha);
    if (source_stat) record.candidate_stat = *source_stat;
    if (target_stat) record.target_stat = *target_stat;
    snprintf(record.previous_sha256, sizeof(record.previous_sha256), "%s", tx->last_sha256);
    record_hash(&record, record.sha256);
    if (!join(path, tx->plan.workspace, "state.bin")) return false;
    int fd = open(path, O_WRONLY | O_APPEND | O_NOFOLLOW);
    if (fd < 0) return false;
    struct stat st; bool ok = fstat(fd, &st) == 0 && S_ISREG(st.st_mode) &&
        st.st_size == (off_t)(tx->sequence * sizeof(record)) && write_all(fd, &record, sizeof(record)) && fsync(fd) == 0;
    if (close(fd) != 0) ok = false;
    if (!ok || !sync_dir(tx->plan.workspace)) return false;
    tx->sequence++; snprintf(tx->last_sha256, sizeof(tx->last_sha256), "%s", record.sha256);
    if (i < tx->plan.count) tx->latest[i] = record; else tx->complete = action == PT_COMPLETE;
    return true;
}
static bool transition(unsigned before, unsigned after) {
    return (before == PT_READY && after == PT_INTENT) ||
        (before == PT_INTENT && after == PT_PUBLISHED) ||
        (before == PT_PUBLISHED && after == PT_VERIFIED);
}
static bool plan_valid(pt_plan_t* p, const char* workspace, const restore_scope_t* scope) {
    char hash[65]; plan_hash(p, hash);
    if (p->magic != PT_MAGIC || p->version != PT_VERSION || p->size != sizeof(*p) ||
        !bounded(p->sha256, 65) || strcmp(hash, p->sha256) || !bounded(p->workspace, 512) ||
        strcmp(p->workspace, workspace) || !bounded(p->target_root, 512) ||
        !scope_bytes_ok(&p->scope) || !restore_scope_valid(&p->scope) ||
        (scope && (!scope_bytes_ok(scope) || !restore_scope_equal(scope, &p->scope))) ||
        !target_root_ok(&p->scope, p->target_root) || p->count != p->scope.selection.count ||
        p->count > RESTORE_SELECTION_MAX || !canonical_directory(workspace, true)) return false;
    for (size_t i = 0; i < p->count; i++) {
        pt_entry_t* e = &p->entries[i]; char target[512], pre[512], leaf[160];
        snprintf(leaf, sizeof(leaf), "sdimg_%s", p->scope.selection.slots[i]);
        if (!join(target, p->target_root, leaf)) return false;
        snprintf(leaf, sizeof(leaf), "pre/sdimg_%s", p->scope.selection.slots[i]);
        if (!join(pre, workspace, leaf) || !bounded(e->slot, 64) || !bounded(e->target, 512) ||
            !bounded(e->preimage, 512) || !bounded(e->pre_sha256, 65) || !hex64(e->pre_sha256) ||
            ((const unsigned char*)&e->row)[offsetof(raw_selected_row_t, owner_verified)] > 1 ||
            strcmp(e->slot, p->scope.selection.slots[i]) || strcmp(e->target, target) || strcmp(e->preimage, pre)) return false;
    }
    return true;
}
static bool reload(portable_transaction_t* tx) {
    char path[512]; pt_plan_t* plan = calloc(1, sizeof(*plan));
    bool ok = plan && join(path, tx->plan.workspace, "plan.bin") && read_exact(path, plan, sizeof(*plan)) &&
        plan_valid(plan, tx->plan.workspace, &tx->plan.scope) && !memcmp(plan, &tx->plan, sizeof(*plan));
    restore_scope_t authority;
    ok = ok && join(path, tx->plan.workspace, "authority.bin") && read_exact(path, &authority, sizeof(authority)) &&
        scope_bytes_ok(&authority) && restore_scope_equal(&authority, &tx->plan.scope) &&
        !memcmp(&authority, &tx->plan.scope, sizeof(authority));
    free(plan);
    if (!ok) return false;
    if (!join(path, tx->plan.workspace, "state.bin")) return false;
    int fd = open(path, O_RDONLY | O_NOFOLLOW); struct stat st;
    if (fd < 0) return false;
    ok = fstat(fd, &st) == 0 && S_ISREG(st.st_mode) && st.st_size >= (off_t)(tx->plan.count * sizeof(pt_record_t)) &&
        st.st_size % sizeof(pt_record_t) == 0 && (uint64_t)st.st_size <= (tx->plan.count * 4 + 1) * sizeof(pt_record_t);
    pt_record_t latest[RESTORE_SELECTION_MAX] = {0}, record; char previous[65] = {0};
    bool complete = false; size_t count = ok ? (size_t)st.st_size / sizeof(record) : 0;
    for (size_t seq = 0; ok && seq < count; seq++) {
        if (read(fd, &record, sizeof(record)) != (ssize_t)sizeof(record)) { ok = false; break; }
        char hash[65]; record_hash(&record, hash);
        if (record.magic != PT_MAGIC || record.version != PT_VERSION || record.size != sizeof(record) ||
            record.sequence != seq + 1 || !bounded(record.sha256, 65) || strcmp(hash, record.sha256) ||
            !bounded(record.previous_sha256, 65) || strcmp(previous, record.previous_sha256) || complete) { ok = false; break; }
        if (record.action == PT_COMPLETE) {
            if (record.entry != RESTORE_SELECTION_MAX) { ok = false; break; }
            for (size_t j = 0; j < tx->plan.count; j++) if (latest[j].action != PT_VERIFIED) ok = false;
            complete = ok;
        } else {
            size_t i = record.entry;
            if (i >= tx->plan.count || (seq < tx->plan.count ?
                (record.action != PT_READY || i != seq) : !transition(latest[i].action, record.action)) ||
                !bounded(record.candidate, 512) || !bounded(record.candidate_sha256, 65)) { ok = false; break; }
            if (record.action != PT_READY && (!hex64(record.candidate_sha256) ||
                (latest[i].action != PT_READY && (strcmp(record.candidate, latest[i].candidate) ||
                    strcmp(record.candidate_sha256, latest[i].candidate_sha256) ||
                    !stat_equal(&record.candidate_stat, &latest[i].candidate_stat))))) { ok = false; break; }
            latest[i] = record;
        }
        snprintf(previous, sizeof(previous), "%s", record.sha256);
    }
    unsigned char extra; if (ok && read(fd, &extra, 1) != 0) ok = false;
    if (close(fd) != 0) ok = false;
    if (!ok || count != tx->sequence || complete != tx->complete || strcmp(previous, tx->last_sha256) ||
        memcmp(latest, tx->latest, sizeof(latest))) return false;
    return true;
}
bool portable_transaction_slot_workspace(const portable_transaction_t* tx,
    const char* slot, char* out, size_t n) {
    if (!tx || !slot || !out) return false;
    for (size_t i = 0; i < tx->plan.count; i++) if (!strcmp(slot, tx->plan.entries[i].slot)) {
        int size = snprintf(out, n, "%s/native/%s", tx->plan.workspace, slot);
        return size > 0 && (size_t)size < n;
    }
    return false;
}
static bool current_guard(portable_transaction_t* tx) {
    if (tx->stopped || !reload(tx) || tx->complete) return false;
    for (size_t i = 0; i < tx->plan.count; i++) {
        pt_entry_t* e = &tx->plan.entries[i]; pt_record_t* r = &tx->latest[i]; char sibling[512]; struct stat st;
        int size = snprintf(sibling, sizeof(sibling), "%s.smnew", e->target);
        if (size <= 0 || size >= (int)sizeof(sibling) || lstat(sibling, &st) == 0 || errno != ENOENT ||
            !observe(e->preimage, e->pre_sha256, &e->preimage_stat, NULL) ||
            !observe_row(&tx->plan.scope, e->slot, &e->row, NULL) ||
            (r->action != PT_READY && r->action != PT_PUBLISHED && r->action != PT_VERIFIED) ||
            !observe(e->target, r->action == PT_READY ? e->pre_sha256 : r->candidate_sha256,
                &r->target_stat, NULL)) return false;
        if (r->action != PT_READY && !observe(r->candidate, r->candidate_sha256, &r->candidate_stat, NULL)) return false;
    }
    return true;
}
portable_transaction_t* portable_transaction_begin(const restore_scope_t* scope,
    const char* root, const char* workspace, char* err, size_t n) {
    char digest[65];
    if (!scope_bytes_ok(scope) || !restore_scope_valid(scope) || !bounded(scope->target_state_sha256, 65) ||
        !hex64(scope->target_state_sha256) || !root || !workspace || strlen(workspace) >= 400 || workspace[0] != '/' ||
        nested(workspace, root) || nested(root, workspace) || strstr(workspace, "_sdimg_rollback") ||
        !portable_transaction_target_digest(scope, root, digest, err, n) || strcmp(digest, scope->target_state_sha256)) {
        fail(err, n, "Portable approved scope/target prestate changed or UNKNOWN"); return NULL;
    }
    portable_transaction_t* tx = calloc(1, sizeof(*tx));
    if (!tx) { fail(err, n, "Portable transaction memory unavailable"); return NULL; }
    pt_plan_t* p = &tx->plan;
    p->magic = PT_MAGIC; p->version = PT_VERSION; p->size = sizeof(*p); p->scope = *scope;
    snprintf(p->workspace, sizeof(p->workspace), "%s", workspace);
    snprintf(p->target_root, sizeof(p->target_root), "%s", root); p->count = scope->selection.count;
    snprintf(tx->report.workspace, sizeof(tx->report.workspace), "%s", workspace);
    tx->report.authorized_images = p->count; tx->report.barrier_retained = true;
    blocked(tx, "Preparation incomplete; preserve evidence and barrier", false);
    tx->stopped = false; // Construction only; no publication has been admitted.
    char path[512], leaf[160];
    if (mkdir(workspace, 0700) != 0 || !canonical_directory(workspace, true)) goto failed;
    snprintf(path, sizeof(path), "%s", workspace);
    char* slash = strrchr(path, '/');
    if (!slash || slash == path) goto failed;
    *slash = 0;
    if (!sync_dir(path)) goto failed;
    if (!join(path, workspace, "pre") || mkdir(path, 0700) != 0 || !sync_dir(workspace) ||
        !join(path, workspace, "native") || mkdir(path, 0700) != 0 || !sync_dir(workspace)) goto failed;
    for (size_t i = 0; i < p->count; i++) {
        pt_entry_t* e = &p->entries[i]; snprintf(e->slot, sizeof(e->slot), "%s", scope->selection.slots[i]);
        snprintf(leaf, sizeof(leaf), "sdimg_%s", e->slot);
        if (!join(e->target, root, leaf) || !raw_selected_file_observe(e->target, &e->target_stat, e->pre_sha256, err, n) ||
            !observe_row(scope, e->slot, NULL, &e->row)) goto failed;
        snprintf(leaf, sizeof(leaf), "pre/sdimg_%s", e->slot);
        if (!join(e->preimage, workspace, leaf) || !raw_selected_copy_private(e->target, e->preimage, e->pre_sha256, err, n) ||
            !observe(e->target, e->pre_sha256, &e->target_stat, NULL) ||
            !observe(e->preimage, e->pre_sha256, NULL, &e->preimage_stat) ||
            !portable_transaction_slot_workspace(tx, e->slot, path, sizeof(path)) || mkdir(path, 0700) != 0) goto failed;
        if (fault("after_preimage", i)) goto failed;
    }
    if (!join(path, workspace, "pre") || !sync_dir(path) ||
        !join(path, workspace, "native") || !sync_dir(path)) goto failed;
    if (!portable_transaction_target_digest(scope, root, digest, err, n) || strcmp(digest, scope->target_state_sha256)) goto failed;
    plan_hash(p, p->sha256); snprintf(tx->report.plan_sha256, 65, "%s", p->sha256);
    if (fault("before_plan", 0) || !join(path, workspace, "plan.bin") || !create_file(path, p, sizeof(*p)) ||
        !join(path, workspace, "authority.bin") || !create_file(path, scope, sizeof(*scope)) ||
        fault("before_initial_state", 0) || !join(path, workspace, "state.bin") || !create_file(path, "", 0) || !sync_dir(workspace)) goto failed;
    for (size_t i = 0; i < p->count; i++) if (!append(tx, PT_READY, i, NULL, NULL, NULL, &p->entries[i].target_stat)) goto failed;
    if (!current_guard(tx)) goto failed;
    snprintf(tx->report.result, sizeof(tx->report.result), "PREPARED"); tx->report.recovery_required = false;
    tx->report.detail[0] = 0; return tx;
failed:
    fail(err, n, "Portable scoped preparation failed; artifacts and barrier retained"); free(tx); return NULL;
}
bool portable_transaction_set_authority(portable_transaction_t* tx,
    bool (*check)(void*), void* context) {
    if (!tx || !check || tx->stopped || tx->complete || tx->authority_check) return false;
    tx->authority_check = check; tx->authority_context = context; return true;
}
bool portable_transaction_publish(portable_transaction_t* tx, const char* candidate,
    const char* target, const char* sha, const char* expected_pre, bool* renamed) {
    if (renamed) *renamed = false;
    if (!tx || !renamed || !candidate || !hex64(sha) || !hex64(expected_pre)) {
        if (tx) blocked(tx, "Malformed Portable publication callback; no writer admitted", false);
        return false;
    }
    size_t i; raw_selected_stat_t source, after; char base[512];
    if (!target_index(tx, target, &i) || !portable_transaction_slot_workspace(tx, tx->plan.entries[i].slot, base, sizeof(base)) ||
        !nested(candidate, base) || !current_guard(tx) || tx->latest[i].action != PT_READY ||
        !tx->authority_check || !tx->authority_check(tx->authority_context) ||
        strcmp(expected_pre, tx->plan.entries[i].pre_sha256) ||
        !observe(candidate, sha, NULL, &source) || source.size != tx->plan.entries[i].target_stat.size ||
        (source.dev == tx->plan.entries[i].target_stat.dev && source.ino == tx->plan.entries[i].target_stat.ino) ||
        !append(tx, PT_INTENT, i, candidate, sha, &source, &tx->plan.entries[i].target_stat)) {
        blocked(tx, "Publication scope/prestate/candidate/checkpoint failed; no next write", false); return false;
    }
    if (fault("after_intent", i)) { blocked(tx, "Synthetic interruption after durable intent", false); return false; }
    // Authority is reloaded immediately before the unchanged writer. Only this
    // exact target and target + .smnew are passed; no title enumeration/pruning.
    char sibling[512]; struct stat sibling_stat;
    int sibling_size = snprintf(sibling, sizeof(sibling), "%s.smnew", target);
    if (!reload(tx) || sibling_size <= 0 || sibling_size >= (int)sizeof(sibling) ||
        lstat(sibling, &sibling_stat) == 0 || errno != ENOENT || !observe(candidate, sha, &source, NULL) ||
        !observe(target, expected_pre, &tx->plan.entries[i].target_stat, NULL) ||
        !tx->authority_check || !tx->authority_check(tx->authority_context) ||
        !observe_row(&tx->plan.scope, tx->plan.entries[i].slot, &tx->plan.entries[i].row, NULL)) {
        blocked(tx, "Selected durable authority changed before writer", false); return false;
    }
    bool ok = savemount_publish_closed_candidate(candidate, target, sha, expected_pre, renamed);
    if (*renamed) tx->report.attempted_images++;
    if (!ok || fault("after_rename", i) || !*renamed || !observe(target, sha, NULL, &after) ||
        !append(tx, PT_PUBLISHED, i, candidate, sha, &source, &after)) {
        blocked(tx, "Selected publication uncertain/incomplete; no automatic recovery", *renamed); return false;
    }
    tx->report.written_images++; return true;
}
bool portable_transaction_verified(portable_transaction_t* tx, const char* target, const char* sha) {
    size_t i;
    if (!tx || !hex64(sha) || !target_index(tx, target, &i) || !current_guard(tx) ||
        !tx->authority_check || !tx->authority_check(tx->authority_context) ||
        tx->latest[i].action != PT_PUBLISHED || strcmp(sha, tx->latest[i].candidate_sha256) ||
        fault("after_published", i) || !append(tx, PT_VERIFIED, i, NULL, NULL, NULL, &tx->latest[i].target_stat)) {
        if (tx) blocked(tx, "Private native post-verification/checkpoint failed; barrier retained", false);
        return false;
    }
    tx->report.verified_images++; return true;
}
bool portable_transaction_finish(portable_transaction_t* tx, char* err, size_t n) {
    if (!tx || !current_guard(tx) || !tx->authority_check || !tx->authority_check(tx->authority_context)) {
        if (tx) blocked(tx, "Portable final authority/poststate changed", tx->report.written_images != 0);
        return fail(err, n, "Portable final authority/poststate changed");
    }
    for (size_t i = 0; i < tx->plan.count; i++) if (tx->latest[i].action != PT_VERIFIED) {
        blocked(tx, "Selected native verification incomplete", false); return fail(err, n, tx->report.detail);
    }
    if (fault("before_final", 0) || !append(tx, PT_COMPLETE, RESTORE_SELECTION_MAX, NULL, NULL, NULL, NULL) || !reload(tx)) {
        blocked(tx, "Final Portable checkpoint failed; barrier retained", false); return fail(err, n, tx->report.detail);
    }
    snprintf(tx->report.result, sizeof(tx->report.result), "PUBLISHED_VERIFIED");
    tx->report.recovery_required = false; tx->report.detail[0] = 0; return true;
}
void portable_transaction_report(const portable_transaction_t* tx, portable_transaction_report_t* report) {
    if (report && tx) *report = tx->report;
}
void portable_transaction_failed(portable_transaction_t* tx, const char* detail, bool uncertain) {
    if (tx) blocked(tx, detail && detail[0] ? detail : "Portable engine failed; preserve evidence and barrier", uncertain);
}
void portable_transaction_free(portable_transaction_t* tx) { free(tx); }
bool portable_transaction_inspect(const char* workspace, const restore_scope_t* scope,
    portable_transaction_report_t* report) {
    if (!report) return false;
    memset(report, 0, sizeof(*report)); snprintf(report->result, sizeof(report->result), "RECOVERY_REQUIRED");
    report->recovery_required = true; report->barrier_retained = true; report->publication_uncertain = true;
    snprintf(report->detail, sizeof(report->detail), "Unknown/incomplete Portable authority; replay and destructive recovery blocked");
    if (!workspace || strlen(workspace) >= sizeof(report->workspace)) return false;
    snprintf(report->workspace, sizeof(report->workspace), "%s", workspace);
    portable_transaction_t* tx = calloc(1, sizeof(*tx)); char path[512];
    bool ok = tx && join(path, workspace, "plan.bin") && read_exact(path, &tx->plan, sizeof(tx->plan)) &&
        plan_valid(&tx->plan, workspace, scope) && join(path, workspace, "authority.bin");
    restore_scope_t authority;
    ok = ok && read_exact(path, &authority, sizeof(authority)) && scope_bytes_ok(&authority) &&
        restore_scope_equal(&authority, &tx->plan.scope);
    if (ok) {
        // Populate only validated hash-chain progress, then use the same reload
        // validator. Never infer whether an uncheckpointed rename occurred.
        ok = join(path, workspace, "state.bin"); int fd = ok ? open(path, O_RDONLY | O_NOFOLLOW) : -1; struct stat st;
        ok = fd >= 0 && fstat(fd, &st) == 0 && S_ISREG(st.st_mode) && st.st_size > 0 &&
            st.st_size % sizeof(pt_record_t) == 0 && (uint64_t)st.st_size <= (tx->plan.count * 4 + 1) * sizeof(pt_record_t);
        size_t count = ok ? (size_t)st.st_size / sizeof(pt_record_t) : 0;
        for (size_t i = 0; ok && i < count; i++) {
            pt_record_t r; if (read(fd, &r, sizeof(r)) != (ssize_t)sizeof(r)) { ok = false; break; }
            if (r.entry < tx->plan.count) tx->latest[r.entry] = r;
            else if (r.action == PT_COMPLETE) tx->complete = true;
            if (!bounded(r.sha256, 65)) { ok = false; break; }
            snprintf(tx->last_sha256, 65, "%s", r.sha256); tx->sequence++;
        }
        if (fd >= 0 && close(fd) != 0) ok = false;
        ok = ok && reload(tx);
    }
    if (ok) {
        report->publication_uncertain = false;
        report->authorized_images = tx->plan.count; snprintf(report->plan_sha256, 65, "%s", tx->plan.sha256);
        for (size_t i = 0; i < tx->plan.count; i++) {
            pt_record_t* r = &tx->latest[i];
            if (r->action == PT_INTENT) report->publication_uncertain = true;
            if (r->action == PT_PUBLISHED || r->action == PT_VERIFIED) { report->attempted_images++; report->written_images++; }
            if (r->action == PT_VERIFIED) report->verified_images++;
            if (!observe(tx->plan.entries[i].preimage, tx->plan.entries[i].pre_sha256, &tx->plan.entries[i].preimage_stat, NULL) ||
                !observe_row(&tx->plan.scope, tx->plan.entries[i].slot, &tx->plan.entries[i].row, NULL) ||
                !observe(tx->plan.entries[i].target, r->action == PT_READY ? tx->plan.entries[i].pre_sha256 : r->candidate_sha256,
                    &r->target_stat, NULL)) ok = false;
        }
        if (ok && tx->complete) {
            snprintf(report->result, sizeof(report->result), "COMPLETE_OBSERVED"); report->recovery_required = false;
            snprintf(report->detail, sizeof(report->detail), "Complete scoped checkpoint observed; no operational authority/replay granted");
        } else if (ok) snprintf(report->detail, sizeof(report->detail), "Unfinished scoped checkpoint; replay/destructive recovery blocked");
    }
    if (!ok) report->publication_uncertain = true;
    free(tx); return ok;
}
