// Checked selected RAW writer. Hookless publication and production recovery
// remain unavailable. The dedicated controller owns admission, one-shot claim,
// the exclusive gate/barrier and fresh native checks through mandatory hooks.
#include "raw_selected.h"
#include "pfs_attributes.h"
#include "savemount.h"
#include "sha256.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static const bool tx_publication_enabled = false;
static const bool tx_recovery_enabled = false;
static void tx_disabled(raw_selected_transaction_report_t* r) {
    if (!r) return;
    memset(r, 0, sizeof(*r));
    r->result = "DISABLED";
    r->publication_enabled = tx_publication_enabled;
    r->recovery_enabled = tx_recovery_enabled;
    snprintf(r->detail, sizeof(r->detail),
             "Selective RAW publication and recovery are not enabled; no I/O performed");
}

void raw_selected_transaction_publish(const char* work,
    const raw_selected_approval_t* approval, raw_selected_transaction_report_t* report) {
    (void)work; (void)approval; tx_disabled(report);
}
void raw_selected_transaction_recover(const char* work,
    const raw_selected_approval_t* approval, raw_selected_transaction_report_t* report) {
    (void)work; (void)approval; tx_disabled(report);
}

#ifdef RAW_SELECTED_TRANSACTION_TESTING
#if !defined(__APPLE__) && !defined(__linux__)
#error "Selective RAW transaction tests are host-only, never a PS5 release backend"
#endif
#endif
// Internal preparation requires the caller to hold the existing exclusive
// restore gate AND existing durable recovery barrier. Checking a private
// marker below is necessary evidence, not proof of gate ownership. The dedicated
// controller must hold the real gate; a marker never grants authority.
#define TX_MAGIC 0x52535458u
#define TX_VERSION 2u
enum { TX_READY = 1, TX_PUBLISH_INTENT, TX_PUBLISHED, TX_RECOVER_INTENT,
       TX_RECOVERED, TX_COMPLETE, TX_RECOVERY_COMPLETE, TX_UNCERTAIN, TX_VERIFIED };
typedef struct {
    unsigned magic, version, size;
    raw_selected_plan_t plan;
    char body_sha256[65];
} tx_plan_file_t;
typedef struct {
    unsigned magic, version, size, sequence, action, entry;
    raw_selected_stat_t stat;
    raw_selected_stat_t preimage_stat;
    char previous_sha256[65];
    char sha256[65];
} tx_record_t;
typedef struct {
    tx_record_t latest[64];
    size_t sequence;
    unsigned terminal;
    char last_sha256[65];
} tx_state_t;
#ifdef RAW_SELECTED_TRANSACTION_TESTING
static const char* tx_fault;
static size_t tx_fault_entry;
void raw_selected_transaction_test_fault(const char* point, size_t entry) {
    tx_fault = point; tx_fault_entry = entry;
}
static bool fault(const char* point, size_t entry) {
    return tx_fault && !strcmp(tx_fault, point) && tx_fault_entry == entry;
}
#else
// No fault state, setter or executable injection path exists in production.
#define fault(point, entry) false
#endif
static bool path_join(char out[512], const char* root, const char* leaf) {
    int n = snprintf(out, 512, "%s/%s", root, leaf);
    return n > 0 && n < 512;
}
static bool stat_equal(const raw_selected_stat_t* a, const raw_selected_stat_t* b) {
    return a->dev == b->dev && a->ino == b->ino && a->size == b->size &&
        a->mode == b->mode && a->uid == b->uid && a->gid == b->gid &&
        a->nlink == b->nlink && a->mtime == b->mtime && a->mtime_nsec == b->mtime_nsec &&
        a->ctime == b->ctime && a->ctime_nsec == b->ctime_nsec && a->flags == b->flags;
}
static bool stable_hash(const char* path, const char* expected,
                        const raw_selected_stat_t* expected_stat,
                        raw_selected_stat_t* observed) {
    raw_selected_stat_t stat; char hash[65];
    if (!raw_selected_file_observe(path, &stat, hash, NULL, 0) ||
        strcmp(hash, expected) || (expected_stat && !stat_equal(&stat, expected_stat))) return false;
    if (observed) *observed = stat;
    return true;
}
static bool sync_directory(const char* work) {
    int fd = open(work, O_RDONLY | O_DIRECTORY | O_NOFOLLOW);
    if (fd < 0) return false;
    bool ok = fsync(fd) == 0;
    if (close(fd) != 0) ok = false;
    return ok;
}
static bool write_all(int fd, const void* bytes, size_t size) {
    const unsigned char* p = bytes;
    while (size) {
        ssize_t n = write(fd, p, size);
        if (n <= 0) return false;
        p += n; size -= (size_t)n;
    }
    return true;
}
static bool new_file(const char* path, const void* bytes, size_t size) {
    int fd = open(path, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW, 0600);
    if (fd < 0) return false;
    bool ok = write_all(fd, bytes, size) && fsync(fd) == 0;
    if (close(fd) != 0) ok = false;
    return ok; // Never delete a partial plan, state or authority file.
}
static bool exact_file(const char* path, void* bytes, size_t size) {
    struct stat st;
    if (lstat(path, &st) != 0 || !S_ISREG(st.st_mode) || st.st_size != (off_t)size) return false;
    int fd = open(path, O_RDONLY | O_NOFOLLOW);
    if (fd < 0) return false;
    unsigned char* p = bytes; size_t left = size;
    while (left) {
        ssize_t n = read(fd, p, left);
        if (n <= 0) break;
        p += n; left -= (size_t)n;
    }
    unsigned char extra; bool ok = !left && read(fd, &extra, 1) == 0;
    if (close(fd) != 0) ok = false;
    return ok;
}
static bool work_guard(const char* work) {
    struct stat st; char barrier[512];
    // Do not share legacy title-wide rollback namespaces or follow a workspace
    // alias. A damaged private marker is uncertainty, not permission to proceed.
    if (!work || strlen(work) >= 480 || strstr(work, "_sdimg_rollback")) return false;
    char* canonical = realpath(work, NULL);
    bool exact = canonical && !strcmp(work, canonical);
    free(canonical);
    return exact &&
        lstat(work, &st) == 0 && S_ISDIR(st.st_mode) &&
        path_join(barrier, work, "barrier") && lstat(barrier, &st) == 0 &&
        S_ISREG(st.st_mode) && st.st_size > 0;
}
static bool nested_path(const char* path, const char* directory) {
    size_t n = strlen(directory);
    return !strncmp(path, directory, n) && (path[n] == 0 || path[n] == '/');
}
static bool private_namespace(const char* work, const raw_selected_plan_t* plan) {
    // Checkpoints and scoped preimages must be outside live, canonical-source
    // and closed-diagnostic trees. Existing files are never overwritten by prep.
    if (nested_path(work, plan->target_root) || nested_path(plan->target_root, work) ||
        nested_path(plan->zip_path, work)) return false;
    for (size_t i = 0; i < plan->count; i++) {
        const char* paths[] = {plan->entries[i].source, plan->entries[i].diagnostic};
        for (size_t j = 0; j < 2; j++) {
            const char* leaf = strrchr(paths[j], '/'); char parent[512];
            if (!leaf || leaf == paths[j]) return false;
            size_t n = (size_t)(leaf - paths[j]);
            memcpy(parent, paths[j], n); parent[n] = 0;
            if (nested_path(work, parent) || nested_path(parent, work)) return false;
        }
    }
    return true;
}
static void report_init(raw_selected_transaction_report_t* r, const char* work) {
    memset(r, 0, sizeof(*r)); r->result = "RECOVERY_REQUIRED";
    r->recovery_required = true; r->barrier_retained = true;
    if (work) snprintf(r->workspace, sizeof(r->workspace), "%s", work);
}
static void failed(raw_selected_transaction_report_t* r, const char* result, const char* detail) {
    r->result = result; r->recovery_required = true; r->barrier_retained = true;
    snprintf(r->detail, sizeof(r->detail), "%s", detail);
}
static bool authorized_path(const raw_selected_plan_t* p, size_t i,
                            const char* path, bool sibling) {
    if (i >= p->count) return false;
    const raw_selected_entry_t* e = &p->entries[i];
    char expected[512];
    int n = snprintf(expected, sizeof(expected), "%s%s", e->target, sibling ? ".smnew" : "");
    if (n <= 0 || n >= (int)sizeof(expected) || strcmp(path, expected)) return false;
    const char* leaf = strrchr(e->target, '/');
    if (!leaf || strcmp(leaf + 1, e->image_name)) return false;
    char parent[512];
    size_t length = (size_t)(leaf - e->target);
    if (!length || length >= sizeof(parent)) return false;
    memcpy(parent, e->target, length); parent[length] = 0;
    char* canonical = realpath(parent, NULL);
    bool exact = canonical && !strcmp(parent, canonical);
    free(canonical);
    return exact;
}
static void bytes_hash(const void* bytes, size_t size, char out[65]) {
    sha256_ctx_t ctx; unsigned char digest[32]; sha256_init(&ctx);
    sha256_update(&ctx, bytes, size); sha256_final(&ctx, digest);
    for (size_t i = 0; i < sizeof(digest); i++) snprintf(out + i * 2, 3, "%02x", digest[i]);
}
static void record_hash(tx_record_t* record, char out[65]) {
    tx_record_t copy = *record; memset(copy.sha256, 0, sizeof(copy.sha256));
    bytes_hash(&copy, sizeof(copy), out);
}
static void plan_file_hash(const tx_plan_file_t* file, char out[65]) {
    const size_t start = offsetof(tx_plan_file_t, body_sha256);
    const size_t end = start + sizeof(file->body_sha256);
    const unsigned char zero[65] = {0}; unsigned char digest[32]; sha256_ctx_t ctx;
    sha256_init(&ctx); sha256_update(&ctx, file, start);
    sha256_update(&ctx, zero, sizeof(zero));
    sha256_update(&ctx, (const unsigned char*)file + end, sizeof(*file) - end);
    sha256_final(&ctx, digest);
    for (size_t i = 0; i < sizeof(digest); i++) snprintf(out + i * 2, 3, "%02x", digest[i]);
}
static bool plan_file_intact(const tx_plan_file_t* file) {
    char hash[65]; plan_file_hash(file, hash);
    // Validate the whole immutable envelope (including padding) before interpreting any contained
    // strings/fields. Authority digest remains separate and domain-scoped.
    return memchr(file->body_sha256, 0, sizeof(file->body_sha256)) &&
        !memcmp(file->body_sha256, hash, sizeof(hash));
}
static bool transition(unsigned before, unsigned after) {
    return (before == TX_READY && after == TX_PUBLISH_INTENT) ||
        (before == TX_PUBLISH_INTENT && after == TX_PUBLISHED) ||
        (before == TX_PUBLISHED && after == TX_VERIFIED) ||
        (before == TX_PUBLISHED && after == TX_RECOVER_INTENT) ||
        (before == TX_VERIFIED && after == TX_RECOVER_INTENT) ||
        (before == TX_RECOVER_INTENT && after == TX_RECOVERED) ||
        (before == TX_PUBLISH_INTENT && after == TX_RECOVERED);
}
static bool read_state(const char* work, const raw_selected_plan_t* plan, tx_state_t* state) {
    char path[512]; struct stat st;
    memset(state, 0, sizeof(*state));
    if (!path_join(path, work, "state.bin") || lstat(path, &st) != 0 ||
        !S_ISREG(st.st_mode) || st.st_size <= 0 || st.st_size % sizeof(tx_record_t)) return false;
    int fd = open(path, O_RDONLY | O_NOFOLLOW);
    if (fd < 0) return false;
    bool ok = true; tx_record_t record;
    size_t total = (size_t)st.st_size / sizeof(record);
    if (total > plan->count * 6 + 3) ok = false;
    for (size_t n = 0; ok && n < total; n++) {
        if (read(fd, &record, sizeof(record)) != (ssize_t)sizeof(record)) { ok = false; break; }
        char hash[65]; record_hash(&record, hash);
        if (record.magic != TX_MAGIC || record.version != TX_VERSION || record.size != sizeof(record) ||
            record.sequence != n + 1 ||
            !memchr(record.sha256, 0, sizeof(record.sha256)) ||
            !memchr(record.previous_sha256, 0, sizeof(record.previous_sha256)) ||
            memcmp(record.sha256, hash, sizeof(hash)) ||
            memcmp(record.previous_sha256, state->last_sha256, sizeof(state->last_sha256)) ||
            state->terminal) { ok = false; break; }
        if (record.action == TX_COMPLETE || record.action == TX_RECOVERY_COMPLETE || record.action == TX_UNCERTAIN) {
            if (record.entry != 64) { ok = false; break; }
            for (size_t i = 0; ok && i < plan->count; i++) {
                unsigned action = state->latest[i].action;
                if (record.action == TX_COMPLETE && action != TX_VERIFIED) ok = false;
                if (record.action == TX_RECOVERY_COMPLETE && action != TX_READY && action != TX_RECOVERED) ok = false;
            }
            state->terminal = record.action;
        } else {
            if (record.entry >= plan->count) { ok = false; break; }
            unsigned previous = state->latest[record.entry].action;
            if (!previous ? (record.action != TX_READY || n >= plan->count || record.entry != n)
                          : (!transition(previous, record.action) || n < plan->count)) { ok = false; break; }
            if (previous && !stat_equal(&record.preimage_stat, &state->latest[record.entry].preimage_stat)) {
                ok = false; break;
            }
            state->latest[record.entry] = record;
        }
        snprintf(state->last_sha256, 65, "%s", record.sha256); state->sequence = n + 1;
    }
    for (size_t i = 0; ok && i < plan->count; i++) if (!state->latest[i].action) ok = false;
    unsigned char extra;
    if (ok && read(fd, &extra, 1) != 0) ok = false;
    if (close(fd) != 0) ok = false;
    return ok;
}
static bool append_state(const char* work, tx_state_t* state, unsigned action,
                         size_t entry, const raw_selected_stat_t* stat) {
    char path[512]; tx_record_t record;
    memset(&record, 0, sizeof(record));
    record.magic = TX_MAGIC; record.version = TX_VERSION; record.size = sizeof(record);
    record.sequence = (unsigned)state->sequence + 1; record.action = action; record.entry = (unsigned)entry;
    if (stat) record.stat = *stat;
    if (entry < 64) record.preimage_stat = state->latest[entry].preimage_stat;
    snprintf(record.previous_sha256, 65, "%s", state->last_sha256); record_hash(&record, record.sha256);
    if (!path_join(path, work, "state.bin")) return false;
    int fd = open(path, O_WRONLY | O_APPEND | O_NOFOLLOW);
    if (fd < 0) return false;
    struct stat existing;
    bool ok = fstat(fd, &existing) == 0 && S_ISREG(existing.st_mode) &&
        existing.st_size == (off_t)(state->sequence * sizeof(record)) &&
        write_all(fd, &record, sizeof(record)) && fsync(fd) == 0;
    if (close(fd) != 0) ok = false;
    if (!ok || !sync_directory(work)) return false;
    state->sequence++;
    snprintf(state->last_sha256, 65, "%s", record.sha256);
    if (entry < 64) state->latest[entry] = record; else state->terminal = action;
    return true;
}
static bool load_authority(const char* work, const raw_selected_approval_t* approval,
                           raw_selected_plan_t* plan, tx_state_t* state,
                           raw_selected_transaction_report_t* report) {
    char path[512]; raw_selected_approval_t saved;
    tx_plan_file_t* file = calloc(1, sizeof(*file));
    if (!file) {
        failed(report, "RECOVERY_REQUIRED", "Authority memory unavailable; barrier retained"); return false;
    }
    if (!work_guard(work) || !path_join(path, work, "plan.bin") ||
        !exact_file(path, file, sizeof(*file)) || file->magic != TX_MAGIC ||
        file->version != TX_VERSION || file->size != sizeof(*file) || !plan_file_intact(file) ||
        !path_join(path, work, "authority.bin") || !exact_file(path, &saved, sizeof(saved)) ||
        !approval || !memchr(saved.plan_sha256, 0, sizeof(saved.plan_sha256)) ||
        !memchr(saved.receipt, 0, sizeof(saved.receipt)) ||
        memcmp(saved.plan_sha256, approval->plan_sha256, sizeof(saved.plan_sha256)) ||
        memcmp(saved.receipt, approval->receipt, sizeof(saved.receipt)) ||
        !raw_selected_approval_matches(&file->plan, approval, NULL, 0) ||
        !private_namespace(work, &file->plan)) {
        failed(report, "RECOVERY_REQUIRED", "Plan/receipt authority unavailable or damaged; barrier retained");
        free(file); return false;
    }
    *plan = file->plan; free(file);
    snprintf(report->plan_sha256, sizeof(report->plan_sha256), "%s", approval->plan_sha256);
    if (!read_state(work, plan, state)) {
        failed(report, "RECOVERY_REQUIRED", "Incomplete/corrupt transaction state; barrier retained"); return false;
    }
    return true;
}
static bool preimage_path(char out[512], const char* work, const raw_selected_entry_t* entry) {
    char leaf[160]; int n = snprintf(leaf, sizeof(leaf), "pre/%s", entry->image_name);
    return n > 0 && n < (int)sizeof(leaf) && path_join(out, work, leaf);
}
void raw_selected_transaction_begin(const char* work, const raw_selected_plan_t* plan,
    const raw_selected_approval_t* approval, raw_selected_transaction_report_t* report) {
    if (!report) return;
    report_init(report, work);
    if (!work_guard(work) || !raw_selected_approval_matches(plan, approval, NULL, 0) ||
        !private_namespace(work, plan) || !raw_selected_plan_validate(plan, NULL, 0)) {
        failed(report, "BLOCKED", "Verified RAW plan, held gate and durable barrier required"); return;
    }
    tx_plan_file_t* file = calloc(1, sizeof(*file));
    if (!file) { failed(report, "RECOVERY_REQUIRED", "Plan memory unavailable"); return; }
    file->magic = TX_MAGIC; file->version = TX_VERSION; file->size = sizeof(*file); file->plan = *plan;
    plan_file_hash(file, file->body_sha256);
    char path[512];
    bool checkpoint = path_join(path, work, "plan.bin") && new_file(path, file, sizeof(*file));
    free(file);
    if (!checkpoint ||
        !path_join(path, work, "authority.bin") || !new_file(path, approval, sizeof(*approval)) ||
        !sync_directory(work) || !path_join(path, work, "pre") ||
        (mkdir(path, 0700) != 0 && errno != EEXIST) ||
        !sync_directory(work)) {
        failed(report, "RECOVERY_REQUIRED", "Immutable plan/authority checkpoint failed; evidence retained"); return;
    }
    struct stat private_directory;
    char* canonical_pre = realpath(path, NULL);
    bool private_pre = canonical_pre && !strcmp(path, canonical_pre) &&
        lstat(path, &private_directory) == 0 && S_ISDIR(private_directory.st_mode);
    free(canonical_pre);
    if (!private_pre) {
        failed(report, "BLOCKED", "Scoped preimage directory is unsafe; evidence retained"); return;
    }
    for (size_t i = 0; i < plan->count; i++) {
        const raw_selected_entry_t* e = &plan->entries[i]; pfs_attribute_image_t copy = {0};
        if (!authorized_path(plan, i, e->target, false) ||
            !stable_hash(e->target, e->pre_sha256, &e->target_stat, NULL) ||
            !stable_hash(e->source, e->source_sha256, &e->source_stat, NULL) ||
            strlen(e->target) >= sizeof(copy.source) || !preimage_path(path, work, e) ||
            strcmp(path, e->preimage) ||
            strlen(path) >= sizeof(copy.copy)) {
            failed(report, "BLOCKED", "Selected source/target changed before scoped snapshot"); return;
        }
        snprintf(copy.source, sizeof(copy.source), "%s", e->target);
        snprintf(copy.copy, sizeof(copy.copy), "%s", path);
        if (!pfs_attributes_copy_private(&copy) || strcmp(copy.sha256, e->pre_sha256)) {
            failed(report, "RECOVERY_REQUIRED", "Scoped encrypted preimage acquisition failed"); return;
        }
    }
    if (!path_join(path, work, "pre") || !sync_directory(path) ||
        !path_join(path, work, "state.bin") || !new_file(path, "", 0) || !sync_directory(work)) {
        failed(report, "RECOVERY_REQUIRED", "Scoped snapshot checkpoint failed"); return;
    }
    tx_state_t* state = calloc(1, sizeof(*state));
    if (!state) { failed(report, "RECOVERY_REQUIRED", "State memory unavailable"); return; }
    for (size_t i = 0; i < plan->count; i++) {
        if (!preimage_path(path, work, &plan->entries[i]) ||
            !stable_hash(path, plan->entries[i].pre_sha256, NULL, &state->latest[i].preimage_stat) ||
            !append_state(work, state, TX_READY, i, &plan->entries[i].target_stat)) {
            failed(report, "RECOVERY_REQUIRED", "Initial durable state failed"); free(state); return;
        }
    }
    raw_selected_plan_t* checked = calloc(1, sizeof(*checked));
    bool verified = checked && load_authority(work, approval, checked, state, report);
    free(checked); free(state);
    if (!verified) {
        failed(report, "RECOVERY_REQUIRED", "Preparation authority/state checkpoint failed"); return;
    }
    report->result = "PREPARED"; report->recovery_required = false;
}
#ifdef RAW_SELECTED_TRANSACTION_TESTING
void raw_selected_transaction_test_begin(const char* work, const raw_selected_plan_t* plan,
    const raw_selected_approval_t* approval, raw_selected_transaction_report_t* report) {
    raw_selected_transaction_begin(work, plan, approval, report);
}
#endif
static bool mutation_guard(const raw_selected_plan_t* plan, size_t i, const char* current_hash,
                           const raw_selected_stat_t* current_stat) {
    // Invariant: every capable live mutation_target belongs to authorized_images;
    // its only permitted sibling is exactly that member's target + ".smnew".
    char sibling[512]; struct stat st;
    int n = snprintf(sibling, sizeof(sibling), "%s.smnew", plan->entries[i].target);
    return n > 0 && n < (int)sizeof(sibling) &&
        authorized_path(plan, i, plan->entries[i].target, false) &&
        authorized_path(plan, i, sibling, true) &&
        lstat(sibling, &st) != 0 && errno == ENOENT &&
        stable_hash(plan->entries[i].target, current_hash, current_stat, NULL);
}
static bool all_images_guard(const raw_selected_plan_t* plan, const tx_state_t* state,
                             bool* changed_published) {
    for (size_t i = 0; i < plan->count; i++) {
        const raw_selected_entry_t* e = &plan->entries[i];
        const tx_record_t* current = &state->latest[i];
        bool verified = current->action == TX_VERIFIED;
        if ((current->action != TX_READY && !verified) ||
            !stable_hash(e->preimage, e->pre_sha256, &current->preimage_stat, NULL)) return false;
        if (!stable_hash(e->source, e->source_sha256, &e->source_stat, NULL) ||
            !mutation_guard(plan, i, verified ? e->source_sha256 : e->pre_sha256, &current->stat)) {
            if (verified) *changed_published = true;
            return false;
        }
    }
    return true;
}
static void report_state(const raw_selected_plan_t* plan, const tx_state_t* state,
                         raw_selected_transaction_report_t* report) {
    for (size_t i = 0; i < plan->count; i++) {
        unsigned action = state->latest[i].action;
        if (action == TX_PUBLISH_INTENT || action == TX_RECOVER_INTENT)
            report->publication_uncertain = true;
        if (action == TX_PUBLISHED || action == TX_VERIFIED || action == TX_RECOVER_INTENT) {
            ++report->attempted_images; ++report->published_images;
            if (plan->entries[i].role == RAW_SELECTED_ROLE_ACTIVE) ++report->published_active_slots;
            else ++report->published_service_images;
        }
        if (action == TX_VERIFIED) ++report->verified_images;
    }
}
void raw_selected_transaction_publish_checked(const char* work,
    const raw_selected_approval_t* approval, const raw_selected_transaction_hooks_t* hooks,
    raw_selected_transaction_report_t* report) {
    if (!report) return;
    // No path read or savedata I/O may occur without the controller's complete
    // revalidation + private native observation contract.
    if (!hooks || !hooks->before_publish || !hooks->after_publish || !hooks->before_complete) {
        tx_disabled(report);
        snprintf(report->detail, sizeof(report->detail), "All checked RAW publication hooks are required; no I/O performed");
        return;
    }
    report_init(report, work);
    report->publication_enabled = true;
    raw_selected_plan_t plan; tx_state_t state;
    if (!load_authority(work, approval, &plan, &state, report)) {
        report->publication_uncertain = true; return;
    }
    report_state(&plan, &state, report);
    if (state.terminal) { failed(report, "BLOCKED", "Terminal/uncertain transaction cannot replay"); return; }
    for (size_t i = 0; i < plan.count; i++) {
        const raw_selected_entry_t* e = &plan.entries[i]; char pre[512];
        if (state.latest[i].action != TX_READY || !preimage_path(pre, work, e) || strcmp(pre, e->preimage) ||
            !stable_hash(pre, e->pre_sha256, &state.latest[i].preimage_stat, NULL) ||
            !stable_hash(e->source, e->source_sha256, &e->source_stat, NULL) ||
            !mutation_guard(&plan, i, e->pre_sha256, &e->target_stat)) {
            failed(report, "BLOCKED", "Publish authority/prestate drift; no further selected writes"); return;
        }
    }
    if (fault("unmount_uncertain", 0)) {
        (void)append_state(work, &state, TX_UNCERTAIN, 64, NULL);
        failed(report, "RECOVERY_REQUIRED", "Synthetic diagnostic unmount uncertainty; no publication"); return;
    }
    for (size_t i = 0; i < plan.count; i++) {
        const raw_selected_entry_t* e = &plan.entries[i]; raw_selected_stat_t after; char err[256] = {0};
        if (!hooks->before_publish(&plan, i, hooks->context, err, sizeof(err))) {
            failed(report, "BLOCKED", err[0] ? err : "Fresh selected RAW publication checks failed"); return;
        }
        // Previous published members remain bound to their recorded post-inode
        // and stat, not merely equal bytes, before any next selected mutation.
        bool changed_published = false;
        if (!all_images_guard(&plan, &state, &changed_published)) {
            report->publication_uncertain |= changed_published;
            failed(report, "BLOCKED", "Selected source/preimage/current inode drift; no next image write"); return;
        }
        if (!stable_hash(e->source, e->source_sha256, &e->source_stat, NULL) ||
            !mutation_guard(&plan, i, e->pre_sha256, &e->target_stat) ||
            !append_state(work, &state, TX_PUBLISH_INTENT, i, &e->target_stat)) {
            failed(report, "RECOVERY_REQUIRED", "Durable publication intent unavailable"); return;
        }
        if (fault("after_intent", i)) {
            failed(report, "RECOVERY_REQUIRED", "Synthetic crash after intent before unchanged publisher"); return;
        }
        bool rename_attempted = false;
        // Guard both the literal live target and its exact owned .smnew sibling
        // before entering the unchanged checked publication primitive.
        bool published = stable_hash(e->source, e->source_sha256, &e->source_stat, NULL) &&
            mutation_guard(&plan, i, e->pre_sha256, &e->target_stat) &&
            savemount_publish_closed_candidate(e->source, e->target,
                e->source_sha256, e->pre_sha256, &rename_attempted);
        if (rename_attempted) ++report->attempted_images;
        if (!published) {
            report->publication_uncertain = rename_attempted;
            failed(report, "RECOVERY_REQUIRED", "Selected publication incomplete; intent retained"); return;
        }
        if (fault("after_rename", i)) {
            report->publication_uncertain = true;
            failed(report, "RECOVERY_REQUIRED", "Synthetic crash after rename before post-inode checkpoint"); return;
        }
        if (!rename_attempted || !stable_hash(e->target, e->source_sha256, NULL, &after) ||
            !append_state(work, &state, TX_PUBLISHED, i, &after)) {
            report->publication_uncertain = rename_attempted;
            failed(report, "RECOVERY_REQUIRED", "Published poststate durability unavailable"); return;
        }
        report->published_images++;
        if (e->role == RAW_SELECTED_ROLE_ACTIVE) ++report->published_active_slots;
        else ++report->published_service_images;
        if (fault("after_published", i)) {
            failed(report, "RECOVERY_REQUIRED", "Synthetic interruption between selected images"); return;
        }
        bool post_verified = hooks->after_publish(&plan, i, &after, hooks->context, err, sizeof(err));
        // A hook can only verify a private copy. Recheck canonical ciphertext
        // and its recorded inode/stat before granting verification progress.
        if (!stable_hash(e->target, e->source_sha256, &after, NULL) ||
            !stable_hash(e->source, e->source_sha256, &e->source_stat, NULL)) {
            report->publication_uncertain = true;
            failed(report, "RECOVERY_REQUIRED", "Canonical ciphertext changed during private post verification"); return;
        }
        if (!post_verified) {
            failed(report, "RECOVERY_REQUIRED", err[0] ? err : "Private published-image native verification failed"); return;
        }
        if (!append_state(work, &state, TX_VERIFIED, i, &after)) {
            failed(report, "RECOVERY_REQUIRED", "Private post-verification checkpoint unavailable"); return;
        }
        ++report->verified_images;
    }
    for (size_t i = 0; i < plan.count; i++)
        if (!stable_hash(plan.entries[i].target, plan.entries[i].source_sha256,
                         &state.latest[i].stat, NULL) ||
            !stable_hash(plan.entries[i].source, plan.entries[i].source_sha256,
                         &plan.entries[i].source_stat, NULL)) {
            report->publication_uncertain = true;
            failed(report, "RECOVERY_REQUIRED", "Final selected publication observations changed"); return;
        }
    char final_err[256] = {0};
    bool final_verified = hooks->before_complete(&plan, hooks->context, final_err, sizeof(final_err));
    // The final callback also cannot mutate a canonical member unnoticed.
    for (size_t i = 0; i < plan.count; i++)
        if (!stable_hash(plan.entries[i].target, plan.entries[i].source_sha256,
                         &state.latest[i].stat, NULL) ||
            !stable_hash(plan.entries[i].source, plan.entries[i].source_sha256,
                         &plan.entries[i].source_stat, NULL)) {
            report->publication_uncertain = true;
            failed(report, "RECOVERY_REQUIRED", "Canonical ciphertext changed during final checks"); return;
        }
    if (!final_verified) {
        failed(report, "RECOVERY_REQUIRED", final_err[0] ? final_err : "Final selected RAW checks failed"); return;
    }
    if (fault("before_final", 0) || !append_state(work, &state, TX_COMPLETE, 64, NULL)) {
        failed(report, "RECOVERY_REQUIRED", "Final transaction checkpoint unavailable"); return;
    }
    report->result = "PUBLISHED_VERIFIED"; report->recovery_required = false;
    // The caller, not this foundation, owns barrier retirement. Never unlink it.
}
#ifdef RAW_SELECTED_TRANSACTION_TESTING
// Synthetic host observations only. These wrappers never claim native/game
// acceptance, and are absent from the PS5 build. The shared production writer
// itself is exercised; no second test-only publication algorithm exists.
static bool test_before(const raw_selected_plan_t* plan, size_t entry,
                        void* context, char* err, size_t err_sz) {
    (void)plan; (void)entry; (void)context; (void)err; (void)err_sz; return true;
}
static bool test_after(const raw_selected_plan_t* plan, size_t entry,
                       const raw_selected_stat_t* stat, void* context, char* err, size_t err_sz) {
    (void)context; (void)err; (void)err_sz;
    return stable_hash(plan->entries[entry].target, plan->entries[entry].source_sha256, stat, NULL);
}
static bool test_complete(const raw_selected_plan_t* plan, void* context, char* err, size_t err_sz) {
    (void)plan; (void)context; (void)err; (void)err_sz; return true;
}
void raw_selected_transaction_test_publish(const char* work,
    const raw_selected_approval_t* approval, raw_selected_transaction_report_t* report) {
    const raw_selected_transaction_hooks_t hooks = { .before_publish = test_before,
        .after_publish = test_after, .before_complete = test_complete };
    raw_selected_transaction_publish_checked(work, approval, &hooks, report);
}
void raw_selected_transaction_test_recover(const char* work,
    const raw_selected_approval_t* approval, raw_selected_transaction_report_t* report) {
    if (!report) return;
    report_init(report, work);
    raw_selected_plan_t plan; tx_state_t state;
    if (!load_authority(work, approval, &plan, &state, report)) return;
    if (state.terminal) { failed(report, "BLOCKED", "Terminal/uncertain transaction cannot recover automatically"); return; }
    // Validate the complete authorized subset before the first recovery write.
    // A hash match without the recorded inode/stat is NOT sufficient after an
    // interrupted rename: no pre-rename inode hook is added to the publisher.
    for (size_t i = 0; i < plan.count; i++) {
        const raw_selected_entry_t* e = &plan.entries[i]; tx_record_t* current = &state.latest[i];
        char pre[512]; unsigned action = current->action;
        const char* expected = action == TX_PUBLISHED || action == TX_VERIFIED || action == TX_RECOVER_INTENT
            ? e->source_sha256 : e->pre_sha256;
        if (!preimage_path(pre, work, e) || strcmp(pre, e->preimage) ||
            !stable_hash(pre, e->pre_sha256, &current->preimage_stat, NULL) ||
            !authorized_path(&plan, i, e->target, false) ||
            !stable_hash(e->target, expected, &current->stat, NULL)) {
            failed(report, "BLOCKED", "Unknown selected image or inode after interruption; barrier retained"); return;
        }
        if (action != TX_READY && action != TX_PUBLISH_INTENT && action != TX_PUBLISHED && action != TX_VERIFIED &&
            action != TX_RECOVER_INTENT && action != TX_RECOVERED) {
            failed(report, "BLOCKED", "Unknown recovery state; barrier retained"); return;
        }
    }
    for (size_t i = 0; i < plan.count; i++) {
        const raw_selected_entry_t* e = &plan.entries[i]; tx_record_t* current = &state.latest[i];
        if (current->action == TX_READY || current->action == TX_RECOVERED) continue;
        if (current->action == TX_PUBLISH_INTENT) {
            // Recorded intent + exact original inode/hash proves no published
            // replacement. Leave the original untouched, not copied back.
            raw_selected_stat_t unchanged = current->stat;
            if (!append_state(work, &state, TX_RECOVERED, i, &unchanged)) {
                failed(report, "RECOVERY_REQUIRED", "Unpublished-intent checkpoint failed"); return;
            }
            continue;
        }
        raw_selected_stat_t before = current->stat, after; char pre[512];
        if (!preimage_path(pre, work, e) ||
            !stable_hash(pre, e->pre_sha256, &current->preimage_stat, NULL) ||
            !mutation_guard(&plan, i, e->source_sha256, &before)) {
            failed(report, "BLOCKED", "Recovery target/sibling changed; no pruning or unlink"); return;
        }
        if (current->action != TX_RECOVER_INTENT &&
            !append_state(work, &state, TX_RECOVER_INTENT, i, &before)) {
            failed(report, "RECOVERY_REQUIRED", "Recovery intent durability unavailable"); return;
        }
        bool renamed = false;
        if (!stable_hash(pre, e->pre_sha256, &current->preimage_stat, NULL) ||
            !mutation_guard(&plan, i, e->source_sha256, &before) ||
            !savemount_publish_closed_candidate(pre, e->target,
                e->pre_sha256, e->source_sha256, &renamed) || !renamed ||
            !stable_hash(e->target, e->pre_sha256, NULL, &after) ||
            !append_state(work, &state, TX_RECOVERED, i, &after)) {
            failed(report, "RECOVERY_REQUIRED", "Selected recovery incomplete; evidence/barrier retained"); return;
        }
        report->recovered_images++;
    }
    for (size_t i = 0; i < plan.count; i++)
        if (!stable_hash(plan.entries[i].target, plan.entries[i].pre_sha256,
                         &state.latest[i].stat, NULL)) {
            failed(report, "RECOVERY_REQUIRED", "Final selected recovery observation changed"); return;
        }
    if (!append_state(work, &state, TX_RECOVERY_COMPLETE, 64, NULL)) {
        failed(report, "RECOVERY_REQUIRED", "Recovery completion durability unavailable"); return;
    }
    report->result = "RECOVERED_VERIFIED"; report->recovery_required = false;
}
#endif
