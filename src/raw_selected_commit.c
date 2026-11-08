// One-shot RAW exact controller. Canonical encrypted images are never mounted.
#include "raw_selected_commit.h"
#include "raw_selected_native.h"
#include "import_session.h"
#include "watcher.h"
#include "lifecycle.h"
#include "config.h"
#include "sha256.h"
#include "version.h"
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

typedef struct {
    char magic[16]; uint32_t version, bytes;
    raw_selected_preflight_request_t request;
    char receipt[65], approval_work[512], approval_sha256[65];
} claim_t;
typedef struct {
    raw_selected_preflight_request_t request;
    raw_selected_plan_t plan;
    raw_selected_approval_t approval;
    raw_selected_commit_report_t report;
    claim_t claim;
    bool verified[RAW_SELECTED_MAX_IMAGES];
} work_t;
static pthread_mutex_t s_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t s_join_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t s_thread_cond = PTHREAD_COND_INITIALIZER;
static pthread_t s_thread;
static bool s_joinable;
static atomic_bool s_active;
static raw_selected_commit_report_t s_report;

static bool fail(char* err, size_t n, const char* why) {
    if (err && n) snprintf(err, n, "%s", why); return false;
}
static bool component(const char* s, size_t max, bool digest) {
    size_t len = s ? strnlen(s, max) : 0;
    if (!len || len >= max || (digest && len != 64)) return false;
    for (size_t i = 0; i < len; i++) {
        char c = s[i];
        if (digest ? !((c >= 'a' && c <= 'f') || (c >= '0' && c <= '9')) :
            !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
              (c >= '0' && c <= '9') || c == '-' || c == '_')) return false;
    }
    return true;
}
static bool join_path(char out[512], const char* a, const char* b) {
    int n = snprintf(out, 512, "%s/%s", a, b); return n > 0 && n < 512;
}
static bool sync_dir(const char* path) {
    int fd = open(path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW);
    if (fd < 0) return false;
    bool ok = fsync(fd) == 0; if (close(fd)) ok = false; return ok;
}
static bool directory_safe(const char* path) {
    struct stat st; char* real = realpath(path, NULL);
    bool ok = real && !strcmp(real, path) && !lstat(path, &st) && S_ISDIR(st.st_mode) &&
        st.st_uid == geteuid() && !(st.st_mode & 0022);
    free(real); return ok;
}
static bool parent_path(char parent[512]) {
    config_t cfg;
    return config_snapshot(&cfg) && join_path(parent, cfg.paths.state_dir, "forensics") &&
        directory_safe(parent);
}
static bool workspace_path(const char* receipt, char out[512]) {
    char parent[512], leaf[96];
    if (!component(receipt, 65, true) || !parent_path(parent)) return false;
    snprintf(leaf, sizeof(leaf), "raw-selected-commit.%s", receipt);
    return join_path(out, parent, leaf);
}
static void digest_bytes(const void* data, size_t n, unsigned char out[32]) {
    sha256_ctx_t h; sha256_init(&h); sha256_update(&h, data, n); sha256_final(&h, out);
}
// Exclusive, immutable record + trailing SHA. Partial writes stay as evidence,
// never as authority. No overwrite, unlink or automatic repair on restart.
static bool record_write(const char* dir, const char* name, const void* data, size_t n,
    char* err, size_t err_sz) {
    char path[512]; unsigned char hash[32];
    if (!join_path(path, dir, name)) return fail(err, err_sz, "Evidence path unavailable");
    digest_bytes(data, n, hash);
    int fd = open(path, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW, 0600);
    if (fd < 0) return fail(err, err_sz, "Evidence already exists or cannot be created; no replay");
    bool ok = true; size_t total = n + sizeof(hash), off = 0;
    while (off < total) {
        const void* p = off < n ? (const void*)((const char*)data + off) : (const void*)(hash + (off - n));
        size_t left = off < n ? n - off : total - off;
        ssize_t got = write(fd, p, left);
        if (got < 0 && errno == EINTR) continue;
        if (got <= 0) { ok = false; break; } off += (size_t)got;
    }
    if (ok && fsync(fd)) ok = false;
    if (close(fd)) ok = false;
    return (ok && sync_dir(dir)) || fail(err, err_sz, "Evidence durability uncertain; retained");
}
static bool record_read(const char* dir, const char* name, void* out, size_t n) {
    char path[512]; struct stat a, b; unsigned char expected[32], actual[32];
    if (!join_path(path, dir, name) || lstat(path, &a) || !S_ISREG(a.st_mode) ||
        a.st_nlink != 1 || a.st_size != (off_t)(n + 32)) return false;
    int fd = open(path, O_RDONLY | O_NOFOLLOW); if (fd < 0) return false;
    bool ok = !fstat(fd, &b) && a.st_dev == b.st_dev && a.st_ino == b.st_ino;
    size_t total = n + 32, off = 0;
    while (ok && off < total) {
        void* p = off < n ? (void*)((char*)out + off) : (void*)(expected + (off - n));
        size_t left = off < n ? n - off : total - off;
        ssize_t got = read(fd, p, left);
        if (got < 0 && errno == EINTR) continue;
        if (got <= 0) { ok = false; break; } off += (size_t)got;
    }
    if (ok) ok = !fstat(fd, &b) && a.st_size == b.st_size && a.st_mtime == b.st_mtime &&
        a.st_ctime == b.st_ctime;
    if (close(fd)) ok = false;
    if (ok) ok = !lstat(path, &b) && a.st_dev == b.st_dev && a.st_ino == b.st_ino && a.st_size == b.st_size;
    if (!ok) return false;
    digest_bytes(out, n, actual); return !memcmp(expected, actual, 32);
}
static bool new_dir(const char* parent, const char* name, char out[512], char* err, size_t n) {
    return (join_path(out, parent, name) && !mkdir(out, 0700) && sync_dir(out) && sync_dir(parent)) ||
        fail(err, n, "New transaction directory unavailable; preserve evidence");
}
static bool stat_equal(const raw_selected_stat_t* a, const raw_selected_stat_t* b) {
    return !memcmp(a, b, sizeof(*a)); // normalized/zero-filled, never struct stat padding
}
static bool unchanged(const char* path, const char* hash, const raw_selected_stat_t* expected,
    char* err, size_t n) {
    raw_selected_stat_t st; char got[65];
    return (raw_selected_file_observe(path, &st, got, err, n) && !strcmp(got, hash) &&
        (!expected || stat_equal(&st, expected))) || fail(err, n, "Approved image/hash/stat changed; no lease or retry");
}
static bool identity_equal(const raw_selected_identity_t* a, const raw_selected_identity_t* b) {
    return a->metadata_complete && b->metadata_complete && a->hmac_present && b->hmac_present &&
        !strcmp(a->title_id, b->title_id) && !strcmp(a->slot, b->slot) &&
        !strcmp(a->game_title_id, b->game_title_id) && !strcmp(a->format, b->format) &&
        a->account_id == b->account_id && a->user_id == b->user_id && a->user_param == b->user_param &&
        a->blocks == b->blocks && a->system_blocks == b->system_blocks &&
        !strcmp(a->sfo_sha256, b->sfo_sha256) && !strcmp(a->hmac_sha256, b->hmac_sha256);
}
static bool fresh_state(const raw_selected_plan_t* p, char* err, size_t n) {
    char uid[16], root[512];
    if (!watcher_raw_selected_target_held(p->target_uid, p->title_id, uid, sizeof(uid), root, sizeof(root), err, n) ||
        strcmp(uid, p->target_uid) || strcmp(root, p->target_root)) return fail(err, n, "Fresh UID/title/game/root unavailable");
    for (size_t i = 0; i < p->count; i++) {
        raw_selected_row_t row; const raw_selected_entry_t* e = &p->entries[i];
        if (!raw_selected_read_exact_row(p->target_uid, p->title_id, e->slot, &row, err, n) ||
            row.status != RAW_SELECTED_ROW_FOUND || !row.owner_verified || row.rowid != e->row.rowid ||
            row.account_id != e->row.account_id || row.user_id != e->row.user_id)
            return fail(err, n, "Exact destination row changed/unavailable; no publication");
    }
    return true;
}
static bool observe(work_t* w, const raw_selected_entry_t* e, const char* canonical,
    const char* hash, const raw_selected_stat_t* st, const raw_selected_identity_t* expected,
    const char* key, const char* phase, char* err, size_t n) {
    char dir[512], private_image[512]; raw_selected_native_observation_t o;
    if (!new_dir(w->report.workspace, phase, dir, err, n) ||
        !join_path(private_image, dir, e->image_name) ||
        !raw_selected_copy_private(canonical, private_image, hash, err, n) || !sync_dir(dir)) return false;
    raw_selected_native_request_t req = {.canonical=canonical, .private_image=private_image,
        .private_workspace=dir, .expected_sha256=hash, .canonical_stat=st,
        .expected_title=w->plan.title_id, .expected_slot=e->slot, .role=e->role};
    memset(&o, 0, sizeof(o)); raw_selected_native_observe(&req, &o, err, n);
    char name[160]; snprintf(name, sizeof(name), "%s.observation.bin", e->image_name);
    if (!record_write(dir, name, &o, sizeof(o), err, n)) return false;
    return (o.status == RAW_SELECTED_NATIVE_READY && o.unmount_confirmed && o.canonical_unchanged &&
        o.metadata_complete && o.geometry_reliable && o.key_available && o.image_size == e->size &&
        identity_equal(expected, &o.identity) && !strcmp(key, o.key_fingerprint)) ||
        fail(err, n, "Native private identity/SFO/key/geometry/unmount verification failed or unknown");
}
static bool before_publish(const raw_selected_plan_t* p, size_t index, void* ctx, char* err, size_t n) {
    work_t* w = ctx;
    if (!fresh_state(p, err, n) || !unchanged(p->zip_path, p->zip_sha256, &p->zip_stat, err, n)) return false;
    for (size_t i = 0; i < p->count; i++) {
        const raw_selected_entry_t* e = &p->entries[i];
        if (!unchanged(e->source, e->source_sha256, &e->source_stat, err, n) ||
            !unchanged(e->target, w->verified[i] ? e->source_sha256 : e->pre_sha256,
                w->verified[i] ? NULL : &e->target_stat, err, n)) return false;
        if (e->omitted_service.state == RAW_SELECTED_OMITTED_PRESENT &&
            !unchanged(e->omitted_service.path, e->omitted_service.sha256, &e->omitted_service.stat, err, n)) return false;
        if (e->omitted_service.state == RAW_SELECTED_OMITTED_ABSENT) {
            struct stat st;
            if (lstat(e->omitted_service.path, &st) == 0 || errno != ENOENT)
                return fail(err, n, "Approved absent service appeared or its state is unknown");
        }
    }
    return index < p->count;
}
static bool after_publish(const raw_selected_plan_t* p, size_t index,
    const raw_selected_stat_t* st, void* ctx, char* err, size_t n) {
    work_t* w = ctx; const raw_selected_entry_t* e = &p->entries[index]; char phase[64];
    snprintf(phase, sizeof(phase), "post-image-%zu", index);
    if (!observe(w, e, e->target, e->source_sha256, st, &e->source_identity,
                 e->source_key_fingerprint, phase, err, n)) return false;
    w->report.images[index].post_verified = true;
    w->verified[index] = true; return true;
}
static bool before_complete(const raw_selected_plan_t* p, void* ctx, char* err, size_t n) {
    work_t* w = ctx;
    for (size_t i = 0; i < p->count; i++) if (!w->verified[i]) return fail(err, n, "Unverified publication remains");
    return before_publish(p, 0, ctx, err, n);
}
static bool find_approval(const raw_selected_preflight_request_t* req, const char* receipt,
    work_t* w, char* err, size_t n) {
    char parent[512], path[512];
    if (!parent_path(parent)) return fail(err, n, "Private server approval directory unavailable");
    DIR* d = opendir(parent); if (!d) return fail(err, n, "Server approval inventory unavailable");
    size_t found = 0; struct dirent* de; raw_selected_plan_t* p = calloc(1, sizeof(*p));
    raw_selected_approval_t a; char ignore[256];
    if (!p) { closedir(d); return fail(err, n, "Approval allocation failed"); }
    errno = 0;
    while ((de = readdir(d))) {
        if (strncmp(de->d_name, "raw-selected-preflight.", 23) ||
            !join_path(path, parent, de->d_name) || !directory_safe(path)) continue;
        if (raw_selected_preflight_load_approval(path, req, receipt, p, &a, ignore, sizeof(ignore))) {
            if (++found == 1) { w->plan = *p; w->approval = a;
                snprintf(w->claim.approval_work, sizeof(w->claim.approval_work), "%s", path); }
        }
        errno = 0;
    }
    bool read_ok = errno == 0; if (closedir(d)) read_ok = false; free(p);
    return (read_ok && found == 1) || fail(err, n, "Exactly one finalized server-held RAW approval required; no client path/fallback");
}
static bool session_matches(const raw_selected_plan_t* p, bool committed, char* err, size_t n) {
    import_session_info_t info;
    // Pure exact session snapshot; unlike current(), this does not expire an
    // unrelated failed upload. The worker separately revalidates the archive.
    bool ok = import_session_status(p->import_id, &info);
    return (ok && !strcmp(info.id, p->import_id) &&
        info.state == (committed ? IMPORT_COMMITTED : IMPORT_READY) &&
        !info.portable_path[0] && !info.restore_selection_required &&
        !strcmp(info.path, p->zip_path) && !strcmp(info.sha256, p->zip_sha256)) ||
        fail(err, n, "Canonical RAW work session required; preserved/portable/cross-mode/changed session blocked");
}
static void report_store_memory(const raw_selected_commit_report_t* r) {
    pthread_mutex_lock(&s_lock); s_report = *r; pthread_mutex_unlock(&s_lock);
}
static bool report_valid(const raw_selected_commit_report_t* r) {
#define BOUNDED(field) (memchr(r->field, 0, sizeof(r->field)) != NULL)
    if (!BOUNDED(result) || !BOUNDED(detail) || !BOUNDED(version) || !BOUNDED(import_id) ||
        !BOUNDED(target_uid) || !BOUNDED(title_id) || !BOUNDED(zip_sha256) ||
        !BOUNDED(selection_receipt) || !BOUNDED(workspace) || !BOUNDED(authority_sha256) ||
        r->image_count > RAW_SELECTED_MAX_IMAGES || r->authorized_images > RAW_SELECTED_MAX_IMAGES ||
        r->selected_active_slots > RESTORE_SELECTION_MAX || r->selected_service_images > RESTORE_SELECTION_MAX ||
        r->written_images > r->authorized_images || r->verified_images > r->written_images) return false;
#undef BOUNDED
    for (size_t i = 0; i < r->image_count; i++) {
        const raw_selected_commit_image_t* e = &r->images[i];
        if (!memchr(e->image_name, 0, sizeof(e->image_name)) || !memchr(e->target, 0, sizeof(e->target)) ||
            !memchr(e->source_sha256, 0, sizeof(e->source_sha256)) || !memchr(e->pre_sha256, 0, sizeof(e->pre_sha256))) return false;
    }
    return true;
}
static void* worker(void* context) {
    work_t* w = context; char err[256] = {0}, path[512], phase[64]; bool gated = false;
    raw_selected_transaction_report_t tx = {0}; claim_t disk_claim;
    w->report.queued = false; snprintf(w->report.result, sizeof(w->report.result), "RUNNING");
    report_store_memory(&w->report);
    int gate = watcher_target_check_begin(err, sizeof(err));
    if (gate != 1) { snprintf(err, sizeof(err), "Worker admission unavailable; one-shot claim retained"); goto done; }
    gated = true;
    // Arm before native acquisition/diagnostics. No automatic replay after crash.
    w->report.barrier_retained = true;
    if (!watcher_raw_selected_barrier_held(true, w->report.workspace, err, sizeof(err)) ||
        !record_write(w->report.workspace, "barrier", w->claim.receipt, 64, err, sizeof(err)) ||
        !record_read(w->report.workspace, "claim.bin", &disk_claim, sizeof(disk_claim)) ||
        memcmp(&disk_claim, &w->claim, sizeof(disk_claim)) ||
        !raw_selected_preflight_load_approval(w->claim.approval_work, &w->request,
             w->claim.receipt, &w->plan, &w->approval, err, sizeof(err)) ||
        !session_matches(&w->plan, true, err, sizeof(err)) ||
        !fresh_state(&w->plan, err, sizeof(err)) ||
        !join_path(path, w->report.workspace, "archive-check") ||
        !raw_selected_verify_archive(&w->plan, path, err, sizeof(err))) goto done;
    // Preimages are in an independent transaction workspace, not inside the
    // canonical source or preflight diagnostic workspace. Rebind server plan,
    // preserving the original diagnostic approval as historical claim evidence.
    if (!new_dir(w->report.workspace, "pre", path, err, sizeof(err))) goto done;
    for (size_t i = 0; i < w->plan.count; i++) {
        raw_selected_entry_t* e = &w->plan.entries[i]; char leaf[160];
        snprintf(leaf, sizeof(leaf), "pre/%s", e->image_name);
        if (!join_path(e->preimage, w->report.workspace, leaf) ||
            !unchanged(e->source, e->source_sha256, &e->source_stat, err, sizeof(err)) ||
            !unchanged(e->target, e->pre_sha256, &e->target_stat, err, sizeof(err))) goto done;
        snprintf(phase, sizeof(phase), "before-source-%zu", i);
        if (!observe(w, e, e->source, e->source_sha256, &e->source_stat,
                     &e->source_identity, e->source_key_fingerprint, phase, err, sizeof(err))) goto done;
        snprintf(phase, sizeof(phase), "before-target-%zu", i);
        if (!observe(w, e, e->target, e->pre_sha256, &e->target_stat,
                     &e->target_identity, e->target_key_fingerprint, phase, err, sizeof(err))) goto done;
        w->report.images[i].pre_verified = true;
    }
    if (!raw_selected_approval_create(&w->plan, &w->approval, err, sizeof(err))) goto done;
    snprintf(w->plan.receipt, sizeof(w->plan.receipt), "%s", w->approval.receipt);
    snprintf(w->report.authority_sha256, sizeof(w->report.authority_sha256), "%s", w->approval.plan_sha256);
    raw_selected_transaction_begin(w->report.workspace, &w->plan, &w->approval, &tx);
    if (!tx.result || strcmp(tx.result, "PREPARED")) { snprintf(err, sizeof(err), "%s", tx.detail); goto done; }
    raw_selected_transaction_hooks_t hooks = {.context=w, .before_publish=before_publish,
        .after_publish=after_publish, .before_complete=before_complete};
    raw_selected_transaction_publish_checked(w->report.workspace, &w->approval, &hooks, &tx);
    w->report.attempted_images = tx.attempted_images;
    w->report.written_images = tx.published_images;
    w->report.written_active_slots = tx.published_active_slots;
    w->report.written_service_images = tx.published_service_images;
    w->report.verified_images = tx.verified_images;
    w->report.publication_uncertain = tx.publication_uncertain;
    w->report.uncertain_images = tx.publication_uncertain ?
        (tx.attempted_images > tx.published_images ? tx.attempted_images - tx.published_images : 1) : 0;
    if (!tx.result || strcmp(tx.result, "PUBLISHED_VERIFIED") || tx.publication_uncertain ||
        tx.published_images != w->plan.count || tx.verified_images != w->plan.count) {
        snprintf(err, sizeof(err), "%s", tx.detail[0] ? tx.detail : "RAW publication incomplete or uncertain"); goto done;
    }
    // Durable verified terminal proof precedes retiring the global barrier.
    // released.bin is a separate completion of finalization; a crash cannot
    // leave a cleared barrier without the already durable content proof.
    snprintf(w->report.result, sizeof(w->report.result), "PUBLISHED_VERIFIED");
done:
    w->report.terminal = true; w->report.queued = false;
    if (strcmp(w->report.result, "PUBLISHED_VERIFIED")) {
        snprintf(w->report.result, sizeof(w->report.result), "%s", w->report.barrier_retained ? "RECOVERY_REQUIRED" : "BLOCKED");
        w->report.recovery_required = w->report.barrier_retained;
        snprintf(w->report.detail, sizeof(w->report.detail), "%s", err[0] ? err : "RAW proof unavailable; no retry/repair");
    }
    char evidence_error[256] = {0};
    if (!record_write(w->report.workspace, "terminal.bin", &w->report, sizeof(w->report), evidence_error, sizeof(evidence_error))) {
        snprintf(w->report.result, sizeof(w->report.result), "RECOVERY_REQUIRED");
        snprintf(w->report.detail, sizeof(w->report.detail), "%s", evidence_error);
        w->report.recovery_required = true;
    } else if (!strcmp(w->report.result, "PUBLISHED_VERIFIED")) {
        bool released = import_session_unclaim_raw_durable(w->request.import_id) &&
            watcher_raw_selected_barrier_held(false, w->report.workspace, evidence_error, sizeof(evidence_error));
        if (released) {
            w->report.barrier_retained = false;
            released = record_write(w->report.workspace, "released.bin", &w->report, sizeof(w->report), evidence_error, sizeof(evidence_error));
        }
        if (!released) {
            snprintf(w->report.result, sizeof(w->report.result), "RECOVERY_REQUIRED");
            snprintf(w->report.detail, sizeof(w->report.detail), "Finalization unknown; verified images retained: %.180s", evidence_error);
            w->report.recovery_required = true;
            if (!w->report.barrier_retained)
                (void)watcher_raw_selected_barrier_held(true, w->report.workspace, evidence_error, sizeof(evidence_error));
            w->report.barrier_retained = true;
            (void)record_write(w->report.workspace, "finalization-failed.bin", &w->report, sizeof(w->report), evidence_error, sizeof(evidence_error));
        }
    }
    report_store_memory(&w->report);
    if (gated) watcher_target_check_end();
    free(w);
    pthread_mutex_lock(&s_lock); atomic_store(&s_active, false);
    pthread_cond_broadcast(&s_thread_cond); pthread_mutex_unlock(&s_lock);
    lifecycle_activity_end(); return NULL;
}

bool raw_selected_commit_parse(const char* body, raw_selected_preflight_request_t* req,
    char receipt[65], char* err, size_t n) {
    return raw_selected_preflight_parse_commit(body, req, receipt, err, n);
}
void raw_selected_commit_submit(const raw_selected_preflight_request_t* req,
    const char* receipt, raw_selected_commit_report_t* out) {
    if (!out) return;
    memset(out, 0, sizeof(*out)); snprintf(out->version, sizeof(out->version), "%s", TOSTONSYNC_VERSION);
    snprintf(out->result, sizeof(out->result), "BLOCKED");
    if (!req || req->mode != RAW_SELECTED_MODE_RAW_EXACT || !component(receipt, 65, true) ||
        !watcher_is_running()) { snprintf(out->detail, sizeof(out->detail), "Dedicated exact RAW running admission required"); return; }
    if (!atomic_load(&s_active)) raw_selected_commit_join();
    pthread_mutex_lock(&s_lock);
    if (atomic_load(&s_active) || s_joinable || !lifecycle_activity_begin()) {
        pthread_mutex_unlock(&s_lock); snprintf(out->detail, sizeof(out->detail), "Dedicated RAW worker/admission busy; no retry"); return;
    }
    atomic_store(&s_active, true); pthread_mutex_unlock(&s_lock);
    work_t* w = calloc(1, sizeof(*w)); char err[256] = {0}; bool gated = false, workspace_created = false;
    if (!w) { snprintf(err, sizeof(err), "Worker allocation failed"); goto blocked; }
    w->request = *req; w->report = *out;
    snprintf(w->report.import_id, sizeof(w->report.import_id), "%s", req->import_id);
    snprintf(w->report.target_uid, sizeof(w->report.target_uid), "%s", req->target_uid);
    snprintf(w->report.title_id, sizeof(w->report.title_id), "%s", req->title_id);
    snprintf(w->report.zip_sha256, sizeof(w->report.zip_sha256), "%s", req->zip_sha256);
    snprintf(w->report.selection_receipt, sizeof(w->report.selection_receipt), "%s", receipt);
    w->report.selected_active_slots = req->active.count; w->report.selected_service_images = req->services.count;
    w->report.authorized_images = req->active.count + req->services.count;
    if (watcher_target_check_begin(err, sizeof(err)) != 1) goto blocked;
    gated = true;
    if (!find_approval(req, receipt, w, err, sizeof(err)) || !session_matches(&w->plan, false, err, sizeof(err)) ||
        !fresh_state(&w->plan, err, sizeof(err)) || !workspace_path(receipt, w->report.workspace)) goto blocked;
    w->report.image_count = w->plan.count;
    for (size_t i = 0; i < w->plan.count; i++) {
        raw_selected_commit_image_t* out_image = &w->report.images[i]; const raw_selected_entry_t* e = &w->plan.entries[i];
        out_image->role = e->role;
        snprintf(out_image->image_name, sizeof(out_image->image_name), "%s", e->image_name);
        snprintf(out_image->target, sizeof(out_image->target), "%s", e->target);
        snprintf(out_image->source_sha256, sizeof(out_image->source_sha256), "%s", e->source_sha256);
        snprintf(out_image->pre_sha256, sizeof(out_image->pre_sha256), "%s", e->pre_sha256);
    }
    // Exclusive directory is the durable spent-receipt guard. Even a partial
    // claim blocks reuse; no restart path resets, deletes or guesses its state.
    if (mkdir(w->report.workspace, 0700)) { snprintf(err, sizeof(err), "Receipt already spent or claim directory unavailable"); goto blocked; }
    workspace_created = true;
    char parent[512]; if (!parent_path(parent) || !sync_dir(parent) || !sync_dir(w->report.workspace)) goto blocked;
    snprintf(w->claim.magic, sizeof(w->claim.magic), "RAW-ONCE"); w->claim.version = 1; w->claim.bytes = sizeof(w->claim);
    w->claim.request = *req; snprintf(w->claim.receipt, sizeof(w->claim.receipt), "%s", receipt);
    snprintf(w->claim.approval_sha256, sizeof(w->claim.approval_sha256), "%s", w->approval.plan_sha256);
    if (!record_write(w->report.workspace, "claim.bin", &w->claim, sizeof(w->claim), err, sizeof(err))) goto blocked;
    import_session_info_t claimed;
    if (!import_session_claim(req->import_id, &claimed) || claimed.state != IMPORT_COMMITTED ||
        strcmp(claimed.path, w->plan.zip_path) || claimed.portable_path[0]) {
        snprintf(err, sizeof(err), "Durable canonical RAW import claim failed; receipt consumed"); goto blocked;
    }
    w->report.queued = true; w->report.publication_enabled = true;
    snprintf(w->report.result, sizeof(w->report.result), "QUEUED");
    if (!record_write(w->report.workspace, "queued.bin", &w->report, sizeof(w->report), err, sizeof(err))) goto blocked;
    // The gate's lifecycle lease is thread-local, so hand it back before the
    // dedicated worker acquires it. The global activity reservation spans this
    // gap. Any incompatible intervening work blocks, never broadens authority.
    watcher_target_check_end(); gated = false;
    pthread_attr_t attr; int code = pthread_attr_init(&attr); bool initialized = code == 0;
    if (!code) code = pthread_attr_setstacksize(&attr, 1024 * 1024);
    pthread_mutex_lock(&s_lock); s_report = w->report;
    if (!watcher_is_running()) code = EBUSY;
    if (!code) code = pthread_create(&s_thread, &attr, worker, w);
    if (!code) { s_joinable = true; *out = w->report; }
    pthread_cond_broadcast(&s_thread_cond);
    pthread_mutex_unlock(&s_lock);
    if (code) { snprintf(err, sizeof(err), "Dedicated RAW worker creation failed (code=%d); claim retained", code);
        if (initialized) pthread_attr_destroy(&attr); goto blocked; }
    pthread_attr_destroy(&attr); return;
blocked:
    if (gated) watcher_target_check_end();
    if (w) { *out = w->report; free(w); }
    out->queued = false; out->terminal = true; snprintf(out->result, sizeof(out->result), "BLOCKED");
    snprintf(out->detail, sizeof(out->detail), "%s", err[0] ? err : "RAW admission/durability unavailable");
    if (workspace_created) {
        char ignored[256]; (void)record_write(out->workspace, "admission-failed.bin", out, sizeof(*out), ignored, sizeof(ignored));
        report_store_memory(out);
    }
    pthread_mutex_lock(&s_lock); atomic_store(&s_active, false);
    pthread_cond_broadcast(&s_thread_cond); pthread_mutex_unlock(&s_lock);
    lifecycle_activity_end();
}
bool raw_selected_commit_status(const char* id, const char* receipt, raw_selected_commit_report_t* out) {
    if (!out || !component(id, 48, false) || !component(receipt, 65, true)) return false;
    pthread_mutex_lock(&s_lock);
    bool live = !strcmp(s_report.import_id, id) && !strcmp(s_report.selection_receipt, receipt);
    if (live) *out = s_report;
    pthread_mutex_unlock(&s_lock); if (live) return true;
    char dir[512]; claim_t claim;
    if (!workspace_path(receipt, dir) || !directory_safe(dir) ||
        !record_read(dir, "claim.bin", &claim, sizeof(claim)) || memcmp(claim.magic, "RAW-ONCE\0\0\0\0\0\0\0\0", 16) ||
        claim.version != 1 || claim.bytes != sizeof(claim) || !component(claim.request.import_id, 48, false) ||
        !component(claim.receipt, 65, true) || strcmp(claim.request.import_id, id) || strcmp(claim.receipt, receipt) ||
        claim.request.mode != RAW_SELECTED_MODE_RAW_EXACT || !claim.request.active.specified ||
        !claim.request.services.specified || !claim.request.active.count ||
        claim.request.active.count > RESTORE_SELECTION_MAX || claim.request.services.count > RESTORE_SELECTION_MAX) return false;
    const char* terminal_names[] = {"admission-failed.bin", "finalization-failed.bin", "released.bin", "terminal.bin"};
    for (size_t i = 0; i < 4; i++) {
        if (!record_read(dir, terminal_names[i], out, sizeof(*out)) || !report_valid(out) ||
            !memchr(out->import_id, 0, sizeof(out->import_id)) ||
            !memchr(out->selection_receipt, 0, sizeof(out->selection_receipt)) ||
            strcmp(out->import_id, id) || strcmp(out->selection_receipt, receipt) || !out->terminal) continue;
        if (i == 3 && !strcmp(out->result, "PUBLISHED_VERIFIED")) {
            snprintf(out->result, sizeof(out->result), "RECOVERY_REQUIRED"); out->recovery_required = true;
            snprintf(out->detail, sizeof(out->detail), "Images durably verified; barrier/claim finalization not confirmed. No replay.");
        }
        return true;
    }
    memset(out, 0, sizeof(*out)); snprintf(out->version, sizeof(out->version), "%s", TOSTONSYNC_VERSION);
    snprintf(out->result, sizeof(out->result), "RECOVERY_REQUIRED");
    snprintf(out->detail, sizeof(out->detail), "Spent claim without valid terminal proof; no replay or automatic recovery");
    snprintf(out->import_id, sizeof(out->import_id), "%s", id);
    snprintf(out->selection_receipt, sizeof(out->selection_receipt), "%s", receipt);
    snprintf(out->workspace, sizeof(out->workspace), "%s", dir);
    out->terminal = true; out->recovery_required = true; out->publication_uncertain = true;
    out->barrier_retained = true; out->uncertain_images = claim.request.active.count + claim.request.services.count;
    out->selected_active_slots = claim.request.active.count; out->selected_service_images = claim.request.services.count;
    out->authorized_images = out->uncertain_images; return true;
}
bool raw_selected_commit_active(void) { return atomic_load(&s_active); }
void raw_selected_commit_join(void) {
    pthread_mutex_lock(&s_join_lock);
    pthread_mutex_lock(&s_lock);
    while (atomic_load(&s_active) && !s_joinable) pthread_cond_wait(&s_thread_cond, &s_lock);
    bool join = s_joinable; pthread_t thread = s_thread;
    pthread_mutex_unlock(&s_lock);
    if (join) pthread_join(thread, NULL);
    pthread_mutex_lock(&s_lock); s_joinable = false; pthread_mutex_unlock(&s_lock);
    pthread_mutex_unlock(&s_join_lock);
}
