// Private RAW diagnostic admission. No live publication/recovery capability.
#include "raw_selected_preflight.h"
#include "raw_selected_native.h"
#include "import_session.h"
#include "watcher.h"
#include "sha256.h"
#include "version.h"
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static bool fail(char* err, size_t n, const char* why) {
    if (err && n) snprintf(err, n, "%s", why);
    return false;
}
static void ws(const char** s) { while (isspace((unsigned char)**s)) ++*s; }
// Authority is deliberately flat and literal: no escapes, nesting or defaults.
static bool literal(const char** s, char* out, size_t n) {
    ws(s); if (*(*s)++ != '"') return false;
    size_t len = 0;
    while (**s && **s != '"') {
        unsigned char c = (unsigned char)*(*s)++;
        if (c < 32 || c == '\\' || len + 1 >= n) return false;
        out[len++] = (char)c;
    }
    if (**s != '"') return false;
    ++*s; out[len] = 0; return true;
}
static bool hex(const char* s, size_t len) {
    if (strlen(s) != len) return false;
    for (size_t i = 0; i < len; i++)
        if (!((s[i] >= '0' && s[i] <= '9') || (s[i] >= 'a' && s[i] <= 'f'))) return false;
    return true;
}
static bool component(const char* s, size_t n) {
    size_t len = strnlen(s, n);
    if (!len || len >= n || !strcmp(s, ".") || !strcmp(s, "..")) return false;
    for (size_t i = 0; i < len; i++)
        if (!((s[i] >= 'a' && s[i] <= 'z') || (s[i] >= 'A' && s[i] <= 'Z') ||
            (s[i] >= '0' && s[i] <= '9') || s[i] == '-' || s[i] == '_')) return false;
    return true;
}
static bool selection_valid(const restore_selection_t* v, bool empty) {
    if (!v->specified || v->count > RESTORE_SELECTION_MAX || (!empty && !v->count)) return false;
    for (size_t i = 0; i < v->count; i++) {
        if (!component(v->slots[i], sizeof(v->slots[i]))) return false;
        for (size_t j = 0; j < i; j++) if (!strcmp(v->slots[i], v->slots[j])) return false;
    }
    return true;
}
static bool request_valid(const raw_selected_preflight_request_t* r) {
    if (!r || r->mode != RAW_SELECTED_MODE_RAW_EXACT || !component(r->import_id, sizeof(r->import_id)) ||
        !memchr(r->zip_sha256, 0, sizeof(r->zip_sha256)) || !hex(r->zip_sha256, 64) ||
        !memchr(r->target_uid, 0, sizeof(r->target_uid)) || !hex(r->target_uid, 8) ||
        strnlen(r->title_id, sizeof(r->title_id)) != 9 || strncmp(r->title_id, "PPSA", 4) ||
        !selection_valid(&r->active, false) || !selection_valid(&r->services, true)) return false;
    for (size_t i = 4; i < 9; i++) if (r->title_id[i] < '0' || r->title_id[i] > '9') return false;
    for (size_t i = 0; i < r->services.count; i++)
        if (!restore_selection_contains(&r->active, r->services.slots[i])) return false;
    return true;
}
static int slot_cmp(const void* a, const void* b) { return strcmp(a, b); }
static bool array(const char** s, restore_selection_t* out) {
    ws(s); if (*(*s)++ != '[') return false;
    out->specified = true; ws(s);
    if (**s == ']') { ++*s; return true; }
    for (;;) {
        if (out->count == RESTORE_SELECTION_MAX ||
            !literal(s, out->slots[out->count], sizeof(out->slots[0]))) return false;
        ++out->count; ws(s);
        if (**s == ']') { ++*s; break; }
        if (*(*s)++ != ',') return false;
    }
    qsort(out->slots, out->count, sizeof(out->slots[0]), slot_cmp); return true;
}
static bool parse_request(const char* body, raw_selected_preflight_request_t* out,
    char* receipt, char* err, size_t n) {
    if (!body || !out || strlen(body) > 8192) return fail(err, n, "Bounded exact RAW request required");
    memset(out, 0, sizeof(*out)); const char* s = body; ws(&s);
    if (*s++ != '{') return fail(err, n, "Flat RAW request object required");
    unsigned seen = 0;
    for (;;) {
        char key[40], mode[32]; ws(&s);
        if (*s == '}') { ++s; break; }
        if (!literal(&s, key, sizeof(key))) goto invalid;
        ws(&s); if (*s++ != ':') goto invalid;
        unsigned bit = !strcmp(key, "restore_mode") ? 1 : !strcmp(key, "id") ? 2 :
            !strcmp(key, "zip_sha256") ? 4 : !strcmp(key, "target_uid") ? 8 :
            !strcmp(key, "title_id") ? 16 : !strcmp(key, "selected_slots") ? 32 :
            !strcmp(key, "service_slots") ? 64 : receipt && !strcmp(key, "selection_receipt") ? 128 : 0;
        if (!bit || (seen & bit)) goto invalid;
        seen |= bit;
        if (bit == 1) {
            if (!literal(&s, mode, sizeof(mode)) || strcmp(mode, "raw_selected_exact")) goto invalid;
            out->mode = RAW_SELECTED_MODE_RAW_EXACT;
        } else if (bit == 2) { if (!literal(&s, out->import_id, sizeof(out->import_id))) goto invalid;
        } else if (bit == 4) { if (!literal(&s, out->zip_sha256, sizeof(out->zip_sha256))) goto invalid;
        } else if (bit == 8) { if (!literal(&s, out->target_uid, sizeof(out->target_uid))) goto invalid;
        } else if (bit == 16) { if (!literal(&s, out->title_id, sizeof(out->title_id))) goto invalid;
        } else if (bit == 128) { if (!literal(&s, receipt, 65) || !hex(receipt, 64)) goto invalid;
        } else if (!array(&s, bit == 32 ? &out->active : &out->services)) goto invalid;
        ws(&s); if (*s == '}') { ++s; break; }
        if (*s++ != ',') goto invalid;
        ws(&s); if (*s == '}') goto invalid;
    }
    ws(&s); if (*s || seen != (receipt ? 255u : 127u) || !request_valid(out)) goto invalid;
    return true;
invalid:
    return fail(err, n, "Exact RAW mode, ID/hash/UID/title and explicit unique active/service arrays required");
}
bool raw_selected_preflight_parse(const char* body, raw_selected_preflight_request_t* out,
    char* err, size_t n) { return parse_request(body, out, NULL, err, n); }
bool raw_selected_preflight_parse_commit(const char* body, raw_selected_preflight_request_t* out,
    char receipt[65], char* err, size_t n) {
    if (!receipt) return fail(err, n, "Literal RAW receipt required");
    receipt[0] = 0; return parse_request(body, out, receipt, err, n);
}
static bool path_join(char* out, size_t n, const char* a, const char* b) {
    int len = snprintf(out, n, "%s/%s", a, b); return len > 0 && (size_t)len < n;
}
static bool sync_dir(const char* dir);
static bool private_dir(const char* root, const char* suffix, char out[512], char* err, size_t n) {
    if (!path_join(out, 512, root, suffix) || mkdir(out, 0700) || !sync_dir(out) || !sync_dir(root))
        return fail(err, n, "Durable new diagnostic directory unavailable");
    return true;
}
static bool identity_equal(const raw_selected_identity_t* a, const raw_selected_identity_t* b) {
    return a->metadata_complete && b->metadata_complete && a->hmac_present && b->hmac_present &&
        !strcmp(a->title_id, b->title_id) && !strcmp(a->slot, b->slot) &&
        !strcmp(a->game_title_id, b->game_title_id) && !strcmp(a->format, b->format) &&
        a->account_id == b->account_id && a->user_id == b->user_id && a->user_param == b->user_param &&
        a->blocks == b->blocks && a->system_blocks == b->system_blocks &&
        !strcmp(a->hmac_sha256, b->hmac_sha256);
}
static bool write_new(const char* work, const char* name, const void* bytes, size_t n, char* err, size_t err_sz);
static bool observe(const char* canonical, const char* private_image, const char* workspace,
    const char* sha, const raw_selected_stat_t* st, const raw_selected_entry_t* e,
    const char* title, raw_selected_native_observation_t* observation, bool* uncertain,
    char* err, size_t n) {
    memset(observation, 0, sizeof(*observation));
    if (!raw_selected_copy_private(canonical, private_image, sha, err, n)) return false;
    char parent[512], name[160]; snprintf(parent, sizeof(parent), "%s", private_image);
    char* leaf = strrchr(parent, '/');
    if (!leaf) return fail(err, n, "Diagnostic observation path unavailable");
    snprintf(name, sizeof(name), "%s.observation.bin", leaf + 1); *leaf = 0;
    if (!sync_dir(parent) || !sync_dir(workspace)) return fail(err, n, "Private-copy directory durability unavailable; no mount");
    raw_selected_native_request_t req = { .canonical = canonical, .private_image = private_image,
        .private_workspace = workspace, .expected_sha256 = sha, .canonical_stat = st,
        .role = e->role, .expected_title = title, .expected_slot = e->slot };
    raw_selected_native_observe(&req, observation, err, n);
    if (!err[0] && observation->status != RAW_SELECTED_NATIVE_READY)
        snprintf(err, n, "%s", observation->detail[0] ? observation->detail : "Native proof unavailable");
    if (observation->status == RAW_SELECTED_NATIVE_UNMOUNT_UNCERTAIN ||
        (observation->mount_attempted && !observation->unmount_confirmed)) *uncertain = true;
    // Retain exact native status/mount/backing even on an uncertain close.
    // The already durable barrier protects a crash before this return; never
    // reconstruct a missing mount identity or clean up by guessing on restart.
    char evidence_err[256] = {0};
    if (!write_new(parent, name, observation, sizeof(*observation), evidence_err, sizeof(evidence_err)))
        return fail(err, n, evidence_err);
    return observation->status == RAW_SELECTED_NATIVE_READY && observation->unmount_confirmed &&
        observation->canonical_unchanged && observation->metadata_complete && observation->geometry_reliable &&
        observation->key_available;
}

// Same-build bounded binary evidence, not a new portable/Restore format. SHA
// envelope + finalized marker must agree; receipt alone never grants a write.
typedef struct {
    char magic[16]; uint32_t version, bytes;
    raw_selected_plan_t plan;
    raw_selected_approval_t approval;
} approval_record_t;
static void memory_sha(const void* bytes, size_t n, char out[65]) {
    sha256_ctx_t ctx; uint8_t hash[32]; sha256_init(&ctx); sha256_update(&ctx, bytes, n); sha256_final(&ctx, hash);
    for (size_t i = 0; i < 32; i++) snprintf(out + 2 * i, 3, "%02x", hash[i]);
}
static bool sync_dir(const char* dir) {
    int fd = open(dir, O_RDONLY | O_DIRECTORY | O_NOFOLLOW); if (fd < 0) return false;
    bool ok = fsync(fd) == 0; if (close(fd)) ok = false; return ok;
}
static bool write_new(const char* work, const char* name, const void* bytes, size_t n, char* err, size_t err_sz) {
    char path[512]; if (!path_join(path, sizeof(path), work, name)) return fail(err, err_sz, "Evidence path too long");
    int fd = open(path, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW, 0600);
    if (fd < 0) return fail(err, err_sz, "Exclusive evidence creation failed");
    size_t off = 0; bool ok = true;
    while (off < n) { ssize_t got = write(fd, (const char*)bytes + off, n - off);
        if (got < 0 && errno == EINTR) continue;
        if (got <= 0) { ok = false; break; } off += (size_t)got; }
    if (ok && fsync(fd)) ok = false;
    if (close(fd)) ok = false;
    if (ok && !sync_dir(work)) ok = false;
    return ok || fail(err, err_sz, "Durable evidence write/sync failed; retain partial evidence");
}
static bool save_approval(const char* work, const raw_selected_plan_t* plan,
    const raw_selected_approval_t* approval, char digest[65], char* err, size_t n) {
    approval_record_t* record = calloc(1, sizeof(*record)); if (!record) return fail(err, n, "Approval allocation failed");
    snprintf(record->magic, sizeof(record->magic), "RAW-PREFLIGHT");
    record->version = RAW_SELECTED_CONTRACT_VERSION; record->bytes = sizeof(*record);
    record->plan = *plan; record->approval = *approval; memory_sha(record, sizeof(*record), digest);
    bool ok = write_new(work, "approval.bin", record, sizeof(*record), err, n) &&
        write_new(work, "approval.sha256", digest, 64, err, n);
    free(record); return ok;
}
static bool read_fixed(const char* work, const char* name, void* data, size_t n) {
    char path[512]; struct stat a, b;
    if (!path_join(path, sizeof(path), work, name) || lstat(path, &a) || !S_ISREG(a.st_mode) ||
        a.st_nlink != 1 || a.st_size != (off_t)n) return false;
    int fd = open(path, O_RDONLY | O_NOFOLLOW); if (fd < 0) return false;
    bool ok = fstat(fd, &b) == 0 && a.st_dev == b.st_dev && a.st_ino == b.st_ino;
    size_t off = 0;
    while (ok && off < n) { ssize_t got = read(fd, (char*)data + off, n - off);
        if (got < 0 && errno == EINTR) continue;
        if (got <= 0) { ok = false; break; } off += (size_t)got; }
    char tail;
    if (ok && (read(fd, &tail, 1) != 0 || fstat(fd, &b) || a.st_size != b.st_size ||
        a.st_mtime != b.st_mtime || a.st_ctime != b.st_ctime)) ok = false;
    if (close(fd)) ok = false;
    if (ok && (lstat(path, &b) || a.st_dev != b.st_dev || a.st_ino != b.st_ino || a.st_size != b.st_size)) ok = false;
    return ok;
}
bool raw_selected_preflight_load_approval(const char* work, const raw_selected_preflight_request_t* req,
    const char* receipt, raw_selected_plan_t* plan, raw_selected_approval_t* approval, char* err, size_t n) {
    if (!work || !request_valid(req) || !receipt || !hex(receipt, 64) || !plan || !approval)
        return fail(err, n, "Bounded RAW read-only approval lookup required");
    char* real = realpath(work, NULL); bool safe = real && !strcmp(real, work); free(real);
    if (!safe) return fail(err, n, "Approval workspace is aliased or unavailable");
    approval_record_t* record = calloc(1, sizeof(*record)); char stored[65] = {0}, finalized[65] = {0}, digest[65];
    if (!record) return fail(err, n, "Approval allocation failed");
    bool ok = read_fixed(work, "approval.bin", record, sizeof(*record)) &&
        read_fixed(work, "approval.sha256", stored, 64) && read_fixed(work, "approval.finalized", finalized, 64);
    if (ok) {
        memory_sha(record, sizeof(*record), digest);
        ok = !memcmp(record->magic, "RAW-PREFLIGHT\0\0\0", 16) && record->version == RAW_SELECTED_CONTRACT_VERSION &&
            record->bytes == sizeof(*record) && !strcmp(digest, stored) && !strcmp(digest, finalized) &&
            raw_selected_approval_matches(&record->plan, &record->approval, err, n);
    }
    if (ok) ok = !strcmp(record->approval.receipt, receipt) && record->plan.mode == req->mode &&
        !strcmp(record->plan.import_id, req->import_id) && !strcmp(record->plan.zip_sha256, req->zip_sha256) &&
        !strcmp(record->plan.target_uid, req->target_uid) && !strcmp(record->plan.title_id, req->title_id) &&
        restore_selection_equal(&record->plan.active, &req->active) &&
        restore_selection_equal(&record->plan.services, &req->services);
    if (ok) { *plan = record->plan; *approval = record->approval; }
    free(record);
    return ok || fail(err, n, "Unfinalized/corrupt/cross-mode or changed RAW approval; no write authority");
}

void raw_selected_preflight_run(const raw_selected_preflight_request_t* req, raw_selected_preflight_report_t* r) {
    if (!r) return;
    memset(r, 0, sizeof(*r)); snprintf(r->version, sizeof(r->version), "%s", TOSTONSYNC_VERSION);
    snprintf(r->result, sizeof(r->result), "BLOCKED");
    if (!request_valid(req)) { snprintf(r->detail, sizeof(r->detail), "Exact RAW request invalid"); return; }
    snprintf(r->import_id, sizeof(r->import_id), "%s", req->import_id);
    snprintf(r->target_uid, sizeof(r->target_uid), "%s", req->target_uid);
    snprintf(r->title_id, sizeof(r->title_id), "%s", req->title_id);
    snprintf(r->zip_sha256, sizeof(r->zip_sha256), "%s", req->zip_sha256);
    r->selected_active_slots = req->active.count; r->selected_service_images = req->services.count;
    r->authorized_images = req->active.count + req->services.count; r->total_slots = req->active.count;
    r->image_count = r->authorized_images;
    for (size_t i = 0; i < r->image_count; i++) {
        raw_selected_preflight_image_report_t* image = &r->images[i]; bool service = i >= req->active.count;
        image->role = service ? RAW_SELECTED_ROLE_SERVICE : RAW_SELECTED_ROLE_ACTIVE;
        snprintf(image->slot, sizeof(image->slot), "%s", service ? req->services.slots[i - req->active.count] : req->active.slots[i]);
        snprintf(image->image_name, sizeof(image->image_name), "sdimg_%s%s", service ? "sce_bu_" : "", image->slot);
        snprintf(image->result, sizeof(image->result), "NOT_CHECKED");
    }
    char err[256] = {0}; int gate = watcher_target_check_begin(err, sizeof(err));
    if (gate != 1) {
        snprintf(r->result, sizeof(r->result), "%s", gate == 0 ? "BUSY" : "RECOVERY_REQUIRED");
        r->recovery_required = gate < 0; snprintf(r->detail, sizeof(r->detail), "%s", err); return;
    }
    raw_selected_plan_t* p = calloc(1, sizeof(*p)); bool uncertain = false; char record_sha[65] = {0};
    raw_selected_approval_t approval = {0}; import_session_info_t session;
    if (!p) { snprintf(err, sizeof(err), "Plan allocation failed"); goto done; }
    if (!import_session_status(req->import_id, &session) || session.state != IMPORT_READY ||
        strcmp(session.id, req->import_id) || strcmp(session.sha256, req->zip_sha256)) {
        snprintf(err, sizeof(err), "Exact READY RAW import/hash unavailable"); goto done;
    }
    p->mode = req->mode; p->active = req->active; p->services = req->services;
    snprintf(p->import_id, sizeof(p->import_id), "%s", req->import_id);
    snprintf(p->zip_sha256, sizeof(p->zip_sha256), "%s", req->zip_sha256);
    snprintf(p->zip_path, sizeof(p->zip_path), "%s", session.path);
    snprintf(p->title_id, sizeof(p->title_id), "%s", req->title_id);
    if (!watcher_raw_selected_workspace_held(r->work, sizeof(r->work), err, sizeof(err))) goto done;
    char source[512];
    if (!path_join(source, sizeof(source), r->work, "source") ||
        !raw_selected_source_prepare(p, source, err, sizeof(err))) {
        r->source_check = RAW_SELECTED_CHECK_FAIL; goto done;
    }
    r->source_check = RAW_SELECTED_CHECK_PASS; r->available_backup_slots = p->archive_report.save_dir_count;
    r->source_title_available_slots = p->available_slots;
    if (!watcher_raw_selected_target_held(req->target_uid, req->title_id, p->target_uid, sizeof(p->target_uid),
        p->target_root, sizeof(p->target_root), err, sizeof(err))) goto done;
    if (strcmp(p->target_uid, req->target_uid)) { snprintf(err, sizeof(err), "Fresh UID differs from exact request"); goto done; }
    p->fresh_target_check = RAW_SELECTED_CHECK_PASS;
    char native[512], source_diag[512], target_diag[512], omitted_diag[512], pre[512];
    if (!private_dir(r->work, "native", native, err, sizeof(err)) ||
        !private_dir(native, "source", source_diag, err, sizeof(err)) ||
        !private_dir(native, "target", target_diag, err, sizeof(err)) ||
        !private_dir(native, "omitted", omitted_diag, err, sizeof(err)) ||
        !private_dir(r->work, "pre", pre, err, sizeof(err))) goto done;
    for (size_t i = 0; i < p->count; i++) {
        raw_selected_entry_t* e = &p->entries[i]; raw_selected_preflight_image_report_t* image = &r->images[i];
        snprintf(image->result, sizeof(image->result), "BLOCKED");
        snprintf(image->source_sha256, sizeof(image->source_sha256), "%s", e->source_sha256);
        if (!path_join(e->target, sizeof(e->target), p->target_root, e->image_name) ||
            !path_join(e->diagnostic, sizeof(e->diagnostic), source_diag, e->image_name) ||
            !path_join(e->preimage, sizeof(e->preimage), pre, e->image_name) ||
            !raw_selected_file_observe(e->target, &e->target_stat, e->pre_sha256, err, sizeof(err))) goto image_failed;
        snprintf(image->target_sha256, sizeof(image->target_sha256), "%s", e->pre_sha256);
        if (e->size != e->target_stat.size) { snprintf(err, sizeof(err), "Existing target image size differs"); goto image_failed; }
        if (!raw_selected_read_exact_row(p->target_uid, p->title_id, e->slot, &e->row, err, sizeof(err))) {
            image->row = e->row; goto image_failed;
        }
        image->row = e->row;
        if (!r->barrier_armed) {
            if (!watcher_raw_selected_barrier_held(true, r->work, err, sizeof(err))) {
                uncertain = true; goto image_failed;
            }
            r->barrier_armed = true;
        }
        raw_selected_native_observation_t a, b; char target_private[512];
        if (!path_join(target_private, sizeof(target_private), target_diag, e->image_name) ||
            !observe(e->source, e->diagnostic, native, e->source_sha256, &e->source_stat, e,
                p->title_id, &a, &uncertain, err, sizeof(err))) goto image_failed;
        e->source_identity = a.identity; image->source_identity = a.identity;
        e->source_sfo_check = e->source_key_check = e->source_unmount_check = RAW_SELECTED_CHECK_PASS;
        snprintf(e->diagnostic_sha256, sizeof(e->diagnostic_sha256), "%s", a.closed_diagnostic_sha256);
        snprintf(e->source_key_fingerprint, sizeof(e->source_key_fingerprint), "%s", a.key_fingerprint);
        snprintf(image->source_key_fingerprint, sizeof(image->source_key_fingerprint), "%s", a.key_fingerprint);
        if (!observe(e->target, target_private, native, e->pre_sha256, &e->target_stat, e,
            p->title_id, &b, &uncertain, err, sizeof(err))) goto image_failed;
        e->target_identity = b.identity; image->target_identity = b.identity;
        e->target_sfo_check = e->target_key_check = e->target_unmount_check = RAW_SELECTED_CHECK_PASS;
        snprintf(e->target_key_fingerprint, sizeof(e->target_key_fingerprint), "%s", b.key_fingerprint);
        snprintf(image->target_key_fingerprint, sizeof(image->target_key_fingerprint), "%s", b.key_fingerprint);
        if (!identity_equal(&a.identity, &b.identity) || strcmp(a.key_fingerprint, b.key_fingerprint) ||
            b.identity.account_id != e->row.account_id || b.identity.user_id != e->row.user_id ||
            b.identity.user_id != (uint32_t)strtoul(p->target_uid, NULL, 16)) {
            snprintf(err, sizeof(err), "Source/native destination exact owner, identity, key or geometry differs"); goto image_failed;
        }
        e->geometry_check = RAW_SELECTED_CHECK_PASS;
        e->save_kind = b.save_kind; e->save_kind_reliable = b.save_kind_reliable;
        image->save_kind = e->save_kind; image->save_kind_reliable = e->save_kind_reliable;
        image->additional_authorization_required = e->save_kind_reliable && e->save_kind == RAW_SELECTED_SAVE_KIND_SYSTEM;
        if (e->role == RAW_SELECTED_ROLE_ACTIVE && !restore_selection_contains(&p->services, e->slot)) {
            raw_selected_omitted_service_t* o = &e->omitted_service; char name[128]; struct stat exists;
            snprintf(name, sizeof(name), "sdimg_sce_bu_%s", e->slot);
            if (!path_join(o->path, sizeof(o->path), p->target_root, name)) goto image_failed;
            o->state = RAW_SELECTED_OMITTED_UNKNOWN;
            if (lstat(o->path, &exists)) {
                if (errno != ENOENT) { snprintf(err, sizeof(err), "Omitted service existence UNKNOWN"); goto image_failed; }
                o->state = RAW_SELECTED_OMITTED_ABSENT;
                snprintf(image->omitted_service_result, sizeof(image->omitted_service_result), "SERVICE OMITTED + ABSENT");
            } else {
                o->state = RAW_SELECTED_OMITTED_PRESENT;
                snprintf(image->omitted_service_result, sizeof(image->omitted_service_result), "SERVICE OMITTED + COHERENCE UNKNOWN");
                if (!raw_selected_file_observe(o->path, &o->stat, o->sha256, err, sizeof(err)) ||
                    strcmp(e->source_sha256, e->pre_sha256) || o->stat.size != e->size) {
                    snprintf(err, sizeof(err), "SERVICE OMITTED + COHERENCE UNKNOWN; no demonstrated unchanged pair"); goto image_failed;
                }
                raw_selected_native_observation_t service;
                raw_selected_entry_t service_entry = *e; service_entry.role = RAW_SELECTED_ROLE_SERVICE;
                if (!path_join(o->diagnostic, sizeof(o->diagnostic), omitted_diag, name) ||
                    !observe(o->path, o->diagnostic, native, o->sha256, &o->stat, &service_entry,
                        p->title_id, &service, &uncertain, err, sizeof(err))) goto image_failed;
                o->identity = service.identity;
                if (!identity_equal(&b.identity, &service.identity)) {
                    snprintf(err, sizeof(err), "SERVICE OMITTED + COHERENCE UNKNOWN; metadata differs"); goto image_failed;
                }
                snprintf(o->key_fingerprint, sizeof(o->key_fingerprint), "%s", service.key_fingerprint);
                snprintf(o->diagnostic_sha256, sizeof(o->diagnostic_sha256), "%s", service.closed_diagnostic_sha256);
                o->sfo_check = o->key_check = o->geometry_check = o->unmount_check = o->coherence_check = RAW_SELECTED_CHECK_PASS;
                snprintf(image->omitted_service_result, sizeof(image->omitted_service_result), "SERVICE OMITTED + COHERENCE DEMONSTRATED");
            }
        }
        snprintf(image->result, sizeof(image->result), "ready");
        if (e->role == RAW_SELECTED_ROLE_ACTIVE) ++r->ready_active_slots; else ++r->ready_service_images;
        continue;
image_failed:
        snprintf(image->detail, sizeof(image->detail), "%s", err); goto done;
    }
    {
        char fresh_uid[16], fresh_root[512];
        if (!watcher_raw_selected_target_held(req->target_uid, req->title_id, fresh_uid, sizeof(fresh_uid),
            fresh_root, sizeof(fresh_root), err, sizeof(err))) goto done;
        if (strcmp(fresh_uid, p->target_uid) || strcmp(fresh_root, p->target_root)) {
            snprintf(err, sizeof(err), "Fresh local UID/root changed before approval"); goto done;
        }
    }
    {
        size_t failed_index = SIZE_MAX; raw_selected_row_t failed_row;
        if (!raw_selected_approval_create_diagnostic(p, &approval, &failed_index, &failed_row, err, sizeof(err))) {
            if (failed_index < r->image_count) {
                r->ready_active_slots = r->ready_service_images = 0;
                for (size_t i = 0; i < r->image_count; i++) {
                    raw_selected_preflight_image_report_t* image = &r->images[i];
                    if (i < failed_index) {
                        if (image->role == RAW_SELECTED_ROLE_ACTIVE) ++r->ready_active_slots; else ++r->ready_service_images;
                    } else {
                        snprintf(image->result, sizeof(image->result), "%s", i == failed_index ? "BLOCKED" : "NOT_CHECKED");
                        if (i == failed_index) { image->row = failed_row; snprintf(image->detail, sizeof(image->detail), "%s", err); }
                        else snprintf(image->detail, sizeof(image->detail), "Final exact-row revalidation NOT_CHECKED after first failure");
                    }
                }
            }
            goto done;
        }
    }
    snprintf(p->receipt, sizeof(p->receipt), "%s", approval.receipt);
    if (!save_approval(r->work, p, &approval, record_sha, err, sizeof(err))) goto done;
    r->approval_durable = true; r->target_check = RAW_SELECTED_CHECK_PASS;
done:
    if (r->barrier_armed && !uncertain) {
        if (watcher_raw_selected_barrier_held(false, r->work, err, sizeof(err))) r->barrier_cleared = true;
        else uncertain = true;
    }
    if (uncertain) { r->barrier_retained = true; r->recovery_required = true;
        snprintf(r->result, sizeof(r->result), "RECOVERY_REQUIRED"); }
    if (r->approval_durable && !uncertain && r->barrier_cleared &&
        write_new(r->work, "approval.finalized", record_sha, 64, err, sizeof(err))) {
        r->ready = true; snprintf(r->result, sizeof(r->result), "READY");
        snprintf(r->selection_receipt, sizeof(r->selection_receipt), "%s", approval.receipt);
        snprintf(r->plan_sha256, sizeof(r->plan_sha256), "%s", approval.plan_sha256);
    }
    if (!r->ready) snprintf(r->detail, sizeof(r->detail), "%s", err[0] ? err : "Required preflight evidence unavailable");
    r->commit_reachable = r->ready; // Dedicated endpoint only; this operation never writes.
    if (r->work[0]) {
        char evidence_err[256] = {0};
        if (!write_new(r->work, "result.bin", r, sizeof(*r), evidence_err, sizeof(evidence_err)) && r->ready) {
            r->ready = false; snprintf(r->result, sizeof(r->result), "BLOCKED");
            r->commit_reachable = false;
            snprintf(r->detail, sizeof(r->detail), "%s", evidence_err);
        }
    }
    free(p); watcher_target_check_end();
}
