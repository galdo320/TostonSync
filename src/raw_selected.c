#include "raw_selected.h"
#include "pfs_attributes.h"
#include "sdimg_restore.h"
#include "sha256.h"
#include "zip.h"

#include <errno.h>
#include <ctype.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdatomic.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static bool fail(char* err, size_t n, const char* detail) {
    if (err && n) snprintf(err, n, "%s", detail);
    return false;
}
static bool bounded(const char* s, size_t n) { return s && memchr(s, 0, n); }
static bool hex64(const char* s) {
    if (!bounded(s, 65) || strlen(s) != 64) return false;
    for (size_t i = 0; i < 64; i++)
        if (!strchr("0123456789abcdef", s[i])) return false;
    return true;
}
static bool component(const char* s, size_t cap) {
    if (!bounded(s, cap) || !*s || !strcmp(s, ".") || !strcmp(s, "..")) return false;
    for (const unsigned char* p = (const unsigned char*)s; *p; p++)
        if (*p < 32 || *p == 127 || *p == '/' || *p == '\\' || *p == '"') return false;
    return true;
}
static bool title_ok(const char* s) {
    if (!bounded(s, 16) || strlen(s) != 9 || strncmp(s, "PPSA", 4)) return false;
    return strspn(s + 4, "0123456789") == 5;
}
static bool uid_ok(const char* s) {
    return bounded(s, 16) && *s && strlen(s) <= 8 &&
           strspn(s, "0123456789abcdef") == strlen(s);
}
static bool path_ok(const char* path) {
    if (!bounded(path, RAW_SELECTED_PATH_MAX) || path[0] != '/' || !path[1]) return false;
    const char* p = path + 1;
    while (*p) {
        const char* end = strchr(p, '/');
        size_t n = end ? (size_t)(end - p) : strlen(p);
        if (!n || n >= RAW_SELECTED_PATH_MAX || (n == 1 && *p == '.') ||
            (n == 2 && p[0] == '.' && p[1] == '.')) return false;
        for (size_t i = 0; i < n; i++)
            if ((unsigned char)p[i] < 32 || (unsigned char)p[i] == 127 || p[i] == '\\') return false;
        if (!end) return true;
        p = end + 1;
        if (!*p) return false;
    }
    return false;
}
static bool target_root_matches(const raw_selected_plan_t* p) {
    char suffix[96];
    int len = snprintf(suffix, sizeof(suffix), "/user/home/%s/savedata_prospero/%s",
                       p->target_uid, p->title_id);
    size_t root_len = strlen(p->target_root);
    return len > 0 && (size_t)len < sizeof(suffix) && root_len >= (size_t)len &&
           !strcmp(p->target_root + root_len - (size_t)len, suffix);
}
// Check every ancestor, not only the leaf. A missing leaf is allowed solely
// for an exclusive new diagnostic/preimage, never for a live destination.
static bool no_alias(const char* path, bool missing_leaf) {
    if (!path_ok(path)) return false;
    char part[RAW_SELECTED_PATH_MAX]; snprintf(part, sizeof(part), "%s", path);
    for (char* p = part + 1;; p++) {
        if (*p && *p != '/') continue;
        char saved = *p; *p = 0;
        struct stat st; int rc = lstat(part, &st); int e = errno;
        *p = saved;
        if (rc) return !saved && missing_leaf && e == ENOENT;
        if (S_ISLNK(st.st_mode) || (saved && !S_ISDIR(st.st_mode))) return false;
        if (!saved) return true;
    }
}
static const char* basename_of(const char* path) { return strrchr(path, '/') + 1; }
static bool selection_ok(const restore_selection_t* s, bool empty) {
    if (!s->specified || s->count > RESTORE_SELECTION_MAX || (!empty && !s->count)) return false;
    for (size_t i = 0; i < s->count; i++)
        if (!component(s->slots[i], 64) || !strncmp(s->slots[i], "sce_bu_", 7) ||
            !strncmp(s->slots[i], "sdimg_", 6) ||
            (i && strcmp(s->slots[i - 1], s->slots[i]) >= 0)) return false;
    return true;
}
static bool contains(const restore_selection_t* s, const char* slot) {
    for (size_t i = 0; i < s->count; i++) if (!strcmp(s->slots[i], slot)) return true;
    return false;
}
const char* raw_selected_mode_name(raw_selected_mode_t mode) {
    switch (mode) {
        case RAW_SELECTED_MODE_RAW_EXACT: return "raw_selected_exact";
        case RAW_SELECTED_MODE_PORTABLE_SELECTED: return "portable_selected";
        case RAW_SELECTED_MODE_RAW_COMPLETE: return "raw_complete";
        default: return "UNKNOWN";
    }
}
bool raw_selected_publication_allowed(void) { return RAW_SELECTED_PUBLICATION_ENABLED; }

static void normalized_stat(const struct stat* s, raw_selected_stat_t* out) {
    memset(out, 0, sizeof(*out));
    out->dev = (uint64_t)s->st_dev; out->ino = (uint64_t)s->st_ino;
    out->size = (uint64_t)s->st_size; out->mode = (uint64_t)s->st_mode;
    out->uid = (uint64_t)s->st_uid; out->gid = (uint64_t)s->st_gid;
    out->nlink = (uint64_t)s->st_nlink;
#ifdef __APPLE__
    out->mtime = s->st_mtimespec.tv_sec; out->mtime_nsec = s->st_mtimespec.tv_nsec;
    out->ctime = s->st_ctimespec.tv_sec; out->ctime_nsec = s->st_ctimespec.tv_nsec;
#else
    out->mtime = s->st_mtim.tv_sec; out->mtime_nsec = s->st_mtim.tv_nsec;
    out->ctime = s->st_ctim.tv_sec; out->ctime_nsec = s->st_ctim.tv_nsec;
#endif
#if defined(__APPLE__) || defined(__FreeBSD__)
    out->flags = (uint64_t)s->st_flags;
#endif
}
static bool same_stat(const raw_selected_stat_t* a, const raw_selected_stat_t* b) {
    return a->dev == b->dev && a->ino == b->ino && a->size == b->size &&
           a->mode == b->mode && a->uid == b->uid && a->gid == b->gid &&
           a->nlink == b->nlink && a->mtime == b->mtime && a->mtime_nsec == b->mtime_nsec &&
           a->ctime == b->ctime && a->ctime_nsec == b->ctime_nsec && a->flags == b->flags;
}
static bool stat_regular(const raw_selected_stat_t* s) {
    return S_ISREG((mode_t)s->mode) && s->nlink == 1 && s->ino &&
           s->mtime_nsec >= 0 && s->mtime_nsec < 1000000000 &&
           s->ctime_nsec >= 0 && s->ctime_nsec < 1000000000;
}
static void finish_digest(sha256_ctx_t* ctx, char out[65]) {
    unsigned char bytes[32]; sha256_final(ctx, bytes);
    for (size_t i = 0; i < 32; i++) snprintf(out + 2 * i, 3, "%02x", bytes[i]);
}
bool raw_selected_file_observe(const char* path, raw_selected_stat_t* out,
    char sha[65], char* err, size_t err_sz) {
    if (sha) sha[0] = 0;
    if (!out || !sha || !no_alias(path, false)) return fail(err, err_sz, "File path is missing, aliased or unsafe");
    struct stat a, b, c, d; raw_selected_stat_t sa, sb, sc, sd;
    if (lstat(path, &a) || !S_ISREG(a.st_mode) || a.st_size < 0 || a.st_nlink != 1)
        return fail(err, err_sz, "File is not an existing unaliased regular file");
    int fd = open(path, O_RDONLY | O_NOFOLLOW | O_NONBLOCK);
    if (fd < 0) return fail(err, err_sz, "No-follow source open failed");
    bool ok = !fstat(fd, &b);
    normalized_stat(&a, &sa);
    if (ok) { normalized_stat(&b, &sb); ok = same_stat(&sa, &sb); }
    sha256_ctx_t ctx; sha256_init(&ctx); unsigned char buf[32768]; uint64_t size = 0;
    while (ok) {
        ssize_t n = read(fd, buf, sizeof(buf));
        if (n < 0) { if (errno == EINTR) continue; ok = false; break; }
        if (!n) break;
        sha256_update(&ctx, buf, (size_t)n); size += (uint64_t)n;
    }
    if (ok) ok = !fstat(fd, &c);
    if (close(fd)) ok = false;
    if (ok) ok = no_alias(path, false) && !lstat(path, &d);
    if (ok) {
        normalized_stat(&c, &sc); normalized_stat(&d, &sd);
        ok = same_stat(&sa, &sc) && same_stat(&sa, &sd) && size == sa.size;
    }
    if (!ok) return fail(err, err_sz, "File changed or could not be hashed stably");
    finish_digest(&ctx, sha); *out = sa; return true;
}
bool raw_selected_copy_private(const char* source, const char* diagnostic,
    const char* expected, char* err, size_t err_sz) {
    raw_selected_stat_t before, after, copy; char sha[65];
    if (!hex64(expected) || !path_ok(source) || !path_ok(diagnostic) ||
        !strcmp(source, diagnostic) || !no_alias(diagnostic, true) ||
        !raw_selected_file_observe(source, &before, sha, err, err_sz) || strcmp(sha, expected))
        return fail(err, err_sz, "Private-copy source/path/hash is not verified");
    pfs_attribute_image_t image = {0};
    if (strlen(source) >= sizeof(image.source) || strlen(diagnostic) >= sizeof(image.copy))
        return fail(err, err_sz, "Private-copy path exceeds existing acquisition helper limit");
    snprintf(image.source, sizeof(image.source), "%s", source);
    snprintf(image.copy, sizeof(image.copy), "%s", diagnostic);
    bool ok = pfs_attributes_copy_private(&image) && !strcmp(image.sha256, expected);
    if (ok) ok = raw_selected_file_observe(source, &after, sha, err, err_sz) &&
                 same_stat(&before, &after) && !strcmp(sha, expected);
    if (ok) ok = raw_selected_file_observe(diagnostic, &copy, sha, err, err_sz) &&
                 copy.size == before.size && !strcmp(sha, expected) &&
                 !(copy.dev == before.dev && copy.ino == before.ino);
    // Failed new copies are retained as evidence; never remove or overwrite a
    // canonical source, an existing diagnostic or another operation's files.
    return ok || fail(err, err_sz, "Private copy failed; source retained, new artifact is evidence");
}

bool raw_selected_read_exact_row(const char* uid, const char* title, const char* slot,
    raw_selected_row_t* out, char* err, size_t err_sz) {
    if (!out) return fail(err, err_sz, "Exact row output is required");
    memset(out, 0, sizeof(*out));
    if (!uid_ok(uid) || !title_ok(title) || !component(slot, 64))
        return fail(err, err_sz, "Invalid exact local row identity");
    sdimg_target_slot_report_t r; uint64_t account = 0; uint32_t user = 0;
    memset(&r, 0, sizeof(r));
    bool ok = sdimg_diagnostic_target_owner(uid, title, slot, &account, &user, &r);
    out->rowid = r.registry_rowid; out->sqlite_code = r.sqlite_code;
    out->sqlite_extended_code = r.sqlite_extended_code;
    if (!strcmp(r.registry_status, "SQLITE_ERROR") || r.sqlite_code || r.sqlite_extended_code)
        out->status = RAW_SELECTED_ROW_SQLITE_ERROR;
    else if (!strcmp(r.registry_status, "ROW_ABSENT")) out->status = RAW_SELECTED_ROW_ABSENT;
    else if (!strcmp(r.registry_status, "ROW_FOUND")) out->status = RAW_SELECTED_ROW_FOUND;
    out->owner_verified = ok && out->status == RAW_SELECTED_ROW_FOUND && user > 0;
    if (out->owner_verified) { out->account_id = account; out->user_id = user; }
    if (out->status == RAW_SELECTED_ROW_SQLITE_ERROR) {
        if (err && err_sz) snprintf(err, err_sz, "Slot %.63s: SQLITE_ERROR; SQLite %d extended=%d %.80s",
            slot, out->sqlite_code, out->sqlite_extended_code,
            r.sqlite_message[0] ? r.sqlite_message : r.detail[0] ? r.detail : "Exact local row error");
        return false;
    }
    return out->owner_verified || fail(err, err_sz, r.detail[0] ? r.detail : "Exact local row is not verified");
}

static bool strings_bounded(const raw_selected_plan_t* p) {
    if (!p || p->count > RAW_SELECTED_MAX_IMAGES || p->active.count > RESTORE_SELECTION_MAX ||
        p->services.count > RESTORE_SELECTION_MAX || !bounded(p->import_id, 48) ||
        !bounded(p->zip_sha256, 65) || !bounded(p->target_uid, 16) || !bounded(p->title_id, 16) ||
        !bounded(p->zip_path, RAW_SELECTED_PATH_MAX) || !bounded(p->target_root, RAW_SELECTED_PATH_MAX) ||
        !bounded(p->receipt, 65) || !bounded(p->producer_version, 32) ||
        !bounded(p->manifest_sha256, 65) || !bounded(p->checksums_sha256, 65)) return false;
    const migration_report_t* r = &p->archive_report;
    if (r->save_dir_count > MIGRATION_MAX_SLOTS || r->selected_slots_count > MIGRATION_MAX_SLOTS ||
        r->service_dir_count > MIGRATION_MAX_SLOTS || r->included_image_count > RAW_SELECTED_MAX_IMAGES ||
        !bounded(r->title_id, 16) || !bounded(r->source_user_uid, 32) || !bounded(r->backup_scope, 32) ||
        !bounded(r->restore_strategy, 16) || !bounded(r->reason, 192)) return false;
    for (size_t i = 0; i < p->active.count; i++) if (!bounded(p->active.slots[i], 64)) return false;
    for (size_t i = 0; i < p->services.count; i++) if (!bounded(p->services.slots[i], 64)) return false;
    for (size_t i = 0; i < r->save_dir_count; i++) if (!bounded(r->save_dirs[i], 64)) return false;
    for (size_t i = 0; i < r->selected_slots_count; i++) if (!bounded(r->selected_slots[i], 64)) return false;
    for (size_t i = 0; i < r->service_dir_count; i++) if (!bounded(r->service_dirs[i], 64)) return false;
    for (size_t i = 0; i < r->included_image_count; i++) if (!bounded(r->included_images[i], 128)) return false;
    for (size_t i = 0; i < p->count; i++) {
        const raw_selected_entry_t* e = &p->entries[i];
        if (!bounded(e->slot, 64) || !bounded(e->image_name, 128) ||
            !bounded(e->source, RAW_SELECTED_PATH_MAX) || !bounded(e->diagnostic, RAW_SELECTED_PATH_MAX) ||
            !bounded(e->target, RAW_SELECTED_PATH_MAX) || !bounded(e->preimage, RAW_SELECTED_PATH_MAX) ||
            !bounded(e->source_sha256, 65) || !bounded(e->diagnostic_sha256, 65) || !bounded(e->pre_sha256, 65) ||
            !bounded(e->source_key_fingerprint, 65) || !bounded(e->target_key_fingerprint, 65) ||
            !bounded(e->source_identity.title_id, 16) || !bounded(e->source_identity.slot, 64) ||
            !bounded(e->source_identity.game_title_id, 16) || !bounded(e->source_identity.format, 8) ||
            !bounded(e->source_identity.sfo_sha256, 65) || !bounded(e->source_identity.hmac_sha256, 65) ||
            !bounded(e->target_identity.title_id, 16) || !bounded(e->target_identity.slot, 64) ||
            !bounded(e->target_identity.game_title_id, 16) || !bounded(e->target_identity.format, 8) ||
            !bounded(e->target_identity.sfo_sha256, 65) || !bounded(e->target_identity.hmac_sha256, 65) ||
            !bounded(e->omitted_service.path, RAW_SELECTED_PATH_MAX) ||
            !bounded(e->omitted_service.diagnostic, RAW_SELECTED_PATH_MAX) ||
            !bounded(e->omitted_service.sha256, 65) || !bounded(e->omitted_service.diagnostic_sha256, 65) ||
            !bounded(e->omitted_service.key_fingerprint, 65) ||
            !bounded(e->omitted_service.identity.title_id, 16) || !bounded(e->omitted_service.identity.slot, 64) ||
            !bounded(e->omitted_service.identity.game_title_id, 16) || !bounded(e->omitted_service.identity.format, 8) ||
            !bounded(e->omitted_service.identity.sfo_sha256, 65) ||
            !bounded(e->omitted_service.identity.hmac_sha256, 65)) return false;
    }
    return true;
}
static bool report_has_image(const migration_report_t* r, const char* name) {
    size_t found = 0;
    for (size_t i = 0; i < r->included_image_count; i++) if (!strcmp(name, r->included_images[i])) found++;
    return found == 1;
}
static bool report_has_slot(const char slots[][64], size_t count, const char* name) {
    size_t found = 0;
    for (size_t i = 0; i < count; i++) if (!strcmp(name, slots[i])) found++;
    return found == 1;
}
static bool identity_matches(const raw_selected_identity_t* id, const raw_selected_entry_t* e,
                             const raw_selected_plan_t* p) {
    return !strcmp(id->title_id, p->title_id) && !strcmp(id->slot, e->slot) &&
           id->account_id == e->row.account_id && id->user_id == e->row.user_id && id->hmac_present &&
           id->metadata_complete && title_ok(id->game_title_id) && !strcmp(id->format, "ppr") &&
           id->blocks > 0 && hex64(id->sfo_sha256) && hex64(id->hmac_sha256);
}
static bool geometry_identity_matches(const raw_selected_identity_t* a, const raw_selected_identity_t* b) {
    return !strcmp(a->game_title_id, b->game_title_id) && !strcmp(a->format, b->format) &&
           a->user_param == b->user_param && a->blocks == b->blocks && a->system_blocks == b->system_blocks;
}
static bool source_input_valid(const raw_selected_plan_t* p, char* err, size_t n) {
    if (!strings_bounded(p) || p->mode != RAW_SELECTED_MODE_RAW_EXACT ||
        !component(p->import_id, 48) || !hex64(p->zip_sha256) || !title_ok(p->title_id) ||
        !path_ok(p->zip_path) || !selection_ok(&p->active, false) || !selection_ok(&p->services, true))
        return fail(err, n, "Exact source mode, retained ZIP/hash/title and both literal selections required");
    for (size_t i = 0; i < p->services.count; i++)
        if (!contains(&p->active, p->services.slots[i])) return fail(err, n, "Source service is outside explicit active selection");
    return true;
}
static bool source_report_valid(const raw_selected_plan_t* p, char* err, size_t n) {
    const migration_report_t* r = &p->archive_report;
    if (!r->valid || !r->has_manifest || !r->has_checksums || !r->selected_containers ||
        r->format != MIGRATION_FORMAT_ENCRYPTED_IMAGE || r->needs_kernel || r->strategy_ready ||
        strcmp(r->restore_strategy, "blocked") || strcmp(r->backup_scope, "selected_containers") ||
        strcmp(r->title_id, p->title_id) || r->reason[0] || r->payload_files ||
        r->available_slots != p->available_slots || r->active_images != p->active_count ||
        r->service_images != p->service_count || r->service_dir_count != p->service_count ||
        r->save_dir_count != p->active_count || r->selected_slots_count != p->active_count ||
        r->included_image_count != p->count || p->active_count != p->active.count ||
        p->service_count != p->services.count || p->count != p->active_count + p->service_count ||
        p->available_slots < p->active_count || p->available_slots > RESTORE_SELECTION_MAX)
        return fail(err, n, "Checksummed partial RAW source inventory does not match literal selection");
    for (size_t i = 0; i < p->count; i++) {
        bool service = i >= p->active_count;
        const char* slot = service ? p->services.slots[i - p->active_count] : p->active.slots[i];
        char image[128]; snprintf(image, sizeof(image), "sdimg_%s%s", service ? "sce_bu_" : "", slot);
        if (!report_has_image(r, image) || (service ? !report_has_slot(r->service_dirs, r->service_dir_count, slot) :
            (!report_has_slot(r->save_dirs, r->save_dir_count, slot) ||
             !report_has_slot(r->selected_slots, r->selected_slots_count, slot))))
            return fail(err, n, "Source literal active/service image is not declared exactly once");
    }
    return true;
}
static bool semantic_validate(const raw_selected_plan_t* p, char* err, size_t n) {
    if (!source_input_valid(p, err, n) || !source_report_valid(p, err, n)) return false;
    if (!uid_ok(p->target_uid) || !path_ok(p->target_root) || !target_root_matches(p) ||
        !stat_regular(&p->zip_stat) || p->contract_version != RAW_SELECTED_CONTRACT_VERSION ||
        p->format_version != 1 || !p->partial || p->complete_recovery ||
        !component(p->producer_version, 32) || !hex64(p->manifest_sha256) || !hex64(p->checksums_sha256) ||
        p->fresh_target_check != RAW_SELECTED_CHECK_PASS)
        return fail(err, n, "Explicit RAW mode, local target and literal selections required");
    for (size_t i = 0; i < p->count; i++) {
        const raw_selected_entry_t* e = &p->entries[i];
        bool service = i >= p->active_count;
        const char* slot = service ? p->services.slots[i - p->active_count] : p->active.slots[i];
        char image[128], target[RAW_SELECTED_PATH_MAX];
        snprintf(image, sizeof(image), "sdimg_%s%s", service ? "sce_bu_" : "", slot);
        int len = snprintf(target, sizeof(target), "%s/%s", p->target_root, image);
        if (e->role != (service ? RAW_SELECTED_ROLE_SERVICE : RAW_SELECTED_ROLE_ACTIVE) ||
            strcmp(e->slot, slot) || strcmp(e->image_name, image) || len < 0 || (size_t)len >= sizeof(target) ||
            strcmp(e->target, target) || !path_ok(e->source) || !path_ok(e->diagnostic) ||
            !path_ok(e->target) || !path_ok(e->preimage) ||
            strcmp(basename_of(e->source), image) || strcmp(basename_of(e->diagnostic), image) ||
            strcmp(basename_of(e->preimage), image) || !strcmp(e->source, e->diagnostic) ||
            !strcmp(e->source, e->target) || !strcmp(e->diagnostic, e->target) ||
            !strcmp(e->preimage, e->target) || !strcmp(e->preimage, e->source) || !strcmp(e->preimage, e->diagnostic) ||
            !hex64(e->source_sha256) || !hex64(e->diagnostic_sha256) || !hex64(e->pre_sha256) ||
            !stat_regular(&e->source_stat) || !stat_regular(&e->target_stat) || e->size != e->source_stat.size ||
            e->size != e->target_stat.size ||
            (e->source_stat.dev == e->target_stat.dev && e->source_stat.ino == e->target_stat.ino))
            return fail(err, n, "Image role, source inventory, existing destination or canonical path differs");
        if (e->source_hash_check != RAW_SELECTED_CHECK_PASS || e->source_sfo_check != RAW_SELECTED_CHECK_PASS ||
            e->target_sfo_check != RAW_SELECTED_CHECK_PASS || e->source_key_check != RAW_SELECTED_CHECK_PASS ||
            e->target_key_check != RAW_SELECTED_CHECK_PASS || e->source_unmount_check != RAW_SELECTED_CHECK_PASS ||
            e->target_unmount_check != RAW_SELECTED_CHECK_PASS || e->geometry_check != RAW_SELECTED_CHECK_PASS ||
            !hex64(e->source_key_fingerprint) || !hex64(e->target_key_fingerprint) ||
            strcmp(e->source_key_fingerprint, e->target_key_fingerprint))
            return fail(err, n, "Source/private diagnostic identity, own sealed key or unmount is UNKNOWN/failed");
        if (e->row.status != RAW_SELECTED_ROW_FOUND || !e->row.owner_verified || e->row.rowid <= 0 ||
            e->row.sqlite_code || e->row.sqlite_extended_code || !e->row.user_id ||
            e->row.user_id != (uint32_t)strtoul(p->target_uid, NULL, 16) ||
            !identity_matches(&e->source_identity, e, p) || !identity_matches(&e->target_identity, e, p))
            return fail(err, n, "Exact local active row/owner/SFO proof is missing or inconsistent");
        if (!geometry_identity_matches(&e->source_identity, &e->target_identity) ||
            strcmp(e->source_identity.hmac_sha256, e->target_identity.hmac_sha256))
            return fail(err, n, "Full source/native destination identity or geometry differs");
        if (e->save_kind < RAW_SELECTED_SAVE_KIND_UNKNOWN || e->save_kind > RAW_SELECTED_SAVE_KIND_SYSTEM ||
            e->save_kind_reliable != (e->save_kind != RAW_SELECTED_SAVE_KIND_UNKNOWN))
            return fail(err, n, "Save kind must be reliable metadata or explicit UNKNOWN");
        const raw_selected_omitted_service_t* o = &e->omitted_service;
        if (service || contains(&p->services, slot)) {
            if (o->state != RAW_SELECTED_OMITTED_NOT_APPLICABLE)
                return fail(err, n, "Declared service must not acquire omitted-service authority");
        } else {
            char omitted[RAW_SELECTED_PATH_MAX];
            int olen = snprintf(omitted, sizeof(omitted), "%s/sdimg_sce_bu_%s", p->target_root, slot);
            if (olen < 0 || (size_t)olen >= sizeof(omitted) || strcmp(o->path, omitted) ||
                (o->state != RAW_SELECTED_OMITTED_ABSENT && o->state != RAW_SELECTED_OMITTED_PRESENT))
                return fail(err, n, "Omitted service presence/coherence is UNKNOWN");
            if (o->state == RAW_SELECTED_OMITTED_PRESENT &&
                (strcmp(e->source_sha256, e->pre_sha256) || !stat_regular(&o->stat) ||
                 o->stat.size != e->target_stat.size || !hex64(o->sha256) ||
                 !path_ok(o->diagnostic) || strcmp(basename_of(o->diagnostic), basename_of(o->path)) ||
                 !strcmp(o->path, o->diagnostic) ||
                 !hex64(o->diagnostic_sha256) || !hex64(o->key_fingerprint) ||
                 o->sfo_check != RAW_SELECTED_CHECK_PASS || o->key_check != RAW_SELECTED_CHECK_PASS ||
                 o->geometry_check != RAW_SELECTED_CHECK_PASS || o->unmount_check != RAW_SELECTED_CHECK_PASS ||
                 o->coherence_check != RAW_SELECTED_CHECK_PASS || !identity_matches(&o->identity, e, p) ||
                 !geometry_identity_matches(&o->identity, &e->target_identity)))
                return fail(err, n, "Omitted service no-change pair/private identity/key/geometry proof is UNKNOWN");
        }
        for (size_t j = 0; j < i; j++) {
            const raw_selected_entry_t* a = &p->entries[j];
            if (!strcmp(e->source, a->source) || !strcmp(e->diagnostic, a->diagnostic) ||
                !strcmp(e->target, a->target) || !strcmp(e->preimage, a->preimage) ||
                (e->target_stat.dev == a->target_stat.dev && e->target_stat.ino == a->target_stat.ino))
                return fail(err, n, "Duplicate source/target/preimage authority");
        }
    }
    return true;
}
// The normal inspector already validates this complete JSON object's syntax
// and duplicate top-level keys. Find only a literal top-level field, never a
// lookalike nested value through the loose OAuth JSON helper.
static const char* manifest_field(const char* json, const char* key) {
    unsigned depth = 0;
    for (const char* p = json; *p;) {
        if (*p == '{' || *p == '[') { depth++; p++; continue; }
        if (*p == '}' || *p == ']') { if (depth) depth--; p++; continue; }
        if (*p != '"') { p++; continue; }
        const char* start = ++p;
        while (*p && *p != '"') {
            if (*p == '\\' && !*++p) return NULL;
            p++;
        }
        if (!*p) return NULL;
        size_t len = (size_t)(p - start); p++;
        while (isspace((unsigned char)*p)) p++;
        if (depth == 1 && *p == ':' && strlen(key) == len && !memcmp(start, key, len)) {
            p++; while (isspace((unsigned char)*p)) p++;
            return p;
        }
    }
    return NULL;
}
static bool manifest_literal(const char* json, const char* key, const char* value) {
    const char* p = manifest_field(json, key); size_t len = strlen(value);
    return p && !strncmp(p, value, len) &&
           (p[len] == ',' || p[len] == '}' || isspace((unsigned char)p[len]));
}
static bool manifest_contract(const char* path, raw_selected_plan_t* p, char* err, size_t n) {
    char json[16384]; size_t used = 0;
    int fd = open(path, O_RDONLY | O_NOFOLLOW | O_NONBLOCK);
    if (fd < 0) return fail(err, n, "Strict source manifest open failed");
    bool ok = true;
    while (used < sizeof(json) - 1) {
        ssize_t got = read(fd, json + used, sizeof(json) - 1 - used);
        if (got < 0) { if (errno == EINTR) continue; ok = false; break; }
        if (!got) break;
        used += (size_t)got;
    }
    unsigned char extra;
    if (used == sizeof(json) - 1 && read(fd, &extra, 1) != 0) ok = false;
    if (close(fd)) ok = false;
    json[used] = 0;
    if (!ok || strlen(json) != used || !manifest_literal(json, "format_version", "1") ||
        !manifest_literal(json, "partial", "true") || !manifest_literal(json, "complete_recovery", "false"))
        return fail(err, n, "Source manifest requires literal format_version=1, partial=true, complete_recovery=false");
    const char* version = manifest_field(json, "tostonsync_version");
    if (!version || *version++ != '"') return fail(err, n, "Source producer version is UNKNOWN");
    const char* end = strchr(version, '"');
    if (!end || end == version || (size_t)(end - version) >= sizeof(p->producer_version))
        return fail(err, n, "Source producer version is missing or oversized");
    memcpy(p->producer_version, version, (size_t)(end - version));
    p->producer_version[end - version] = 0;
    if (!component(p->producer_version, sizeof(p->producer_version)))
        return fail(err, n, "Source producer version is non-literal");
    p->contract_version = RAW_SELECTED_CONTRACT_VERSION; p->format_version = 1;
    p->partial = true; p->complete_recovery = false;
    return true;
}
bool raw_selected_source_prepare(raw_selected_plan_t* p, const char* work, char* err, size_t n) {
    if (!source_input_valid(p, err, n) || !no_alias(work, true)) return false;
    p->receipt[0] = 0; // A new source phase cannot retain an earlier approval.
    raw_selected_stat_t before, private_before, after; char hash[65];
    if (!raw_selected_file_observe(p->zip_path, &before, hash, err, n) || strcmp(hash, p->zip_sha256))
        return fail(err, n, "Canonical source ZIP does not match expected SHA-256");
    if (mkdir(work, 0700)) return fail(err, n, "Source workspace must be new and exclusive");
    char zip[RAW_SELECTED_PATH_MAX], members[RAW_SELECTED_PATH_MAX], metadata[RAW_SELECTED_PATH_MAX];
    int zlen = snprintf(zip, sizeof(zip), "%s/archive.zip", work);
    int mlen = snprintf(members, sizeof(members), "%s/members", work);
    if (zlen < 0 || (size_t)zlen >= sizeof(zip) || mlen < 0 || (size_t)mlen >= sizeof(members) ||
        !raw_selected_copy_private(p->zip_path, zip, p->zip_sha256, err, n) ||
        !raw_selected_file_observe(zip, &private_before, hash, err, n) || strcmp(hash, p->zip_sha256)) return false;
    if (!migration_inspect_zip(zip, p->title_id, &p->archive_report))
        return fail(err, n, "Source ZIP CRC/checksums/declared inventory inspection failed");
    p->available_slots = p->archive_report.available_slots;
    p->active_count = p->active.count; p->service_count = p->services.count;
    p->count = p->active_count + p->service_count;
    if (!source_report_valid(p, err, n)) return false;
    if (mkdir(members, 0700) || !zip_extract_to_directory_checked(zip, members, err, n))
        return fail(err, n, "Canonical source-only extraction/CRC failed");
    int len = snprintf(metadata, sizeof(metadata), "%s/%s/manifest.json", members, p->title_id);
    if (len < 0 || (size_t)len >= sizeof(metadata) ||
        !raw_selected_file_observe(metadata, &after, p->manifest_sha256, err, n) ||
        !manifest_contract(metadata, p, err, n)) return false;
    len = snprintf(metadata, sizeof(metadata), "%s/%s/checksums.json", members, p->title_id);
    if (len < 0 || (size_t)len >= sizeof(metadata) ||
        !raw_selected_file_observe(metadata, &after, p->checksums_sha256, err, n)) return false;
    memset(p->entries, 0, sizeof(p->entries)); p->receipt[0] = 0;
    for (size_t i = 0; i < p->count; i++) {
        raw_selected_entry_t* e = &p->entries[i]; bool service = i >= p->active_count;
        const char* slot = service ? p->services.slots[i - p->active_count] : p->active.slots[i];
        e->role = service ? RAW_SELECTED_ROLE_SERVICE : RAW_SELECTED_ROLE_ACTIVE;
        snprintf(e->slot, sizeof(e->slot), "%s", slot);
        snprintf(e->image_name, sizeof(e->image_name), "sdimg_%s%s", service ? "sce_bu_" : "", slot);
        len = snprintf(e->source, sizeof(e->source), "%s/%s/%s", members, p->title_id, e->image_name);
        if (len < 0 || (size_t)len >= sizeof(e->source) ||
            !raw_selected_file_observe(e->source, &e->source_stat, e->source_sha256, err, n)) return false;
        e->size = e->source_stat.size; e->source_hash_check = RAW_SELECTED_CHECK_PASS;
    }
    if (!raw_selected_file_observe(zip, &after, hash, err, n) ||
        !same_stat(&private_before, &after) || strcmp(hash, p->zip_sha256) ||
        !raw_selected_file_observe(p->zip_path, &after, hash, err, n) ||
        !same_stat(&before, &after) || strcmp(hash, p->zip_sha256))
        return fail(err, n, "Canonical/private ZIP changed during source-only preparation");
    p->zip_stat = before;
    return true;
}
bool raw_selected_plan_validate(const raw_selected_plan_t* p, char* err, size_t n) {
    if (!source_input_valid(p, err, n)) return false;
    static atomic_uint sequence;
    char work[RAW_SELECTED_PATH_MAX];
    int len = snprintf(work, sizeof(work), "%s.raw-check-%ld-%u", p->zip_path,
                       (long)getpid(), atomic_fetch_add(&sequence, 1));
    if (len < 0 || (size_t)len >= sizeof(work)) return fail(err, n, "Archive evidence path exceeds limit");
    if (!raw_selected_verify_archive(p, work, err, n) || !semantic_validate(p, err, n)) return false;
    raw_selected_stat_t st; char sha[65];
    if (!raw_selected_file_observe(p->zip_path, &st, sha, err, n) ||
        !same_stat(&p->zip_stat, &st) || strcmp(sha, p->zip_sha256))
        return fail(err, n, "Canonical archive differs from inspected immutable ZIP");
    for (size_t i = 0; i < p->count; i++) {
        const raw_selected_entry_t* e = &p->entries[i]; raw_selected_stat_t diagnostic;
        if (!raw_selected_file_observe(e->source, &st, sha, err, n) ||
            !same_stat(&e->source_stat, &st) || strcmp(sha, e->source_sha256) ||
            !raw_selected_file_observe(e->diagnostic, &diagnostic, sha, err, n) ||
            diagnostic.size != e->size || strcmp(sha, e->diagnostic_sha256) ||
            (diagnostic.dev == st.dev && diagnostic.ino == st.ino) ||
            !raw_selected_file_observe(e->target, &st, sha, err, n) ||
            !same_stat(&e->target_stat, &st) || strcmp(sha, e->pre_sha256))
            return fail(err, n, "Canonical source, disposable diagnostic or approved target prestate changed");
        if (!no_alias(e->preimage, true)) return fail(err, n, "Preimage path is unsafe or aliased");
        struct stat present;
        if (!lstat(e->preimage, &present)) {
            if (!raw_selected_file_observe(e->preimage, &st, sha, err, n) ||
                st.size != e->target_stat.size || strcmp(sha, e->pre_sha256) ||
                (st.dev == e->target_stat.dev && st.ino == e->target_stat.ino) ||
                (st.dev == e->source_stat.dev && st.ino == e->source_stat.ino))
                return fail(err, n, "Existing preimage is not an independent approved copy");
        } else if (errno != ENOENT) return fail(err, n, "Preimage existence is UNKNOWN");
        const raw_selected_omitted_service_t* o = &e->omitted_service;
        if (o->state == RAW_SELECTED_OMITTED_ABSENT) {
            if (!no_alias(o->path, true) || !lstat(o->path, &present) || errno != ENOENT)
                return fail(err, n, "Omitted service absence changed or is UNKNOWN");
        } else if (o->state == RAW_SELECTED_OMITTED_PRESENT) {
            if (!raw_selected_file_observe(o->path, &st, sha, err, n) ||
                !same_stat(&st, &o->stat) || strcmp(sha, o->sha256) ||
                !raw_selected_file_observe(o->diagnostic, &diagnostic, sha, err, n) ||
                diagnostic.size != o->stat.size || strcmp(sha, o->diagnostic_sha256) ||
                (diagnostic.dev == st.dev && diagnostic.ino == st.ino))
                return fail(err, n, "Omitted service fresh prestate/private proof changed");
        }
    }
    return true;
}

bool raw_selected_verify_archive(const raw_selected_plan_t* p, const char* work,
    char* err, size_t n) {
    if (!source_input_valid(p, err, n)) return false;
    raw_selected_plan_t* actual = malloc(sizeof(*actual));
    raw_selected_plan_t* checked = malloc(sizeof(*checked));
    if (!actual || !checked) {
        free(actual); free(checked); return fail(err, n, "Cannot allocate bounded source contract");
    }
    *actual = *p;
    bool ok = raw_selected_source_prepare(actual, work, err, n);
    if (!ok) { free(actual); free(checked); return false; }
    *checked = *p;
    checked->archive_report = actual->archive_report; checked->zip_stat = actual->zip_stat;
    checked->contract_version = actual->contract_version; checked->format_version = actual->format_version;
    checked->partial = actual->partial; checked->complete_recovery = actual->complete_recovery;
    snprintf(checked->producer_version, sizeof(checked->producer_version), "%s", actual->producer_version);
    snprintf(checked->manifest_sha256, sizeof(checked->manifest_sha256), "%s", actual->manifest_sha256);
    snprintf(checked->checksums_sha256, sizeof(checked->checksums_sha256), "%s", actual->checksums_sha256);
    checked->available_slots = actual->available_slots; checked->active_count = actual->active_count;
    checked->service_count = actual->service_count; checked->count = actual->count;
    // No destination evidence is required/read here. Actual source metadata,
    // including exact manifest/checksums bytes, must match the stored contract.
    char supplied[65], inspected[65];
    ok = raw_selected_plan_digest(p, supplied) &&
         raw_selected_plan_digest(checked, inspected) && !strcmp(supplied, inspected);
    free(checked);
    for (size_t i = 0; ok && i < p->count; i++) {
        const raw_selected_entry_t* e = &p->entries[i]; const raw_selected_entry_t* a = &actual->entries[i];
        raw_selected_stat_t st; char hash[65];
        ok = e->role == a->role && !strcmp(e->slot, a->slot) && !strcmp(e->image_name, a->image_name) &&
             path_ok(e->source) && !strcmp(basename_of(e->source), a->image_name) &&
             e->size == a->size && !strcmp(e->source_sha256, a->source_sha256) &&
             raw_selected_file_observe(e->source, &st, hash, err, n) &&
             same_stat(&st, &e->source_stat) && !strcmp(hash, a->source_sha256);
    }
    free(actual);
    return ok || fail(err, n, "Canonical images/manifest/checksums are not the actual inspected ZIP source");
}

static void number(sha256_ctx_t* ctx, uint64_t value) {
    unsigned char bytes[8];
    for (unsigned i = 0; i < 8; i++) bytes[i] = (unsigned char)(value >> (i * 8));
    sha256_update(ctx, bytes, sizeof(bytes));
}
static void text_field(sha256_ctx_t* ctx, const char* s) { number(ctx, strlen(s)); sha256_update(ctx, s, strlen(s)); }
static void digest_stat(sha256_ctx_t* ctx, const raw_selected_stat_t* s) {
    number(ctx, s->dev); number(ctx, s->ino); number(ctx, s->size); number(ctx, s->mode);
    number(ctx, s->uid); number(ctx, s->gid); number(ctx, s->nlink);
    number(ctx, (uint64_t)s->mtime); number(ctx, (uint64_t)s->mtime_nsec);
    number(ctx, (uint64_t)s->ctime); number(ctx, (uint64_t)s->ctime_nsec); number(ctx, s->flags);
}
static void digest_identity(sha256_ctx_t* ctx, const raw_selected_identity_t* id) {
    text_field(ctx, id->title_id); text_field(ctx, id->slot);
    text_field(ctx, id->game_title_id); text_field(ctx, id->format);
    number(ctx, id->account_id); number(ctx, id->user_id); number(ctx, id->user_param);
    number(ctx, id->blocks); number(ctx, id->system_blocks); number(ctx, id->metadata_complete);
    number(ctx, id->hmac_present); text_field(ctx, id->sfo_sha256); text_field(ctx, id->hmac_sha256);
}
bool raw_selected_plan_digest(const raw_selected_plan_t* p, char out[65]) {
    if (!out || !strings_bounded(p)) return false;
    sha256_ctx_t ctx; sha256_init(&ctx);
    text_field(&ctx, "TostonSync raw-selected immutable plan v2");
    text_field(&ctx, raw_selected_mode_name(p->mode)); text_field(&ctx, p->import_id);
    number(&ctx, p->contract_version); number(&ctx, p->format_version);
    number(&ctx, p->partial); number(&ctx, p->complete_recovery);
    text_field(&ctx, p->producer_version); text_field(&ctx, p->manifest_sha256); text_field(&ctx, p->checksums_sha256);
    text_field(&ctx, p->zip_path); text_field(&ctx, p->zip_sha256); digest_stat(&ctx, &p->zip_stat);
    text_field(&ctx, p->target_uid); text_field(&ctx, p->title_id); text_field(&ctx, p->target_root);
    number(&ctx, p->fresh_target_check); number(&ctx, p->available_slots);
    number(&ctx, p->active.specified); number(&ctx, p->active.count);
    for (size_t i = 0; i < p->active.count; i++) text_field(&ctx, p->active.slots[i]);
    number(&ctx, p->services.specified); number(&ctx, p->services.count);
    for (size_t i = 0; i < p->services.count; i++) text_field(&ctx, p->services.slots[i]);
    number(&ctx, p->active_count); number(&ctx, p->service_count); number(&ctx, p->count);
    const migration_report_t* r = &p->archive_report;
    number(&ctx, r->format); text_field(&ctx, r->title_id); text_field(&ctx, r->source_user_uid);
    text_field(&ctx, r->backup_scope); number(&ctx, r->valid); number(&ctx, r->has_manifest);
    number(&ctx, r->has_checksums); number(&ctx, r->selected_containers); number(&ctx, r->needs_kernel);
    number(&ctx, r->strategy_ready); text_field(&ctx, r->restore_strategy); text_field(&ctx, r->reason);
    number(&ctx, r->available_slots); number(&ctx, r->active_images); number(&ctx, r->service_images);
    number(&ctx, r->payload_files); number(&ctx, r->save_dir_count);
    for (size_t i = 0; i < r->save_dir_count; i++) text_field(&ctx, r->save_dirs[i]);
    number(&ctx, r->service_dir_count);
    for (size_t i = 0; i < r->service_dir_count; i++) text_field(&ctx, r->service_dirs[i]);
    number(&ctx, r->selected_slots_count);
    for (size_t i = 0; i < r->selected_slots_count; i++) text_field(&ctx, r->selected_slots[i]);
    number(&ctx, r->included_image_count);
    for (size_t i = 0; i < r->included_image_count; i++) text_field(&ctx, r->included_images[i]);
    for (size_t i = 0; i < p->count; i++) {
        const raw_selected_entry_t* e = &p->entries[i];
        number(&ctx, e->role); number(&ctx, e->save_kind); number(&ctx, e->save_kind_reliable);
        text_field(&ctx, e->slot); text_field(&ctx, e->image_name);
        text_field(&ctx, e->source); text_field(&ctx, e->diagnostic); text_field(&ctx, e->target);
        text_field(&ctx, e->preimage); text_field(&ctx, e->source_sha256);
        text_field(&ctx, e->diagnostic_sha256); text_field(&ctx, e->pre_sha256);
        number(&ctx, e->size); digest_stat(&ctx, &e->source_stat); digest_stat(&ctx, &e->target_stat);
        digest_identity(&ctx, &e->source_identity); digest_identity(&ctx, &e->target_identity);
        number(&ctx, e->row.status); number(&ctx, (uint64_t)e->row.rowid); number(&ctx, e->row.account_id);
        number(&ctx, e->row.user_id); number(&ctx, (uint64_t)e->row.sqlite_code);
        number(&ctx, (uint64_t)e->row.sqlite_extended_code); number(&ctx, e->row.owner_verified);
        number(&ctx, e->source_hash_check); number(&ctx, e->source_sfo_check); number(&ctx, e->target_sfo_check);
        number(&ctx, e->source_key_check); number(&ctx, e->target_key_check);
        number(&ctx, e->geometry_check);
        number(&ctx, e->source_unmount_check); number(&ctx, e->target_unmount_check);
        text_field(&ctx, e->source_key_fingerprint); text_field(&ctx, e->target_key_fingerprint);
        const raw_selected_omitted_service_t* o = &e->omitted_service;
        number(&ctx, o->state); text_field(&ctx, o->path); text_field(&ctx, o->diagnostic);
        text_field(&ctx, o->sha256); text_field(&ctx, o->diagnostic_sha256); text_field(&ctx, o->key_fingerprint);
        digest_stat(&ctx, &o->stat); digest_identity(&ctx, &o->identity);
        number(&ctx, o->sfo_check); number(&ctx, o->key_check); number(&ctx, o->geometry_check);
        number(&ctx, o->unmount_check); number(&ctx, o->coherence_check);
    }
    finish_digest(&ctx, out); return true;
}
static void approval_receipt(const char* plan_sha, char out[65]) {
    sha256_ctx_t ctx; sha256_init(&ctx);
    text_field(&ctx, "TostonSync raw_selected_exact server approval v2");
    text_field(&ctx, plan_sha); finish_digest(&ctx, out);
}
bool raw_selected_approval_create(const raw_selected_plan_t* p,
    raw_selected_approval_t* out, char* err, size_t n) {
    return raw_selected_approval_create_diagnostic(p, out, NULL, NULL, err, n);
}
bool raw_selected_approval_create_diagnostic(const raw_selected_plan_t* p,
    raw_selected_approval_t* out, size_t* failed_index, raw_selected_row_t* failed_row,
    char* err, size_t n) {
    if (failed_index) *failed_index = SIZE_MAX;
    if (failed_row) memset(failed_row, 0, sizeof(*failed_row));
    if (!out) return fail(err, n, "Approval output required");
    memset(out, 0, sizeof(*out));
    if (!raw_selected_plan_validate(p, err, n)) return false;
    for (size_t i = 0; i < p->count; i++) {
        raw_selected_row_t row;
        if (!raw_selected_read_exact_row(p->target_uid, p->title_id, p->entries[i].slot, &row, err, n)) {
            if (failed_index) *failed_index = i;
            if (failed_row) *failed_row = row;
            return false; // Preserve the exact reader's SQLite/absence/UNKNOWN detail.
        }
        if (row.rowid != p->entries[i].row.rowid || row.account_id != p->entries[i].row.account_id ||
            row.user_id != p->entries[i].row.user_id) {
            if (failed_index) *failed_index = i;
            if (failed_row) *failed_row = row;
            return fail(err, n, "Fresh exact local row differs from approved owner evidence");
        }
    }
    if (!raw_selected_plan_digest(p, out->plan_sha256)) return false;
    approval_receipt(out->plan_sha256, out->receipt); return true;
}
bool raw_selected_approval_matches(const raw_selected_plan_t* p,
    const raw_selected_approval_t* approval, char* err, size_t n) {
    char sha[65], receipt[65];
    if (!approval || !hex64(approval->plan_sha256) || !hex64(approval->receipt) ||
        !semantic_validate(p, err, n) || !raw_selected_plan_digest(p, sha))
        return fail(err, n, "Authoritative immutable RAW approval is unavailable");
    approval_receipt(sha, receipt);
    return (!strcmp(sha, approval->plan_sha256) && !strcmp(receipt, approval->receipt) &&
            !strcmp(p->receipt, approval->receipt)) || fail(err, n, "RAW selection/target prestate differs from server-held approval");
}
