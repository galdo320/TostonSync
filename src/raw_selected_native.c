#include "raw_selected_native.h"
#include "pfs_keys.h"
#include "savemount.h"
#include "sha256.h"
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static void wipe(void* bytes, size_t n) { volatile unsigned char* p = bytes; while (n--) *p++ = 0; }
static void digest(const void* bytes, size_t n, char out[65]) {
    sha256_ctx_t ctx; unsigned char hash[32]; sha256_init(&ctx);
    sha256_update(&ctx, bytes, n); sha256_final(&ctx, hash);
    for (size_t i = 0; i < sizeof(hash); i++) snprintf(out + i * 2, 3, "%02x", hash[i]);
}
static bool same_stat(const raw_selected_stat_t* a, const raw_selected_stat_t* b) {
    return a->dev == b->dev && a->ino == b->ino && a->size == b->size && a->mode == b->mode &&
        a->uid == b->uid && a->gid == b->gid && a->nlink == b->nlink && a->flags == b->flags &&
        a->mtime == b->mtime && a->mtime_nsec == b->mtime_nsec &&
        a->ctime == b->ctime && a->ctime_nsec == b->ctime_nsec;
}
static bool canonical_path(const char* path) {
    if (!path || path[0] != '/' || strlen(path) >= SAVEMOUNT_PATH_MAX) return false;
    char* resolved = realpath(path, NULL);
    bool ok = resolved && !strcmp(path, resolved); free(resolved); return ok;
}
static bool within(const char* path, const char* parent) {
    size_t n = strlen(parent); return !strncmp(path, parent, n) && path[n] == '/';
}
static bool observed(const char* path, const char* hash, const raw_selected_stat_t* expected,
                     raw_selected_stat_t* out) {
    raw_selected_stat_t st; char sha[65];
    bool ok = raw_selected_file_observe(path, &st, sha, NULL, 0) &&
        st.nlink == 1 && !strcmp(sha, hash) && (!expected || same_stat(&st, expected));
    if (ok && out) *out = st;
    return ok;
}
static void blocked(raw_selected_native_observation_t* out, const char* detail,
                    char* err, size_t n) {
    snprintf(out->detail, sizeof(out->detail), "%s", detail);
    if (err && n) snprintf(err, n, "%s", detail);
}
static uint16_t u16(const unsigned char* p) { return (uint16_t)(p[0] | p[1] << 8); }
static uint32_t u32(const unsigned char* p) {
    return (uint32_t)p[0] | (uint32_t)p[1] << 8 | (uint32_t)p[2] << 16 | (uint32_t)p[3] << 24;
}
static bool text_value(const unsigned char* p, size_t n, size_t cap) {
    const unsigned char* end = memchr(p, 0, n);
    return end && end != p && (size_t)(end - p) < cap;
}
// sfo_parse is reused for metadata. This small presence/type check prevents its
// zero/default fields from being mistaken for native evidence. Hash all SFO
// bytes, including unknown fields, without exporting or changing the tree.
static bool strict_sfo(const char* path, sfo_info_t* meta, char sha[65]) {
    raw_selected_stat_t before, after; char final_sha[65];
    if (!canonical_path(path) || !raw_selected_file_observe(path, &before, sha, NULL, 0) ||
        !before.size || before.size > 1024 * 1024 || before.nlink != 1) return false;
    unsigned char* b = malloc((size_t)before.size); if (!b) return false;
    int fd = open(path, O_RDONLY | O_NOFOLLOW); size_t got = 0;
    if (fd >= 0) while (got < before.size) {
        ssize_t n = read(fd, b + got, (size_t)before.size - got); if (n <= 0) break; got += (size_t)n;
    }
    bool ok = fd >= 0 && got == before.size;
    unsigned char extra; if (ok) ok = read(fd, &extra, 1) == 0;
    if (fd >= 0 && close(fd)) ok = false;
    enum { TITLE = 1, SLOT = 2, FORMAT = 4, ACCOUNT = 8, PARAMS = 16, BLOCKS = 32, SYSTEM = 64 };
    unsigned fields = 0; const unsigned char* params = NULL;
    uint32_t key = 0, data = 0, count = 0;
    if (ok) ok = got >= 20 && !memcmp(b, "\0PSF", 4);
    if (ok) {
        key = u32(b + 8); data = u32(b + 12); count = u32(b + 16);
        ok = count <= 4096 && 20u + (uint64_t)count * 16 <= got && key < data && data <= got;
    }
    for (uint32_t i = 0; ok && i < count; i++) {
        const unsigned char* idx = b + 20 + (size_t)i * 16;
        uint16_t format = u16(idx + 2); uint32_t len = u32(idx + 4), max = u32(idx + 8), off = u32(idx + 12);
        uint64_t k = (uint64_t)key + u16(idx), v = (uint64_t)data + off;
        if (k >= data || !memchr(b + k, 0, data - (size_t)k) || !len || len > max || v > got || max > got - v) {
            ok = false; break;
        }
        const char* name = (const char*)(b + k); const unsigned char* value = b + v;
        unsigned field = 0;
        if (!strcmp(name, "TITLE_ID")) field = TITLE;
        else if (!strcmp(name, "SAVEDATA_DIRECTORY")) field = SLOT;
        else if (!strcmp(name, "FORMAT")) field = FORMAT;
        else if (!strcmp(name, "ACCOUNT_ID")) field = ACCOUNT;
        else if (!strcmp(name, "PARAMS")) field = PARAMS;
        else if (!strcmp(name, "SAVEDATA_BLOCKS")) field = BLOCKS;
        else if (!strcmp(name, "SYSTEM_BLOCKS")) field = SYSTEM;
        if (!field) continue;
        if (fields & field) { ok = false; break; }
        if (field == TITLE || field == SLOT || field == FORMAT)
            // Existing PSF strings may put their NUL in max-size padding:
            // FORMAT has length 3 ("ppr") and maximum 4. Never require edits.
            ok = format == 0x0204 && text_value(value, max, field == SLOT ? 64 : field == FORMAT ? 8 : 16) &&
                strnlen((const char*)value, max) <= len;
        else if (field == ACCOUNT) ok = format == 0x0004 && len == 8;
        else if (field == BLOCKS || field == SYSTEM)
            ok = (format == 0x0004 && (len == 4 || len == 8)) || (format == 0x0404 && len == 4);
        else if (field == PARAMS) {
            ok = format == 0x0004 && len >= 0x58 && text_value(value + 0x2c, 12, 16) &&
                text_value(value + 0x38, 12, 16);
            if (ok) params = value;
        }
        fields |= field;
    }
    if (ok) ok = fields == 127 && sfo_parse(path, meta) == 0 && !meta->zeroed && meta->has_hmac &&
        !strcmp(meta->format, "ppr") && meta->blocks && params &&
        !strcmp(meta->title_id, (const char*)params + 0x2c) &&
        meta->user_param == u32(params) && meta->user_id == u32(params + 4);
    if (ok) snprintf(meta->game_title_id, sizeof(meta->game_title_id), "%s", params + 0x38);
    if (ok) ok = raw_selected_file_observe(path, &after, final_sha, NULL, 0) &&
        same_stat(&before, &after) && !strcmp(sha, final_sha);
    free(b); return ok;
}

void raw_selected_native_observe(const raw_selected_native_request_t* r,
    raw_selected_native_observation_t* out, char* err, size_t n) {
    if (!out) return;
    memset(out, 0, sizeof(*out)); out->status = RAW_SELECTED_NATIVE_BLOCKED;
    out->unmount_confirmed = true; // No kernel resource exists before a successful mount.
    if (err && n) *err = 0;
    raw_selected_stat_t canonical, private_before; char expected_name[128];
    if (!r || !r->canonical_stat || !r->expected_sha256 || strlen(r->expected_sha256) != 64 ||
        strspn(r->expected_sha256, "0123456789abcdef") != 64 || !r->expected_title || !r->expected_slot ||
        strlen(r->expected_title) != 9 || strncmp(r->expected_title, "PPSA", 4) ||
        strspn(r->expected_title + 4, "0123456789") != 5 || !*r->expected_slot ||
        strlen(r->expected_slot) >= 64 || strpbrk(r->expected_slot, "/\\") ||
        !strncmp(r->expected_slot, "sce_bu_", 7) || !strncmp(r->expected_slot, "sdimg_", 6) ||
        (r->role != RAW_SELECTED_ROLE_ACTIVE && r->role != RAW_SELECTED_ROLE_SERVICE) ||
        !canonical_path(r->canonical) || !canonical_path(r->private_workspace) ||
        !canonical_path(r->private_image) || !within(r->private_image, r->private_workspace) ||
        within(r->canonical, r->private_workspace) || !strcmp(r->canonical, r->private_image) ||
        strstr(r->private_workspace, "/savedata_prospero/") || strstr(r->private_workspace, "_sdimg_rollback") ||
        !observed(r->canonical, r->expected_sha256, r->canonical_stat, &canonical) ||
        !observed(r->private_image, r->expected_sha256, NULL, &private_before) ||
        (canonical.dev == private_before.dev && canonical.ino == private_before.ino)) {
        blocked(out, "Canonical/private image proof, role or owned workspace is unsafe", err, n); return;
    }
    int length = snprintf(expected_name, sizeof(expected_name), "%s%s", r->role == RAW_SELECTED_ROLE_SERVICE
        ? "sdimg_sce_bu_" : "sdimg_", r->expected_slot);
    const char* leaf = strrchr(r->canonical, '/');
    if (length <= 0 || length >= (int)sizeof(expected_name) || !leaf || strcmp(leaf + 1, expected_name)) {
        blocked(out, "Literal native image role/slot does not match canonical member", err, n); return;
    }
    out->role = r->role; out->image_size = canonical.size; out->canonical_unchanged = true;
    unsigned char sealed[PFS_SEALED_KEY_SIZE] = {0}, key[PFS_PLAIN_KEY_SIZE] = {0};
    if (!pfs_read_sealed_key(r->private_image, sealed) || !pfs_decrypt_save_key(r->private_image, key)) {
        wipe(sealed, sizeof(sealed)); wipe(key, sizeof(key));
        out->canonical_unchanged = observed(r->canonical, r->expected_sha256, r->canonical_stat, NULL);
        blocked(out, "Private image's own sealed key is unavailable", err, n); return;
    }
    digest(sealed, sizeof(sealed), out->key_fingerprint); wipe(sealed, sizeof(sealed));
    out->key_available = true;
    savemount_t mount = {0}; out->mount_attempted = true;
    bool mounted = observed(r->private_image, r->expected_sha256, &private_before, NULL) &&
        savemount_mount(r->private_image, key, &mount); wipe(key, sizeof(key));
    if (!mounted) {
        out->canonical_unchanged = observed(r->canonical, r->expected_sha256, r->canonical_stat, NULL);
        blocked(out, "Verified private diagnostic mount failed", err, n); return;
    }
    out->mounted = true; out->unmount_confirmed = false;
    char sfo[512]; int path_length = snprintf(sfo, sizeof(sfo), "%s/sce_sys/param.sfo", mount.mount_point);
    bool ok = !mount.writeback && !mount.image_origin[0] && path_length > 0 && path_length < (int)sizeof(sfo) &&
        strict_sfo(sfo, &out->metadata, out->identity.sfo_sha256);
    if (!savemount_unmount(&mount)) {
        out->status = RAW_SELECTED_NATIVE_UNMOUNT_UNCERTAIN;
        snprintf(out->retained_mount, sizeof(out->retained_mount), "%s", mount.mount_point);
        snprintf(out->retained_backing, sizeof(out->retained_backing), "%s",
            mount.image_backing[0] ? mount.image_backing : r->private_image);
        blocked(out, "Private unmount uncertain; retain barrier/evidence and stop native operations", err, n); return;
    }
    out->unmount_confirmed = true;
    out->canonical_unchanged = observed(r->canonical, r->expected_sha256, r->canonical_stat, NULL);
    bool closed = raw_selected_file_observe(r->private_image, &out->closed_diagnostic_stat,
        out->closed_diagnostic_sha256, NULL, 0) && out->closed_diagnostic_stat.nlink == 1 &&
        out->closed_diagnostic_stat.dev == private_before.dev && out->closed_diagnostic_stat.ino == private_before.ino &&
        out->closed_diagnostic_stat.size == private_before.size && pfs_read_sealed_key(r->private_image, sealed);
    char closed_key_fingerprint[65] = {0}; if (closed) digest(sealed, sizeof(sealed), closed_key_fingerprint);
    wipe(sealed, sizeof(sealed));
    if (!ok || !closed || !out->canonical_unchanged || strcmp(closed_key_fingerprint, out->key_fingerprint) ||
        strcmp(out->metadata.title_id, r->expected_title) || strcmp(out->metadata.dir_name, r->expected_slot)) {
        blocked(out, "Private SFO/geometry, closed key or canonical identity proof failed", err, n); return;
    }
    raw_selected_identity_t* id = &out->identity; sfo_info_t* meta = &out->metadata;
    snprintf(id->title_id, sizeof(id->title_id), "%s", meta->title_id);
    snprintf(id->slot, sizeof(id->slot), "%s", meta->dir_name);
    snprintf(id->game_title_id, sizeof(id->game_title_id), "%s", meta->game_title_id);
    snprintf(id->format, sizeof(id->format), "%s", meta->format);
    id->account_id = meta->account_id; id->user_id = meta->user_id; id->user_param = meta->user_param;
    id->blocks = meta->blocks; id->system_blocks = meta->system_blocks;
    id->hmac_present = meta->has_hmac; digest(meta->hmac, sizeof(meta->hmac), id->hmac_sha256);
    id->metadata_complete = out->metadata_complete = out->geometry_reliable = true;
    out->blocks = meta->blocks; out->system_blocks = meta->system_blocks;
    snprintf(out->format, sizeof(out->format), "%s", meta->format);
    // No reliable local field schema identifies SystemSaveData. UNKNOWN is
    // truthful and receipt-bound; neither slot spelling nor block counts infer it.
    out->save_kind = RAW_SELECTED_SAVE_KIND_UNKNOWN; out->save_kind_reliable = false;
    out->status = RAW_SELECTED_NATIVE_READY;
    snprintf(out->detail, sizeof(out->detail), "Private native metadata read; save kind UNKNOWN; no publication");
}
