#include "pfs_mode_trial.h"
#include "pfs_keys.h"
#include "savemount.h"
#include "sha256.h"
#include "pfs_candidate_publish.h"
#include "sfo.h"
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static const char* const trial_paths[] = {
    ".", "sce_sys", "sce_sys/param.sfo", "sce_sys/keystone",
    "sce_sys/icon0.png", "data001Slot.bin"
};
static const mode_t initial_modes[] = {0777, 0770, 0770, 0770, 0770, 0770};
static const mode_t candidate_modes[] = {0777, 0770, 0775, 0770, 0775, 0777};

static void trial_fail(pfs_mode_trial_report_t* r, const char* result, const char* detail) {
    r->result = result;
    snprintf(r->detail, sizeof(r->detail), "%s (errno=%d)", detail, errno);
}

static void trial_digest(const void* bytes, size_t length, char out[65]) {
    sha256_ctx_t context; unsigned char digest[32];
    sha256_init(&context); sha256_update(&context, bytes, length); sha256_final(&context, digest);
    for (size_t i = 0; i < 32; i++) snprintf(out + i * 2, 3, "%02x", digest[i]);
}

static void trial_wipe(void* value, size_t length) {
    volatile unsigned char* p = value;
    while (length--) *p++ = 0;
}

static bool trial_stat_equal(const struct stat* a, const struct stat* b, bool same_mount) {
    return a->st_mode == b->st_mode && a->st_size == b->st_size &&
        a->st_uid == b->st_uid && a->st_gid == b->st_gid && a->st_nlink == b->st_nlink &&
        a->st_rdev == b->st_rdev && a->st_blocks == b->st_blocks && a->st_blksize == b->st_blksize &&
        a->st_ino == b->st_ino && (!same_mount || a->st_dev == b->st_dev)
#if defined(__APPLE__) || defined(__FreeBSD__)
        && a->st_flags == b->st_flags && a->st_gen == b->st_gen
#endif
        ;
}

static bool trial_times_equal(const struct stat* a, const struct stat* b) {
    return a->st_atime == b->st_atime && a->st_mtime == b->st_mtime && a->st_ctime == b->st_ctime
#ifdef __APPLE__
        && a->st_atimespec.tv_nsec == b->st_atimespec.tv_nsec &&
        a->st_mtimespec.tv_nsec == b->st_mtimespec.tv_nsec && a->st_ctimespec.tv_nsec == b->st_ctimespec.tv_nsec &&
        a->st_birthtimespec.tv_sec == b->st_birthtimespec.tv_sec && a->st_birthtimespec.tv_nsec == b->st_birthtimespec.tv_nsec
#else
        && a->st_atim.tv_nsec == b->st_atim.tv_nsec && a->st_mtim.tv_nsec == b->st_mtim.tv_nsec &&
        a->st_ctim.tv_nsec == b->st_ctim.tv_nsec
#ifdef __FreeBSD__
        && a->st_birthtim.tv_sec == b->st_birthtim.tv_sec && a->st_birthtim.tv_nsec == b->st_birthtim.tv_nsec
#endif
#endif
        ;
}

static bool trial_source_times_equal(const struct stat* a, const struct stat* b) {
    return a->st_mtime == b->st_mtime && a->st_ctime == b->st_ctime
#ifdef __APPLE__
        && a->st_mtimespec.tv_nsec == b->st_mtimespec.tv_nsec && a->st_ctimespec.tv_nsec == b->st_ctimespec.tv_nsec
#else
        && a->st_mtim.tv_nsec == b->st_mtim.tv_nsec && a->st_ctim.tv_nsec == b->st_ctim.tv_nsec
#endif
        ;
}

static bool trial_hash_file(const char* path, const struct stat* expected, char out[65]) {
    int fd = open(path, O_RDONLY | O_NOFOLLOW);
    if (fd < 0) return false;
    struct stat before = {0}, after = {0}, named = {0};
    if (fstat(fd, &before) != 0) { int error = errno; close(fd); errno = error; return false; }
    if (!S_ISREG(before.st_mode) || !trial_stat_equal(expected, &before, true)) {
        close(fd); errno = ESTALE; return false;
    }
    bool ok = true;
    sha256_ctx_t context; sha256_init(&context);
    unsigned char buffer[32768], digest[32]; ssize_t n = 0; uint64_t length = 0;
    while (ok && (n = read(fd, buffer, sizeof(buffer))) > 0) {
        sha256_update(&context, buffer, (size_t)n); length += (size_t)n;
    }
    if (n < 0 || length != (uint64_t)before.st_size || fstat(fd, &after) != 0 ||
        !trial_stat_equal(&before, &after, true) || lstat(path, &named) != 0 ||
        !trial_stat_equal(&before, &named, true)) ok = false;
    if (close(fd) != 0) ok = false;
    if (!ok) { if (!errno) errno = ESTALE; return false; }
    sha256_final(&context, digest);
    for (size_t i = 0; i < 32; i++) snprintf(out + i * 2, 3, "%02x", digest[i]);
    return true;
}

static const pfs_attribute_entry_t* trial_entry(const pfs_mode_observation_t* o,
                                               const char* path, size_t* index) {
    for (size_t i = 0; i < o->attrs.count; i++) if (!strcmp(o->attrs.entries[i].path, path)) {
        if (index) *index = i;
        return &o->attrs.entries[i];
    }
    return NULL;
}

static bool trial_observe_tree(const char* root, pfs_mode_observation_t* o) {
    snprintf(o->attrs.mount, sizeof(o->attrs.mount), "%s", root);
    if (!pfs_attributes_collect(root, &o->attrs)) return false;
    // This experiment admits the already-observed literal six-entry tree only.
    if (o->attrs.count != sizeof(trial_paths) / sizeof(trial_paths[0])) { errno = EINVAL; return false; }
    for (size_t p = 0; p < sizeof(trial_paths) / sizeof(trial_paths[0]); p++) {
        const pfs_attribute_entry_t* e = trial_entry(o, trial_paths[p], NULL);
        snprintf(o->attrs.error_path, sizeof(o->attrs.error_path), "%s", trial_paths[p]);
        if (!e || (p < 2 ? !S_ISDIR(e->stat.st_mode) : !S_ISREG(e->stat.st_mode))) { errno = EINVAL; return false; }
        for (size_t i = 0; i < 3; i++) if (!strcmp(e->acl[i].status, "ERROR") ||
            !strcmp(e->acl[i].status, "INCOMPLETE")) { errno = e->acl[i].error ? e->acl[i].error : EIO; return false; }
        for (size_t i = 0; i < 2; i++) {
            if (!strcmp(e->xattrs[i].status, "ERROR") || !strcmp(e->xattrs[i].status, "INCOMPLETE")) {
                errno = e->xattrs[i].error ? e->xattrs[i].error : EIO; return false;
            }
            for (size_t j = 0; j < e->xattrs[i].count; j++) if (e->xattrs[i].entries[j].error) {
                errno = e->xattrs[i].entries[j].error; return false;
            }
        }
    }
    o->file_sha256 = calloc(o->attrs.count, sizeof(*o->file_sha256));
    if (!o->file_sha256) return false;
    for (size_t i = 0; i < o->attrs.count; i++) {
        const pfs_attribute_entry_t* entry = &o->attrs.entries[i];
        if (!S_ISREG(entry->stat.st_mode)) continue;
        char path[1400]; int n = snprintf(path, sizeof(path), "%s/%s", root, entry->path);
        snprintf(o->attrs.error_path, sizeof(o->attrs.error_path), "%s", entry->path);
        if (n < 0 || (size_t)n >= sizeof(path)) { errno = ENAMETOOLONG; return false; }
        if (!trial_hash_file(path, &entry->stat, o->file_sha256[i])) return false;
        o->regular_file_count++;
    }
    o->hashes_complete = o->regular_file_count == 4;
    return o->hashes_complete;
}

static bool trial_observe(const char* root, pfs_mode_observation_t* o) {
    bool ok = trial_observe_tree(root, o);
    o->attrs.result = ok ? "OBSERVED" : "INCOMPLETE";
    if (!ok) { o->attrs.error = errno ? errno : EIO; return false; }
    o->attrs.error_path[0] = 0;
    return true;
}

static bool trial_extra_equal(const pfs_attribute_entry_t* a, const pfs_attribute_entry_t* b) {
    for (size_t i = 0; i < 3; i++) {
        const pfs_acl_observation_t *x = &a->acl[i], *y = &b->acl[i];
        if (strcmp(x->status, y->status) || x->error != y->error || x->count != y->count) return false;
        for (size_t j = 0; j < x->count; j++) if (x->entries[j].tag != y->entries[j].tag ||
            x->entries[j].id != y->entries[j].id || x->entries[j].perm != y->entries[j].perm ||
            x->entries[j].type != y->entries[j].type || x->entries[j].flags != y->entries[j].flags) return false;
    }
    for (size_t i = 0; i < 2; i++) {
        const pfs_xattr_observation_t *x = &a->xattrs[i], *y = &b->xattrs[i];
        if (strcmp(x->status, y->status) || x->error != y->error || x->count != y->count) return false;
        for (size_t j = 0; j < x->count; j++) if (strcmp(x->entries[j].name, y->entries[j].name) ||
            x->entries[j].size != y->entries[j].size || x->entries[j].error != y->entries[j].error) return false;
    }
    return true; // Matching unavailable getters remain UNKNOWN, not absence.
}

static bool trial_compare(const pfs_mode_observation_t* a, const pfs_mode_observation_t* b,
                          bool same_mount, bool candidate_delta, bool* content, bool* times) {
    bool metadata = a->attrs.complete && b->attrs.complete && a->attrs.count == b->attrs.count;
    *content = a->hashes_complete && b->hashes_complete; *times = true;
    for (size_t i = 0; i < a->attrs.count; i++) {
        const pfs_attribute_entry_t* x = &a->attrs.entries[i]; size_t index = 0;
        const pfs_attribute_entry_t* y = trial_entry(b, x->path, &index);
        if (!y) { metadata = false; *content = false; continue; }
        struct stat expected = x->stat;
        if (candidate_delta) for (size_t p = 0; p < sizeof(trial_paths) / sizeof(trial_paths[0]); p++)
            if (!strcmp(x->path, trial_paths[p])) expected.st_mode = (expected.st_mode & ~07777) | candidate_modes[p];
        if (!trial_stat_equal(&expected, &y->stat, same_mount) || !trial_extra_equal(x, y)) metadata = false;
        if (!trial_times_equal(&x->stat, &y->stat)) *times = false;
        if (S_ISREG(x->stat.st_mode) && (!a->file_sha256 || !b->file_sha256 ||
            strcmp(a->file_sha256[i], b->file_sha256[index]))) *content = false;
    }
    return metadata;
}

static void trial_comparison_fields(pfs_mode_trial_report_t* r) {
    const pfs_mode_observation_t *a = &r->arms[0].closed, *b = &r->arms[1].closed;
    r->inventory_equal = a->attrs.complete && b->attrs.complete && a->attrs.count == b->attrs.count;
    r->identities_equal = r->flags_equal = r->links_equal = true;
    r->other_modes_equal = r->requested_modes_observed = true;
    for (size_t p = 0; p < sizeof(trial_paths) / sizeof(trial_paths[0]); p++) {
        const pfs_attribute_entry_t *x = trial_entry(a, trial_paths[p], NULL), *y = trial_entry(b, trial_paths[p], NULL);
        if (!x || !y) {
            r->inventory_equal = r->identities_equal = r->flags_equal = r->links_equal = false;
            r->other_modes_equal = r->requested_modes_observed = false;
            continue;
        }
        if ((x->stat.st_mode & S_IFMT) != (y->stat.st_mode & S_IFMT)) r->inventory_equal = false;
        if (x->stat.st_uid != y->stat.st_uid || x->stat.st_gid != y->stat.st_gid ||
            x->stat.st_ino != y->stat.st_ino) r->identities_equal = false;
        if (x->stat.st_nlink != y->stat.st_nlink) r->links_equal = false;
#if defined(__APPLE__) || defined(__FreeBSD__)
        if (x->stat.st_flags != y->stat.st_flags) r->flags_equal = false;
#endif
        bool mode_expected = (x->stat.st_mode & 07777) == initial_modes[p] &&
            (y->stat.st_mode & 07777) == candidate_modes[p];
        if (p == 2 || p == 4 || p == 5) {
            if (!mode_expected) r->requested_modes_observed = false;
        } else if (!mode_expected) r->other_modes_equal = false;
    }
    r->modes_expected = r->requested_modes_observed && r->other_modes_equal;
    r->content_hashes_equal = r->content_equal;
}

static void trial_json_string(FILE* file, const char* value) {
    if (!value) value = "UNKNOWN";
    fputc('"', file);
    for (const unsigned char* p = (const unsigned char*)value; *p; p++) {
        if (*p == '"' || *p == '\\') { fputc('\\', file); fputc(*p, file); }
        else if (*p < 0x20) fprintf(file, "\\u%04x", *p);
        else fputc(*p, file);
    }
    fputc('"', file);
}

static bool trial_flush(FILE* file, const char* work) {
    bool ok = fflush(file) == 0 && !ferror(file) && fsync(fileno(file)) == 0;
    if (fclose(file) != 0) ok = false;
    int dir = open(work, O_RDONLY | O_DIRECTORY | O_NOFOLLOW);
    if (dir < 0) return false;
    if (fsync(dir) != 0) ok = false;
    if (close(dir) != 0) ok = false;
    return ok;
}

static FILE* trial_new_evidence(const char* path) {
    int fd = open(path, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW, 0600);
    if (fd < 0) return NULL;
    FILE* file = fdopen(fd, "w");
    if (!file) close(fd);
    return file;
}

static bool trial_phase(pfs_mode_trial_report_t* r, unsigned* sequence, const char* phase) {
    snprintf(r->phase, sizeof(r->phase), "%s", phase);
    int n = snprintf(r->evidence_path, sizeof(r->evidence_path), "%s/%03u-%s.json", r->work, (*sequence)++, phase);
    FILE* file = n > 0 && (size_t)n < sizeof(r->evidence_path) ? trial_new_evidence(r->evidence_path) : NULL;
    if (!file) goto failed;
    fprintf(file, "{\"operation\":\"private-pfs-mode-trial\",\"uid\":\"%s\",\"title_id\":\"%s\",\"slot\":\"%s\",\"phase\":",
            PFS_ATTRIBUTES_UID, PFS_ATTRIBUTES_TITLE, PFS_ATTRIBUTES_SLOT);
    trial_json_string(file, phase); fputs(",\"result\":", file); trial_json_string(file, r->result);
    fputs(",\"detail\":", file); trial_json_string(file, r->detail);
    fprintf(file, ",\"recovery_required\":%s,\"source_sha256\":\"%s\",\"arms\":[",
            r->recovery_required ? "true" : "false", r->source_sha256);
    for (size_t i = 0; i < 2; i++) fprintf(file,
        "%s{\"name\":\"%s\",\"closed_sha256\":\"%s\",\"first_unmounted\":%s,\"verify_unmounted\":%s}",
        i ? "," : "", i ? "CANDIDATE" : "CONTROL", r->arms[i].closed_sha256,
        r->arms[i].first_unmounted ? "true" : "false", r->arms[i].verify_unmounted ? "true" : "false");
    fputs("]}\n", file);
    if (!trial_flush(file, r->work)) goto failed;
    r->evidence_durable = true; return true;
failed:
    r->evidence_durable = false; r->recovery_required = true;
    trial_fail(r, "EVIDENCE_ERROR", "Could not durably record private experiment phase");
    return false;
}

static bool trial_save_observation(pfs_mode_trial_report_t* r, const char* arm,
                                   const char* phase, const pfs_mode_observation_t* o) {
    char path[320]; int n = snprintf(path, sizeof(path), "%s/%s-%s-observation.json", r->work, arm, phase);
    FILE* file = n > 0 && (size_t)n < sizeof(path) ? trial_new_evidence(path) : NULL;
    if (!file) goto failed;
    fprintf(file, "{\"inventory_complete\":%s,\"hashes_complete\":%s,\"regular_file_count\":%zu,\"errno\":%d,\"error_path\":",
            o->attrs.complete ? "true" : "false", o->hashes_complete ? "true" : "false", o->regular_file_count, o->attrs.error);
    trial_json_string(file, o->attrs.error_path); fputs(",\"entries\":[", file);
    for (size_t i = 0; i < o->attrs.count; i++) {
        const pfs_attribute_entry_t* e = &o->attrs.entries[i]; const struct stat* s = &e->stat;
        fprintf(file, "%s{\"path\":", i ? "," : ""); trial_json_string(file, e->path);
        fprintf(file, ",\"mode\":%llu,\"device\":%llu,\"inode\":%llu,\"size\":%lld,\"uid\":%llu,\"gid\":%llu,\"nlink\":%llu,\"rdev\":%llu,\"blocks\":%lld,\"block_size\":%lld,\"atime\":%lld,\"mtime\":%lld,\"ctime\":%lld",
            (unsigned long long)s->st_mode, (unsigned long long)s->st_dev, (unsigned long long)s->st_ino,
            (long long)s->st_size, (unsigned long long)s->st_uid, (unsigned long long)s->st_gid,
            (unsigned long long)s->st_nlink, (unsigned long long)s->st_rdev, (long long)s->st_blocks,
            (long long)s->st_blksize, (long long)s->st_atime, (long long)s->st_mtime, (long long)s->st_ctime);
#ifdef __APPLE__
        fprintf(file, ",\"atime_nsec\":%ld,\"mtime_nsec\":%ld,\"ctime_nsec\":%ld,\"birthtime\":%lld,\"birthtime_nsec\":%ld",
            s->st_atimespec.tv_nsec, s->st_mtimespec.tv_nsec, s->st_ctimespec.tv_nsec,
            (long long)s->st_birthtimespec.tv_sec, s->st_birthtimespec.tv_nsec);
#else
        fprintf(file, ",\"atime_nsec\":%ld,\"mtime_nsec\":%ld,\"ctime_nsec\":%ld", s->st_atim.tv_nsec, s->st_mtim.tv_nsec, s->st_ctim.tv_nsec);
#ifdef __FreeBSD__
        fprintf(file, ",\"birthtime\":%lld,\"birthtime_nsec\":%ld", (long long)s->st_birthtim.tv_sec, s->st_birthtim.tv_nsec);
#endif
#endif
#if defined(__APPLE__) || defined(__FreeBSD__)
        fprintf(file, ",\"flags\":%llu,\"generation\":%llu", (unsigned long long)s->st_flags, (unsigned long long)s->st_gen);
#endif
        fprintf(file, ",\"sha256\":\"%s\",\"acl\":[", o->file_sha256 ? o->file_sha256[i] : "");
        for (size_t a = 0; a < 3; a++) {
            const pfs_acl_observation_t* x = &e->acl[a];
            fprintf(file, "%s{\"kind\":%zu,\"status\":", a ? "," : "", a); trial_json_string(file, x->status);
            fprintf(file, ",\"errno\":%d,\"entries\":[", x->error);
            for (size_t j = 0; j < x->count; j++) {
                const pfs_acl_entry_t* v = &x->entries[j];
                fprintf(file, "%s{\"tag\":%u,\"id\":%u,\"perm\":%u,\"type\":%u,\"flags\":%u}",
                    j ? "," : "", v->tag, v->id, v->perm, v->type, v->flags);
            }
            fputs("]}", file);
        }
        fputs("],\"xattrs\":[", file);
        for (size_t a = 0; a < 2; a++) {
            const pfs_xattr_observation_t* x = &e->xattrs[a];
            fprintf(file, "%s{\"namespace\":%zu,\"status\":", a ? "," : "", a); trial_json_string(file, x->status);
            fprintf(file, ",\"errno\":%d,\"entries\":[", x->error);
            for (size_t j = 0; j < x->count; j++) {
                fprintf(file, "%s{\"name\":", j ? "," : ""); trial_json_string(file, x->entries[j].name);
                fprintf(file, ",\"size\":%lld,\"errno\":%d}", (long long)x->entries[j].size, x->entries[j].error);
            }
            fputs("]}", file);
        }
        fputs("]}", file);
    }
    fputs("]}\n", file);
    if (!trial_flush(file, r->work)) goto failed;
    return true;
failed:
    r->evidence_durable = false; r->recovery_required = true;
    trial_fail(r, "EVIDENCE_ERROR", "Could not durably retain internal observations before unmount");
    return false;
}

static bool trial_initial_modes(const pfs_mode_observation_t* o) {
    for (size_t i = 0; i < sizeof(trial_paths) / sizeof(trial_paths[0]); i++) {
        const pfs_attribute_entry_t* e = trial_entry(o, trial_paths[i], NULL);
        if (!e || (e->stat.st_mode & 07777) != initial_modes[i]) { errno = EINVAL; return false; }
    }
    return true;
}

static bool trial_change_modes(const char* root, const pfs_mode_observation_t* before, bool candidate) {
    const size_t changed[] = {2, 4, 5};
    for (size_t i = 0; i < sizeof(changed) / sizeof(changed[0]); i++) {
        size_t index = changed[i]; const pfs_attribute_entry_t* e = trial_entry(before, trial_paths[index], NULL);
        char path[1400]; int n = snprintf(path, sizeof(path), "%s/%s", root, trial_paths[index]);
        if (!e || n < 0 || (size_t)n >= sizeof(path)) return false;
        int fd = open(path, O_RDONLY | O_NOFOLLOW); if (fd < 0) return false;
        struct stat pinned;
        bool ok = fstat(fd, &pinned) == 0 && S_ISREG(pinned.st_mode) && trial_stat_equal(&e->stat, &pinned, true);
        if (ok && candidate) ok = fchmod(fd, candidate_modes[index]) == 0;
        if (ok) ok = fsync(fd) == 0;
        if (close(fd) != 0) ok = false;
        if (!ok) return false;
    }
    return true;
}

static bool trial_observe_record(pfs_mode_trial_report_t* r, const char* arm, const char* phase,
                                 const char* root, pfs_mode_observation_t* observation) {
    bool ok = trial_observe(root, observation);
    int error = errno;
    if (!trial_save_observation(r, arm, phase, observation)) return false;
    if (!ok) errno = error;
    return ok;
}

static bool trial_arm(pfs_mode_trial_report_t* r, size_t which, bool verify, unsigned* sequence,
                       const unsigned char baseline_sealed[PFS_SEALED_KEY_SIZE],
                       const unsigned char baseline_key[PFS_PLAIN_KEY_SIZE]) {
    pfs_mode_arm_t* arm = &r->arms[which];
    char phase[64]; snprintf(phase, sizeof(phase), "%s-%s-mount", arm->name, verify ? "verify" : "first");
    if (!trial_phase(r, sequence, phase)) return false;
    unsigned char sealed[PFS_SEALED_KEY_SIZE], key[PFS_PLAIN_KEY_SIZE];
    const char* image = verify ? arm->verification_copy : arm->image;
    bool keyed = pfs_read_sealed_key(image, sealed) && pfs_decrypt_save_key(image, key) &&
        !memcmp(sealed, baseline_sealed, sizeof(sealed)) && !memcmp(key, baseline_key, sizeof(key));
    if (!keyed) { trial_wipe(key, sizeof(key)); trial_wipe(sealed, sizeof(sealed)); trial_fail(r, "KEY_ERROR", "Private image key identity is unconfirmed"); return false; }
    trial_digest(sealed, sizeof(sealed), arm->sealed_key_sha256); trial_digest(key, sizeof(key), arm->plain_key_sha256);
    savemount_t mount = {0}; bool mounted = savemount_mount(image, key, &mount);
    trial_wipe(key, sizeof(key)); trial_wipe(sealed, sizeof(sealed));
    if (!mounted) { trial_fail(r, "MOUNT_ERROR", "Private diagnostic mount failed"); return false; }
    bool ok;
    if (verify) {
        ok = trial_observe_record(r, arm->name, "closed", mount.mount_point, &arm->closed);
        if (ok) {
            bool content, times;
            arm->closed_observation_matches = trial_compare(&arm->after, &arm->closed, false, false, &content, &times) && content;
            ok = arm->closed_observation_matches;
        }
    } else {
        ok = trial_observe_record(r, arm->name, "before", mount.mount_point, &arm->before);
        if (ok) ok = trial_initial_modes(&arm->before);
        // Matched opens/stat/fsync/close on both arms; only CANDIDATE calls fchmod.
        if (ok) ok = trial_change_modes(mount.mount_point, &arm->before, which == 1);
        if (ok) ok = trial_observe_record(r, arm->name, "after", mount.mount_point, &arm->after);
        if (ok) {
            bool times;
            arm->attributes_preserved = trial_compare(&arm->before, &arm->after, true, which == 1, &arm->content_unchanged, &times);
            ok = arm->attributes_preserved && arm->content_unchanged;
        }
    }
    if (!ok && strcmp(r->result, "EVIDENCE_ERROR")) trial_fail(r, "OBSERVATION_MISMATCH", "Private tree, hashes or non-mode metadata failed validation");
    // Even a failed observation must release THIS disposable mount. Never retry.
    if (!savemount_unmount(&mount)) {
        r->recovery_required = true; trial_fail(r, "RECOVERY_REQUIRED", "Private unmount is uncertain; all evidence retained"); return false;
    }
    if (verify) { arm->verify_unmounted = true; arm->closed.attrs.unmounted = true; }
    else { arm->first_unmounted = true; arm->before.attrs.unmounted = arm->after.attrs.unmounted = true; }
    if (!ok) return false;
    if (!verify) {
        if (!sha256_file_hex(arm->image, arm->closed_sha256)) { trial_fail(r, "HASH_ERROR", "Closed private image hash failed"); return false; }
        unsigned char closed_sealed[PFS_SEALED_KEY_SIZE], closed_key[PFS_PLAIN_KEY_SIZE];
        bool identity = pfs_read_sealed_key(arm->image, closed_sealed) && pfs_decrypt_save_key(arm->image, closed_key) &&
            !memcmp(closed_sealed, baseline_sealed, sizeof(closed_sealed)) && !memcmp(closed_key, baseline_key, sizeof(closed_key));
        trial_wipe(closed_sealed, sizeof(closed_sealed)); trial_wipe(closed_key, sizeof(closed_key));
        if (!identity) { trial_fail(r, "KEY_ERROR", "Closed private image key changed"); return false; }
    }
    snprintf(phase, sizeof(phase), "%s-%s-unmounted", arm->name, verify ? "verify" : "first");
    return trial_phase(r, sequence, phase);
}

void pfs_mode_trial_run(pfs_mode_trial_report_t* r) {
    r->result = "RUNNING"; r->evidence_durable = false;
    r->arms[0].name = "CONTROL"; r->arms[1].name = "CANDIDATE";
    unsigned sequence = 0; unsigned char baseline_sealed[PFS_SEALED_KEY_SIZE] = {0}, baseline_key[PFS_PLAIN_KEY_SIZE] = {0};
    if (!trial_phase(r, &sequence, "begin")) goto done;
    for (size_t i = 0; i < 2; i++) {
        pfs_mode_arm_t* arm = &r->arms[i]; pfs_attribute_image_t acquired = {0};
        int n = snprintf(arm->image, sizeof(arm->image), "%s/%s.img", r->work, arm->name);
        int v = snprintf(arm->verification_copy, sizeof(arm->verification_copy), "%s/%s.verify.img", r->work, arm->name);
        snprintf(acquired.source, sizeof(acquired.source), "%s", PFS_ATTRIBUTES_REJECTED);
        snprintf(acquired.copy, sizeof(acquired.copy), "%s", arm->image);
        bool acquired_ok = n > 0 && (size_t)n < sizeof(arm->image) && v > 0 &&
            (size_t)v < sizeof(arm->verification_copy) && pfs_attributes_copy_private(&acquired);
        if (i == 0 && acquired.outer_available) { r->source_before = acquired.outer_before; r->source_available = true; }
        if (acquired.outer_available) r->source_after = acquired.outer_after;
        if (acquired.sha256[0]) snprintf(r->source_sha256, sizeof(r->source_sha256), "%s", acquired.sha256);
        if (!acquired_ok || strcmp(acquired.sha256, PFS_MODE_TRIAL_EXPECTED_SHA)) {
            trial_fail(r, "SOURCE_MISMATCH", "Rejected source acquisition is not the expected stable image"); goto done;
        }
    }
    r->source_stable = trial_stat_equal(&r->source_before, &r->source_after, true) &&
        trial_source_times_equal(&r->source_before, &r->source_after);
    if (!r->source_stable || !pfs_read_sealed_key(r->arms[0].image, baseline_sealed) ||
        !pfs_decrypt_save_key(r->arms[0].image, baseline_key)) { trial_fail(r, "KEY_ERROR", "Source identity or key unavailable before private mounts"); goto done; }
    if (!trial_phase(r, &sequence, "source-verified")) goto done;
    for (size_t i = 0; i < 2; i++) if (!trial_arm(r, i, false, &sequence, baseline_sealed, baseline_key)) goto done;
    for (size_t i = 0; i < 2; i++) {
        pfs_attribute_image_t acquired = {0};
        snprintf(acquired.source, sizeof(acquired.source), "%s", r->arms[i].image);
        snprintf(acquired.copy, sizeof(acquired.copy), "%s", r->arms[i].verification_copy);
        if (!pfs_attributes_copy_private(&acquired) || strcmp(acquired.sha256, r->arms[i].closed_sha256)) {
            trial_fail(r, "VERIFY_COPY_ERROR", "Closed private image verification acquisition failed"); goto done;
        }
        if (!trial_arm(r, i, true, &sequence, baseline_sealed, baseline_key)) goto done;
        char retained_hash[65];
        if (!sha256_file_hex(r->arms[i].image, retained_hash) || strcmp(retained_hash, r->arms[i].closed_sha256)) {
            trial_fail(r, "CLOSED_IMAGE_CHANGED", "Verification did not preserve the closed private artifact"); goto done;
        }
    }
    {
        bool content, times;
        r->metadata_equal = trial_compare(&r->arms[0].closed, &r->arms[1].closed, false, true, &content, &times);
        r->content_equal = content; r->timestamps_equal = times;
        trial_comparison_fields(r);
        r->sealed_keys_equal = !strcmp(r->arms[0].sealed_key_sha256, r->arms[1].sealed_key_sha256);
        r->plain_keys_equal = !strcmp(r->arms[0].plain_key_sha256, r->arms[1].plain_key_sha256);
        if (!r->metadata_equal || !content || !r->sealed_keys_equal || !r->plain_keys_equal) {
            trial_fail(r, "COMPARISON_MISMATCH", "Control and candidate differ beyond the three requested modes or timestamps"); goto done;
        }
    }
    {
        struct stat final_before, final_after; char hash[65];
        bool stable = lstat(PFS_ATTRIBUTES_REJECTED, &final_before) == 0 &&
            trial_stat_equal(&r->source_before, &final_before, true) &&
            trial_hash_file(PFS_ATTRIBUTES_REJECTED, &final_before, hash) &&
            lstat(PFS_ATTRIBUTES_REJECTED, &final_after) == 0 && trial_stat_equal(&final_before, &final_after, true);
        r->source_unchanged = stable && !strcmp(hash, PFS_MODE_TRIAL_EXPECTED_SHA);
        if (stable) r->source_after = final_after;
        if (!r->source_unchanged) { trial_fail(r, "SOURCE_CHANGED", "Live encrypted source did not remain the expected image"); goto done; }
    }
    r->result = "PRIVATE_PASS";
    snprintf(r->detail, sizeof(r->detail), "Private experiment only; no live publication or proof of PS5/game acceptance. Unavailable ACL/xattrs remain UNKNOWN.");
done:
    trial_wipe(baseline_key, sizeof(baseline_key)); trial_wipe(baseline_sealed, sizeof(baseline_sealed));
    // Preserve all clones, observations and partial evidence, on every outcome.
    if (r->evidence_durable) trial_phase(r, &sequence, "terminal");
}

void pfs_mode_trial_free(pfs_mode_trial_report_t* r) {
    for (size_t i = 0; i < 2; i++) {
        pfs_mode_observation_t* observations[] = {&r->arms[i].before, &r->arms[i].after, &r->arms[i].closed};
        for (size_t j = 0; j < 3; j++) {
            pfs_attributes_image_free(&observations[j]->attrs);
            free(observations[j]->file_sha256); observations[j]->file_sha256 = NULL;
        }
    }
}

static bool publication_phase(pfs_candidate_publication_t* p, unsigned* sequence,
                              const char* phase) {
    pfs_mode_trial_report_t* r = &p->trial;
    snprintf(r->phase, sizeof(r->phase), "%s", phase);
    int n = snprintf(r->evidence_path, sizeof(r->evidence_path), "%s/%03u-%s.json",
                     r->work, (*sequence)++, phase);
    FILE* file = n > 0 && (size_t)n < sizeof(r->evidence_path)
        ? trial_new_evidence(r->evidence_path) : NULL;
    if (!file) goto failed;
    fprintf(file, "{\"operation\":\"publish-save-mode-candidate\",\"uid\":\"%s\","
        "\"title_id\":\"%s\",\"slot\":\"%s\",\"candidate\":\"%s\","
        "\"expected_candidate_sha256\":\"%s\",\"expected_source_sha256\":\"%s\","
        "\"receipt_sha256\":\"%s\",\"phase\":", PFS_ATTRIBUTES_UID,
        PFS_ATTRIBUTES_TITLE, PFS_ATTRIBUTES_SLOT, PFS_CANDIDATE_IMAGE,
        PFS_CANDIDATE_SHA, PFS_MODE_TRIAL_EXPECTED_SHA, PFS_CANDIDATE_RECEIPT_SHA);
    trial_json_string(file, phase); fputs(",\"result\":", file); trial_json_string(file, r->result);
    fputs(",\"detail\":", file); trial_json_string(file, r->detail);
    bool uncertain = p->rename_attempted && !p->published;
    char writes[24]; snprintf(writes, sizeof(writes), "%u", p->live_writebacks);
    fprintf(file, ",\"rename_attempted\":%s,\"publication_uncertain\":%s,\"published\":%s,\"live_writebacks\":%s,"
        "\"recovery_required\":%s,\"pre_verified\":%s,\"post_verified\":%s,"
        "\"final_hash_verified\":%s,\"final_sha256\":\"%s\",\"original_retained\":\"%s\"}\n",
        p->rename_attempted ? "true" : "false", uncertain ? "true" : "false",
        uncertain ? "null" : p->published ? "true" : "false", uncertain ? "null" : writes,
        r->recovery_required ? "true" : "false", p->pre_verified ? "true" : "false",
        p->post_verified ? "true" : "false", p->final_hash_verified ? "true" : "false",
        p->final_sha256, r->arms[0].image);
    if (!trial_flush(file, r->work)) goto failed;
    r->evidence_durable = true; return true;
failed:
    r->evidence_durable = false; r->recovery_required = true;
    trial_fail(r, "EVIDENCE_ERROR", "Publication evidence could not be made durable");
    return false;
}

static bool publication_hash(const char* path, const char* expected, struct stat* stat_out) {
    struct stat st; char hash[65];
    if (lstat(path, &st) != 0) return false;
    if (!S_ISREG(st.st_mode)) { errno = EINVAL; return false; }
    if (!trial_hash_file(path, &st, hash)) return false;
    if (strcmp(hash, expected)) { errno = ESTALE; return false; }
    if (stat_out) *stat_out = st;
    return true;
}

static bool publication_retained_valid(void) {
    // Exact byte-bound PRIVATE_PASS response, not a permissive JSON interpretation.
    return publication_hash(PFS_CANDIDATE_RECEIPT, PFS_CANDIDATE_RECEIPT_SHA, NULL) &&
        publication_hash(PFS_CANDIDATE_CONTROL, PFS_CANDIDATE_CONTROL_SHA, NULL) &&
        publication_hash(PFS_CANDIDATE_IMAGE, PFS_CANDIDATE_SHA, NULL);
}

static bool publication_copy(const char* from, const char* to, const char* hash,
                             struct stat* source_stat) {
    pfs_attribute_image_t copy = {0};
    snprintf(copy.source, sizeof(copy.source), "%s", from);
    snprintf(copy.copy, sizeof(copy.copy), "%s", to);
    if (!pfs_attributes_copy_private(&copy) || strcmp(copy.sha256, hash)) return false;
    if (source_stat) *source_stat = copy.outer_before;
    return true;
}

static bool publication_observe(pfs_candidate_publication_t* p, const char* name,
    const char* phase, const char* image, pfs_mode_observation_t* out) {
    pfs_mode_trial_report_t* r = &p->trial;
    unsigned char a[PFS_SEALED_KEY_SIZE] = {0}, b[PFS_SEALED_KEY_SIZE] = {0};
    unsigned char ak[PFS_PLAIN_KEY_SIZE] = {0}, bk[PFS_PLAIN_KEY_SIZE] = {0};
    bool keys = pfs_read_sealed_key(r->arms[0].image, a) && pfs_read_sealed_key(image, b) &&
        pfs_decrypt_save_key(r->arms[0].image, ak) && pfs_decrypt_save_key(image, bk) &&
        !memcmp(a, b, sizeof(a)) && !memcmp(ak, bk, sizeof(ak));
    if (keys) {
        size_t arm = !strcmp(name, "SOURCE") ? 0 : 1;
        trial_digest(b, sizeof(b), r->arms[arm].sealed_key_sha256);
        trial_digest(bk, sizeof(bk), r->arms[arm].plain_key_sha256);
    }
    savemount_t mount = {0};
    bool mounted = keys && savemount_mount(image, bk, &mount);
    trial_wipe(a, sizeof(a)); trial_wipe(b, sizeof(b));
    trial_wipe(ak, sizeof(ak)); trial_wipe(bk, sizeof(bk));
    if (!mounted) { trial_fail(r, keys ? "MOUNT_ERROR" : "KEY_ERROR", "Private verification key/mount failed"); return false; }
    bool ok = trial_observe_record(r, name, phase, mount.mount_point, out);
    if (!ok && !strcmp(r->result, "RUNNING")) {
        errno = out->attrs.error;
        trial_fail(r, "OBSERVATION_ERROR", out->attrs.error_path[0]
            ? out->attrs.error_path : "Private inventory/content hashing incomplete");
    }
    if (ok) {
        char path[512]; sfo_info_t sfo;
        snprintf(path, sizeof(path), "%s/sce_sys/param.sfo", mount.mount_point);
        ok = sfo_parse(path, &sfo) == 0 && !strcmp(sfo.title_id, PFS_ATTRIBUTES_TITLE) &&
            !strcmp(sfo.dir_name, PFS_ATTRIBUTES_SLOT) && sfo.account_id == p->account_id &&
            sfo.user_id == p->user_id && sfo.has_hmac;
        if (!ok) trial_fail(r, "IDENTITY_ERROR", "Private SFO disagrees with exact fresh destination owner/title/slot");
    }
    if (!savemount_unmount(&mount)) {
        r->recovery_required = true;
        trial_fail(r, "RECOVERY_REQUIRED", "Private verification unmount uncertain; evidence retained"); return false;
    }
    out->attrs.unmounted = true;
    return ok;
}

void pfs_candidate_publish_run(pfs_candidate_publication_t* p,
                               bool (*revalidate)(pfs_candidate_publication_t*)) {
    pfs_mode_trial_report_t* r = &p->trial;
    unsigned sequence = 0;
    r->result = "RUNNING";
    r->arms[0].name = "SOURCE"; r->arms[1].name = "CANDIDATE";
    if (!publication_phase(p, &sequence, "begin")) goto done;
    if (strlen(r->work) > sizeof(r->arms[0].image) - 32) {
        errno = ENAMETOOLONG;
        trial_fail(r, "SETUP_ERROR", "Private workspace does not fit image path budget"); goto done;
    }
    if (!publication_retained_valid()) {
        trial_fail(r, "RETAINED_EVIDENCE_MISMATCH", "Pinned PRIVATE_PASS response/control/candidate changed or unavailable"); goto done;
    }
    // Permanent attempt claim: no replay after success, failure or daemon restart.
    FILE* claim = trial_new_evidence(PFS_CANDIDATE_ATTEMPT);
    if (!claim) { trial_fail(r, "ALREADY_ATTEMPTED", "Publication attempt exists or cannot be created; no retry"); goto done; }
    fprintf(claim, "{\"workspace\":\"%s\",\"candidate_sha256\":\"%s\",\"receipt_sha256\":\"%s\"}\n",
        r->work, PFS_CANDIDATE_SHA, PFS_CANDIDATE_RECEIPT_SHA);
    p->attempt_durable = trial_flush(claim, PFS_CANDIDATE_WORK);
    if (!p->attempt_durable) { trial_fail(r, "EVIDENCE_ERROR", "Attempt claim durability uncertain"); goto done; }
    char source_verify[256], staged[256];
    snprintf(r->arms[0].image, sizeof(r->arms[0].image), "%s/SOURCE.img", r->work);
    snprintf(source_verify, sizeof(source_verify), "%s/SOURCE.verify.img", r->work);
    snprintf(staged, sizeof(staged), "%s/CANDIDATE.closed.img", r->work);
    snprintf(r->arms[1].verification_copy, sizeof(r->arms[1].verification_copy), "%s/CANDIDATE.verify.img", r->work);
    snprintf(r->arms[1].image, sizeof(r->arms[1].image), "%s", PFS_CANDIDATE_IMAGE);
    if (!publication_copy(PFS_ATTRIBUTES_REJECTED, r->arms[0].image, PFS_MODE_TRIAL_EXPECTED_SHA, &r->source_before) ||
        !publication_copy(r->arms[0].image, source_verify, PFS_MODE_TRIAL_EXPECTED_SHA, NULL) ||
        !publication_copy(PFS_CANDIDATE_IMAGE, staged, PFS_CANDIDATE_SHA, NULL) ||
        !publication_copy(staged, r->arms[1].verification_copy, PFS_CANDIDATE_SHA, NULL)) {
        trial_fail(r, "COPY_ERROR", "Stable verified source/candidate acquisition failed"); goto done;
    }
    snprintf(r->source_sha256, sizeof(r->source_sha256), "%s", PFS_MODE_TRIAL_EXPECTED_SHA);
    r->source_available = r->source_stable = true;
    if (!publication_phase(p, &sequence, "private-verification") || !revalidate(p)) goto done;
    if (!publication_observe(p, "SOURCE", "pre", source_verify, &r->arms[0].before) ||
        !publication_observe(p, "CANDIDATE", "pre", r->arms[1].verification_copy, &r->arms[1].after)) goto done;
    {
        bool content, times;
        bool metadata = trial_compare(&r->arms[0].before, &r->arms[1].after, false, true, &content, &times);
        p->pre_verified = metadata && content && trial_initial_modes(&r->arms[0].before);
        r->timestamps_equal = times;
        if (!p->pre_verified) { trial_fail(r, "PRE_VERIFICATION_FAILED", "Candidate differs beyond authorized modes/timestamps"); goto done; }
    }
    if (!revalidate(p) || !publication_retained_valid() ||
        !publication_hash(staged, PFS_CANDIDATE_SHA, NULL) ||
        !publication_hash(PFS_ATTRIBUTES_REJECTED, PFS_MODE_TRIAL_EXPECTED_SHA, &r->source_after) ||
        !trial_stat_equal(&r->source_before, &r->source_after, true) ||
        !trial_source_times_equal(&r->source_before, &r->source_after)) {
        if (!strcmp(r->result, "RUNNING")) trial_fail(r, "SOURCE_CHANGED", "Final source, identity or retained evidence revalidation failed");
        goto done;
    }
    r->source_unchanged = true;
    // Persist intent BEFORE the single rename. Failure afterward is uncertain,
    // never authority for auto-replay or an automatic rollback.
    if (!publication_phase(p, &sequence, "publication-intent")) goto done;
    bool installed = savemount_publish_closed_candidate(staged, PFS_ATTRIBUTES_REJECTED,
        PFS_CANDIDATE_SHA, PFS_MODE_TRIAL_EXPECTED_SHA, &p->rename_attempted);
    if (!installed) {
        trial_fail(r, p->rename_attempted ? "RECOVERY_REQUIRED" : "PUBLICATION_FAILED",
            "Closed image publication failed or durability uncertain; do not retry"); goto done;
    }
    p->published = true; p->live_writebacks = 1;
    if (!publication_phase(p, &sequence, "published")) goto done;
    char post_verify[256]; snprintf(post_verify, sizeof(post_verify), "%s/PUBLISHED.verify.img", r->work);
    if (!publication_copy(PFS_ATTRIBUTES_REJECTED, post_verify, PFS_CANDIDATE_SHA, NULL)) {
        trial_fail(r, "POST_COPY_ERROR", "Published image private acquisition failed or changed"); goto done;
    }
    if (!publication_observe(p, "PUBLISHED", "post", post_verify, &r->arms[1].closed)) goto done;
    {
        bool content, times;
        p->post_verified = trial_compare(&r->arms[1].after, &r->arms[1].closed, false, false, &content, &times) && content;
        if (!p->post_verified) { trial_fail(r, "POST_VERIFICATION_FAILED", "Published private observation differs from verified candidate"); goto done; }
    }
    p->retained_unchanged = publication_retained_valid();
    p->final_hash_verified = publication_hash(PFS_ATTRIBUTES_REJECTED, PFS_CANDIDATE_SHA, NULL);
    if (p->final_hash_verified) snprintf(p->final_sha256, sizeof(p->final_sha256), "%s", PFS_CANDIDATE_SHA);
    if (!revalidate(p) || !p->retained_unchanged || !p->final_hash_verified) {
        if (!strcmp(r->result, "RUNNING")) trial_fail(r, "FINAL_VERIFICATION_FAILED", "Final live/retained hash or identity changed");
        goto done;
    }
    r->result = "PUBLISHED_VERIFIED";
    snprintf(r->detail, sizeof(r->detail), "One closed candidate published; observable invariants verified. HMAC cryptography and PS5/game acceptance NOT demonstrated. ACL/xattrs remain UNKNOWN where unavailable.");
done:
    if (strcmp(r->result, "PUBLISHED_VERIFIED")) r->recovery_required = true;
    if (r->evidence_durable) publication_phase(p, &sequence, "terminal");
}
