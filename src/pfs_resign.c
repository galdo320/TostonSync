// TostónSync — kernel-mediated backup/restore. See pfs_resign.h.

#include "pfs_resign.h"
#include "pfs_keys.h"
#include "savemount.h"
#include "sfo.h"
#include "fs.h"
#include "log.h"
#include "sha256.h"
#include "pfs_attributes.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

// --------------------------------------------------------------------
// Filesystem helpers used during a copy. Kept local because they are
// simple enough not to deserve their own module, and using rsync-like
// tree-copy logic from `fs.c` would tempt callers to use it for paths
// outside the staging area.
// --------------------------------------------------------------------

static bool copy_file_bytes(const char* src, const char* dst) {
    int in = open(src, O_RDONLY);
    if (in < 0) return false;
    int out = open(dst, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (out < 0) { close(in); return false; }
    // 64 KB copy buffer on the heap, not the stack: copy_file_bytes runs on
    // the worker during restore and must not depend on stack headroom.
    char* buf = (char*)malloc(65536);
    if (!buf) { close(in); close(out); unlink(dst); return false; }
    ssize_t n;
    bool ok = true;
    while ((n = read(in, buf, 65536)) > 0) {
        ssize_t off = 0;
        while (off < n) {
            ssize_t w = write(out, buf + off, (size_t)(n - off));
            if (w <= 0) { ok = false; break; }
            off += w;
        }
        if (!ok) break;
    }
    if (n < 0) ok = false;
    close(in);
    if (ok && fsync(out) != 0) ok = false;
    if (close(out) != 0) ok = false;
    free(buf);
    if (!ok) unlink(dst);
    return ok;
}

// Remove every file (and empty subdirectory) inside `dir`. The dir
// itself stays. Best-effort; bails out only on a truly stuck entry.
static bool wipe_dir_contents(const char* dir) {
    DIR* d = opendir(dir);
    if (!d) return false;
    struct dirent* e;
    bool ok = true;
    while ((e = readdir(d)) != NULL) {
        if (e->d_name[0] == '.' &&
            (e->d_name[1] == '\0' ||
             (e->d_name[1] == '.' && e->d_name[2] == '\0')))
            continue;
        char p[1024];
        snprintf(p, sizeof(p), "%s/%s", dir, e->d_name);
        struct stat st;
        if (lstat(p, &st) != 0) continue;
        if (S_ISDIR(st.st_mode)) {
            if (!wipe_dir_contents(p)) { ok = false; continue; }
            rmdir(p);
        } else {
            if (unlink(p) != 0) ok = false;
        }
    }
    closedir(d);
    return ok;
}

bool pfs_fs_wipe_contents(const char* dir) {
    return wipe_dir_contents(dir);
}

// Mirror everything in `src` into `dst`. Creates dirs as needed.
// Returns false on any failure. Pre-existing files in `dst` are
// overwritten file-by-file (caller wipes first if a clean install is
// required). Exposed in pfs_resign.h so the watcher can reuse it
// when routing between the kernel-mediated and encrypted-blob paths.
static bool copy_tree(const char* src, const char* dst, bool skip_apple) {
    DIR* d = opendir(src);
    if (!d) return false;
    if (!fs_mkdir_p(dst)) { closedir(d); return false; }
    bool ok = true;
    for (;;) {
        errno = 0;
        struct dirent* e = readdir(d);
        if (!e) { if (errno) ok = false; break; }
        if (e->d_name[0] == '.' &&
            (e->d_name[1] == '\0' ||
             (e->d_name[1] == '.' && e->d_name[2] == '\0')))
            continue;
        // ZIPs created on macOS may carry AppleDouble sidecars. Never import
        // those into a PS5 save mount.
        if (skip_apple && (strcmp(e->d_name, "__MACOSX") == 0 ||
            strcmp(e->d_name, ".DS_Store") == 0 ||
            strncmp(e->d_name, "._", 2) == 0))
            continue;
        char sp[1024], dp[1024];
        int sn = snprintf(sp, sizeof(sp), "%s/%s", src, e->d_name);
        int dn = snprintf(dp, sizeof(dp), "%s/%s", dst, e->d_name);
        struct stat st;
        if (sn < 0 || (size_t)sn >= sizeof(sp) ||
            dn < 0 || (size_t)dn >= sizeof(dp) || lstat(sp, &st) != 0) {
            ok = false;
            break;
        }
        if (S_ISDIR(st.st_mode)) {
            if (!copy_tree(sp, dp, skip_apple)) { ok = false; break; }
        } else if (S_ISREG(st.st_mode)) {
            if (!copy_file_bytes(sp, dp)) { ok = false; break; }
        } else {
            // Refuse unsupported entries, rather than report a successful
            // export/restore after silently omitting part of its source.
            ok = false;
            break;
        }
    }
    if (closedir(d) != 0) ok = false;
    return ok;
}

bool pfs_fs_copy_tree(const char* src, const char* dst) {
    return copy_tree(src, dst, true);
}

void pfs_fs_rmrf(const char* dir) {
    if (!dir || !*dir) return;
    wipe_dir_contents(dir);
    rmdir(dir);
}

// True if `dir` (recursively) contains at least one regular file. Used as a
// safety net before a destructive restore: if a decrypted backup came out
// empty (e.g. the kernel mount silently produced nothing), we must NOT wipe
// the target save to re-seal nothing into it.
bool pfs_fs_dir_has_files(const char* dir) {
    if (!dir) return false;
    DIR* d = opendir(dir);
    if (!d) return false;
    struct dirent* e;
    bool found = false;
    while (!found && (e = readdir(d)) != NULL) {
        if (e->d_name[0] == '.' &&
            (e->d_name[1] == '\0' ||
             (e->d_name[1] == '.' && e->d_name[2] == '\0')))
            continue;
        char p[1024];
        snprintf(p, sizeof(p), "%s/%s", dir, e->d_name);
        struct stat st;
        if (lstat(p, &st) != 0) continue;
        if (S_ISREG(st.st_mode)) found = true;
        else if (S_ISDIR(st.st_mode)) found = pfs_fs_dir_has_files(p);
    }
    closedir(d);
    return found;
}

// Total bytes of all regular files under `dir` (recursive). Used as a restore
// diagnostic: distinguishes an empty decrypt (~0) from a real payload, and lets
// us compare the backup payload against the target container size.
uint64_t pfs_fs_dir_bytes(const char* dir) {
    if (!dir) return 0;
    DIR* d = opendir(dir);
    if (!d) return 0;
    struct dirent* e;
    uint64_t total = 0;
    while ((e = readdir(d)) != NULL) {
        if (e->d_name[0] == '.' &&
            (e->d_name[1] == '\0' ||
             (e->d_name[1] == '.' && e->d_name[2] == '\0')))
            continue;
        char p[1024];
        snprintf(p, sizeof(p), "%s/%s", dir, e->d_name);
        struct stat st;
        if (lstat(p, &st) != 0) continue;
        if (S_ISREG(st.st_mode)) total += (uint64_t)st.st_size;
        else if (S_ISDIR(st.st_mode)) total += pfs_fs_dir_bytes(p);
    }
    closedir(d);
    return total;
}

bool pfs_fs_is_plain_pfs_marker(const char* dir) {
    if (!dir) return false;
    char path[1024];
    snprintf(path, sizeof(path), "%s/.tostonsync_format", dir);
    FILE* f = fopen(path, "r");
    if (!f) return false;
    char line[64] = {0};
    fgets(line, sizeof(line), f);
    fclose(f);
    // strip trailing CR/LF
    size_t L = strlen(line);
    while (L && (line[L-1] == '\n' || line[L-1] == '\r')) line[--L] = '\0';
    // v1 = single flat pfs/ (savedata0.bin). v2/multi-image sdimg backups
    // were experimental and are deliberately not accepted: treating each
    // sdimg_* as an independently re-sealable save corrupts some games.
    return strcmp(line, "plain-pfs-v1") == 0;
}

bool pfs_fs_is_plain_sdimg_marker(const char* dir) {
    if (!dir) return false;
    char path[1024];
    snprintf(path, sizeof(path), "%s/.tostonsync_format", dir);
    FILE* f = fopen(path, "r");
    if (!f) return false;
    char line[64] = {0};
    fgets(line, sizeof(line), f);
    fclose(f);
    size_t L = strlen(line);
    while (L && (line[L-1] == '\n' || line[L-1] == '\r')) line[--L] = '\0';
    return strcmp(line, "plain-sdimg-v1") == 0;
}

// --------------------------------------------------------------------
// Public API.
// --------------------------------------------------------------------

// Find the classic single-image PFS format (`savedata0.bin`). Modern sdimg_*
// titles are handled by dumping each slot to a plain folder set instead.
bool save_find_primary_image(const char* dir, char* out, size_t outsz) {
    if (!dir || !out) return false;
    char p[1024];
    struct stat st;
    snprintf(p, sizeof(p), "%s/savedata0.bin", dir);
    if (stat(p, &st) == 0 && S_ISREG(st.st_mode)) {
        snprintf(out, outsz, "%s", p);
        return true;
    }
    return false;
}

// READ-ONLY verification that the kernel decrypt+mount path actually works on
// this console's saves. Mounts the primary PFS image, counts the decrypted
// bytes, and unmounts — it never writes. The log line tells us whether the
// full universal re-seal feature is buildable on this firmware. Returns true
// if decrypt+mount succeeded.
bool pfs_kernel_probe(const char* save_dir) {
    char img[1024];
    if (!save_find_primary_image(save_dir, img, sizeof(img))) {
        log_warn("pfs: kernel probe — no PFS image found in %s", save_dir);
        return false;
    }
    log_info("pfs: [bc] kernel probe on %s", img);
    uint8_t plain[PFS_PLAIN_KEY_SIZE];
    if (!pfs_decrypt_save_key(img, plain)) {
        log_warn("pfs: [bc] kernel probe — DECRYPT failed for %s "
                 "(ioctl/offset/kstuff)", img);
        return false;
    }
    log_info("pfs: [bc] kernel probe — decrypt OK, mounting");
    savemount_t mnt = {0};
    bool mounted = savemount_mount_inspect(img, plain, &mnt);
    memset(plain, 0, sizeof(plain));
    if (!mounted) {
        log_warn("pfs: [bc] kernel probe — MOUNT failed for %s "
                 "(sceFsMountSaveData)", img);
        return false;
    }
    uint64_t bytes = pfs_fs_dir_bytes(mnt.mount_point);
    log_info("pfs: [bc] kernel probe — MOUNT OK: %s has %llu decrypted bytes "
             "(kernel re-seal IS viable on this save)",
             img, (unsigned long long)bytes);
    savemount_unmount(&mnt);
    return true;
}

// Read/dump: decrypt + mount, parse sce_sys/param.sfo, then unmount without
// application writeback. Native mounts may re-seal their private backing;
// the owner must retain a durable barrier across this kernel operation.
// This is how we recover a slot's authentic metadata (SAVEDATA_DIRECTORY, real
// block counts, account id, the PARAMS HMAC) from a backup image instead of
// guessing from the filename and byte size. Returns:
//   0  parsed OK (out filled),
//  -2  mounted but param.sfo is all-zero (out->zeroed set),
//  -1  decrypt/mount/parse failed (kernel unavailable, game running, etc),
//  PFS_SFO_READ_UNMOUNT_UNCERTAIN when mount/backing must be retained.
int pfs_read_image_param_sfo(const char* image_path, sfo_info_t* out) {
    if (!image_path || !out) return -1;
    memset(out, 0, sizeof(*out));
    uint8_t plain[PFS_PLAIN_KEY_SIZE];
    if (!pfs_decrypt_save_key(image_path, plain)) {
        log_warn("pfs_resign: param.sfo read — cannot unwrap key for %s",
                 image_path);
        return -1;
    }
    savemount_t mnt = {0};
    bool mounted = savemount_mount_inspect(image_path, plain, &mnt);
    memset(plain, 0, sizeof(plain));
    if (!mounted) {
        log_warn("pfs_resign: param.sfo read — mount failed for %s", image_path);
        return -1;
    }
    char sfo_path[1100];
    snprintf(sfo_path, sizeof(sfo_path), "%s/sce_sys/param.sfo",
             mnt.mount_point);
    int r = sfo_parse(sfo_path, out);
    if (!savemount_unmount(&mnt)) {
        memset(out, 0, sizeof(*out));
        log_warn("pfs_resign: param.sfo read — unmount uncertain for %s; "
                 "retained mount=%s backing=%s",
                 image_path, mnt.mount_point, mnt.image_backing);
        return PFS_SFO_READ_UNMOUNT_UNCERTAIN;
    }
    if (r == 0)
        log_info("pfs_resign: param.sfo for %s — dir=%s blocks=%llu",
                 image_path, out->dir_name, (unsigned long long)out->blocks);
    else if (r == -2)
        log_warn("pfs_resign: param.sfo for %s is zeroed/corrupt", image_path);
    else
        log_warn("pfs_resign: no readable param.sfo in %s", image_path);
    return r;
}

// Newest regular-file mtime under `dir` (recursive), as a unix time. 0 if none.
static int64_t newest_mtime_in_dir(const char* dir) {
    DIR* d = opendir(dir);
    if (!d) return 0;
    int64_t newest = 0;
    struct dirent* e;
    while ((e = readdir(d)) != NULL) {
        if (e->d_name[0] == '.' &&
            (e->d_name[1] == '\0' ||
             (e->d_name[1] == '.' && e->d_name[2] == '\0')))
            continue;
        char p[1024];
        snprintf(p, sizeof(p), "%s/%s", dir, e->d_name);
        struct stat st;
        if (lstat(p, &st) != 0) continue;
        if (S_ISREG(st.st_mode)) {
            if ((int64_t)st.st_mtime > newest) newest = (int64_t)st.st_mtime;
        } else if (S_ISDIR(st.st_mode)) {
            int64_t sub = newest_mtime_in_dir(p);
            if (sub > newest) newest = sub;
        }
    }
    closedir(d);
    return newest;
}

// READ-ONLY: mount a sealed image and return the newest internal file mtime —
// the real "how recent is this save" signal the save service writes. Used to
// decide whether a service backup (sce_bu) is actually newer than the active
// slot before promoting it over the active save. Returns true and sets
// *out_unix on success; false (and *out_unix=0) if the image can't be mounted
// or carries no usable mtime.
bool pfs_image_newest_mtime(const char* image_path, int64_t* out_unix) {
    if (out_unix) *out_unix = 0;
    if (!image_path) return false;
    uint8_t plain[PFS_PLAIN_KEY_SIZE];
    if (!pfs_decrypt_save_key(image_path, plain)) return false;
    savemount_t mnt = {0};
    bool mounted = savemount_mount_inspect(image_path, plain, &mnt);
    memset(plain, 0, sizeof(plain));
    if (!mounted) return false;
    int64_t t = newest_mtime_in_dir(mnt.mount_point);
    savemount_unmount(&mnt);
    if (out_unix) *out_unix = t;
    return t > 0;
}

// EXPERIMENTAL, opt-in (crypto.fix_zeroed_sfo). If `image_path`'s
// sce_sys/param.sfo is all-zero, rewrite it from `meta` (+ reused PARAMS
// `hmac`, may be NULL) and re-seal on unmount. This is the ONE narrow case
// where TostónSync re-seals an sdimg image: same image, same key, fixing a
// single corrupt metadata file — NOT importing foreign decrypted contents
// across keys (which is what corrupted saves before). The original param.sfo
// is snapshotted and restored if the rewrite fails. Returns:
//   1  fixed and re-sealed,
//   0  nothing to do (param.sfo was valid, or missing),
//  -1  decrypt/mount/write/reseal failure (image left as-was on best effort).
int pfs_resign_fix_zeroed_sfo(const char* image_path, const sfo_info_t* meta,
                              const uint8_t* hmac, const char* work_dir) {
    if (!image_path || !meta) return -1;
    uint8_t plain[PFS_PLAIN_KEY_SIZE];
    if (!pfs_decrypt_save_key(image_path, plain)) {
        log_warn("pfs_resign: fix_sfo — cannot unwrap key for %s", image_path);
        return -1;
    }
    savemount_t mnt = {0};
    // Write mount: we edit param.sfo inside and need it persisted back to the
    // (possibly savedata_prospero) image, so use the writeback variant.
    bool mounted = savemount_mount_rw(image_path, plain, &mnt);
    memset(plain, 0, sizeof(plain));
    if (!mounted) {
        log_warn("pfs_resign: fix_sfo — mount failed for %s", image_path);
        return -1;
    }

    char sfo_path[1100];
    snprintf(sfo_path, sizeof(sfo_path), "%s/sce_sys/param.sfo",
             mnt.mount_point);

    sfo_info_t cur;
    int pr = sfo_parse(sfo_path, &cur);
    if (pr != -2) {
        // Valid (pr==0) or unreadable/missing (pr==-1): do NOT touch a save
        // whose param.sfo we don't positively know to be zeroed.
        savemount_unmount(&mnt);
        return 0;
    }

    // Snapshot the (zeroed) param.sfo so we can put it back on failure.
    char bak[1200];
    snprintf(bak, sizeof(bak), "%s/param.sfo.bak", work_dir ? work_dir : "/data");
    bool have_bak = copy_file_bytes(sfo_path, bak);

    log_info("pfs_resign: fix_sfo — rewriting zeroed param.sfo for %s "
             "(dir=%s, hmac=%s)", image_path, meta->dir_name,
             hmac ? "reused" : "none");

    if (sfo_write(sfo_path, meta, hmac) != 0) {
        log_warn("pfs_resign: fix_sfo — write failed; rolling back %s", image_path);
        if (have_bak) copy_file_bytes(bak, sfo_path);
        if (have_bak) unlink(bak);
        savemount_unmount(&mnt);   // re-seal the unchanged contents back
        return -1;
    }
    if (have_bak) unlink(bak);

    bool sealed = savemount_unmount(&mnt);  // unmount = re-seal with new SFO
    if (!sealed) {
        log_warn("pfs_resign: fix_sfo — re-seal (unmount) failed for %s",
                 image_path);
        return -1;
    }
    log_info("pfs_resign: fix_sfo — re-sealed %s with rebuilt param.sfo",
             image_path);
    return 1;
}

// Treat sdimg_* as PFS-side images for metadata filtering, but not as safe
// kernel re-seal targets. They belong to a game-managed multi-image set.
static bool is_pfs_image_name(const char* name) {
    return strcmp(name, "savedata0.bin") == 0 || strncmp(name, "sdimg_", 6) == 0;
}

static bool safe_stage_component(const char* s) {
    if (!s || !s[0]) return false;
    if (strcmp(s, ".") == 0 || strcmp(s, "..") == 0) return false;
    for (const unsigned char* p = (const unsigned char*)s; *p; p++) {
        if (*p < 0x20 || *p == 0x7f || *p == '/' || *p == '\\')
            return false;
    }
    return true;
}

static bool is_sdimg_regular_name(const char* name) {
    if (!safe_stage_component(name)) return false;
    if (strncmp(name, "sdimg_", 6) != 0) return false;
    return safe_stage_component(name + 6);
}

static bool sdimg_is_service_backup(const char* name) {
    return is_sdimg_regular_name(name) &&
           strncmp(name + 6, "sce_bu_", 7) == 0;
}

static const char* sdimg_slot_suffix(const char* name) {
    if (!name) return NULL;
    if (sdimg_is_service_backup(name))
        return name + 13; // "sdimg_" + "sce_bu_"
    if (is_sdimg_regular_name(name))
        return name + 6;
    return NULL;
}

// List safe kernel re-seal images in a save dir. Only savedata0.bin is
// supported. sdimg_* is intentionally excluded; see pfs_fs_is_plain_pfs_marker.
static size_t list_pfs_images(const char* dir, char names[][64], size_t max) {
    if (!dir || max == 0) return 0;
    char p[1024];
    struct stat st;
    snprintf(p, sizeof(p), "%s/savedata0.bin", dir);
    if (stat(p, &st) == 0 && S_ISREG(st.st_mode)) {
        snprintf(names[0], 64, "savedata0.bin");
        return 1;
    }
    return 0;
}

// Copy every non-image, non-hidden regular file in `src` to `dst` — the
// param.sfo / icon / other Sony metadata that lives beside the PFS image(s).
static void copy_outside_blob_metadata(const char* src, const char* dst) {
    DIR* d = opendir(src);
    if (!d) return;
    struct dirent* e;
    while ((e = readdir(d)) != NULL) {
        if (e->d_name[0] == '.') continue;
        if (is_pfs_image_name(e->d_name)) continue;
        char sp[1024], dp[1024];
        snprintf(sp, sizeof(sp), "%s/%s", src, e->d_name);
        snprintf(dp, sizeof(dp), "%s/%s", dst, e->d_name);
        struct stat st;
        if (lstat(sp, &st) != 0) continue;
        if (S_ISREG(st.st_mode)) copy_file_bytes(sp, dp);
    }
    closedir(d);
}

static bool restore_metadata_name_allowed(const char* name) {
    if (!name || !*name) return false;
    if (name[0] == '.') return false;
    // Never overwrite the target's own PFS image(s): they carry the target's
    // key, and we re-seal their contents through the kernel mount instead.
    if (is_pfs_image_name(name)) return false;
    // The keystone is tied to the target blob/key. Keeping the target's
    // keystone avoids breaking re-seal when restoring across users or
    // consoles. Backups still keep the source copy for archival value.
    if (strcmp(name, "keystone") == 0) return false;
    return true;
}

// Decrypt + mount `image_path`, copy its decrypted contents into `out_dir`,
// then unmount. Read-only on the image. Returns true on success.
static bool dump_image(const char* image_path, const char* out_dir) {
    uint8_t plain[PFS_PLAIN_KEY_SIZE];
    if (!pfs_decrypt_save_key(image_path, plain)) {
        log_warn("pfs_resign: cannot unwrap key for %s", image_path);
        return false;
    }
    savemount_t mnt = {0};
    bool mounted = savemount_mount_inspect(image_path, plain, &mnt);
    memset(plain, 0, sizeof(plain));
    if (!mounted) return false;
    bool ok = fs_mkdir_p(out_dir) && pfs_fs_copy_tree(mnt.mount_point, out_dir);
    if (ok)
        log_info("pfs_resign: [bc] dumped %llu decrypted bytes from %s",
                 (unsigned long long)pfs_fs_dir_bytes(out_dir), image_path);
    bool unmounted = savemount_unmount(&mnt);
    return ok && unmounted;
}

static bool patch_ps5_param_identity(const char* mount_point,
                                     uint64_t account_id,
                                     uint32_t user_id,
                                     const uint8_t* params_hmac);

// Mount target `image_path`, snapshot its contents, wipe, copy `src_dir` in,
// re-seal on unmount. Rolls back to the snapshot if the copy fails. Keeps the
// target image's own key. The imported title keystone is part of the source
// save tree and must remain byte-identical; replacing it produced mountable
// images that the PS5 and game rejected as corrupt.
static bool reseal_image_with_identity(const char* image_path,
                                       const char* src_dir,
                                       const char* snap_dir,
                                       uint64_t account_id,
                                       uint32_t user_id,
                                       bool patch_identity,
                                       const uint8_t* params_hmac) {
    uint8_t plain[PFS_PLAIN_KEY_SIZE];
    if (!pfs_decrypt_save_key(image_path, plain)) {
        log_warn("pfs_resign: cannot unwrap target key for %s", image_path);
        return false;
    }
    savemount_t mnt = {0};
    // Write mount: this re-seals the slot (wipe + copy + patch identity), so
    // the modified image must be persisted back via the writeback variant.
    // This is also the path that previously mounted a live savedata_prospero
    // image directly and hit EPIPE — staging onto /data fixes that.
    bool mounted = savemount_mount_rw(image_path, plain, &mnt);
    memset(plain, 0, sizeof(plain));
    if (!mounted) return false;

    pfs_fs_rmrf(snap_dir);
    if (!fs_mkdir_p(snap_dir) ||
        !pfs_fs_copy_tree(mnt.mount_point, snap_dir)) {
        log_warn("pfs_resign: could not snapshot %s before restore", image_path);
        pfs_fs_rmrf(snap_dir);
        savemount_unmount(&mnt);
        return false;
    }

    bool ok = wipe_dir_contents(mnt.mount_point);
    if (ok) ok = pfs_fs_copy_tree(src_dir, mnt.mount_point);
    if (ok && patch_identity)
        ok = patch_ps5_param_identity(mnt.mount_point, account_id, user_id,
                                      params_hmac);
    if (!ok) {
        log_warn("pfs_resign: copy failed for %s — rolling back", image_path);
        if (wipe_dir_contents(mnt.mount_point))
            pfs_fs_copy_tree(snap_dir, mnt.mount_point);
        savemount_unmount(&mnt);
        pfs_fs_rmrf(snap_dir);
        return false;
    }

    bool sealed = savemount_unmount(&mnt);  // unmount = re-seal
    if (sealed) sync();
    pfs_fs_rmrf(snap_dir);
    return sealed;
}

static bool reseal_image(const char* image_path, const char* src_dir,
                         const char* snap_dir) {
    return reseal_image_with_identity(image_path, src_dir, snap_dir,
                                      0, 0, false, NULL);
}

static bool patch_ps5_param_identity(const char* mount_point,
                                     uint64_t account_id,
                                     uint32_t user_id,
                                     const uint8_t* params_hmac) {
    if ((!account_id && !user_id && !params_hmac) || !mount_point) return true;
    char sfo_path[1200];
    snprintf(sfo_path, sizeof(sfo_path), "%s/sce_sys/param.sfo",
             mount_point);
    bool ok = sfo_patch_identity_hmac(sfo_path, account_id, user_id,
                                      params_hmac);
    if (ok)
        log_info("pfs_resign: patched PS5 param.sfo destination identity "
                 "(aid=%llx uid=0x%x hmac=%s)",
                 (unsigned long long)account_id, user_id,
                 params_hmac ? "local" : "preserved");
    else
        log_warn("pfs_resign: failed to patch PS5 param.sfo identity");
    return ok;
}

bool pfs_resign_dump_image_to_dir(const char* image_path,
                                  const char* out_dir) {
    if (!image_path || !out_dir) return false;
    pfs_fs_rmrf(out_dir);
    if (!fs_mkdir_p(out_dir)) return false;
    return dump_image(image_path, out_dir);
}

// Recovery needs the complete mounted tree, including empty files/directories
// and names that the normal ZIP-import copy intentionally filters out.
static bool recovery_tree_equal(const char* src, const char* dst, int depth,
                                 size_t* files) {
    if (depth < 0) return false;
    struct stat st;
    if (lstat(src, &st) != 0 || !S_ISDIR(st.st_mode) ||
        (dst && (lstat(dst, &st) != 0 || !S_ISDIR(st.st_mode)))) return false;
    DIR* d = opendir(src);
    if (!d) return false;
    bool ok = true;
    size_t entries = 0;
    for (;;) {
        errno = 0;
        struct dirent* e = readdir(d);
        if (!e) { if (errno) ok = false; break; }
        if (!strcmp(e->d_name, ".") || !strcmp(e->d_name, "..")) continue;
        if (!safe_stage_component(e->d_name)) { ok = false; break; }
        char a[1200], b[1200];
        int an = snprintf(a, sizeof(a), "%s/%s", src, e->d_name);
        int bn = dst ? snprintf(b, sizeof(b), "%s/%s", dst, e->d_name) : 0;
        struct stat other;
        if (an < 0 || (size_t)an >= sizeof(a) || bn < 0 ||
            (size_t)bn >= sizeof(b) || lstat(a, &st) != 0) {
            ok = false; break;
        }
        entries++;
        if (S_ISDIR(st.st_mode)) {
            if (!recovery_tree_equal(a, dst ? b : NULL, depth - 1, files)) {
                ok = false; break;
            }
        } else if (S_ISREG(st.st_mode)) {
            if (++*files > 16384) { ok = false; break; }
            if (dst) {
                char ah[65], bh[65];
                if (lstat(b, &other) != 0 || !S_ISREG(other.st_mode) ||
                    st.st_size != other.st_size || !sha256_file_hex(a, ah) ||
                    !sha256_file_hex(b, bh) || strcmp(ah, bh) != 0) {
                    ok = false; break;
                }
            }
        } else {
            ok = false; break;
        }
    }
    if (closedir(d) != 0) ok = false;
    if (!ok || !dst) return ok;
    d = opendir(dst);
    if (!d) return false;
    size_t copied_entries = 0;
    for (;;) {
        errno = 0;
        struct dirent* e = readdir(d);
        if (!e) { if (errno) ok = false; break; }
        if (strcmp(e->d_name, ".") && strcmp(e->d_name, ".."))
            copied_entries++;
    }
    if (closedir(d) != 0) ok = false;
    return ok && copied_entries == entries;
}

bool pfs_fs_verify_tree(const char* src, const char* dst) {
    size_t files = 0;
    return src && src[0] && dst && dst[0] &&
           recovery_tree_equal(src, dst, 8, &files);
}

static bool recovery_mount_marker(int fd, const char* copied_image,
                                  const char* out_dir, const savemount_t* m) {
    char text[4096];
    int n = snprintf(text, sizeof(text),
                     "image=%s\noutput=%s\nmount=%s\nbacking=%s\n",
                     copied_image, out_dir, m ? m->mount_point : "",
                     m ? m->image_backing : "");
    if (n < 0 || (size_t)n >= sizeof(text) || lseek(fd, 0, SEEK_SET) < 0 ||
        ftruncate(fd, 0) != 0) return false;
    size_t written = 0;
    while (written < (size_t)n) {
        ssize_t r = write(fd, text + written, (size_t)n - written);
        if (r < 0 && errno == EINTR) continue;
        if (r <= 0) return false;
        written += (size_t)r;
    }
    return fsync(fd) == 0;
}

static bool recovery_marker_remove_owned(const char* path,
                                         const struct stat* created) {
    struct stat current;
    // lstat never follows a replacement symlink. This observation is not an
    // atomic defense against an external replacement after the check.
    return created && S_ISREG(created->st_mode) &&
           lstat(path, &current) == 0 && S_ISREG(current.st_mode) &&
           current.st_dev == created->st_dev && current.st_ino == created->st_ino &&
           unlink(path) == 0;
}

bool pfs_resign_recover_image_copy(const char* copied_image,
                                   const char* out_dir,
                                   const char* title_id, const char* slot,
                                   char* err, size_t err_sz) {
    if (err && err_sz) err[0] = '\0';
#define RECOVERY_ERROR(message) do { \
    if (err && err_sz) snprintf(err, err_sz, "%s", (message)); \
} while (0)
    struct stat st;
    if (!copied_image || !copied_image[0] || !out_dir || !out_dir[0] ||
        !title_id || strncmp(title_id, "PPSA", 4) != 0 ||
        !safe_stage_component(slot) || strlen(slot) >= 64 ||
        lstat(copied_image, &st) != 0 || !S_ISREG(st.st_mode)) {
        RECOVERY_ERROR("Invalid disposable PS5 recovery image or slot");
        return false;
    }
    uint8_t sealed[PFS_SEALED_KEY_SIZE], key[PFS_PLAIN_KEY_SIZE];
    bool valid_key = pfs_read_sealed_key(copied_image, sealed);
    memset(sealed, 0, sizeof(sealed));
    if (!valid_key || !pfs_decrypt_save_key(copied_image, key)) {
        memset(key, 0, sizeof(key));
        RECOVERY_ERROR("Recovery image key cannot be unwrapped on this PS5; export portable on the source console");
        return false;
    }
    char marker[1280];
    int mn = snprintf(marker, sizeof(marker), "%s.recovery_mount_pending",
                      copied_image);
    int fd = mn >= 0 && (size_t)mn < sizeof(marker)
        ? open(marker, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW, 0600) : -1;
    if (fd < 0) {
        memset(key, 0, sizeof(key));
        RECOVERY_ERROR("Recovery mount evidence cannot be created; retained workspace must not be reused");
        return false;
    }
    struct stat marker_created;
    if (fstat(fd, &marker_created) != 0 || !S_ISREG(marker_created.st_mode)) {
        close(fd);
        memset(key, 0, sizeof(key));
        RECOVERY_ERROR("Recovery mount evidence ownership is uncertain; image was not mounted");
        return false;
    }
    if (!recovery_mount_marker(fd, copied_image, out_dir, NULL)) {
        close(fd);
        memset(key, 0, sizeof(key));
        RECOVERY_ERROR("Could not persist recovery mount evidence; image was not mounted");
        return false;
    }
    savemount_t m = {0};
    bool mounted = savemount_mount(copied_image, key, &m);
    memset(key, 0, sizeof(key));
    if (!mounted) {
        bool marker_closed = close(fd) == 0;
        // A false mount can retain native resources. Clear only our marker
        // when the mount subsystem positively reports no lifecycle barrier.
        if (!marker_closed || savemount_lifecycle_snapshot() != LIFE_CLEAR ||
            !recovery_marker_remove_owned(marker, &marker_created)) {
            RECOVERY_ERROR("Recovery mount cleanup is uncertain; retained evidence requires reboot before retry");
            return false;
        }
        RECOVERY_ERROR("Recovery image mount failed; no portable artifact was produced");
        return false;
    }
    bool ok = recovery_mount_marker(fd, copied_image, out_dir, &m);
    bool marker_closed = close(fd) == 0;
    if (!marker_closed) ok = false;
    if (!ok) RECOVERY_ERROR("Could not persist mounted recovery evidence");
    // Validate every parent/entry before opening metadata: an imported PFS
    // must not redirect the SFO reader through a symlink outside the mount.
    size_t files = 0;
    if (ok && (!recovery_tree_equal(m.mount_point, NULL, 8, &files) || !files)) {
        ok = false;
        RECOVERY_ERROR("Recovery image has an unsafe or incomplete decrypted inventory");
    }
    char sfo_path[1200], key_path[1200];
    int sn = snprintf(sfo_path, sizeof(sfo_path), "%s/sce_sys/param.sfo",
                      m.mount_point);
    int kn = snprintf(key_path, sizeof(key_path), "%s/sce_sys/keystone",
                      m.mount_point);
    sfo_info_t sfo;
    if (ok && (sn < 0 || (size_t)sn >= sizeof(sfo_path) || kn < 0 ||
               (size_t)kn >= sizeof(key_path) || sfo_parse(sfo_path, &sfo) != 0 ||
               strcmp(sfo.title_id, title_id) != 0 || strcmp(sfo.dir_name, slot) ||
               strcmp(sfo.format, "ppr") || lstat(key_path, &st) != 0 ||
               !S_ISREG(st.st_mode) || st.st_size != 96)) {
        ok = false;
        RECOVERY_ERROR("Recovery image SFO title/directory/PS5 format or keystone is invalid");
    }
    if (ok && (mkdir(out_dir, 0700) != 0 ||
               !copy_tree(m.mount_point, out_dir, false))) {
        ok = false;
        RECOVERY_ERROR("Recovery could not copy every decrypted file; partial output was retained");
    }
    if (ok && !pfs_fs_verify_tree(m.mount_point, out_dir)) {
        ok = false;
        RECOVERY_ERROR("Recovery decrypted inventory or SHA-256 verification failed");
    }
    // A failed unmount retains the marker and copied image. Never delete or
    // recursively inspect the kernel mount point on this path.
    if (!savemount_unmount(&m)) {
        RECOVERY_ERROR("Recovery mount cleanup is uncertain; retained evidence requires reboot before retry");
        return false;
    }
    if (!marker_closed || !recovery_marker_remove_owned(marker, &marker_created)) {
        RECOVERY_ERROR("Recovery mount evidence could not be cleared; output remains unpublished");
        return false;
    }
#undef RECOVERY_ERROR
    return ok;
}

bool pfs_resign_restore_plain_dir_to_image(const char* plain_dir,
                                           const char* target_image_path,
                                           const char* snap_dir) {
    return pfs_resign_restore_plain_dir_to_image_for_user(
        plain_dir, target_image_path, snap_dir, 0, 0);
}

bool pfs_resign_restore_plain_dir_to_image_for_user(const char* plain_dir,
                                                    const char* target_image_path,
                                                    const char* snap_dir,
                                                    uint64_t account_id,
                                                    uint32_t user_id) {
    if (!plain_dir || !target_image_path || !snap_dir) return false;
    uint64_t payload_bytes = pfs_fs_dir_bytes(plain_dir);
    if (payload_bytes == 0) {
        log_warn("pfs_resign: refusing to import empty plain dir into %s",
                 target_image_path);
        return false;
    }

    // PS5 import path: create a fresh PPR/PFS image, mount it with the zero
    // key returned by the create call, copy decrypted files into it, then
    // install that finished encrypted image as sdimg_<SAVEDATA_DIRECTORY>.
    uint64_t image_size = payload_bytes + (payload_bytes / 4) +
                          (4ULL * 1024ULL * 1024ULL);
    if (image_size < 32ULL * 1024ULL * 1024ULL)
        image_size = 32ULL * 1024ULL * 1024ULL;
    image_size = ((image_size + 32767ULL) / 32768ULL) * 32768ULL;

    pfs_fs_rmrf(snap_dir);
    if (!fs_mkdir_p(snap_dir)) return false;

    char new_image[1200];
    char install_tmp[1200];
    snprintf(new_image, sizeof(new_image), "%s/new_ppr_image", snap_dir);
    snprintf(install_tmp, sizeof(install_tmp), "%s.tostonsync_tmp_%ld",
             target_image_path, (long)getpid());

    uint8_t key[32];
    if (!savemount_create_ppr_image(new_image, image_size, key)) {
        pfs_fs_rmrf(snap_dir);
        return false;
    }

    savemount_t mnt = {0};
    if (!savemount_mount(new_image, key, &mnt)) {
        memset(key, 0, sizeof(key));
        pfs_fs_rmrf(snap_dir);
        return false;
    }
    memset(key, 0, sizeof(key));

    // Preserve the complete imported tree, including sce_sys/keystone.
    // Garlic's working PS5 import follows the same create -> mount -> copy-all
    // sequence. A previous TostónSync build put the fresh container's
    // keystone back after this copy; that created a false-success image which
    // mounted cleanly but was rejected by the game.
    bool ok = pfs_fs_copy_tree(plain_dir, mnt.mount_point);
    if (!ok) {
        log_warn("pfs_resign: copy into fresh PPR failed for %s", new_image);
        savemount_unmount(&mnt);
        pfs_fs_rmrf(snap_dir);
        return false;
    }
    if (!patch_ps5_param_identity(mnt.mount_point, account_id, user_id,
                                  NULL)) {
        savemount_unmount(&mnt);
        pfs_fs_rmrf(snap_dir);
        return false;
    }
    ok = savemount_unmount(&mnt);
    if (!ok) {
        pfs_fs_rmrf(snap_dir);
        return false;
    }

    unlink(install_tmp);
    if (!copy_file_bytes(new_image, install_tmp)) {
        log_warn("pfs_resign: could not stage imported image for %s",
                 target_image_path);
        unlink(install_tmp);
        pfs_fs_rmrf(snap_dir);
        return false;
    }
    if (rename(install_tmp, target_image_path) != 0) {
        log_warn("pfs_resign: could not install imported image %s",
                 target_image_path);
        unlink(install_tmp);
        pfs_fs_rmrf(snap_dir);
        return false;
    }
    chmod(target_image_path, 0644);
    sync();
    log_info("pfs_resign: imported %llu decrypted bytes into fresh PPR %s",
             (unsigned long long)payload_bytes, target_image_path);
    pfs_fs_rmrf(snap_dir);
    return true;
}

// Native portable restore modes: references come from the mounted destination,
// never from ZIP permissions, a title-specific table or an exported copy.
static bool native_modes_ignored(const char* path) {
    const char* p = path;
    while (*p) {
        const char* end = strchr(p, '/');
        size_t n = end ? (size_t)(end - p) : strlen(p);
        if ((n == 8 && !memcmp(p, "__MACOSX", 8)) ||
            (n == 9 && !memcmp(p, ".DS_Store", 9)) ||
            (n >= 2 && !memcmp(p, "._", 2))) return true;
        if (!end) break;
        p = end + 1;
    }
    return false; // Exactly the existing tree-copy exclusion, per component.
}

static const pfs_attribute_entry_t* native_modes_entry(
    const pfs_attribute_image_t* image, const char* path) {
    for (size_t i = 0; i < image->count; i++)
        if (!strcmp(image->entries[i].path, path)) return &image->entries[i];
    return NULL;
}

static bool native_modes_capture(const char* mounted_root, const char* plain_root,
                                 pfs_attribute_image_t* plan) {
    pfs_attribute_image_t native = {0};
    bool ok = pfs_attributes_collect(mounted_root, &native) &&
              pfs_attributes_collect(plain_root, plan);
    for (size_t i = 0; ok && i < plan->count; i++) {
        pfs_attribute_entry_t* expected = &plan->entries[i];
        if (native_modes_ignored(expected->path)) continue;
        const pfs_attribute_entry_t* observed = native_modes_entry(&native, expected->path);
        snprintf(plan->error_path, sizeof(plan->error_path), "%s", expected->path);
        if (!observed) { errno = ENOENT; ok = false; break; }
        if ((!S_ISREG(expected->stat.st_mode) && !S_ISDIR(expected->stat.st_mode)) ||
            (expected->stat.st_mode & S_IFMT) != (observed->stat.st_mode & S_IFMT)) {
            errno = EINVAL; ok = false; break;
        }
        expected->stat.st_mode = observed->stat.st_mode;
        log_info("native-modes: captured path=%s mode=%04o inside_PFS=yes",
                 expected->path, (unsigned)(observed->stat.st_mode & 07777));
    }
    if (!ok) {
        plan->error = errno ? errno : EIO;
        if (!plan->error_path[0])
            snprintf(plan->error_path, sizeof(plan->error_path), "%s", native.error_path);
    } else plan->error_path[0] = 0;
    pfs_attributes_image_free(&native);
    return ok;
}

static bool native_modes_apply(const char* root, pfs_attribute_image_t* plan) {
    // Collector order is parent before child. Apply files/children first, root
    // last, after all writes (which can clear special permission bits).
    for (size_t i = plan->count; i > 0; i--) {
        const pfs_attribute_entry_t* entry = &plan->entries[i - 1];
        if (native_modes_ignored(entry->path)) continue;
        char path[1400];
        int n = snprintf(path, sizeof(path), "%s/%s", root, entry->path);
        snprintf(plan->error_path, sizeof(plan->error_path), "%s", entry->path);
        if (n < 0 || (size_t)n >= sizeof(path)) { errno = ENAMETOOLONG; return false; }
        struct stat before, pinned, after;
        if (lstat(path, &before) != 0) return false;
        if ((before.st_mode & S_IFMT) != (entry->stat.st_mode & S_IFMT)) { errno = EINVAL; return false; }
        int fd = open(path, O_RDONLY | O_NOFOLLOW | (S_ISDIR(before.st_mode) ? O_DIRECTORY : 0));
        if (fd < 0) return false;
        bool ok = fstat(fd, &pinned) == 0;
        if (ok && (pinned.st_dev != before.st_dev || pinned.st_ino != before.st_ino)) {
            errno = EIO; ok = false;
        }
        if (ok) ok = fchmod(fd, entry->stat.st_mode & 07777) == 0 && fstat(fd, &after) == 0;
        if (ok && (after.st_mode & 07777) != (entry->stat.st_mode & 07777)) {
            log_warn("native-modes: path=%s expected=%04o observed=%04o after fchmod",
                     entry->path, (unsigned)(entry->stat.st_mode & 07777),
                     (unsigned)(after.st_mode & 07777));
            errno = EIO; ok = false;
        }
        int error = errno;
        if (close(fd) != 0) { ok = false; error = errno; }
        if (!ok) { errno = error ? error : EIO; return false; }
    }
    plan->error_path[0] = 0;
    return true;
}

static bool native_modes_verify(const char* root, pfs_attribute_image_t* plan) {
    pfs_attribute_image_t actual = {0};
    bool ok = pfs_attributes_collect(root, &actual);
    size_t required = 0;
    for (size_t i = 0; ok && i < plan->count; i++) {
        const pfs_attribute_entry_t* expected = &plan->entries[i];
        if (native_modes_ignored(expected->path)) continue;
        required++;
        const pfs_attribute_entry_t* observed = native_modes_entry(&actual, expected->path);
        snprintf(plan->error_path, sizeof(plan->error_path), "%s", expected->path);
        if (!observed || (observed->stat.st_mode & S_IFMT) != (expected->stat.st_mode & S_IFMT) ||
            (observed->stat.st_mode & 07777) != (expected->stat.st_mode & 07777)) {
            log_warn("native-modes: path=%s expected=%04o observed=%04o present=%s",
                     expected->path, (unsigned)(expected->stat.st_mode & 07777),
                     (unsigned)(observed ? observed->stat.st_mode & 07777 : 0),
                     observed ? "yes" : "no");
            errno = EIO; ok = false; break;
        }
        log_info("native-modes: verified path=%s expected=%04o observed=%04o inside_PFS=yes",
                 expected->path, (unsigned)(expected->stat.st_mode & 07777),
                 (unsigned)(observed->stat.st_mode & 07777));
    }
    if (ok && actual.count != required) { errno = EINVAL; ok = false; }
    if (!ok) {
        plan->error = errno ? errno : EIO;
        if (!plan->error_path[0])
            snprintf(plan->error_path, sizeof(plan->error_path), "%s", actual.error_path);
    } else plan->error_path[0] = 0;
    pfs_attributes_image_free(&actual);
    return ok;
}

// Append-only evidence outside PFS. Literal paths are length-prefixed, not
// normalized. A failed evidence write stops before another mount/publication.
static bool native_modes_evidence(pfs_native_restore_report_t* report,
                                   const char* phase, const char* detail,
                                   const pfs_attribute_image_t* plan) {
    if (phase != report->phase)
        snprintf(report->phase, sizeof(report->phase), "%s", phase);
    snprintf(report->detail, sizeof(report->detail), "%s", detail ? detail : "");
    char path[320];
    int n = snprintf(path, sizeof(path), "%s/evidence.txt", report->workspace);
    if (n < 0 || (size_t)n >= sizeof(path)) { errno = ENAMETOOLONG; return false; }
    int fd = open(path, O_WRONLY | O_CREAT | O_APPEND | O_NOFOLLOW, 0600);
    if (fd < 0) return false;
    FILE* file = fdopen(fd, "a");
    if (!file) { close(fd); return false; }
    bool ok = fprintf(file, "phase=%s detail=%s error=%d unmount_uncertain=%d published=%d rename_attempted=%d\n",
                      report->phase, report->detail, report->error,
                      report->unmount_uncertain, report->published, report->rename_attempted) > 0;
    if (plan) for (size_t i = 0; ok && i < plan->count; i++) {
        const pfs_attribute_entry_t* entry = &plan->entries[i];
        if (native_modes_ignored(entry->path)) continue;
        ok = fprintf(file, "path_bytes=%zu mode=%04o type=%s path=", strlen(entry->path),
                     (unsigned)(entry->stat.st_mode & 07777),
                     S_ISDIR(entry->stat.st_mode) ? "directory" : "file") > 0 &&
             fwrite(entry->path, 1, strlen(entry->path), file) == strlen(entry->path) &&
             fputc('\n', file) != EOF;
    }
    if (fflush(file) != 0 || fsync(fd) != 0) ok = false;
    if (fclose(file) != 0) ok = false;
    int dir = open(report->workspace, O_RDONLY | O_DIRECTORY);
    if (dir < 0) return false;
    if (fsync(dir) != 0) ok = false;
    if (close(dir) != 0) ok = false;
    // Persist the new workspace's directory entry too (not just its contents).
    char parent[256];
    snprintf(parent, sizeof(parent), "%s", report->workspace);
    char* slash = strrchr(parent, '/');
    if (slash) *slash = 0; else snprintf(parent, sizeof(parent), ".");
    dir = open(parent[0] ? parent : "/", O_RDONLY | O_DIRECTORY);
    if (dir < 0) return false;
    if (fsync(dir) != 0) ok = false;
    if (close(dir) != 0) ok = false;
    return ok;
}

static bool native_modes_close(savemount_t* mount, pfs_native_restore_report_t* report) {
    // No change to native unmount: private /data copies have no live origin.
    if (savemount_unmount(mount)) return true;
    report->unmount_uncertain = true;
    report->error = errno ? errno : EIO;
    char detail[256];
    snprintf(detail, sizeof(detail), "Uncertain private unmount: mount=%s backing=%s",
             mount->mount_point, mount->image_backing);
    (void)native_modes_evidence(report, "UNMOUNT_UNCERTAIN", detail, NULL);
    return false;
}

static bool native_modes_check_closed(const char* image, const char* label,
                                      const char* expected_sha,
                                      pfs_attribute_image_t* plan,
                                      pfs_native_restore_report_t* report,
                                      pfs_native_restore_validate_fn validate, void* context) {
    pfs_attribute_image_t copy = {0};
    char dump[320];
    int a = snprintf(copy.source, sizeof(copy.source), "%s", image);
    int b = snprintf(copy.copy, sizeof(copy.copy), "%s/%s.img", report->workspace, label);
    int c = snprintf(dump, sizeof(dump), "%s/%s.tree", report->workspace, label);
    if (a < 0 || (size_t)a >= sizeof(copy.source) || b < 0 || (size_t)b >= sizeof(copy.copy) ||
        c < 0 || (size_t)c >= sizeof(dump)) { errno = ENAMETOOLONG; return false; }
    if (!pfs_attributes_copy_private(&copy)) return false;
    if (strcmp(copy.sha256, expected_sha)) { errno = EIO; return false; }
    if (!native_modes_evidence(report, label, copy.sha256, NULL)) return false;
    uint8_t key[PFS_PLAIN_KEY_SIZE] = {0}; savemount_t mount = {0};
    bool keyed = pfs_decrypt_save_key(copy.copy, key);
    bool mounted = keyed && savemount_mount(copy.copy, key, &mount);
    memset(key, 0, sizeof(key));
    if (!mounted) return false;
    // Observe modes directly in PFS, not those of the exported validation tree.
    bool ok = !mount.image_origin[0];
    if (!ok) errno = EINVAL;
    if (ok) ok = native_modes_verify(mount.mount_point, plan) &&
                 fs_mkdir_p(dump) && pfs_fs_copy_tree(mount.mount_point, dump);
    if (ok && !validate(image, dump, context)) {
        errno = EIO; ok = false; // Boolean validators log the exact mismatch.
    }
    int error = errno ? errno : EIO;
    if (!native_modes_close(&mount, report)) return false;
    if (!ok) { errno = error; return false; }
    return true;
}

bool pfs_resign_restore_plain_dir_into_existing_image_for_user_checked(
    const char* plain_dir, const char* target_image_path,
    const char* snap_dir, uint64_t account_id, uint32_t user_id,
    const uint8_t params_hmac[SFO_HMAC_LEN], pfs_native_restore_report_t* report,
    pfs_native_restore_validate_fn validate, void* context,
    const pfs_native_restore_transaction_t* transaction) {
    if (!report) { errno = EINVAL; return false; }
    memset(report, 0, sizeof(*report));
    snprintf(report->phase, sizeof(report->phase), "INPUT");
    if (!plain_dir || !target_image_path || !snap_dir || !params_hmac || !validate ||
        (transaction && (!transaction->publish || !transaction->verified)) ||
        !pfs_fs_dir_has_files(plain_dir)) {
        report->error = EINVAL;
        snprintf(report->detail, sizeof(report->detail), "Portable payload, destination HMAC or validator unavailable");
        return false;
    }
    log_info("pfs_resign: preserving target container/key/HMAC for %s; native per-path modes",
             target_image_path);
    int n = snprintf(report->workspace, sizeof(report->workspace), "%s.native-modes.XXXXXX", snap_dir);
    if (n < 0 || (size_t)n >= sizeof(report->workspace) || !mkdtemp(report->workspace)) {
        report->error = errno ? errno : ENAMETOOLONG;
        report->workspace[0] = 0;
        snprintf(report->detail, sizeof(report->detail), "Could not create private native-mode evidence workspace");
        return false;
    }
    pfs_attribute_image_t candidate = {0}, plan = {0};
    savemount_t mount = {0}; bool mounted = false, ok = false;
    uint8_t key[PFS_PLAIN_KEY_SIZE] = {0};
    char closed_sha[65] = {0}, live_sha[65] = {0};
    int a = snprintf(candidate.source, sizeof(candidate.source), "%s", target_image_path);
    int b = snprintf(candidate.copy, sizeof(candidate.copy), "%s/CANDIDATE.img", report->workspace);
    if (a < 0 || (size_t)a >= sizeof(candidate.source) || b < 0 || (size_t)b >= sizeof(candidate.copy)) {
        errno = ENAMETOOLONG; goto done;
    }
    if (!native_modes_evidence(report, "ACQUIRE", target_image_path, NULL) ||
        !pfs_attributes_copy_private(&candidate) ||
        !native_modes_evidence(report, "NATIVE_MOUNT", candidate.sha256, NULL) ||
        !pfs_decrypt_save_key(candidate.copy, key)) goto done;
    mounted = savemount_mount(candidate.copy, key, &mount);
    memset(key, 0, sizeof(key));
    if (!mounted) goto done;
    if (mount.image_origin[0]) { errno = EINVAL; goto done; }
    if (!native_modes_evidence(report, "CAPTURE_NATIVE_MODES", "Before wipe", NULL) ||
        !native_modes_capture(mount.mount_point, plain_dir, &plan) ||
        !native_modes_evidence(report, "NATIVE_REFERENCE", "Captured inside destination PFS before wipe", &plan)) goto done;
    if (!native_modes_evidence(report, "RECREATE_PRIVATE_TREE", "Original remains untouched", NULL) ||
        !wipe_dir_contents(mount.mount_point) || !pfs_fs_copy_tree(plain_dir, mount.mount_point) ||
        !patch_ps5_param_identity(mount.mount_point, account_id, user_id, params_hmac) ||
        !native_modes_evidence(report, "APPLY_NATIVE_MODES", "Literal per-path destination modes", NULL) ||
        !native_modes_apply(mount.mount_point, &plan) ||
        !native_modes_evidence(report, "VERIFY_PRIVATE_MODES", "Before unmount", NULL) ||
        !native_modes_verify(mount.mount_point, &plan)) goto done;
    report->modes_pre_verified = true;
    if (!native_modes_evidence(report, "MODES_PRE_VERIFIED", "Before private candidate unmount", &plan)) goto done;
    if (!native_modes_close(&mount, report)) { mounted = false; goto done; }
    mounted = false;
    struct stat closed;
    if (lstat(candidate.copy, &closed) != 0) goto done;
    if (!S_ISREG(closed.st_mode) || closed.st_size != candidate.outer_before.st_size) {
        errno = EIO; goto done;
    }
    if (!sha256_file_hex(candidate.copy, closed_sha)) goto done;
    if (!native_modes_check_closed(candidate.copy, "CLOSED_CHECK", closed_sha, &plan, report, validate, context)) goto done;
    report->modes_closed_verified = true;
    if (!native_modes_evidence(report, "MODES_CLOSED_VERIFIED", closed_sha, &plan)) goto done;
    // The existing closed-candidate publication primitive remains unchanged.
    if (!native_modes_evidence(report, "PUBLISH_CLOSED_CANDIDATE", closed_sha, NULL) ||
        !(transaction
            ? transaction->publish(transaction->context, candidate.copy,
                target_image_path, closed_sha, candidate.sha256, &report->rename_attempted)
            : savemount_publish_closed_candidate(candidate.copy, target_image_path,
                closed_sha, candidate.sha256, &report->rename_attempted))) goto done;
    report->published = true;
    if (!native_modes_evidence(report, "PUBLISHED", closed_sha, NULL) ||
        !native_modes_check_closed(target_image_path, "POST_CHECK", closed_sha, &plan, report, validate, context)) goto done;
    report->modes_post_verified = true;
    if (!sha256_file_hex(target_image_path, live_sha) || strcmp(live_sha, closed_sha)) { errno = EIO; goto done; }
    ok = native_modes_evidence(report, "VERIFIED", live_sha, &plan) &&
        (!transaction || transaction->verified(transaction->context, target_image_path, live_sha));
done:
    memset(key, 0, sizeof(key));
    if (!ok && !report->unmount_uncertain) {
        report->error = errno ? errno : EIO;
        char detail[256];
        snprintf(detail, sizeof(detail), "Native mode/content validation stopped: path=%.160s errno=%d",
                 plan.error_path[0] ? plan.error_path : "(see phase)", report->error);
        (void)native_modes_evidence(report, report->phase, detail, NULL);
    }
    if (mounted && !native_modes_close(&mount, report)) ok = false;
    pfs_attributes_image_free(&plan);
    // Keep encrypted candidate, verification copies and evidence on every exit.
    // The existing caller owns snapshots/barriers and releases them only on success.
    return ok;
}

bool pfs_resign_restore_plain_dir_into_existing_image_for_user(
    const char* plain_dir, const char* target_image_path,
    const char* snap_dir, uint64_t account_id, uint32_t user_id,
    const uint8_t params_hmac[SFO_HMAC_LEN], pfs_native_restore_report_t* report,
    pfs_native_restore_validate_fn validate, void* context) {
    return pfs_resign_restore_plain_dir_into_existing_image_for_user_checked(
        plain_dir, target_image_path, snap_dir, account_id, user_id, params_hmac,
        report, validate, context, NULL);
}

static bool copy_restore_metadata(const char* src, const char* dst) {
    DIR* d = opendir(src);
    if (!d) return false;
    struct dirent* e;
    bool ok = true;
    while ((e = readdir(d)) != NULL) {
        if (!restore_metadata_name_allowed(e->d_name)) continue;
        char sp[1024], dp[1024];
        snprintf(sp, sizeof(sp), "%s/%s", src, e->d_name);
        snprintf(dp, sizeof(dp), "%s/%s", dst, e->d_name);
        struct stat st;
        if (lstat(sp, &st) != 0) { ok = false; continue; }
        if (!S_ISREG(st.st_mode)) continue;
        if (!copy_file_bytes(sp, dp)) ok = false;
    }
    closedir(d);
    return ok;
}

bool pfs_resign_backup_to_staging(const char* source_save_dir,
                                  const char* staging_dir) {
    if (!source_save_dir || !staging_dir) return false;

    char images[8][64];
    size_t n = list_pfs_images(source_save_dir, images, 8);
    if (n == 0) {
        log_warn("pfs_resign: no supported PFS image (savedata0.bin) in %s",
                 source_save_dir);
        return false;
    }
    log_info("pfs_resign: [bc] BACKUP start — %zu image(s) in %s",
             n, source_save_dir);

    if (!fs_mkdir_p(staging_dir)) return false;
    wipe_dir_contents(staging_dir);

    char pfs_root[1100], meta_dir[1100];
    snprintf(pfs_root, sizeof(pfs_root), "%s/pfs",  staging_dir);
    snprintf(meta_dir, sizeof(meta_dir), "%s/meta", staging_dir);
    fs_mkdir_p(pfs_root);
    fs_mkdir_p(meta_dir);

    // Decrypt + dump the supported single image into pfs/<imagename>/.
    bool ok = true;
    for (size_t i = 0; i < n && ok; i++) {
        char img[1200], out[1200];
        snprintf(img, sizeof(img), "%s/%s", source_save_dir, images[i]);
        snprintf(out, sizeof(out), "%s/%s", pfs_root, images[i]);
        log_info("pfs_resign: [bc] dumping image %s", images[i]);
        ok = dump_image(img, out);
        if (!ok) log_warn("pfs_resign: failed to dump %s", images[i]);
    }

    copy_outside_blob_metadata(source_save_dir, meta_dir);

    char marker[1024];
    snprintf(marker, sizeof(marker), "%s/.tostonsync_format", staging_dir);
    FILE* f = fopen(marker, "w");
    if (f) { fputs("plain-pfs-v1\n", f); fclose(f); }
    return ok;
}

bool pfs_resign_backup_sdimg_to_staging(const char* source_save_dir,
                                        const char* staging_dir) {
    if (!source_save_dir || !staging_dir) return false;

    if (!fs_mkdir_p(staging_dir)) return false;
    wipe_dir_contents(staging_dir);

    char slots_root[1100], service_root[1100];
    snprintf(slots_root, sizeof(slots_root), "%s/slots", staging_dir);
    snprintf(service_root, sizeof(service_root), "%s/service", staging_dir);
    if (!fs_mkdir_p(slots_root) || !fs_mkdir_p(service_root))
        return false;

    DIR* d = opendir(source_save_dir);
    if (!d) return false;

    size_t dumped_active = 0;
    size_t dumped_service = 0;
    bool ok = true;
    for (;;) {
        errno = 0;
        struct dirent* e = readdir(d);
        if (!e) { if (errno) ok = false; break; }
        if (!is_sdimg_regular_name(e->d_name)) continue;
        char img[1200];
        int in = snprintf(img, sizeof(img), "%s/%s", source_save_dir, e->d_name);
        struct stat st;
        if (in < 0 || (size_t)in >= sizeof(img) ||
            lstat(img, &st) != 0 || !S_ISREG(st.st_mode)) {
            ok = false;
            break;
        }

        const char* suffix = sdimg_slot_suffix(e->d_name);
        if (!safe_stage_component(suffix)) {
            log_warn("pfs_resign: refusing sdimg with unsafe suffix: %s",
                     e->d_name);
            ok = false;
            break;
        }

        char out[1200];
        if (sdimg_is_service_backup(e->d_name)) {
            snprintf(out, sizeof(out), "%s/%s", service_root, suffix);
            dumped_service++;
        } else {
            snprintf(out, sizeof(out), "%s/%s", slots_root, suffix);
            dumped_active++;
        }

        log_info("pfs_resign: [bc] dumping sdimg %s -> %s",
                 e->d_name, out);
        pfs_fs_rmrf(out);
        if (!dump_image(img, out)) {
            log_warn("pfs_resign: failed to dump sdimg %s", e->d_name);
            ok = false;
            break;
        }
    }
    if (closedir(d) != 0) ok = false;

    if (ok && dumped_active == 0 && dumped_service == 0) {
        log_warn("pfs_resign: no sdimg_* images in %s", source_save_dir);
        ok = false;
    }

    if (ok) {
        char marker[1024];
        snprintf(marker, sizeof(marker), "%s/.tostonsync_format",
                 staging_dir);
        FILE* f = fopen(marker, "w");
        if (!f) {
            ok = false;
        } else {
            fputs("plain-sdimg-v1\n", f);
            fclose(f);
        }
    }

    if (ok)
        log_info("pfs_resign: sdimg backup staged as plain-sdimg-v1 "
                 "(%zu active, %zu service)",
                 dumped_active, dumped_service);
    return ok;
}

bool pfs_resign_restore_from_staging(const char* staging_dir,
                                     const char* target_save_dir) {
    if (!staging_dir || !target_save_dir) return false;

    struct stat st;
    char pfs_root[1100];
    snprintf(pfs_root, sizeof(pfs_root), "%s/pfs", staging_dir);
    if (stat(pfs_root, &st) != 0 || !S_ISDIR(st.st_mode)) {
        log_warn("pfs_resign: staging dir %s has no pfs/ subdir", staging_dir);
        return false;
    }

    // v2 backups store pfs/<imagename>/ per image; v1 (legacy) stored a flat
    // pfs/ for a single savedata0.bin. Detect which by looking for image-name
    // subdirs under pfs/.
    char images[8][64];
    size_t n = 0;
    DIR* d = opendir(pfs_root);
    if (d) {
        struct dirent* e;
        while ((e = readdir(d)) != NULL && n < 8) {
            if (e->d_name[0] == '.') continue;
            if (!is_pfs_image_name(e->d_name)) continue;
            char sp[1200];
            snprintf(sp, sizeof(sp), "%s/%s", pfs_root, e->d_name);
            struct stat s2;
            if (lstat(sp, &s2) == 0 && S_ISDIR(s2.st_mode))
                snprintf(images[n++], 64, "%s", e->d_name);
        }
        closedir(d);
    }

    char snap[1200];
    snprintf(snap, sizeof(snap), "%s/.target_backup", staging_dir);
    bool ok = true;

    if (n > 0) {
        log_warn("pfs_resign: refusing plain-pfs-v2/multi-image restore for "
                 "%s — sdimg_* re-seal is disabled to avoid corrupting saves",
                 target_save_dir);
        return false;
    } else {
        // v1 legacy: flat pfs/ -> single savedata0.bin.
        char tgt[1200];
        snprintf(tgt, sizeof(tgt), "%s/savedata0.bin", target_save_dir);
        if (stat(tgt, &st) != 0) {
            log_warn("pfs_resign: target savedata0.bin missing — recreate the "
                     "save in-game first, then restore");
            return false;
        }
        ok = reseal_image(tgt, pfs_root, snap);
    }

    if (ok) {
        char meta_dir[1100];
        snprintf(meta_dir, sizeof(meta_dir), "%s/meta", staging_dir);
        if (stat(meta_dir, &st) == 0 && S_ISDIR(st.st_mode)) {
            if (!copy_restore_metadata(meta_dir, target_save_dir))
                log_warn("pfs_resign: restored PFS but some metadata not copied");
        }
    }
    return ok;
}
