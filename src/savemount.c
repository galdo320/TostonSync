// TostónSync — savedata mount/unmount. See savemount.h.

#include "savemount.h"
#include "fs.h"
#include "log.h"
#include "pfs_attributes.h"
#include "sha256.h"

#include <errno.h>
#include <dlfcn.h>
#include <fcntl.h>
#include <limits.h>
#include <pthread.h>
#include <ps5/kernel.h>
#include <signal.h>
#include <stdatomic.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

// --- Sony API surface ------------------------------------------------
//
// The pinned SDK supplies import symbols, not savedata prototypes or option
// definitions. These local declarations reflect the existing mount/PPR path;
// compiling against its stubs does NOT validate a native creator's ABI,
// detached creation, ownership/HMAC or savedata.db registration contract.
// Do not infer new transaction signatures from exported names.

// SaveData mount options are not exposed by the public SDK headers.
// The only field we need to set is budgetid; the rest stays opaque and
// is initialized by sceFsInit* below.
typedef struct {
    unsigned char reserved;
    unsigned char _pad[7];
    const char* budgetid;
    unsigned char _opaque[0xf0];
} pfs_mount_opt_t;

_Static_assert(offsetof(pfs_mount_opt_t, budgetid) == 8,
               "pfs_mount_opt_t.budgetid must stay at ABI offset 8");

typedef struct { unsigned char _opaque[0x100]; } pfs_umount_opt_t;
typedef struct {
    int blockSize;
    unsigned char flags[2];
    unsigned char _opaque[0xf8];
} pfs_create_opt_t;
typedef int (*pfs_ppr_create_fn)(pfs_create_opt_t* opt,
                                 const char* image_path,
                                 int unk,
                                 uint64_t image_size,
                                 uint8_t* key);

extern void sceFsInitMountSaveDataOpt(pfs_mount_opt_t* opt);
extern int  sceFsMountSaveData(pfs_mount_opt_t* opt,
                               const char* image_path,
                               const char* mount_point,
                               const unsigned char* plain_key);
extern void sceFsInitUmountSaveDataOpt(pfs_umount_opt_t* opt);
extern int  sceFsUmountSaveData(pfs_umount_opt_t* opt,
                                const char* mount_point,
                                int handle,
                                int flags);
extern void sceFsInitCreatePfsSaveDataOpt(pfs_create_opt_t* opt);
extern int  sceFsUfsAllocateSaveData(int fd,
                                     uint64_t image_size,
                                     uint64_t flags,
                                     int ext);

// --------------------------------------------------------------------

#define MOUNT_BASE "/data/tostonsync/mounts"
#define SAVEMOUNT_AUTHID 0x4800000000000010ULL

static atomic_uint s_slot_next = 0;
static pthread_mutex_t s_mount_lock = PTHREAD_MUTEX_INITIALIZER;
static atomic_uint s_lifecycle_mounts = 0;
static atomic_bool s_lifecycle_mount_uncertain = false;
static pfs_ppr_create_fn s_ppr_create = NULL;

typedef struct savemount_owner {
    savemount_t* caller;
    savemount_t snapshot;
    struct stat base, directory, mounted, backing;
    bool directory_owned, backing_owned, native_attempted, mounted_known;
    bool unmount_attempted;
    struct savemount_owner* next;
} savemount_owner_t;

static savemount_owner_t* s_mount_owners = NULL;

static bool savemount_handle_same(const savemount_t* a, const savemount_t* b) {
    return a->handle == b->handle && a->writeback == b->writeback &&
        !memcmp(a->mount_point, b->mount_point, sizeof(a->mount_point)) &&
        !memcmp(a->image_backing, b->image_backing, sizeof(a->image_backing)) &&
        !memcmp(a->image_origin, b->image_origin, sizeof(a->image_origin));
}

static savemount_owner_t* savemount_owner_find(const savemount_t* caller) {
    for (savemount_owner_t* owner = s_mount_owners; owner; owner = owner->next)
        if (owner->caller == caller) return owner;
    return NULL;
}

static void savemount_owner_release(savemount_owner_t* owner) {
    savemount_owner_t** link = &s_mount_owners;
    while (*link && *link != owner) link = &(*link)->next;
    if (*link) *link = owner->next;
    free(owner);
}

static bool savemount_identity(const char* path, const struct stat* pinned,
                                mode_t type) {
    struct stat current;
    return lstat(path, &current) == 0 && (current.st_mode & S_IFMT) == type &&
        current.st_dev == pinned->st_dev && current.st_ino == pinned->st_ino;
}

static bool savemount_base(struct stat* pinned) {
    char parent[SAVEMOUNT_PATH_MAX], resolved[PATH_MAX];
    snprintf(parent, sizeof(parent), "%s", MOUNT_BASE);
    char* slash = strrchr(parent, '/');
    if (!slash) return false;
    *slash = 0;
    struct stat st;
    if (!realpath(parent, resolved) || strcmp(parent, resolved) ||
        lstat(parent, &st) != 0 || !S_ISDIR(st.st_mode)) return false;
    errno = 0;
    if (lstat(MOUNT_BASE, &st) != 0 &&
        (errno != ENOENT || mkdir(MOUNT_BASE, 0700) != 0)) return false;
    return lstat(MOUNT_BASE, pinned) == 0 && S_ISDIR(pinned->st_mode) &&
        realpath(MOUNT_BASE, resolved) && !strcmp(MOUNT_BASE, resolved);
}

life_check_t savemount_lifecycle_snapshot(void) {
    int locked = pthread_mutex_trylock(&s_mount_lock);
    if (locked) return locked == EBUSY ? LIFE_BUSY : LIFE_UNKNOWN;
    pthread_mutex_unlock(&s_mount_lock);
    if (atomic_load(&s_lifecycle_mount_uncertain)) return LIFE_UNKNOWN;
    return atomic_load(&s_lifecycle_mounts) ? LIFE_BUSY : LIFE_CLEAR;
}

typedef struct {
    pid_t pid;
    uint64_t authid;
    uint8_t caps[16];
    uid_t uid;
    uid_t ruid;
    uid_t svuid;
    bool have_authid;
    bool have_caps;
    bool have_uids;
} savemount_cred_snapshot_t;

// Stream-copy a file. Used by the EPIPE workaround to stage an image onto
// /data before mounting (and to copy a re-sealed image back afterwards).
static bool copy_file_bytes(const char* src, const char* dst) {
    int in = open(src, O_RDONLY);
    if (in < 0) return false;
    int out = open(dst, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (out < 0) { close(in); return false; }
    char buf[65536];
    ssize_t n;
    bool ok = true;
    while ((n = read(in, buf, sizeof(buf))) > 0) {
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
    if (close(out) != 0) ok = false;
    if (!ok) unlink(dst);
    return ok;
}

static void block_sigpipe_for_this_thread(void) {
    sigset_t set;
    sigemptyset(&set);
    sigaddset(&set, SIGPIPE);
    pthread_sigmask(SIG_BLOCK, &set, NULL);
}

static bool elevate_savedata_creds(savemount_cred_snapshot_t* snap) {
    if (!snap) return false;
    memset(snap, 0, sizeof(*snap));
    snap->pid = getpid();

    snap->authid = kernel_get_ucred_authid(snap->pid);
    snap->have_authid = (snap->authid != 0);
    snap->have_caps = (kernel_get_ucred_caps(snap->pid, snap->caps) == 0);
    snap->uid = kernel_get_ucred_uid(snap->pid);
    snap->ruid = kernel_get_ucred_ruid(snap->pid);
    snap->svuid = kernel_get_ucred_svuid(snap->pid);
    snap->have_uids = true;

    if (!snap->have_authid || !snap->have_caps) {
        log_warn("savemount: cannot snapshot process credentials");
        return false;
    }

    uint8_t caps[16];
    memcpy(caps, snap->caps, sizeof(caps));
    caps[7] |= 0x40; // LOGIN_SETUSER: permits setuid(0) for savedata mount.

    bool ok = true;
    if (kernel_set_ucred_authid(snap->pid, SAVEMOUNT_AUTHID) != 0) ok = false;
    if (kernel_set_ucred_caps(snap->pid, caps) != 0) ok = false;
    if (setuid(0) != 0) {
        // Keep the syscall path first, but fall back to direct ucred
        // writes when the payload environment does not allow setuid.
        if (kernel_set_ucred_uid(snap->pid, 0) != 0) ok = false;
        if (kernel_set_ucred_ruid(snap->pid, 0) != 0) ok = false;
        if (kernel_set_ucred_svuid(snap->pid, 0) != 0) ok = false;
    }
    return ok;
}

static void restore_savedata_creds(const savemount_cred_snapshot_t* snap) {
    if (!snap) return;
    if (snap->have_uids) {
        kernel_set_ucred_uid(snap->pid, snap->uid);
        kernel_set_ucred_ruid(snap->pid, snap->ruid);
        kernel_set_ucred_svuid(snap->pid, snap->svuid);
    }
    if (snap->have_caps)
        kernel_set_ucred_caps(snap->pid, snap->caps);
    if (snap->have_authid)
        kernel_set_ucred_authid(snap->pid, snap->authid);
}

static pfs_ppr_create_fn load_ppr_create(void) {
    if (s_ppr_create) return s_ppr_create;
    void* vsh = dlopen("libSceFsInternalForVsh.sprx", RTLD_LAZY);
    if (!vsh) {
        log_warn("savemount: cannot open libSceFsInternalForVsh.sprx");
        return NULL;
    }
    s_ppr_create = (pfs_ppr_create_fn)dlsym(vsh,
                                            "sceFsCreatePprPfsSaveDataImage");
    if (!s_ppr_create)
        log_warn("savemount: sceFsCreatePprPfsSaveDataImage not found");
    return s_ppr_create;
}

static bool savemount_create_ppr_image_impl(const char* image_path,
                                uint64_t image_size,
                                uint8_t out_key[32]) {
    if (!image_path || !out_key || image_size == 0) return false;
    memset(out_key, 0, 32);
    pfs_ppr_create_fn ppr_create = load_ppr_create();
    if (!ppr_create) return false;

    unlink(image_path);
    int fd = open(image_path, O_CREAT | O_TRUNC | O_RDWR, 0600);
    if (fd < 0) {
        log_warn("savemount: cannot create PPR image %s", image_path);
        return false;
    }

    block_sigpipe_for_this_thread();
    pthread_mutex_lock(&s_mount_lock);
    savemount_cred_snapshot_t creds;
    bool elevated = elevate_savedata_creds(&creds);
    int ar = elevated ? sceFsUfsAllocateSaveData(fd, image_size, 0, 0) : -1;
    if (ar < 0) {
        log_warn("savemount: UfsAllocate failed for %s (ret=%d); using ftruncate",
                 image_path, ar);
        if (ftruncate(fd, (off_t)image_size) != 0) {
            restore_savedata_creds(&creds);
            pthread_mutex_unlock(&s_mount_lock);
            close(fd);
            unlink(image_path);
            return false;
        }
    }
    close(fd);

    pfs_create_opt_t opt;
    memset(&opt, 0, sizeof(opt));
    sceFsInitCreatePfsSaveDataOpt(&opt);
    opt.flags[1] = 0x02;  // PPR/compressed PS5 savedata image.
    int ret = elevated ? ppr_create(&opt, image_path, 0, image_size, out_key)
                       : -1;
    restore_savedata_creds(&creds);
    pthread_mutex_unlock(&s_mount_lock);

    if (!elevated) {
        log_warn("savemount: could not elevate credentials for PPR create");
        unlink(image_path);
        return false;
    }
    if (ret < 0) {
        log_warn("savemount: PPR create failed for %s (ret=%d)",
                 image_path, ret);
        unlink(image_path);
        return false;
    }
    log_info("savemount: created PPR image %s (%llu bytes)",
             image_path, (unsigned long long)image_size);
    return true;
}

static bool mount_impl_body(const char* image_path,
                       const uint8_t plain_key[32],
                       bool writeback, bool inspection,
                       savemount_t* out) {
    if (!image_path || !plain_key || !out ||
        strlen(image_path) >= SAVEMOUNT_PATH_MAX) return false;
    pthread_mutex_lock(&s_mount_lock);
    if (savemount_owner_find(out) || atomic_load(&s_lifecycle_mount_uncertain)) {
        pthread_mutex_unlock(&s_mount_lock);
        return false;
    }
    savemount_owner_t* owner = calloc(1, sizeof(*owner));
    if (!owner) { pthread_mutex_unlock(&s_mount_lock); return false; }
    owner->caller = out;
    owner->next = s_mount_owners;
    s_mount_owners = owner;
    memset(out, 0, sizeof(*out));
    if (!savemount_base(&owner->base)) goto before_native_failure;
    unsigned slot = atomic_fetch_add(&s_slot_next, 1);
    int length = snprintf(out->mount_point, sizeof(out->mount_point),
                          "%s/m%u", MOUNT_BASE, slot);
    if (length < 0 || (size_t)length >= sizeof(out->mount_point) ||
        mkdir(out->mount_point, 0700) != 0) goto before_native_failure;
    if (lstat(out->mount_point, &owner->directory) != 0 ||
        !S_ISDIR(owner->directory.st_mode)) {
        atomic_store(&s_lifecycle_mount_uncertain, true);
        goto retained_failure;
    }
    owner->directory_owned = true;

    // EPIPE workaround: sceFsMountSaveData fails with EPIPE when the image
    // lives under /user/home/.../savedata_prospero (confirmed by the
    // ps5-payload-manager reference: "Direct mount from savedata_prospero
    // causes EPIPE"). If the image is not already on /data, stage a copy
    // onto /data and mount that instead. Inspection always copies, even on
    // /data: native mounts can rewrite headers. On unmount we copy back when
    // `writeback` is set (re-seal/write mounts only — read/dump mounts must
    // never rewrite the live save).
    const char* to_mount = image_path;
    out->writeback = writeback;
    if (inspection || strncmp(image_path, "/data/", 6) != 0) {
        length = snprintf(out->image_backing, sizeof(out->image_backing),
                          "%s/work_m%u.img", MOUNT_BASE, slot);
        if (length < 0 || (size_t)length >= sizeof(out->image_backing))
            goto before_native_failure;
        pfs_attribute_image_t copy = {0};
        snprintf(copy.source, sizeof(copy.source), "%s", image_path);
        snprintf(copy.copy, sizeof(copy.copy), "%s", out->image_backing);
        if (!pfs_attributes_copy_private(&copy)) {
            log_warn("savemount: cannot stage %s onto /data for mount",
                     image_path);
            // The helper retains partial files and does not transfer ownership on failure.
            goto before_native_failure;
        }
        if (lstat(out->image_backing, &owner->backing) != 0 ||
            !S_ISREG(owner->backing.st_mode)) {
            atomic_store(&s_lifecycle_mount_uncertain, true);
            goto retained_failure;
        }
        owner->backing_owned = true;
        snprintf(out->image_origin, sizeof(out->image_origin),
                 "%s", image_path);
        to_mount = out->image_backing;
        log_info("savemount: staged %s -> %s (EPIPE-safe, writeback=%d)",
                 image_path, out->image_backing, writeback);
    }

    pfs_mount_opt_t opt;
    memset(&opt, 0, sizeof(opt));
    sceFsInitMountSaveDataOpt(&opt);
    opt.budgetid = "system";

    // SIGPIPE disposition is process-global, so never flip it with
    // signal() from a worker. Block it only in this thread and serialize
    // sceFs mount calls. Credentials are process-global too, so the
    // elevation window is kept inside the same lock.
    block_sigpipe_for_this_thread();
    if (!savemount_identity(MOUNT_BASE, &owner->base, S_IFDIR) ||
        !savemount_identity(out->mount_point, &owner->directory, S_IFDIR) ||
        (owner->backing_owned &&
         !savemount_identity(out->image_backing, &owner->backing, S_IFREG))) {
        atomic_store(&s_lifecycle_mount_uncertain, true);
        goto retained_failure;
    }
    log_info("savemount: [bc] elevating creds for %s", to_mount);
    savemount_cred_snapshot_t creds;
    bool elevated = elevate_savedata_creds(&creds);
    log_info("savemount: [bc] elevated=%d, calling sceFsMountSaveData",
             elevated);
    owner->native_attempted = elevated;
    int ret = elevated
        ? sceFsMountSaveData(&opt, to_mount, out->mount_point, plain_key)
        : -1;
    log_info("savemount: [bc] sceFsMountSaveData returned %d", ret);
    restore_savedata_creds(&creds);

    if (!elevated)
        log_warn("savemount: could not elevate credentials for savedata mount");
    if (ret < 0) {
        log_warn("savemount: mount %s at %s failed (ret=%d)",
                 to_mount, out->mount_point, ret);
        if (!owner->native_attempted) goto before_native_failure;
        atomic_store(&s_lifecycle_mount_uncertain, true);
        goto retained_failure;
    }

    out->handle = ret;
    atomic_fetch_add(&s_lifecycle_mounts, 1);
    if (lstat(out->mount_point, &owner->mounted) != 0 ||
        !S_ISDIR(owner->mounted.st_mode)) {
        atomic_store(&s_lifecycle_mount_uncertain, true);
        goto retained_failure;
    }
    owner->mounted_known = true;
    owner->snapshot = *out;
    log_info("savemount: mounted %s -> %s (handle=%d)",
             to_mount, out->mount_point, ret);
    pthread_mutex_unlock(&s_mount_lock);
    return true;

before_native_failure:
    if (owner->backing_owned &&
        (!savemount_identity(MOUNT_BASE, &owner->base, S_IFDIR) ||
         !savemount_identity(out->image_backing, &owner->backing, S_IFREG) ||
         unlink(out->image_backing) != 0)) {
        atomic_store(&s_lifecycle_mount_uncertain, true);
        goto retained_failure;
    }
    if (owner->directory_owned &&
        (!savemount_identity(MOUNT_BASE, &owner->base, S_IFDIR) ||
         !savemount_identity(out->mount_point, &owner->directory, S_IFDIR) ||
         rmdir(out->mount_point) != 0)) {
        atomic_store(&s_lifecycle_mount_uncertain, true);
        goto retained_failure;
    }
    savemount_owner_release(owner);
    memset(out, 0, sizeof(*out));
    pthread_mutex_unlock(&s_mount_lock);
    return false;

retained_failure:
    owner->snapshot = *out;
    pthread_mutex_unlock(&s_mount_lock);
    return false;
}

static bool mount_impl(const char* image_path, const uint8_t plain_key[32],
                       bool writeback, bool inspection, savemount_t* out) {
    if (!lifecycle_operation_begin()) return false;
    bool ok = mount_impl_body(image_path, plain_key, writeback, inspection, out);
    lifecycle_operation_end();
    return ok;
}

bool savemount_create_ppr_image(const char* image_path, uint64_t image_size,
                                uint8_t out_key[32]) {
    if (!lifecycle_operation_begin()) return false;
    bool ok = savemount_create_ppr_image_impl(image_path, image_size, out_key);
    lifecycle_operation_end();
    return ok;
}

bool savemount_mount(const char* image_path,
                     const uint8_t plain_key[32],
                     savemount_t* out) {
    return mount_impl(image_path, plain_key, false, false, out);
}

bool savemount_mount_inspect(const char* image_path,
                             const uint8_t plain_key[32], savemount_t* out) {
    return mount_impl(image_path, plain_key, false, true, out);
}

bool savemount_mount_rw(const char* image_path,
                        const uint8_t plain_key[32],
                        savemount_t* out) {
    return mount_impl(image_path, plain_key, true, false, out);
}

// Keep the existing write-mount rename/sync order shared, without changing its
// durability or cleanup policy. Closed publication adds its own checked fsyncs.
static bool savemount_publish_rename(const char* staged, const char* target,
                                    bool* rename_attempted) {
    if (rename_attempted) *rename_attempted = true;
    if (rename(staged, target) != 0) return false;
    sync();
    return true;
}

static bool savemount_closed_stat_equal(const struct stat* a, const struct stat* b) {
    return S_ISREG(b->st_mode) && a->st_dev == b->st_dev && a->st_ino == b->st_ino &&
        a->st_mode == b->st_mode && a->st_size == b->st_size && a->st_uid == b->st_uid &&
        a->st_gid == b->st_gid && a->st_nlink == b->st_nlink &&
        a->st_mtime == b->st_mtime && a->st_ctime == b->st_ctime
#ifdef __APPLE__
        && a->st_mtimespec.tv_nsec == b->st_mtimespec.tv_nsec && a->st_ctimespec.tv_nsec == b->st_ctimespec.tv_nsec
#else
        && a->st_mtim.tv_nsec == b->st_mtim.tv_nsec && a->st_ctim.tv_nsec == b->st_ctim.tv_nsec
#endif
#if defined(__APPLE__) || defined(__FreeBSD__)
        && a->st_flags == b->st_flags
#endif
        ;
}

static bool savemount_closed_hash(const char* path, const char* expected,
                                  struct stat* observed) {
    struct stat named = {0}, before = {0}, after = {0};
    if (lstat(path, &named) != 0 || !S_ISREG(named.st_mode)) return false;
    int fd = open(path, O_RDONLY | O_NOFOLLOW);
    if (fd < 0) return false;
    bool ok = fstat(fd, &before) == 0 && savemount_closed_stat_equal(&named, &before);
    sha256_ctx_t context; sha256_init(&context);
    unsigned char buffer[32768], digest[32]; char hex[65];
    uint64_t length = 0; ssize_t n = 0;
    while (ok && (n = read(fd, buffer, sizeof(buffer))) > 0) {
        sha256_update(&context, buffer, (size_t)n); length += (size_t)n;
    }
    if (n < 0 || length != (uint64_t)before.st_size || fstat(fd, &after) != 0 ||
        !savemount_closed_stat_equal(&before, &after) || lstat(path, &named) != 0 ||
        !savemount_closed_stat_equal(&before, &named)) ok = false;
    if (close(fd) != 0) ok = false;
    if (!ok) { errno = ESTALE; return false; }
    sha256_final(&context, digest);
    for (size_t i = 0; i < sizeof(digest); i++) snprintf(hex + i * 2, 3, "%02x", digest[i]);
    if (strcmp(hex, expected)) { errno = ESTALE; return false; }
    if (observed) *observed = before;
    return true;
}

static bool savemount_publish_closed_candidate_impl(const char* closed_copy, const char* target,
                                        const char* expected_candidate_sha,
                                        const char* expected_target_sha,
                                        bool* rename_attempted) {
    if (rename_attempted) *rename_attempted = false;
    if (!closed_copy || !target || !expected_candidate_sha || !expected_target_sha ||
        !rename_attempted || strlen(expected_candidate_sha) != 64 ||
        strlen(expected_target_sha) != 64 || !strcmp(closed_copy, target)) {
        errno = EINVAL; return false;
    }
    pfs_attribute_image_t image = {0};
    int n = snprintf(image.source, sizeof(image.source), "%s", closed_copy);
    int t = snprintf(image.copy, sizeof(image.copy), "%s.smnew", target);
    if (n < 0 || (size_t)n >= sizeof(image.source) || t < 0 ||
        (size_t)t >= sizeof(image.copy) || !strcmp(closed_copy, image.copy)) {
        errno = ENAMETOOLONG; return false;
    }
    char parent[SAVEMOUNT_PATH_MAX];
    n = snprintf(parent, sizeof(parent), "%s", target);
    if (n < 0 || (size_t)n >= sizeof(parent)) { errno = ENAMETOOLONG; return false; }
    char* slash = strrchr(parent, '/');
    if (slash) { if (slash == parent) slash[1] = 0; else *slash = 0; }
    else snprintf(parent, sizeof(parent), ".");
    int dir = open(parent, O_RDONLY | O_DIRECTORY | O_NOFOLLOW);
    if (dir < 0) return false;
    struct stat original = {0}, current = {0};
    bool ok = savemount_closed_hash(target, expected_target_sha, &original) &&
        pfs_attributes_copy_private(&image);
    if (ok && strcmp(image.sha256, expected_candidate_sha)) { errno = ESTALE; ok = false; }
    // The verified acquisition fsyncs the file. Pin and sync it again before
    // committing its directory entry; every failure retains the owned sibling.
    int staged = ok ? open(image.copy, O_RDONLY | O_NOFOLLOW) : -1;
    if (ok) ok = staged >= 0 && fsync(staged) == 0;
    if (staged >= 0 && close(staged) != 0) ok = false;
    if (ok) ok = fsync(dir) == 0 &&
        savemount_closed_hash(image.copy, expected_candidate_sha, NULL) &&
        savemount_closed_hash(target, expected_target_sha, &current);
    if (ok && !savemount_closed_stat_equal(&original, &current)) { errno = ESTALE; ok = false; }
    if (ok) ok = savemount_publish_rename(image.copy, target, rename_attempted);
    if (ok) ok = fsync(dir) == 0 && savemount_closed_hash(target, expected_candidate_sha, NULL);
    if (close(dir) != 0) ok = false;
    return ok; // Never remove the closed input or failure evidence, even after rename.
}

bool savemount_publish_closed_candidate(const char* closed_copy, const char* target,
                                        const char* candidate_sha, const char* target_sha,
                                        bool* rename_attempted) {
    if (rename_attempted) *rename_attempted = false;
    if (!lifecycle_operation_begin()) return false;
    bool ok = savemount_publish_closed_candidate_impl(closed_copy, target,
        candidate_sha, target_sha, rename_attempted);
    lifecycle_operation_end();
    return ok;
}

// Existing write-mount publication only; intentionally private to unmount.
static bool savemount_publish_staged(const savemount_t* m) {
    // Atomic copy-back: write to a temp sibling on the SAME filesystem
    // as the live save, then rename over it. A failed/partial copy can
    // no longer truncate the real save (the old in-place O_TRUNC copy
    // could), and on failure the resealed work image is kept for
    // manual recovery instead of being deleted.
    char tmp[SAVEMOUNT_PATH_MAX + 16];
    snprintf(tmp, sizeof(tmp), "%s.smnew", m->image_origin);
    unlink(tmp);
    if (copy_file_bytes(m->image_backing, tmp) &&
        savemount_publish_rename(tmp, m->image_origin, NULL)) {
        unlink(m->image_backing);
        log_info("savemount: copied resealed image back to %s",
                 m->image_origin);
        return true;
    }
    unlink(tmp);
    log_warn("savemount: FAILED atomic copy-back to %s — original "
             "left intact; resealed image kept at %s",
             m->image_origin, m->image_backing);
    return false;
}

static bool savemount_unmount_impl(savemount_t* m) {
    if (!m) return true;
    pthread_mutex_lock(&s_mount_lock);
    savemount_owner_t* owner = savemount_owner_find(m);
    if (!owner) {
        savemount_t empty_handle = {0};
        bool empty = savemount_handle_same(m, &empty_handle);
        pthread_mutex_unlock(&s_mount_lock);
        return empty;
    }
    if (!owner->native_attempted || !owner->mounted_known ||
        owner->unmount_attempted || !savemount_handle_same(m, &owner->snapshot) ||
        !savemount_identity(MOUNT_BASE, &owner->base, S_IFDIR) ||
        !savemount_identity(m->mount_point, &owner->mounted, S_IFDIR) ||
        (owner->backing_owned &&
         !savemount_identity(m->image_backing, &owner->backing, S_IFREG))) {
        owner->unmount_attempted = true;
        atomic_store(&s_lifecycle_mount_uncertain, true);
        pthread_mutex_unlock(&s_mount_lock);
        return false;
    }
    owner->unmount_attempted = true;

    sync();

    pfs_umount_opt_t opt;
    memset(&opt, 0, sizeof(opt));
    sceFsInitUmountSaveDataOpt(&opt);

    log_info("savemount: [bc] elevating creds for unmount %s",
             m->mount_point);
    savemount_cred_snapshot_t creds;
    bool elevated = elevate_savedata_creds(&creds);
    log_info("savemount: [bc] unmount elevated=%d, calling "
             "sceFsUmountSaveData", elevated);
    int ret = elevated ? sceFsUmountSaveData(&opt, m->mount_point,
                                             m->handle, 0) : -1;
    log_info("savemount: [bc] sceFsUmountSaveData returned %d", ret);
    restore_savedata_creds(&creds);
    if (!elevated)
        log_warn("savemount: could not elevate credentials for savedata unmount");
    if (ret < 0) {
        log_warn("savemount: unmount %s failed (ret=%d) — leaking until reboot",
                 m->mount_point, ret);
        atomic_store(&s_lifecycle_mount_uncertain, true);
        pthread_mutex_unlock(&s_mount_lock);
        return false;
    }
    sync();
    // shortcut: path checks detect observed replacement, not an external race after lstat.
    if (!savemount_identity(MOUNT_BASE, &owner->base, S_IFDIR) ||
        !savemount_identity(m->mount_point, &owner->directory, S_IFDIR) ||
        rmdir(m->mount_point) != 0 ||
        (owner->backing_owned &&
         !savemount_identity(m->image_backing, &owner->backing, S_IFREG))) {
        atomic_store(&s_lifecycle_mount_uncertain, true);
        pthread_mutex_unlock(&s_mount_lock);
        return false;
    }

    // EPIPE workaround completion: if the image was staged onto /data, copy
    // the now-resealed work file back to its original location (write mounts
    // only), then drop the work copy. Read/dump mounts discard it untouched,
    // so a backup never rewrites the live save.
    bool ok = true;
    if (m->image_origin[0]) {
        if (m->writeback) {
            ok = savemount_publish_staged(m);
        } else {
            ok = unlink(m->image_backing) == 0;   // read/dump mount: discard owned work copy
            if (!ok) {
                atomic_store(&s_lifecycle_mount_uncertain, true);
                pthread_mutex_unlock(&s_mount_lock);
                return false;
            }
        }
    }

    log_info("savemount: unmounted %s", m->mount_point);
    unsigned pending = atomic_load(&s_lifecycle_mounts);
    while (pending && !atomic_compare_exchange_weak(&s_lifecycle_mounts, &pending, pending - 1)) {}
    if (!pending) atomic_store(&s_lifecycle_mount_uncertain, true);
    memset(m, 0, sizeof(*m));
    savemount_owner_release(owner);
    pthread_mutex_unlock(&s_mount_lock);
    return ok;
}

bool savemount_unmount(savemount_t* m) {
    if (!lifecycle_operation_begin()) return false;
    bool ok = savemount_unmount_impl(m);
    lifecycle_operation_end();
    return ok;
}
