#include "pfs_attributes.h"
#include "pfs_keys.h"
#include "savemount.h"
#include "sha256.h"
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#ifdef __FreeBSD__
#define _ACL_PRIVATE
#include <sys/acl.h>
#include <sys/extattr.h>
#ifdef __PROSPERO__
#include <sys/syscall.h>
// Like at_io.h: these pinned SDK syscall stubs also omit carry/errno handling.
// Only SDK-declared metadata GET/LIST operations are routed through this shim.
static long metadata_get(long number, const char* path, long kind, const void* data,
                         long fourth) {
    register long arg4 __asm__("r10") = fourth;
    register long arg5 __asm__("r8") = 0;
    long arg3 = (long)data, result; unsigned char failed;
    __asm__ volatile("syscall" : "=a"(result), "=@ccc"(failed),
        "+d"(arg3), "+r"(arg4), "+r"(arg5)
        : "0"(number), "D"((long)path), "S"(kind)
        : "rcx", "r9", "r11", "memory", "cc");
    if (failed) { errno = (int)result; return -1; }
    return result;
}
#define metadata_acl_get(p,t,a) metadata_get(SYS___acl_get_link,p,t,a,0)
#define metadata_xattr_list(p,n,b,s) metadata_get(SYS_extattr_list_link,p,n,b,s)
#define metadata_xattr_size(p,n,k) metadata_get(SYS_extattr_get_link,p,n,k,0)
#else
#define metadata_acl_get __acl_get_link
#define metadata_xattr_list extattr_list_link
#define metadata_xattr_size(p,n,k) extattr_get_link(p,n,k,NULL,0)
#endif
#endif

#ifdef __FreeBSD__
static const char* attribute_status(int error) {
    return error == ENOSYS || error == EOPNOTSUPP ? "UNAVAILABLE" : "ERROR";
}
#endif

static void observe_extra(const char* path, pfs_attribute_entry_t* entry) {
    for (size_t i = 0; i < 3; i++) entry->acl[i].status = "UNAVAILABLE_SDK";
    for (size_t i = 0; i < 2; i++) entry->xattrs[i].status = "UNAVAILABLE_SDK";
#ifdef __FreeBSD__
    const acl_type_t types[] = {ACL_TYPE_ACCESS, ACL_TYPE_DEFAULT, ACL_TYPE_NFS4};
    struct acl* acl = calloc(1, sizeof(*acl));
    for (size_t i = 0; i < 3; i++) {
        pfs_acl_observation_t* a = &entry->acl[i];
        if (!acl) { a->status = "ERROR"; a->error = ENOMEM; continue; }
        memset(acl, 0, sizeof(*acl)); acl->acl_maxcnt = ACL_MAX_ENTRIES;
        errno = 0;
        int rc = (int)metadata_acl_get(path, types[i], acl);
        if (rc != 0) { a->error = errno ? errno : EIO; a->status = attribute_status(a->error); continue; }
        if (acl->acl_cnt > ACL_MAX_ENTRIES) { a->error = EOVERFLOW; a->status = "INCOMPLETE"; continue; }
        a->entries = calloc(acl->acl_cnt ? acl->acl_cnt : 1, sizeof(*a->entries));
        if (!a->entries) { a->status = "ERROR"; a->error = ENOMEM; continue; }
        a->count = acl->acl_cnt; a->status = "OBSERVED";
        for (size_t j = 0; j < a->count; j++) {
            struct acl_entry* e = &acl->acl_entry[j];
            a->entries[j] = (pfs_acl_entry_t){e->ae_tag, e->ae_id, e->ae_perm, e->ae_entry_type, e->ae_flags};
        }
    }
    free(acl);
    for (size_t i = 0; i < 2; i++) {
        pfs_xattr_observation_t* x = &entry->xattrs[i];
        int ns = i ? EXTATTR_NAMESPACE_SYSTEM : EXTATTR_NAMESPACE_USER;
        char names[4096]; errno = 0;
        ssize_t n = metadata_xattr_list(path, ns, names, sizeof(names));
        if (n < 0) { x->error = errno; x->status = attribute_status(errno); continue; }
        if ((size_t)n > sizeof(names)) { x->error = EOVERFLOW; x->status = "INCOMPLETE"; continue; }
        x->status = "OBSERVED";
        size_t pos = 0;
        while (pos < (size_t)n) {
            size_t len = (unsigned char)names[pos++];
            if (!len || len > (size_t)n - pos || memchr(names + pos, 0, len)) {
                x->error = EINVAL; x->status = "INCOMPLETE"; break;
            }
            pfs_xattr_t* more = realloc(x->entries, (x->count + 1) * sizeof(*more));
            if (!more) { x->error = ENOMEM; x->status = "INCOMPLETE"; break; }
            x->entries = more;
            pfs_xattr_t* item = &more[x->count++]; memset(item, 0, sizeof(*item));
            memcpy(item->name, names + pos, len); pos += len;
            errno = 0;
            item->size = metadata_xattr_size(path, ns, item->name);
            if (item->size < 0) item->error = errno ? errno : EIO;
        }
    }
#else
    (void)path;
#endif
}

static bool observe_tree(const char* root, const char* relative, unsigned depth,
                         pfs_attribute_image_t* out) {
    char path[2048];
    int n = snprintf(path, sizeof(path), "%s%s%s", root,
                     !strcmp(relative, ".") ? "" : "/",
                     !strcmp(relative, ".") ? "" : relative);
    if (n < 0 || (size_t)n >= sizeof(path) || depth > 64 ||
        out->count >= PFS_ATTRIBUTES_MAX_ENTRIES) { errno = EOVERFLOW; goto failed; }
    struct stat s;
    if (lstat(path, &s) != 0) goto failed;
    pfs_attribute_entry_t* more = realloc(out->entries, (out->count + 1) * sizeof(*more));
    if (!more) { errno = ENOMEM; goto failed; }
    out->entries = more;
    pfs_attribute_entry_t* entry = &more[out->count++]; memset(entry, 0, sizeof(*entry));
    snprintf(entry->path, sizeof(entry->path), "%s", relative); entry->stat = s;
    observe_extra(path, entry);
    if (!S_ISDIR(s.st_mode)) return true; // lstat records links/devices, never follows/opens them.
    int fd = open(path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW);
    if (fd < 0) goto failed;
    struct stat pinned;
    if (fstat(fd, &pinned) != 0 || pinned.st_dev != s.st_dev || pinned.st_ino != s.st_ino) {
        int error = errno ? errno : ESTALE; close(fd); errno = error; goto failed;
    }
    DIR* d = fdopendir(fd);
    if (!d) { int error = errno; close(fd); errno = error; goto failed; }
    bool ok = true;
    for (;;) {
        errno = 0; struct dirent* e = readdir(d);
        if (!e) { if (errno) ok = false; break; }
        if (!strcmp(e->d_name, ".") || !strcmp(e->d_name, "..")) continue;
        char child[1024];
        int length = snprintf(child, sizeof(child), "%s%s%s",
            !strcmp(relative, ".") ? "" : relative,
            !strcmp(relative, ".") ? "" : "/", e->d_name);
        if (length < 0 || (size_t)length >= sizeof(child)) { errno = EOVERFLOW; ok = false; break; }
        if (!observe_tree(root, child, depth + 1, out)) { ok = false; break; }
    }
    int error = errno;
    if (closedir(d) != 0 && ok) { error = errno; ok = false; }
    if (ok) return true;
    if (out->error) return false;
    errno = error;
failed:
    out->error = errno ? errno : EIO;
    snprintf(out->error_path, sizeof(out->error_path), "%s", relative);
    return false;
}

bool pfs_attributes_collect(const char* root, pfs_attribute_image_t* out) {
    out->complete = observe_tree(root, ".", 0, out);
    return out->complete;
}

static bool same_source(const struct stat* a, const struct stat* b) {
    return S_ISREG(b->st_mode) && a->st_dev == b->st_dev && a->st_ino == b->st_ino &&
        a->st_size == b->st_size && a->st_mtime == b->st_mtime && a->st_ctime == b->st_ctime
#ifdef __APPLE__
        && a->st_mtimespec.tv_nsec == b->st_mtimespec.tv_nsec && a->st_ctimespec.tv_nsec == b->st_ctimespec.tv_nsec
#else
        && a->st_mtim.tv_nsec == b->st_mtim.tv_nsec && a->st_ctim.tv_nsec == b->st_ctim.tv_nsec
#endif
        ;
}

// Only encrypted image bytes are read here. Nothing from the mounted tree.
bool pfs_attributes_copy_private(pfs_attribute_image_t* image) {
    struct stat pinned;
    if (lstat(image->source, &image->outer_before) != 0) return false;
    image->outer_available = true;
    if (!S_ISREG(image->outer_before.st_mode)) { errno = EINVAL; return false; }
    int in = open(image->source, O_RDONLY | O_NOFOLLOW);
    if (in < 0) return false;
    bool ok = fstat(in, &pinned) == 0 && same_source(&image->outer_before, &pinned);
    int out = ok ? open(image->copy, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW, 0600) : -1;
    if (out < 0) { close(in); return false; }
    unsigned char buffer[32768]; sha256_ctx_t hash; sha256_init(&hash);
    uint64_t bytes = 0; ssize_t n;
    while ((n = read(in, buffer, sizeof(buffer))) > 0) {
        sha256_update(&hash, buffer, (size_t)n); bytes += (size_t)n;
        ssize_t off = 0;
        while (off < n) { ssize_t w = write(out, buffer + off, (size_t)(n - off)); if (w <= 0) { ok = false; break; } off += w; }
        if (!ok) break;
    }
    if (n < 0 || bytes != (uint64_t)image->outer_before.st_size || fsync(out) != 0) ok = false;
    if (close(out) != 0) ok = false;
    if (fstat(in, &pinned) != 0 || !same_source(&image->outer_before, &pinned)) ok = false;
    close(in);
    if (lstat(image->source, &image->outer_after) != 0 || !same_source(&image->outer_before, &image->outer_after)) ok = false;
    image->source_stable = ok;
    unsigned char digest[32]; sha256_final(&hash, digest);
    for (size_t i = 0; i < sizeof(digest); i++) snprintf(image->sha256 + i * 2, 3, "%02x", digest[i]);
    char copied_hash[65];
    if (!ok || !sha256_file_hex(image->copy, copied_hash) || strcmp(copied_hash, image->sha256)) { errno = EIO; return false; }
    return true;
}

void pfs_attributes_compare(pfs_attributes_report_t* report) {
    const char* sources[] = {PFS_ATTRIBUTES_PRE, PFS_ATTRIBUTES_REJECTED};
    report->result = "ERROR";
    for (size_t i = 0; i < 2; i++) report->images[i].result = "NOT_CHECKED";
    // Copy BOTH inputs before mounting either. Neither /data snapshot nor live image is ever passed to mount.
    for (size_t i = 0; i < 2; i++) {
        pfs_attribute_image_t* image = &report->images[i]; image->result = "NOT_CHECKED";
        snprintf(image->source, sizeof(image->source), "%s", sources[i]);
        int n = snprintf(image->copy, sizeof(image->copy), "%s/%s.img", report->work, i ? "REJECTED" : "PRE");
        if (n < 0 || (size_t)n >= sizeof(image->copy) || !pfs_attributes_copy_private(image)) {
            image->error = errno ? errno : EIO; image->result = "COPY_ERROR"; return;
        }
    }
    for (size_t i = 0; i < 2; i++) {
        pfs_attribute_image_t* image = &report->images[i];
        uint8_t key[PFS_PLAIN_KEY_SIZE] = {0}; savemount_t mount = {0};
        bool keyed = pfs_decrypt_save_key(image->copy, key);
        bool mounted = keyed && savemount_mount(image->copy, key, &mount);
        memset(key, 0, sizeof(key));
        if (!mounted) { image->result = keyed ? "MOUNT_ERROR" : "KEY_ERROR"; return; }
        snprintf(image->mount, sizeof(image->mount), "%s", mount.mount_point);
        bool observed = pfs_attributes_collect(mount.mount_point, image);
        if (!savemount_unmount(&mount)) {
            image->result = "UNMOUNT_UNCERTAIN"; report->result = "RECOVERY_REQUIRED";
            report->recovery_required = true; return; // No second image, no copy deletion.
        }
        image->unmounted = true;
        image->result = observed ? "OBSERVED" : "INCOMPLETE";
        if (!observed) return;
    }
    // Delete only our two disposable encrypted files, only after BOTH clean unmounts.
    for (size_t i = 0; i < 2; i++) {
        pfs_attribute_image_t* image = &report->images[i];
        if (unlink(image->copy) != 0) { image->error = errno; report->result = "COPY_DISCARD_ERROR"; return; }
        image->copy_discarded = true;
    }
    report->result = "OBSERVED";
}

void pfs_attributes_image_free(pfs_attribute_image_t* image) {
    for (size_t j = 0; j < image->count; j++) {
        for (size_t k = 0; k < 3; k++) free(image->entries[j].acl[k].entries);
        for (size_t k = 0; k < 2; k++) free(image->entries[j].xattrs[k].entries);
    }
    free(image->entries); image->entries = NULL; image->count = 0;
}

void pfs_attributes_free(pfs_attributes_report_t* report) {
    for (size_t i = 0; i < 2; i++) pfs_attributes_image_free(&report->images[i]);
}
