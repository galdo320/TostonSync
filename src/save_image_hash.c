#include "save_image_hash.h"
#include "sha256.h"

#include <errno.h>
#include <stdio.h>
#include <string.h>

bool save_image_hash_target(const char* uid, const char* title, const char* slot,
                            char* path, size_t capacity) {
    if (!uid || strlen(uid) != 8 || strspn(uid, "0123456789abcdefABCDEF") != 8 ||
        !title || strlen(title) != 9 || strncmp(title, "PPSA", 4) ||
        strspn(title + 4, "0123456789") != 5 || !slot || !*slot ||
        strlen(slot) >= 243 || !strcmp(slot, ".") || !strcmp(slot, "..") ||
        !strncmp(slot, "sce_bu_", 7) || !path || !capacity) return false;
    for (const unsigned char* p = (const unsigned char*)slot; *p; p++)
        if (*p < 32 || *p == 127 || *p == '/' || *p == '\\') return false;
    int n = snprintf(path, capacity,
        "/user/home/%s/savedata_prospero/%s/sdimg_%s", uid, title, slot);
    return n > 0 && (size_t)n < capacity;
}

void save_image_hash_collect(const char* path, save_image_hash_report_t* out) {
    if (!out) return;
    memset(out, 0, sizeof(*out));
    out->result = "ERROR";
    if (!path || !*path) { out->pre_errno = EINVAL; return; }
    if (lstat(path, &out->pre) != 0) { out->pre_errno = errno; return; }
    out->pre_available = true;
    // Never intentionally follow a symlink or open a device/directory.
    if (!S_ISREG(out->pre.st_mode)) { out->pre_errno = EINVAL; return; }
    char observed[65] = {0};
    errno = 0;
    bool hashed = sha256_file_hex(path, observed);
    if (!hashed) out->hash_errno = errno ? errno : EIO;
    if (lstat(path, &out->post) != 0) { out->post_errno = errno; return; }
    out->post_available = true;
    if (!S_ISREG(out->post.st_mode) || out->pre.st_dev != out->post.st_dev ||
        out->pre.st_ino != out->post.st_ino || out->pre.st_size != out->post.st_size) {
        out->result = "UNSTABLE";
        return;
    }
    if (!hashed) return;
    memcpy(out->sha256, observed, sizeof(out->sha256));
    out->result = "STABLE";
}
