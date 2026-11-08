// Direct encrypted-image observation; no mount, copy, database or save writer.
#ifndef TOSTONSYNC_SAVE_IMAGE_HASH_H
#define TOSTONSYNC_SAVE_IMAGE_HASH_H

#include <stdbool.h>
#include <stddef.h>
#include <sys/stat.h>

typedef struct {
    const char* result;          // STABLE, UNSTABLE or ERROR; not game acceptance.
    bool pre_available, post_available;
    struct stat pre, post;
    int pre_errno, post_errno, hash_errno;
    char sha256[65];             // Empty unless the observed identity/size is stable.
} save_image_hash_report_t;

// Fixed PS5 savedata root, literal components; no arbitrary pathname endpoint.
bool save_image_hash_target(const char* uid, const char* title, const char* slot,
                            char* path, size_t capacity);
// Only lstat + existing O_RDONLY SHA helper + lstat. Caller owns the I/O gate.
// Stable dev/inode/size is observational, not an atomic snapshot of the bytes.
void save_image_hash_collect(const char* path, save_image_hash_report_t* out);

#endif
