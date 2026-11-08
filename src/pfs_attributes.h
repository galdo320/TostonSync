// One forensic comparison, never a restore or a plaintext export.
#ifndef TOSTONSYNC_PFS_ATTRIBUTES_H
#define TOSTONSYNC_PFS_ATTRIBUTES_H
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/stat.h>

#define PFS_ATTRIBUTES_UID "00000001"
#define PFS_ATTRIBUTES_TITLE "PPSA00001"
#define PFS_ATTRIBUTES_SLOT "SAVESERVICE-LINE-0-1Slot"
#define PFS_ATTRIBUTES_PRE "/data/tostonsync/staging/restore_00000001_PPSA00001_sdimg_rollback/sdimg_" PFS_ATTRIBUTES_SLOT
#define PFS_ATTRIBUTES_REJECTED "/user/home/" PFS_ATTRIBUTES_UID "/savedata_prospero/" PFS_ATTRIBUTES_TITLE "/sdimg_" PFS_ATTRIBUTES_SLOT
#define PFS_ATTRIBUTES_MAX_ENTRIES 1024

typedef struct { unsigned tag, id, perm, type, flags; } pfs_acl_entry_t;
typedef struct {
    const char* status;
    int error;
    size_t count;
    pfs_acl_entry_t* entries;
} pfs_acl_observation_t;
typedef struct { char name[256]; int64_t size; int error; } pfs_xattr_t;
typedef struct {
    const char* status;
    int error;
    size_t count;
    pfs_xattr_t* entries;
} pfs_xattr_observation_t;
typedef struct {
    char path[1024];             // Literal relative path; root is ".".
    struct stat stat;
    pfs_acl_observation_t acl[3]; // access, default, NFSv4; no setters.
    pfs_xattr_observation_t xattrs[2]; // user, system: names/sizes, not values.
} pfs_attribute_entry_t;
typedef struct {
    const char* result;
    char source[256], copy[256], mount[256];
    struct stat outer_before, outer_after;
    bool outer_available, source_stable, complete, unmounted, copy_discarded;
    char sha256[65], error_path[1024];
    int error;
    size_t count;
    pfs_attribute_entry_t* entries;
} pfs_attribute_image_t;
typedef struct {
    const char* result;
    char work[256], detail[256];
    bool recovery_required;
    pfs_attribute_image_t images[2];
} pfs_attributes_report_t;

// Metadata collector only. Never opens a regular file or follows symlinks.
bool pfs_attributes_collect(const char* mounted_root, pfs_attribute_image_t* out);
// Verified encrypted acquisition only. Caller supplies authorized source and
// an exclusive NEW private copy path, and owns the gate/barrier.
bool pfs_attributes_copy_private(pfs_attribute_image_t* image);
void pfs_attributes_image_free(pfs_attribute_image_t* image);
// Caller owns the exclusive gate + existing durable barrier. work is a new
// private /data directory. Only these two fixed encrypted sources are copied.
void pfs_attributes_compare(pfs_attributes_report_t* report);
void pfs_attributes_free(pfs_attributes_report_t* report);
#endif
