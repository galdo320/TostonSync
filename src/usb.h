// TostónSync — USB / external-drive backup backend.
//
// Mirrors the Google Drive operations (copy a backup, list versions,
// prune old ones) but against a plugged-in USB mass-storage device that
// the PS5 mounts under /mnt/usb0 .. /mnt/usb7. Works with no network and
// no sign-in — if a drive is present and the feature is enabled, every
// backup is also written there, and saves can be restored straight from
// the stick.

#ifndef TOSTONSYNC_USB_H
#define TOSTONSYNC_USB_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "config.h"
#include "catalog_scan.h"
#include "individual_catalog.h"

#ifdef __cplusplus
extern "C" {
#endif

#define USB_PATH_MAX 256

// One backup archive found on the USB drive.
typedef struct {
    char     path[USB_PATH_MAX];   // absolute path on the mounted drive
    char     name[128];            // file name only
    uint64_t size_bytes;
    int64_t  created_unix;         // file mtime
} usb_version_t;

// One backup archive found while scanning all usable USB volumes.
typedef struct {
    char     user[32];
    char     title_id[16];
    char     path[USB_PATH_MAX];   // absolute path; pass to restore
    char     name[128];
    uint64_t size_bytes;
    int64_t  created_unix;
    char     destination_identity[65];
    char     file_stamp[65]; // listed inode/size/mtime/ctime incarnation proof
    char     destination_label[512]; // original scan, no credentials
    char     volume_id[65];
    char     mount[64];
    bool     older_unconfirmed; // absent folder marker, never a deletion/retention proof
} usb_backup_t;

typedef enum {
    USB_READY, USB_LOW_SPACE, USB_FULL, USB_READ_ONLY, USB_LOCKED,
    USB_NOT_USABLE, USB_UNSUPPORTED_FORMAT, USB_NOT_CONNECTED
} usb_state_t;

typedef struct {
    char     path[64];
    char     display_name[64];
    char     label_source[16];
    uint64_t free_bytes;
    uint64_t total_bytes;
    bool     writable;
    bool     selected;
    usb_state_t state;
    char     reason[48], fs_type[16], device[128], volume_id[65];
    char     selection_reason[32];
    uint64_t mount_flags, max_file_bytes;
    size_t   usable_count;
    bool     space_known, identity_confirmed;
} usb_mount_t;

// Explicit scan action only; passive listing must never call this cache update.
void usb_note_backup_size(uint64_t bytes);
const char* usb_state_name(usb_state_t state);
void usb_classify_mount(usb_mount_t* mount, uint64_t incoming_bytes, bool incoming_known);
// Pure enumeration includes observed volumes that cannot accept writes.
size_t usb_observe_mounts(usb_mount_t* out, size_t max_out);
size_t usb_observe_snapshot(usb_mount_t* selected, usb_mount_t* mounts, size_t capacity);
// Only the explicit selection/backup action may create a volume marker.
bool usb_select_volume_identity(const char* mount);
bool usb_copy_backup_authorized(const char* user, const char* title, const char* filename,
    const char* source, char out_identity[65], bool individual, bool allow_marker);
const char* usb_last_copy_failure(void);

// Wire up the config pointer (call once at startup).
void usb_init(const config_t* cfg);

// Find the selected usable USB drive. Writes the mount point (e.g.
// "/mnt/usb0") into out and returns true, or false if none is present.
bool usb_detect(char* out, size_t out_sz);

// Passive selected-volume observation includes rejected mounts for diagnostics.
// Returns false only when no mount was observed; selected grants write selection.
// This never creates markers, writes probes or changes configuration.
bool usb_observe_selected(usb_mount_t* out);

// Enumerate mounted USB partitions under /mnt/usbN. Returns the number
// written into out. If out is NULL or max_out is 0, returns the count.
size_t usb_list_mounts(usb_mount_t* out, size_t max_out);

// Read an exFAT volume label from a block device/image in read-only mode.
// Public mainly so the host safety test can exercise the parser.
bool usb_read_exfat_volume_label(const char* device_path,
                                 char* out, size_t out_sz);

// Stable exFAT volume identity (serial + immutable geometry), read-only.
// Unknown/unreadable/unsupported filesystems return false and an empty token.
bool usb_read_exfat_volume_identity(const char* device_path, char out[65]);

// Store a UI-only name in <mount>/<usb.folder>/.drive.json. An empty name
// removes the custom label. The real filesystem label is not changed.
bool usb_set_display_name(const char* mount_path, const char* name);

// Convenience: is any USB drive currently mounted?
bool usb_is_present(void);

// Free / total bytes on the mounted USB drive. Returns false if none.
bool usb_free_space(uint64_t* free_bytes, uint64_t* total_bytes);

// Verify the currently selected/auto-detected volume with a real temporary
// write + fsync + delete. Returns the mount used and a UI-friendly detail.
bool usb_test_write(char* mount_out, size_t mount_out_sz,
                    char* detail, size_t detail_sz);

// Copy a finished backup zip onto the USB drive at
//   <mount>/<usb.folder>/<readable user - UID>/<readable game - Title ID>/<filename>
// Matching is by the literal final code. User Settings renames occur on the
// next backup; an already readable game folder changes only for a manual alias.
// The caller supplies the stable PS5 UID. Legacy configured aliases still work.
// Returns false if disabled, no drive, or the copy failed.
bool usb_copy_backup(const char* user_alias,
                     const char* title_id, const char* filename,
                     const char* local_zip_path);

// Confirm the selected volume and a marker in the actual destination directory.
// The random marker is created only after a successful backup to that directory.
// Mount-slot numbers and friendly labels are never used as volume identity.
bool usb_backup_identity(const char* user_alias, const char* title_id,
                         char out[65]);

// Read-only receipt check: a regular, non-symlink ZIP of the exact positive
// size must still exist in the same confirmed volume/directory.
bool usb_backup_exists(const char* user_alias, const char* title_id,
                        const char* filename, uint64_t expected_size,
                        const char* expected_identity);

// As above, returning the identity of the actual successfully written target.
// A successful copy may have an empty identity: it must not seed dedupe then.
bool usb_copy_backup_identified(const char* user_alias,
                                const char* title_id, const char* filename,
                                const char* local_zip_path,
                                char out_identity[65]);

// Store one individual archive in the fixed title child "Individual saves".
// No destination marker/receipt is created; out_identity remains empty.
bool usb_copy_backup_individual_identified(const char* user_alias,
                                const char* title_id, const char* filename,
                                const char* local_zip_path,
                                char out_identity[65]);

// List backups for one (user, title) across all matching physical folders,
// including bare/readable duplicates, newest first. References stay physical.
// Returns the number written into out.
size_t usb_list_versions(const char* user_alias, const char* title_id,
                         usb_version_t* out, size_t max_out);

// Scan every usable USB volume for backups under
//   <mount>/<usb.folder>/<user_uid>/<title_id>/*.zip
// Returns newest-first entries across all users/titles/volumes.
size_t usb_list_all_versions(usb_backup_t* out, size_t max_out);

// Complete/empty means the bounded all-volume scan finished without gaps.
// Partial rows stay visible, but uncertainty is never evidence of emptiness.
size_t usb_catalog_scan(usb_backup_t* out, size_t max_out, catalog_scan_t* scan);

// Separate read-only child scan; never feeds Full policies or delete tickets.
size_t usb_individual_scan(const char* user, const char* title,
        individual_backup_t* out, size_t cap, catalog_scan_t* scan);
bool usb_individual_revalidate(const individual_backup_t* item);
// local_path must not exist. Exact bounded copy; no retry or source mutation.
bool usb_individual_download_bounded(const individual_backup_t* item,
        const char* local_path, char* err, size_t err_sz);

// Apply max_versions retention to the USB copies of a (user, title).
// keep_filename is the just-written archive, or NULL for ordinary cleanup.
void usb_enforce_retention(const char* user_alias, const char* title_id,
                           const char* keep_filename);

// Post-copy cleanup is bound to the actual accepted volume/directory identity.
// Unknown/changed identities, incomplete listings and failed deletes stop
// pruning. The just-written regular ZIP must remain present when supplied.
bool usb_enforce_retention_identified(const char* user_alias,
                                      const char* title_id,
                                      const char* keep_filename,
                                      const char* expected_identity);

// Delete a single backup archive by its absolute path (from the catalog).
// Validates it is a .zip under /mnt/usb* with no ".." before unlinking.
bool usb_delete_backup(const char* path);

// Explicit Library deletion: the listed volume/folder identity and positive
// archive size must still match. Unknown proof never authorizes deletion.
bool usb_delete_backup_identified(const char* path, uint64_t expected_size,
                                  const char* expected_identity,
                                  const char* expected_file_stamp);

#ifdef __cplusplus
}
#endif
#endif // TOSTONSYNC_USB_H
