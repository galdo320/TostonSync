// TostónSync — kernel-mediated backup/restore of PS5 saves.
//
// Bundles pfs_keys (sealed-key unwrap) and savemount (kernel mount)
// into two high-level operations:
//
//   backup_via_mount:
//     Mount the live save, copy its decrypted contents into a staging
//     directory the watcher can zip. The backup is plain PFS content;
//     it still must be re-sealed through an existing target save before
//     the game can use it again.
//
//   restore_via_mount:
//     Mount the target save (which must already exist on disk so the
//     kernel has a sealed key to re-seal with), snapshot its current
//     contents, copy in everything from the extracted backup staging
//     directory, then unmount. The kernel re-seals automatically.
//
// Both functions always unmount on every exit path, including
// failure. That is the only way to avoid leaking a /data/tostonsync/
// mount slot until reboot.
//
// Limitations of this version:
//   - Restore requires an *existing* target save (we don't create one
//     from scratch — that needs sceFsCreateSaveData which is a much
//     larger surface). Users must create a save in-game once before
//     restoring a plain-PFS backup over it.
//   - Cross-console restore is out of scope: the destination console
//     needs to do the re-seal, so the user must run TostónSync on
//     both ends, and the destination title/profile must already have
//     a target save blob/key. This module only handles the local half.

#ifndef TOSTONSYNC_PFS_RESIGN_H
#define TOSTONSYNC_PFS_RESIGN_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "sfo.h"

#ifdef __cplusplus
extern "C" {
#endif

// Distinct from ordinary read failure: a kernel mount may still be active.
// Its backing/mount must be retained, further mounts stopped and the owner's
// durable save-I/O barrier kept until authorized recovery inspection.
#define PFS_SFO_READ_UNMOUNT_UNCERTAIN (-3)

// Read/dump mount: parse sce_sys/param.sfo without application writeback.
// Returns 0 on success (out filled), -2 if param.sfo is zeroed (out->zeroed
// set), -1 on decrypt/mount/parse failure, or the uncertainty result above
// with out zeroed. Native mounts are not MOUNT_RO; stage private copies of
// live images and persist the owner's barrier before entering this reader.
int pfs_read_image_param_sfo(const char* image_path, sfo_info_t* out);

// READ-ONLY: mount a sealed PFS image and return the newest internal file
// mtime (unix). True on success. Used to compare a service backup's age
// against the active slot before promoting it. Never modifies the image.
bool pfs_image_newest_mtime(const char* image_path, int64_t* out_unix);

// EXPERIMENTAL: if `image_path`'s sce_sys/param.sfo is all-zero, rebuild it
// from `meta` (+ reused PARAMS `hmac`, may be NULL) and re-seal on unmount.
// Snapshots/rolls back on write failure. Returns 1 fixed, 0 nothing to do,
// -1 failure. `work_dir` holds the temporary param.sfo snapshot.
int pfs_resign_fix_zeroed_sfo(const char* image_path, const sfo_info_t* meta,
                              const uint8_t* hmac, const char* work_dir);

// Copy the decrypted contents of `source_save_dir` (the directory
// containing savedata0.bin) into `staging_dir`. The staging dir is
// created if missing and wiped before the copy.
//
// Returns false on any failure. On failure the staging dir may be
// partially populated; callers should treat it as invalid.
bool pfs_resign_backup_to_staging(const char* source_save_dir,
                                  const char* staging_dir);

// Copy each PS5 sdimg_* slot from `source_save_dir` into a Garlic-style
// decrypted folder set:
//   .tostonsync_format = plain-sdimg-v1
//   slots/<SAVEDATA_DIRECTORY>/...
//   service/<SAVEDATA_DIRECTORY>/...
// The service/ entries come from sdimg_sce_bu_* and are restored after active
// slots, so the save service's newer snapshot can win without raw image copy.
bool pfs_resign_backup_sdimg_to_staging(const char* source_save_dir,
                                        const char* staging_dir);

// Mirror the contents of `staging_dir` (produced by backup_to_staging
// or by extracting a plain-format backup ZIP) into the live save at
// `target_save_dir`. The kernel re-seals with the target's sealed
// key on unmount.
//
// Returns false on any failure.
bool pfs_resign_restore_from_staging(const char* staging_dir,
                                     const char* target_save_dir);

// READ-ONLY: decrypt + mount a sealed PFS image and copy its decrypted tree
// into `out_dir`. The output dir is recreated. Used to inspect/promote PS5
// save-service backup images (`sdimg_sce_bu_*`) without treating them as real
// playable slots.
bool pfs_resign_dump_image_to_dir(const char* image_path,
                                  const char* out_dir);

// Recovery-only reader. `copied_image` MUST be a disposable imported-image
// copy in a private /data workspace, never a live/original save. Kernel dump
// mounts prohibit application edits/writeback but are not kernel MOUNT_RO.
// `out_dir` must not exist; its private parent must already exist. Validate
// the PS5 SFO/keystone and copy/checksum the complete mounted tree before a
// clean unmount. Never wipes evidence on failure. An uncertain unmount keeps
// <copied_image>.recovery_mount_pending (with mount/backing paths): the owner
// must preserve that workspace, block further attempts and require reboot.
bool pfs_resign_recover_image_copy(const char* copied_image,
                                   const char* out_dir,
                                   const char* title_id, const char* slot,
                                   char* err, size_t err_sz);

// Legacy developer helper: create a fresh PS5 PPR/PFS image from `plain_dir`.
// The normal cross-console restore path does not use this; it preserves an
// existing destination container through the API below.
bool pfs_resign_restore_plain_dir_to_image(const char* plain_dir,
                                           const char* target_image_path,
                                           const char* snap_dir);

// Same as above, but patches the PS5 param.sfo identity before unmounting the
// freshly-created PPR image. `account_id` and `user_id` are local destination
// values; pass 0 to leave a field unchanged.
bool pfs_resign_restore_plain_dir_to_image_for_user(const char* plain_dir,
                                                    const char* target_image_path,
                                                    const char* snap_dir,
                                                    uint64_t account_id,
                                                    uint32_t user_id);

typedef struct {
    char workspace[256], phase[32], detail[256];
    int error;
    bool unmount_uncertain, published, rename_attempted;
    bool modes_pre_verified, modes_closed_verified, modes_post_verified;
} pfs_native_restore_report_t;

// Keep the normal complete payload/SFO/identity validators at the call site.
// Called on a private dump only AFTER modes were observed inside its PFS.
typedef bool (*pfs_native_restore_validate_fn)(const char* image,
                                              const char* dump, void* context);

// Admission/journaling only: the single native Portable engine still creates
// and validates the candidate. Both callbacks are mandatory when provided.
typedef struct {
    void* context;
    bool (*publish)(void*, const char*, const char*, const char*, const char*, bool*);
    bool (*verified)(void*, const char*, const char*);
} pfs_native_restore_transaction_t;

bool pfs_resign_restore_plain_dir_into_existing_image_for_user_checked(
    const char* plain_dir, const char* target_image_path,
    const char* snap_dir, uint64_t account_id, uint32_t user_id,
    const uint8_t params_hmac[SFO_HMAC_LEN], pfs_native_restore_report_t* report,
    pfs_native_restore_validate_fn validate, void* context,
    const pfs_native_restore_transaction_t* transaction);

// Restore an existing destination through private copies only. Capture native
// modes before recreating the tree; verify modes and the supplied normal
// validators on a closed candidate and again on a private published-image copy.
// Caller owns the exclusive gate, durable barrier and encrypted rollback. A
// false result retains the workspace: do not auto-rollback, clean or continue.
bool pfs_resign_restore_plain_dir_into_existing_image_for_user(
    const char* plain_dir, const char* target_image_path,
    const char* snap_dir, uint64_t account_id, uint32_t user_id,
    const uint8_t params_hmac[SFO_HMAC_LEN], pfs_native_restore_report_t* report,
    pfs_native_restore_validate_fn validate, void* context);

// Generic filesystem helpers used by the watcher when routing between
// kernel-mediated and encrypted-blob paths. Exposed here so they are
// implemented once.
bool pfs_fs_copy_tree(const char* src, const char* dst);
// Bounded complete recursive directory/type/size/SHA-256 equality, including
// empty files/directories and every hidden name. Refuses symlinks and special
// entries. Does not edit either tree; equal empty trees are valid.
bool pfs_fs_verify_tree(const char* src, const char* dst);
bool pfs_fs_wipe_contents(const char* dir);
void pfs_fs_rmrf(const char* dir);

// True if `dir` recursively contains at least one regular file. Safety check
// before a destructive restore (don't wipe the target to re-seal an empty
// decrypted backup).
bool pfs_fs_dir_has_files(const char* dir);

// Total bytes of all regular files under `dir` (recursive). Restore diagnostic.
uint64_t pfs_fs_dir_bytes(const char* dir);

// Find the single-image PFS format (`savedata0.bin`).
bool save_find_primary_image(const char* dir, char* out, size_t outsz);

// READ-ONLY check that the kernel decrypt+mount path works on this save. Logs
// the result. Returns true on success. Never writes.
bool pfs_kernel_probe(const char* save_dir);

// Look for the `.tostonsync_format` marker that backup_to_staging()
// drops. Returns true if the file exists AND its first non-blank line
// matches a plain-PFS format tag (currently only "plain-pfs-v1").
bool pfs_fs_is_plain_pfs_marker(const char* dir);

// Marker for decrypted PS5 sdimg slot-set backups (`plain-sdimg-v1`).
bool pfs_fs_is_plain_sdimg_marker(const char* dir);

#ifdef __cplusplus
}
#endif
#endif // TOSTONSYNC_PFS_RESIGN_H
