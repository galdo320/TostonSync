// TostónSync — kernel-mediated savedata mount/unmount.
//
// Wraps Sony's `sceFsMountSaveData()` so we can read and write a
// save's decrypted contents through a regular filesystem path. The
// sealed-key unwrap is done first by pfs_keys.c; this module takes
// the resulting plain key, hands it to the kernel, and the kernel
// mounts the encrypted blob as a real PFS at our mount point.
//
// "Resign" is automatic on unmount: the kernel re-seals whatever
// content lives inside the mount using the same console keys that
// unwrapped it. To restore to another local profile, that profile
// must already have a target save blob/sealed key; TostónSync does
// not create a brand-new save container in this module.
//
// References for the API contracts used here:
//   - ps5-payload-sdk exported libSceFsInternalForVsh symbol names (import
//     stubs only, not declarations or native-creator ABI documentation).
//   - ps5-payload-sdk public ps5/kernel.h credential helpers.
//   - Public ps5-dev notes / sd_util material documenting the savedata
//     ucred requirements, MountOpt budgetid field and UmountOpt ABI.
//
// Hardware note: every function here calls into kernel-jailbreak
// surface (sceFs* lives in libSceFs / libkernel and requires the
// payload sandbox-escape to have succeeded). Without kstuff loaded
// these calls will fail; callers must be ready to fall back.

#ifndef TOSTONSYNC_SAVEMOUNT_H
#define TOSTONSYNC_SAVEMOUNT_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include "lifecycle.h"

#ifdef __cplusplus
extern "C" {
#endif

#define SAVEMOUNT_PATH_MAX 256

// Handle returned by savemount_mount; opaque to callers.
typedef struct {
    int  handle;                       // sceFsMountSaveData return
    char mount_point[SAVEMOUNT_PATH_MAX];
    // EPIPE workaround bookkeeping (see savemount.c): sceFsMountSaveData
    // fails with EPIPE when the image lives under /user/home/.../
    // savedata_prospero, so off-/data images are copied to a /data work
    // file and that is what gets mounted. `image_origin` is the original
    // path to copy the resealed image back to (empty when mounted in
    // place); `image_backing` is the /data work file; `writeback` says
    // whether to copy back on unmount (true only for re-seal/write mounts).
    char image_backing[SAVEMOUNT_PATH_MAX];
    char image_origin[SAVEMOUNT_PATH_MAX];
    bool writeback;
} savemount_t;

// Mount the savedata image at `image_path` using the 32-byte plain
// key produced by pfs_decrypt_save_key(). On success, `out` receives
// the live mount handle + the absolute mount point path; pass `out`
// back at the same address, unchanged, to savemount_unmount() to release.
//
// Mount points live under /data/tostonsync/mounts/m<N>/ where <N>
// is process-unique. We never recycle slots within a process so two
// concurrent mounts cannot collide.
//
// Returns false on failure. A native attempt or uncertain observation may
// retain resources and latch LIFE_UNKNOWN; do not retry or remove them.
bool savemount_mount(const char* image_path,
                     const uint8_t plain_key[32],
                     savemount_t* out);

// Native inspection can rewrite PFS headers even without application writes.
// Always mount an owned disposable work copy, including for sources under /data.
bool savemount_mount_inspect(const char* image_path,
                             const uint8_t plain_key[32], savemount_t* out);

// Same as savemount_mount, but the mounted image is copied back to its
// original location on unmount (so an in-mount edit + kernel re-seal
// persists). Use this ONLY when the caller modifies the mount and wants
// the change saved to `image_path`; the plain savemount_mount discards the
// /data work copy (read-only / dump mounts, which must never rewrite a live
// save). When `image_path` is already under /data, both behave identically.
bool savemount_mount_rw(const char* image_path,
                        const uint8_t plain_key[32],
                        savemount_t* out);

// Unmount only a registered, unchanged handle at its original address.
// A fresh zero-initialized struct is a no-op. Native unmount is admitted once;
// false can retain resources and LIFE_UNKNOWN, even after native success.
// Do not retry, copy handles, or clean retained paths after a false return.
bool savemount_unmount(savemount_t* m);
// In-memory observation only. An uncertain unmount remains a stop barrier.
life_check_t savemount_lifecycle_snapshot(void);

// Publish one already-closed encrypted copy; never mounts, modifies or deletes
// closed_copy. Caller owns the exclusive save-I/O gate, persistent barrier and
// retained rollback/evidence. The target must remain closed to external writers.
// An existing target.smnew is a hard stop; all failure artifacts are retained.
// rename_attempted is required and becomes true immediately before the one
// rename, including a failed rename. A false return after that point does NOT
// prove no live write.
bool savemount_publish_closed_candidate(const char* closed_copy, const char* target,
                                        const char* expected_candidate_sha,
                                        const char* expected_target_sha,
                                        bool* rename_attempted);

// Legacy PPR helper: uses a locally declared create-image call and supplies
// a zero key. The SDK import stub does not prove this ABI or native slot
// creation/registration, and a mount does not prove owner/HMAC acceptance.
// The helper remains dormant; it must not create missing restore targets.
// Existing `image_path` is overwritten as a caller-chosen build artifact.
bool savemount_create_ppr_image(const char* image_path,
                                uint64_t image_size,
                                uint8_t out_key[32]);

#ifdef __cplusplus
}
#endif
#endif // TOSTONSYNC_SAVEMOUNT_H
