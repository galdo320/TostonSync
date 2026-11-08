// TostónSync — sealed-key extractor for PS5 savedata.
//
// Every PS5 savedata0.bin blob carries its own per-save "sealed key"
// embedded at a fixed offset. The kernel master keys that unwrap it
// are not exposed to userland; instead, the jailbreak-loaded `pfsmgr`
// kernel module exposes an ioctl that performs the unwrap in-kernel.
//
// We send the sealed key in, we receive a 32-byte plain key out. That
// plain key is what sceFsMountSaveData() expects, which is how the
// kernel mounts the save as a filesystem we can read and write.
//
// This is the same mechanism Sony's own save data subsystem uses
// internally; the jailbreak just provides userland a way to call the
// unwrap directly. The crypto itself stays kernel-side — we never
// touch the master keys.
//
// References for the constants and API contracts used here:
//   - notch & contributors, "PS5 PFS save format notes" (ps5-dev wiki).
//   - sleirsgoevy, sealedkey unwrap traces shared on the ps5-dev IRC
//     and reproduced in ps5-payload-dev/sd_util.
//   - public ps5-payload-sdk headers (Sony API surface).
//
// Stability: ioctl number 0xc0845302 is stable across firmware 1.xx ..
// 12.xx and matches what the public sd_util uses. If Sony renumbers it
// on a future firmware, only this file changes.

#ifndef TOSTONSYNC_PFS_KEYS_H
#define TOSTONSYNC_PFS_KEYS_H

#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

// Size of the plain key sceFsMountSaveData() expects.
#define PFS_PLAIN_KEY_SIZE 32
#define PFS_SEALED_KEY_SIZE 0x60

// Read the sealed-key block from `save_image_path` (a savedata0.bin
// file) and unwrap it via /dev/pfsmgr. Writes the 32-byte plain key
// into `out_plain` on success.
//
// Returns false if:
//   - the image cannot be opened,
//   - the sealed-key block is missing or too short,
//   - /dev/pfsmgr is not available (kstuff not loaded),
//   - the unwrap ioctl returns failure.
//
// On failure `out_plain` is left untouched.
bool pfs_decrypt_save_key(const char* save_image_path,
                          uint8_t     out_plain[PFS_PLAIN_KEY_SIZE]);

// Read the wrapped key block without decrypting it. This is used only as an
// identity check before a raw byte-for-byte restore.
bool pfs_read_sealed_key(const char* save_image_path,
                         uint8_t out_sealed[PFS_SEALED_KEY_SIZE]);

// Raw images are interchangeable only when they carry the exact same wrapped
// key block (the same registered save lineage on this console).
bool pfs_save_images_share_sealed_key(const char* a, const char* b);

// Lower-level: caller already has the raw 0x60-byte sealed key
// (e.g., read from a different layout). Unwrap it in place. Useful
// for cases where the sealed key was extracted earlier or cached.
bool pfs_decrypt_sealed_key_buffer(uint8_t sealed_in[0x60],
                                   uint8_t out_plain[PFS_PLAIN_KEY_SIZE]);

#ifdef __cplusplus
}
#endif
#endif // TOSTONSYNC_PFS_KEYS_H
