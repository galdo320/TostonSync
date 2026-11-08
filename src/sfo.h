// TostónSync — PS5/PS4 param.sfo (PSF) reader/writer.
//
// The save-service param.sfo (sce_sys/param.sfo) carries the metadata the PS5
// uses to validate and register a save: SAVEDATA_DIRECTORY (the TRUE slot
// name), TITLE_ID, account id, block counts, and a 32-byte HMAC inside the
// PARAMS blob. TostónSync's earlier bug derived the slot name from the
// *filename* (so "sdimg_sce_bu_…" became a phantom slot). The correct source
// of truth is SAVEDATA_DIRECTORY parsed from this file.
//
// The HMAC is a keyed digest we cannot recompute without console secrets.
// Existing-slot restore preserves the HMAC read from that native destination
// slot. A cached value from another slot, or equality observed in samples,
// does not authorize fresh native creation. A source HMAC is not local proof.
//
// The PSF container format itself is public (psdevwiki). This is a clean
// reimplementation, not copied code.

#ifndef TOSTONSYNC_SFO_H
#define TOSTONSYNC_SFO_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define SFO_HMAC_LEN 32

typedef struct {
    char     title_id[16];
    char     dir_name[64];       // SAVEDATA_DIRECTORY — the real slot name
    char     main_title[128];
    char     sub_title[128];
    char     detail[256];
    char     game_title_id[16];
    char     format[8];          // "ppr" (PS5) or "obs" (PS4)
    uint64_t account_id;
    uint32_t user_id;
    uint32_t user_param;        // first u32 in PARAMS; copied into savedata.db
    uint64_t blocks;
    uint64_t system_blocks;
    bool     zeroed;             // file was all-zero (corrupted SFO)
    bool     has_hmac;           // a non-zero PARAMS HMAC was present
    uint8_t  hmac[SFO_HMAC_LEN];
} sfo_info_t;

// Parse `path`. Returns 0 on success, -1 on read/format error, -2 if the
// file is all-zero (corrupted). On -2, `out->zeroed` is set.
int sfo_parse(const char* path, sfo_info_t* out);

// Read just the 32-byte PARAMS HMAC from a valid param.sfo into `hmac`.
// Returns true only if a non-zero HMAC was found.
bool sfo_read_hmac(const char* path, uint8_t hmac[SFO_HMAC_LEN]);

// Write a complete, valid param.sfo to `path` from `in`. If `hmac` is non-NULL
// it is embedded at PARAMS+0x08; this copies bytes, it does not compute or
// validate a HMAC. If NULL the HMAC bytes are left zero.
// Returns 0 on success, -1 on failure.
int sfo_write(const char* path, const sfo_info_t* in,
              const uint8_t* hmac /* SFO_HMAC_LEN bytes, or NULL */);

// Patch only the local identity fields inside an existing param.sfo, preserving
// every other byte and the existing PARAMS HMAC. Returns false if a requested
// identity field could not be found/written.
bool sfo_patch_identity(const char* path, uint64_t account_id, uint32_t user_id);

// Cross-console variant: patch identity and replace PARAMS HMAC with one read
// from the destination PS5. A source-console HMAC must never be retained after
// changing the owner fields.
bool sfo_patch_identity_hmac(const char* path, uint64_t account_id,
                             uint32_t user_id,
                             const uint8_t hmac[SFO_HMAC_LEN]);

#ifdef __cplusplus
}
#endif
#endif // TOSTONSYNC_SFO_H
