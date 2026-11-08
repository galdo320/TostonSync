// Private diagnostic adapter; no canonical/live mount, export or writeback.
#ifndef TOSTONSYNC_RAW_SELECTED_NATIVE_H
#define TOSTONSYNC_RAW_SELECTED_NATIVE_H
#include "raw_selected.h"
#include "sfo.h"

typedef enum {
    RAW_SELECTED_NATIVE_BLOCKED = 0,
    RAW_SELECTED_NATIVE_READY,
    RAW_SELECTED_NATIVE_UNMOUNT_UNCERTAIN
} raw_selected_native_status_t;
typedef struct {
    const char *canonical, *private_image, *private_workspace;
    const char *expected_sha256, *expected_title, *expected_slot;
    const raw_selected_stat_t* canonical_stat;
    raw_selected_role_t role; // Literal transport role; never a save-kind guess.
} raw_selected_native_request_t;
typedef struct {
    raw_selected_native_status_t status;
    raw_selected_role_t role;
    raw_selected_save_kind_t save_kind;
    bool save_kind_reliable, metadata_complete, geometry_reliable;
    bool key_available, mount_attempted, mounted, unmount_confirmed;
    bool canonical_unchanged;
    uint64_t image_size, blocks, system_blocks;
    char format[8], key_fingerprint[65], closed_diagnostic_sha256[65];
    raw_selected_stat_t closed_diagnostic_stat;
    raw_selected_identity_t identity;
    sfo_info_t metadata;
    char retained_mount[256], retained_backing[256], detail[256];
} raw_selected_native_observation_t;

// Caller holds the existing exclusive save-I/O gate and durable barrier before
// entry. private_image is a NEW verified disposable copy under an owned private
// workspace, not canonical, not a live path, not a future publication image.
// Native mounts are not kernel MOUNT_RO: only this disposable copy may reseal.
// No edits/export/writeback or cleanup. On uncertain unmount retain workspace
// and barrier and stop all native attempts; do not retry from this function.
// READY proves observable metadata/key availability, not HMAC/game acceptance.
void raw_selected_native_observe(const raw_selected_native_request_t* request,
    raw_selected_native_observation_t* out, char* err, size_t err_sz);
#endif
