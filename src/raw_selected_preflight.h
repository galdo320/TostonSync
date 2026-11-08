// Read-only RAW exact preflight. No publication or recovery caller is exposed.
#ifndef TOSTONSYNC_RAW_SELECTED_PREFLIGHT_H
#define TOSTONSYNC_RAW_SELECTED_PREFLIGHT_H
#include "raw_selected.h"

typedef struct {
    char import_id[48], zip_sha256[65], target_uid[16], title_id[16];
    raw_selected_mode_t mode;
    restore_selection_t active, services; // Both explicit, never restore-all.
} raw_selected_preflight_request_t;
typedef struct {
    char slot[64], image_name[128], result[32], detail[256];
    raw_selected_role_t role;
    raw_selected_save_kind_t save_kind;
    bool save_kind_reliable, additional_authorization_required;
    raw_selected_row_t row;
    raw_selected_identity_t source_identity, target_identity;
    char source_sha256[65], target_sha256[65];
    char source_key_fingerprint[65], target_key_fingerprint[65];
    char omitted_service_result[80];
} raw_selected_preflight_image_report_t;
typedef struct {
    char result[32], detail[256], version[32], import_id[48], target_uid[16], title_id[16];
    char work[512], zip_sha256[65], selection_receipt[65], plan_sha256[65];
    bool ready, publication_enabled, commit_reachable, destructive_recovery_enabled;
    bool barrier_armed, barrier_cleared, barrier_retained, recovery_required, approval_durable;
    raw_selected_check_t source_check, target_check;
    size_t available_backup_slots, source_title_available_slots;
    size_t selected_active_slots, selected_service_images, authorized_images;
    size_t ready_active_slots, ready_service_images, total_slots, written_slots, written_images;
    size_t image_count;
    raw_selected_preflight_image_report_t images[RAW_SELECTED_MAX_IMAGES];
} raw_selected_preflight_report_t;

// Flat literal HTTP envelope. Requires restore_mode, id, ZIP hash, UID/title,
// selected_slots and service_slots arrays. Empty services must be explicit.
bool raw_selected_preflight_parse(const char* body, raw_selected_preflight_request_t* out,
    char* err, size_t err_sz);
bool raw_selected_preflight_parse_commit(const char* body, raw_selected_preflight_request_t* out,
    char receipt[65], char* err, size_t err_sz);
// Owns the existing exclusive gate and durable native-mount barrier. Resolves
// a READY import by its exact ID; diagnostics only mount independently acquired
// private copies. Canonical ZIP/images and live targets never get mounted.
void raw_selected_preflight_run(const raw_selected_preflight_request_t* request,
    raw_selected_preflight_report_t* report);
// Read-only verification of a finalized server-held approval after restart.
// Does not grant a commit, mount, lease or recovery capability. Caller owns the
// gate if subsequently reading target state. No HTTP accepts a supplied path.
bool raw_selected_preflight_load_approval(const char* work,
    const raw_selected_preflight_request_t* request, const char* receipt,
    raw_selected_plan_t* plan, raw_selected_approval_t* approval,
    char* err, size_t err_sz);
#endif
