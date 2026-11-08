// Dedicated encrypted RAW publication. No portable worker, replay or recovery.
#ifndef TOSTONSYNC_RAW_SELECTED_COMMIT_H
#define TOSTONSYNC_RAW_SELECTED_COMMIT_H
#include "raw_selected_preflight.h"
typedef struct {
    char image_name[128], target[512], source_sha256[65], pre_sha256[65];
    raw_selected_role_t role;
    bool pre_verified, post_verified;
} raw_selected_commit_image_t;
typedef struct {
    char result[40], detail[256], version[32];
    char import_id[48], target_uid[16], title_id[16], zip_sha256[65];
    char selection_receipt[65], workspace[512], authority_sha256[65];
    bool queued, terminal, publication_enabled, destructive_recovery_enabled;
    bool recovery_required, barrier_retained, publication_uncertain;
    size_t selected_active_slots, selected_service_images, authorized_images;
    size_t attempted_images, written_images, written_active_slots, written_service_images;
    size_t verified_images, uncertain_images;
    size_t image_count;
    raw_selected_commit_image_t images[RAW_SELECTED_MAX_IMAGES];
} raw_selected_commit_report_t;
bool raw_selected_commit_parse(const char* body, raw_selected_preflight_request_t* request,
    char receipt[65], char* err, size_t err_sz);
// An HTTP request supplies scope, never a server workspace or authority path.
// Durable claim is permanently single-use even after restart/response loss.
void raw_selected_commit_submit(const raw_selected_preflight_request_t* request,
    const char* receipt, raw_selected_commit_report_t* report);
bool raw_selected_commit_status(const char* import_id, const char* receipt,
    raw_selected_commit_report_t* report);
bool raw_selected_commit_active(void);
void raw_selected_commit_join(void);
#endif
