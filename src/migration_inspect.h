// TostónSync - independent ZIP format detector and restore preflight.

#ifndef TOSTONSYNC_MIGRATION_INSPECT_H
#define TOSTONSYNC_MIGRATION_INSPECT_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include "paired_capture.h"

#define MIGRATION_MAX_SLOTS 32

typedef enum {
    MIGRATION_FORMAT_INVALID = 0,
    MIGRATION_FORMAT_ENCRYPTED_IMAGE,
    MIGRATION_FORMAT_TOSTON_DECRYPTED,
    MIGRATION_FORMAT_GARLIC_DECRYPTED,
    MIGRATION_FORMAT_METADATA_ONLY
} migration_format_t;

// Scratch observations before admission and after cleanup; not proof of ownership.
typedef enum {
    MIGRATION_SCRATCH_UNCHECKED = 0,
    MIGRATION_SCRATCH_ABSENT,
    MIGRATION_SCRATCH_REMAINS,
    MIGRATION_SCRATCH_UNKNOWN
} migration_scratch_state_t;

typedef struct {
    migration_scratch_state_t state;
    int lstat_return;
    bool errno_valid;
    int error_number;
} migration_scratch_diagnostic_t;

typedef struct {
    migration_format_t format;
    char title_id[16];
    char title_name[128];
    char source_console_name[64];
    char source_console_type[32];
    char source_user_uid[32];
    char created_at_utc[32];
    int64_t created_at_epoch;
    char save_dirs[MIGRATION_MAX_SLOTS][64];
    size_t save_dir_count;
    size_t active_images;
    size_t service_images;
    char service_dirs[MIGRATION_MAX_SLOTS][64];
    size_t service_dir_count;
    size_t missing_service_images;
    char first_missing_service_image[128];
    char raw_completeness[40];
    // Explicit partial RAW export scope, never proof of a whole-title backup.
    char backup_scope[32];
    bool selected_containers;
    size_t available_slots;
    size_t selected_slots_count;
    char selected_slots[MIGRATION_MAX_SLOTS][64];
    size_t included_image_count;
    char included_images[MIGRATION_MAX_SLOTS * 2][128];
    size_t payload_files;
    bool has_manifest;
    bool has_checksums;
    bool has_capture;
    char capture_id[64];
    bool valid;
    bool needs_kernel;
    char restore_strategy[16];
    bool strategy_ready;
    bool target_identity_required;
    char strategy_reason[192];
    char reason[192];
    bool capture_diagnostic_attempted;
    paired_capture_diagnostic_t capture_title_diagnostic;
    paired_capture_diagnostic_t capture_raw_diagnostic;
    migration_scratch_diagnostic_t scratch_before_create;
    migration_scratch_diagnostic_t scratch_after_cleanup;
    migration_scratch_diagnostic_t capture_raw_scratch_after_cleanup;
} migration_report_t;

bool migration_inspect_zip(const char* zip_path, const char* title_hint,
                           migration_report_t* out);
// Complete recursive payload inventory, excluding only slot-root sce_sys.
bool migration_count_plain_payload(const char* dir, size_t* count);
bool migration_verify_extracted_checksums(const char* root, bool* present,
                                          char* error, size_t error_sz);
// Optional TITLE/.capture pair validation, including only the fixed RAW child.
// Child extraction uses new sibling scratch, never a Portable payload path.
bool migration_verify_extracted_capture(const char* root, bool* present,
                                        char* error, size_t error_sz);
void migration_plan_report(migration_report_t* report);
const char* migration_format_name(migration_format_t format);
void migration_report_json(const migration_report_t* report,
                           char* out, size_t out_sz);
// Returns required bytes excluding NUL; no scratch path is serialized.
size_t migration_scratch_diagnostic_json(const migration_scratch_diagnostic_t* diagnostic,
                                         char* out, size_t out_sz);

#endif
