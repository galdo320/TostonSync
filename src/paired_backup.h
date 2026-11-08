// Manual selected capture: one immutable encrypted acquisition, then Portable
// derived only from disposable clones. This producer grants no Restore authority.
#ifndef TOSTONSYNC_PAIRED_BACKUP_H
#define TOSTONSYNC_PAIRED_BACKUP_H

#include "paired_capture.h"
#include "migration_inspect.h"
#include "restore_selection.h"
#include <sys/stat.h>

typedef struct {
    struct stat stat;
    char sha256[65];
} paired_backup_observation_t;

typedef struct {
    char source[512], workspace[512], uid[16], title_id[16];
    restore_selection_t active, services;
    size_t available_slots;
    bool deflate;
} paired_backup_request_t;

typedef struct {
    char uid[16], title_id[16], service_slots[2048];
    restore_selection_t active;
} paired_backup_manual_request_t;

// Exact five-field manual HTTP contract. No nested/duplicate/unknown fields,
// truncation, alias expansion or non-boolean closed-game consent.
bool paired_backup_parse_manual(const char*, paired_backup_manual_request_t*, char*, size_t);

typedef struct {
    void* context;
    bool (*observe)(void*, const char*, paired_backup_observation_t*, char*, size_t);
    bool (*copy)(void*, const char*, const char*, const char*, char*, size_t);
    bool (*convert)(void*, const char*, const char*, const char*, const char*, bool*, char*, size_t);
    bool (*barrier)(void*, bool, const char*, char*, size_t);
    bool (*revalidate)(void*, char*, size_t);
    bool (*finalize_portable)(void*, const char*, const char*, const paired_capture_t*,
                              const char*, char*, size_t);
} paired_backup_callbacks_t;

typedef struct {
    char outcome[40], detail[256], workspace[512], artifact[512];
    char raw_zip_path[512], raw_zip_sha256[65];
    uint64_t raw_zip_size;
    char portable_zip_path[512], portable_zip_sha256[65];
    uint64_t portable_zip_size;
    char capture_id[64], uid[16], title_id[16];
    size_t selected_active_slots, selected_service_images, acquired_images;
    bool raw_verified, portable_verified, migration_ready;
    bool acquisition_stable_observed;
    bool barrier_retained, unmount_uncertain;
    bool capture_diagnostic_attempted, inspector_diagnostic_attempted;
    paired_capture_diagnostic_t capture_diagnostic;
    paired_capture_diagnostic_t inspector_title_diagnostic, inspector_raw_diagnostic;
    migration_scratch_diagnostic_t scratch_before_create, scratch_after_cleanup,
                                   capture_raw_scratch_after_cleanup;
} paired_backup_report_t;

// Bounded public summary: no paths, unexpected names or archive/save hashes.
size_t paired_backup_diagnostic_summary(const paired_backup_report_t*, char*, size_t);

// Caller owns the exclusive gate and validates fresh UID/title/service inventory.
// workspace is a new private directory. No retries, deletes or live writes.
// true means PAIRED_VERIFIED or RAW_ONLY; consult migration_ready explicitly.
bool paired_backup_run(const paired_backup_request_t*, const paired_backup_callbacks_t*,
                       paired_backup_report_t*);

#endif
