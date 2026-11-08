// TostonSync — observational savedata inventory. No image payload access.
#ifndef TOSTONSYNC_SAVE_METADATA_H
#define TOSTONSYNC_SAVE_METADATA_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define SAVE_METADATA_MAX_ENTRIES 128

typedef enum {
    SAVE_METADATA_UNKNOWN = 0,
    SAVE_METADATA_PASS = 1,
    SAVE_METADATA_FAIL = 2
} save_metadata_check_t;

typedef struct {
    char name[256];              // Exact dir_name/sdimg suffix; never normalized.
    char image_name[256];
    bool service;
    save_metadata_check_t registered;
    bool rowid_available;
    int64_t rowid;
    save_metadata_check_t sdimg;
    int stat_errno;
    bool metadata_available;
    char type[16];
    uint64_t size, dev, inode;
    int64_t mtime, ctime;
    uint32_t mode;
    int64_t mtime_nsec, ctime_nsec;
} save_metadata_entry_t;

typedef struct {
    bool present;
    char operation[48];
    char sql[128];
    int return_code, primary_code, extended_code;
    bool database_error_available;
    char message[256];
    bool message_truncated;
} save_metadata_sql_failure_t;

typedef struct {
    bool present;
    int action_code;
    bool argument1_present, argument2_present, database_present, context_present;
    char argument1[128], argument2[128], database[64], context[128];
    bool truncated;
} save_metadata_authorizer_denial_t;

typedef struct {
    save_metadata_sql_failure_t sqlite_failure;
    save_metadata_authorizer_denial_t authorizer_denial;
    char validation_rejection[64];
    bool post_query_stability_checked, post_query_stable;
    char stability_operation[32];
    int stability_errno;
} save_metadata_registry_diagnostic_t;

typedef struct {
    save_metadata_check_t filesystem;
    int filesystem_errno;
    char filesystem_detail[192];
    save_metadata_check_t registry;
    int registry_errno;
    char registry_detail[192];
    save_metadata_registry_diagnostic_t registry_diagnostic;
    save_metadata_entry_t active[SAVE_METADATA_MAX_ENTRIES];
    size_t active_count;
    save_metadata_entry_t service[SAVE_METADATA_MAX_ENTRIES];
    size_t service_count;
} save_metadata_report_t;

// Paths must already be resolved by the caller. Uses only directory metadata,
// lstat and read-only SQLite metadata rows for this exact title. Image files are
// never opened. Database reads use immutable=1 (no locks/sidecar writes); they
// are accepted only without WAL/journal and with unchanged metadata throughout.
// Observational, not an atomic snapshot or authorization to restore/write.
void save_metadata_collect(const char* saves_dir, const char* db_path,
                           const char* title_id, save_metadata_report_t* out);

#endif
