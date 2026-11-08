// Destination-to-owned-import adapter; selected Restore remains the only writer.
#ifndef TOSTONSYNC_INDIVIDUAL_RESTORE_H
#define TOSTONSYNC_INDIVIDUAL_RESTORE_H
#include "individual_catalog.h"
#include "import_session.h"
#include "migration_inspect.h"

bool individual_restore_review(const import_session_info_t* info,
    const individual_backup_t* item, migration_report_t* report,
    char container[64], char* error, size_t error_cap);
bool individual_restore_prepare(const config_t* cfg, individual_backup_t* item,
    uint64_t reserve_bytes, import_session_info_t* info,
    migration_report_t* report, char container[64], char* error, size_t error_cap);
bool individual_restore_source_current(const individual_backup_t* item);
bool individual_restore_target_exists(const config_t* cfg,
    const individual_backup_t* item, const char* container,
    char* error, size_t error_cap);
#endif
