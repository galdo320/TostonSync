// Offline recovery transaction for a future, independently approved slot creator.
// This module NEVER creates native containers or registers new savedata rows.
#ifndef TOSTONSYNC_SDIMG_EXPANSION_H
#define TOSTONSYNC_SDIMG_EXPANSION_H

#include <stdbool.h>
#include <stddef.h>

#define SDIMG_EXPANSION_NAME_MAX 128
#define SDIMG_EXPANSION_JOURNAL ".expansion.sqlite"
#define SDIMG_EXPANSION_REQUIRED ".expansion-required"

// Caller owns the save-I/O barrier and has already snapshotted every original
// sdimg_* (including service images) in rollback_dir. Approved staging contains
// only the future images' immutable expected bytes; approved_rows_db must have
// the identical savedata schema and exactly those new rows for this title.
// arm writes only its journal. A failed arm never authorizes publication.
bool sdimg_expansion_arm(const char* uid, const char* title,
                         const char* target_dir, const char* db_path,
                         const char* rollback_dir,
                         const char* approved_staging_dir,
                         const char* approved_rows_db,
                         const char added_names[][SDIMG_EXPANSION_NAME_MAX],
                         size_t added_count, char* err, size_t err_sz);

// Confirms the exact approved new files/rows are present, then durably records
// COMMITTED. Original rows must remain byte/type-identical; original images
// must retain their target sealed keys. No live data is modified.
bool sdimg_expansion_commit(const char* target_dir, const char* db_path,
                            const char* rollback_dir, char* err, size_t err_sz);

// Restores original images using the shared verified-copy helper, removes only
// approved added images/rows, and records RECOVERED. Unknown bytes/rows/schema
// fail closed. ARMED/COMMITTED/RECOVERING can all recover after interruption.
// Holds BEGIN IMMEDIATE from live validation through file work and DB COMMIT.
// SQL recovery preserves original rows/rowids; it does not rewind the global
// sqlite_sequence. Unknown atomic-copy temporaries/SQLite sidecars require
// manual review. The expansion-required sentinel is never deleted here.
bool sdimg_expansion_recover(const char* target_dir, const char* db_path,
                             const char* rollback_dir, char* err, size_t err_sz);

// Read-only journal + snapshot + current-target validation. No mounts or PPR.
bool sdimg_expansion_validate(const char* target_dir, const char* db_path,
                              const char* rollback_dir, char* err, size_t err_sz);
bool sdimg_expansion_identity(const char* rollback_dir, char uid[16],
                              char title[16], char* err, size_t err_sz);
// Errors/corruption are pending, never mistaken for an absent/completed plan.
// COMMITTED remains pending in this offline foundation: it is not permission
// to activate the future native creator or clear the caller's restore barrier.
bool sdimg_expansion_exists(const char* rollback_dir);
bool sdimg_expansion_pending(const char* rollback_dir);

// Shared implementation supplied by sdimg_restore.c (host fixtures stub it).
bool sdimg_restore_copy_verified(const char* source, const char* destination);
bool sdimg_restore_images_share_key(const char* a, const char* b);

#endif
