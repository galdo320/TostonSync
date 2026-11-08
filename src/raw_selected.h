// Exact selected RAW authority. Generic/hookless publication remains disabled;
// the dedicated controller must supply every checked-publication hook.
#ifndef TOSTONSYNC_RAW_SELECTED_H
#define TOSTONSYNC_RAW_SELECTED_H

#include "migration_inspect.h"
#include "restore_selection.h"
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define RAW_SELECTED_PUBLICATION_ENABLED false
#define RAW_SELECTED_MAX_IMAGES (RESTORE_SELECTION_MAX * 2)
#define RAW_SELECTED_PATH_MAX 512
#define RAW_SELECTED_CONTRACT_VERSION 2u

typedef enum {
    RAW_SELECTED_MODE_UNKNOWN = 0,
    RAW_SELECTED_MODE_RAW_EXACT,
    RAW_SELECTED_MODE_PORTABLE_SELECTED,
    RAW_SELECTED_MODE_RAW_COMPLETE
} raw_selected_mode_t;
typedef enum {
    RAW_SELECTED_CHECK_UNKNOWN = 0,
    RAW_SELECTED_CHECK_PASS,
    RAW_SELECTED_CHECK_FAIL
} raw_selected_check_t;
typedef enum {
    RAW_SELECTED_ROLE_UNKNOWN = 0,
    RAW_SELECTED_ROLE_ACTIVE,
    RAW_SELECTED_ROLE_SERVICE
} raw_selected_role_t;
typedef enum {
    RAW_SELECTED_SAVE_KIND_UNKNOWN = 0,
    RAW_SELECTED_SAVE_KIND_REGULAR,
    RAW_SELECTED_SAVE_KIND_SYSTEM
} raw_selected_save_kind_t;
typedef enum {
    RAW_SELECTED_OMITTED_NOT_APPLICABLE = 0,
    RAW_SELECTED_OMITTED_UNKNOWN,
    RAW_SELECTED_OMITTED_ABSENT,
    RAW_SELECTED_OMITTED_PRESENT
} raw_selected_omitted_state_t;
typedef enum {
    RAW_SELECTED_ROW_UNKNOWN = 0,
    RAW_SELECTED_ROW_FOUND,
    RAW_SELECTED_ROW_ABSENT,
    RAW_SELECTED_ROW_SQLITE_ERROR
} raw_selected_row_status_t;

// Normalized fields, not native struct stat padding or a short key fingerprint.
typedef struct {
    uint64_t dev, ino, size, mode, uid, gid, nlink;
    int64_t mtime, mtime_nsec, ctime, ctime_nsec;
    uint64_t flags;
} raw_selected_stat_t;
typedef struct {
    char title_id[16], slot[64], game_title_id[16], format[8];
    uint64_t account_id;
    uint32_t user_id, user_param;
    uint64_t blocks, system_blocks;
    char sfo_sha256[65], hmac_sha256[65];
    bool metadata_complete; // Required fields were present/typed, not defaults.
    bool hmac_present; // Presence only. Never a claim of cryptographic validity.
} raw_selected_identity_t;
typedef struct {
    raw_selected_row_status_t status;
    int64_t rowid;
    uint64_t account_id;
    uint32_t user_id;
    int sqlite_code, sqlite_extended_code;
    bool owner_verified;
} raw_selected_row_t;
typedef struct {
    raw_selected_omitted_state_t state;
    char path[RAW_SELECTED_PATH_MAX], diagnostic[RAW_SELECTED_PATH_MAX];
    char sha256[65], diagnostic_sha256[65], key_fingerprint[65];
    raw_selected_stat_t stat;
    raw_selected_identity_t identity;
    raw_selected_check_t sfo_check, key_check, geometry_check, unmount_check;
    raw_selected_check_t coherence_check;
} raw_selected_omitted_service_t;
typedef struct {
    raw_selected_role_t role;
    raw_selected_save_kind_t save_kind;
    bool save_kind_reliable; // UNKNOWN is reported, never inferred from a name.
    char slot[64], image_name[128];
    char source[RAW_SELECTED_PATH_MAX], diagnostic[RAW_SELECTED_PATH_MAX];
    char target[RAW_SELECTED_PATH_MAX], preimage[RAW_SELECTED_PATH_MAX];
    char source_sha256[65], diagnostic_sha256[65], pre_sha256[65];
    uint64_t size; // Source/native destination sizes must match; no resizing.
    // target_stat.size is also the exact approved preimage size.
    raw_selected_stat_t source_stat, target_stat;
    raw_selected_identity_t source_identity, target_identity;
    raw_selected_row_t row;
    raw_selected_check_t source_hash_check, source_sfo_check, target_sfo_check;
    raw_selected_check_t source_key_check, target_key_check;
    raw_selected_check_t geometry_check;
    raw_selected_check_t source_unmount_check, target_unmount_check;
    char source_key_fingerprint[65], target_key_fingerprint[65];
    raw_selected_omitted_service_t omitted_service;
} raw_selected_entry_t;
typedef struct {
    raw_selected_mode_t mode;
    uint32_t contract_version, format_version;
    bool partial, complete_recovery;
    char producer_version[32], manifest_sha256[65], checksums_sha256[65];
    char import_id[48], zip_sha256[65], target_uid[16], title_id[16];
    char zip_path[RAW_SELECTED_PATH_MAX], target_root[RAW_SELECTED_PATH_MAX];
    // Target root ends in /user/home/<target_uid>/savedata_prospero/<title_id>.
    // Any optional host root prefix uses the same check, never a test bypass.
    raw_selected_stat_t zip_stat;
    migration_report_t archive_report;
    raw_selected_check_t fresh_target_check;
    restore_selection_t active, services; // Both explicit; services may be empty.
    size_t available_slots, active_count, service_count, count;
    raw_selected_entry_t entries[RAW_SELECTED_MAX_IMAGES];
    char receipt[65];
} raw_selected_plan_t;
typedef struct {
    char plan_sha256[65], receipt[65];
} raw_selected_approval_t;

const char* raw_selected_mode_name(raw_selected_mode_t mode);
bool raw_selected_publication_allowed(void);
// Source-only first phase: no target reads, DB calls, keys or mounts. Prefill
// mode/import, retained ZIP path+SHA, title and both exact literal selections.
// Creates a NEW private workspace and canonical unmounted image extraction.
// Fills source inventory/metadata hashes; target/probe proof stays UNKNOWN.
bool raw_selected_source_prepare(raw_selected_plan_t* plan, const char* new_work,
    char* err, size_t err_sz);
bool raw_selected_plan_validate(const raw_selected_plan_t* plan, char* err, size_t err_sz);
bool raw_selected_plan_digest(const raw_selected_plan_t* plan, char out[65]);
// Trusted server code only: never manufacture this record from request fields.
// The transaction owns exclusive persistence of immutable plan + approval;
// progress/state is separate. A digest alone is not a permission grant.
bool raw_selected_approval_create(const raw_selected_plan_t* plan,
    raw_selected_approval_t* out, char* err, size_t err_sz);
// Optional exact-row failure evidence for the readonly preflight report.
// failed_index=SIZE_MAX if no final row was attempted; never issues aliases.
bool raw_selected_approval_create_diagnostic(const raw_selected_plan_t* plan,
    raw_selected_approval_t* out, size_t* failed_index, raw_selected_row_t* failed_row,
    char* err, size_t err_sz);
// Semantic immutable authority only: does not require live targets still equal
// prestate after publication. Transactions revalidate live state per phase.
bool raw_selected_approval_matches(const raw_selected_plan_t* plan,
    const raw_selected_approval_t* server_approval, char* err, size_t err_sz);
bool raw_selected_read_exact_row(const char* uid, const char* title, const char* slot,
    raw_selected_row_t* out, char* err, size_t err_sz);
// No-follow stable descriptor hashing, no mounts/DB/network. Rejects path aliases.
bool raw_selected_file_observe(const char* path, raw_selected_stat_t* out,
    char sha256[65], char* err, size_t err_sz);
// Exclusive new disposable copy; verifies source before/after. Never mounts it.
bool raw_selected_copy_private(const char* source, const char* diagnostic,
    const char* expected_sha256, char* err, size_t err_sz);
// New private evidence workspace only. Calls the normal ZIP/CRC/checksum
// inspector on a verified copy, then binds canonical images to actual members.
// No source/destination image mounts; successful and failed evidence retained.
bool raw_selected_verify_archive(const raw_selected_plan_t* plan,
    const char* new_work, char* err, size_t err_sz);

typedef struct {
    const char* result;
    bool publication_enabled, recovery_enabled, recovery_required, barrier_retained;
    // An attempted rename is not proof of success or failure. If uncertain,
    // these confirmed counters must never be presented as total live writes.
    bool publication_uncertain;
    size_t attempted_images;
    size_t published_images, recovered_images;
    size_t published_active_slots, published_service_images, verified_images;
    char workspace[512], plan_sha256[65], detail[256];
} raw_selected_transaction_report_t;
typedef struct {
    void* context;
    // Caller holds the exclusive gate and durable barrier throughout. Recheck
    // fresh closure/UID/rows and unchanged approved scope before each writer.
    bool (*before_publish)(const raw_selected_plan_t* plan, size_t entry,
        void* context, char* err, size_t err_sz);
    // Verify a newly acquired private copy of the published canonical image,
    // including native identity/key/geometry and confirmed unmount. Persist the
    // observation before returning true; never mount the canonical target.
    bool (*after_publish)(const raw_selected_plan_t* plan, size_t entry,
        const raw_selected_stat_t* published_stat, void* context,
        char* err, size_t err_sz);
    bool (*before_complete)(const raw_selected_plan_t* plan,
        void* context, char* err, size_t err_sz);
} raw_selected_transaction_hooks_t;
// Private preparation only: caller must already hold the existing exclusive
// restore gate and durable recovery barrier. A workspace marker is not a lock
// or authorization. A finalized read-only preflight is not a commit lease.
void raw_selected_transaction_begin(const char* work, const raw_selected_plan_t* plan,
    const raw_selected_approval_t* approval, raw_selected_transaction_report_t* report);
void raw_selected_transaction_publish(const char* work, const raw_selected_approval_t* approval,
    raw_selected_transaction_report_t* report);
// Only the dedicated RAW controller may call this, with durable one-shot claim,
// held gate/barrier and all three mandatory hooks. No automatic replay/recovery.
void raw_selected_transaction_publish_checked(const char* work,
    const raw_selected_approval_t* approval, const raw_selected_transaction_hooks_t* hooks,
    raw_selected_transaction_report_t* report);
void raw_selected_transaction_recover(const char* work, const raw_selected_approval_t* approval,
    raw_selected_transaction_report_t* report);
#ifdef RAW_SELECTED_TRANSACTION_TESTING
void raw_selected_transaction_test_begin(const char* work, const raw_selected_plan_t* plan,
    const raw_selected_approval_t* approval, raw_selected_transaction_report_t* report);
void raw_selected_transaction_test_publish(const char* work, const raw_selected_approval_t* approval,
    raw_selected_transaction_report_t* report);
void raw_selected_transaction_test_recover(const char* work, const raw_selected_approval_t* approval,
    raw_selected_transaction_report_t* report);
#endif
#endif
