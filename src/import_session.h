// TostónSync - bounded, resumable browser ZIP imports.

#ifndef TOSTONSYNC_IMPORT_SESSION_H
#define TOSTONSYNC_IMPORT_SESSION_H

#include "config.h"
#include "restore_selection.h"
#include "lifecycle.h"
#include "individual_catalog.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define IMPORT_MAX_BYTES  (8ULL * 1024ULL * 1024ULL * 1024ULL)
#define IMPORT_CHUNK_BYTES (8U * 1024U * 1024U)

typedef enum {
    IMPORT_IDLE = 0,
    IMPORT_RECEIVING,
    IMPORT_VERIFYING,
    IMPORT_READY,
    IMPORT_COMMITTED,
    IMPORT_FAILED,
    IMPORT_RECOVERING
} import_state_t;

typedef struct {
    char id[48];
    char name[96];
    char path[512];
    char location[32];
    char source[24];
    char title_hint[16];
    char user_hint[16];
    char sha256[65];
    char portable_path[512];
    char portable_sha256[65];
    char error[160];
    uint64_t expected;
    uint64_t received;
    int64_t updated_unix;
    import_state_t state;
    // Sticky once an explicit selection is requested. Missing/corrupt scope
    // never downgrades it into legacy restore-all permission after restart.
    bool restore_selection_required;
    restore_scope_t restore_scope;
} import_session_info_t;

// Historical records are NOT work sessions: no claim, Restore, receipt or
// reactivation authority. Fingerprints come from the normal ZIP inspector.
typedef struct {
    char source_format[32];
    char title_id[16];
    char source_uid[16];
    char raw_manifest_sha256[65];
    char raw_inventory_sha256[65];
    char portable_manifest_sha256[65];
    char portable_inventory_sha256[65];
} import_preserve_metadata_t;

typedef struct {
    import_session_info_t historical;
    import_preserve_metadata_t metadata;
    uint64_t raw_size;
    uint64_t portable_size;
    int64_t preserved_unix;
    char preserved_version[32];
    char record_path[512];
    char record_sha256[65];
    char checkpoint_sha256[65];
    uint64_t checkpoint_offset;
    uint64_t checkpoint_size;
    char receipt_domain[32]; // HISTORICAL_NON_AUTHORIZING, including checkpoint.
    char inventory_fingerprint_scope[48];
    bool operational_authority; // Always false; receipts are HISTORICAL.
} import_preserved_info_t;

// Caller owns the existing exclusive gate and checks workers/recovery first.
// The core additionally requires a stable READY session with no claim.
bool import_session_preserve(const char* id,
                             const import_preserve_metadata_t* metadata,
                             import_preserved_info_t* out,
                             char* error, size_t error_cap);
bool import_session_preserved_status(const char* id, import_preserved_info_t* out);
bool import_session_preserved_count(size_t* out);
// Pure observations report registry errors without latching operational state.
bool import_session_preserved_status_observe(const char* id, import_preserved_info_t* out);
// Blocks historical RAW/portable aliases and uncertain registry state. No
// historical path is ever granted operational authority by this helper.
bool import_session_preserved_path_blocked(const char* path);

#ifdef IMPORT_SESSION_TEST
typedef enum {
    IMPORT_PRESERVE_AFTER_TEMP_WRITE = 1,
    IMPORT_PRESERVE_AFTER_TEMP_FSYNC,
    IMPORT_PRESERVE_AFTER_PUBLISH,
    IMPORT_PRESERVE_AFTER_DIRECTORY_FSYNC,
    IMPORT_PRESERVE_AFTER_RELOAD,
    IMPORT_PRESERVE_BEFORE_RELEASE,
    IMPORT_PRESERVE_AFTER_RELEASE,
    IMPORT_PRESERVE_AFTER_POST_VERIFY
} import_preserve_boundary_t;
typedef bool (*import_preserve_fault_fn)(import_preserve_boundary_t boundary);
void import_session_preserve_test_fault(import_preserve_fault_fn fault);
#endif

void import_session_init(const config_t* cfg);
// Called by the daemon loop, never by a request. Uses existing expiry policy.
void import_session_maintenance(void);
// Sticky read-only initialization for validation: no cleanup, normalization,
// source hashing, receipt authority or later promotion to operational imports.
typedef struct {
    import_session_info_t info;
    life_check_t result;
    bool checkpoint_present;
    bool checkpoint_valid; // Includes known absence/IDLE; not runtime CLEAR.
    bool historical_receipt_present;
    bool operational_authority; // Always false.
    char detail[160];
} import_session_observation_t;
void import_session_observe_init(const config_t* cfg);
bool import_session_observe_snapshot(import_session_observation_t* out);
bool import_session_start(const config_t* cfg, const char* name,
                          uint64_t expected, uint64_t reserve_bytes,
                          const char* title_hint, const char* user_hint,
                          const char* source, const char* resume_id,
                          import_session_info_t* out);
// Explicit RAW identity survives reload; Portable keeps its separate approved scope.
bool import_session_start_uid(const config_t* cfg, const char* name,
                              uint64_t expected, uint64_t reserve_bytes,
                              const char* title_hint, const char* uid,
                              const char* source, const char* resume_id,
                              import_session_info_t* out);
// Pure identity observation: 1 explicit, 0 legacy, -1 unavailable/stale.
int import_session_restore_uid(const char* id, char uid[16]);
bool import_session_restore_target_allowed(const char* path, const char* uid, bool explicit_uid);
bool import_session_release_target_rejected(const char* id, const char* uid);
bool import_session_target_reviewed(const char* id, const char* uid);
const char* import_session_rejected_uid(const import_session_info_t* info);
bool import_session_write(const char* id, uint64_t offset,
                          const void* data, size_t len,
                          import_session_info_t* out);
bool import_session_finish(const char* id, const char* expected_sha256,
                           import_session_info_t* out);
// Current-session observation never expires or mutates the session.
bool import_session_current(import_session_info_t* out);
// Pure in-memory observation: no expiry, load, hashing, persistence or cleanup.
life_check_t import_session_lifecycle_snapshot(void);
typedef enum {
    IMPORT_JOBS_OBSERVED, IMPORT_JOBS_BUSY, IMPORT_JOBS_UNKNOWN
} import_jobs_observation_t;
typedef struct {
    char native_id[48]; // Private correlation only; never a receipt or public job ID.
    char title_id[16], user_uid[16], container[64];
    import_state_t state;
    uint64_t received, expected;
    int64_t updated_unix;
    bool current_present, uncertain, observation_only;
} import_jobs_snapshot_t;
// Trylock and allowlisted memory only. BUSY/UNKNOWN never means no work.
import_jobs_observation_t import_session_jobs_snapshot(import_jobs_snapshot_t* out);
bool import_session_status(const char* id, import_session_info_t* out);
// Same validation result without latching registry uncertainty.
bool import_session_status_observe(const char* id, import_session_info_t* out);
bool import_session_set_title_hint(const char* id, const char* title_hint);
// Recovery always retains the original upload. Only this session's fixed
// temporary sidecar may be published after source/candidate SHA verification.
bool import_session_recovery_candidate(const import_session_info_t* info,
                                       char* out, size_t out_sz);
bool import_session_begin_recovery(const char* id, import_session_info_t* out);
bool import_session_finish_recovery(const char* id, const char* candidate_path,
                                    const char* title_hint, const char* error,
                                    import_session_info_t* out);
const char* import_session_selected_path(const import_session_info_t* info);
bool import_session_validate_selected(const import_session_info_t* info);
// True only for the finalized ZIP owned by the current reviewed session.
// This lets the restore queue accept USB-backed staging without trusting an
// arbitrary path supplied by a client.
bool import_session_owns_ready_path(const char* path);
bool import_session_claim(const char* id, import_session_info_t* out);
bool import_session_invalidate_restore_scope(const char* id, bool require_selection);
bool import_session_bind_restore_scope(const import_session_info_t* reviewed,
                                      const restore_scope_t* scope);
bool import_session_get_restore_scope(const char* id, restore_scope_t* out);
bool import_session_claim_restore_scope(const restore_scope_t* scope,
                                       import_session_info_t* out);
bool import_session_validate_restore_scope(const restore_scope_t* scope,
                                           const char* path);
bool import_session_legacy_restore_allowed(const char* path);
// Metadata-only guard for absolute-path transports of this session's source,
// including aliases. Uncertain identity blocks when selective authority exists.
bool import_session_path_requires_selection(const char* path);
// Selected Portable finalization consumes its receipt, retains the sticky
// selection guard and requires a durable checkpoint. An uncertain checkpoint
// remains committed/blocked; RAW's separate finalizer is unchanged.
bool import_session_unclaim(const char* id);
// Dedicated RAW finalization only. Success includes checkpoint fsync; failure
// retains uncertain committed authority rather than pretending it is released.
bool import_session_unclaim_raw_durable(const char* id);
bool import_session_cancel(const char* id);
const char* import_state_name(import_state_t state);

// Individual Library adapters add no Restore authority. Their marker is durable
// and sticky before transfer/inspection; the fixed private binding requires the
// exact owned READY ZIP. Existing selected preflight/receipt/commit remains the
// only way to authorize the writer. Missing/corrupt bindings fail closed.
bool import_session_individual_mark(const char* id, import_session_info_t* out);
bool import_session_individual_browser_mark(const char* id, import_session_info_t* out);
bool import_session_individual_checkpoint(const char* id, import_session_info_t* out);
bool import_session_individual_bind(const char* id, const individual_backup_t* item,
                                    const char* container, import_session_info_t* out);
bool import_session_individual_get(const char* id, individual_backup_t* item,
                                   char container[64]);

#endif
