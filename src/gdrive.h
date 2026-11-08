// TostónSync — Google Drive backend.
//
// Implements:
//   - OAuth 2.0 Device Authorization Grant (RFC 8628) for sign-in
//     without a keyboard. The PS5 polls Google; the user authorizes
//     on a phone by scanning a QR code that points at the verification
//     URL pre-filled with the device's user_code.
//   - Resumable uploads via the Drive v3 REST API.
//   - Listing and deletion (for retention pruning).
//   - Refresh-token rotation. Tokens are persisted in tokens.json
//     under state_dir; never embedded in the binary, never shared.
//
// All HTTPS is performed via libSceHttp / libSceSsl (no libcurl
// dependency).

#ifndef TOSTONSYNC_GDRIVE_H
#define TOSTONSYNC_GDRIVE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "config.h"
#include "catalog_scan.h"
#include "individual_catalog.h"

#ifdef __cplusplus
extern "C" {
#endif

#define GDRIVE_USERCODE_MAX     32
#define GDRIVE_DEVICECODE_MAX   128
#define GDRIVE_VERIFY_URL_MAX   256
#define GDRIVE_EMAIL_MAX        128
#define GDRIVE_FILEID_MAX       64
#define GDRIVE_DIAG_CODE_MAX    40
#define GDRIVE_DIAG_DETAIL_MAX  256

// State of the Drive backend at any point in time.
typedef enum {
    GDRIVE_STATE_NOT_CONFIGURED = 0,  // client_id / client_secret empty
    GDRIVE_STATE_NOT_SIGNED_IN,       // configured but no refresh token
    GDRIVE_STATE_DEVICE_PENDING,      // device flow in progress
    GDRIVE_STATE_DEVICE_DENIED,       // user denied or code expired
    GDRIVE_STATE_READY,               // signed in; uploads possible
    GDRIVE_STATE_ERROR
} gdrive_state_t;

// Result of starting the device flow. The verification_url_complete is
// what the QR code should encode — Google accepts the user_code as a
// query parameter so the phone side requires zero typing.
typedef struct {
    char user_code[GDRIVE_USERCODE_MAX];
    char device_code[GDRIVE_DEVICECODE_MAX];
    char verification_url[GDRIVE_VERIFY_URL_MAX];
    char verification_url_complete[GDRIVE_VERIFY_URL_MAX];
    int  interval_seconds;
    int  expires_in_seconds;
} gdrive_device_flow_t;

// Lightweight account info, populated after a successful sign-in.
typedef struct {
    char     email[GDRIVE_EMAIL_MAX];
    uint64_t quota_total_bytes;
    uint64_t quota_used_bytes;
} gdrive_account_t;

typedef struct {
    char code[GDRIVE_DIAG_CODE_MAX];
    char detail[GDRIVE_DIAG_DETAIL_MAX];
    int  http_status;
    int  transport_error;
} gdrive_diagnostic_t;

// Initialize configuration. Automatic startup loads/validates tokens as before;
// exact manual-only startup defers all token/account access until an explicit
// Drive operation. Passive status and background recovery do not activate it.
gdrive_state_t gdrive_init(const config_t* cfg);

// Explicit Drive operation only (browse/download/manual Drive backup). Load and
// validate a deferred saved session once; otherwise return the current state.
// Call before availability filtering. Never call from polling/background retry.
gdrive_state_t gdrive_activate(void);

// Re-evaluate credentials/state after the config changes at runtime (e.g.
// the user pasted a Client ID/Secret in the UI and saved). Without this the
// state machine stays NOT_CONFIGURED until a restart, so /api/oauth/start
// keeps failing with "Could not start Google sign-in" right after saving.
// Only call for Drive settings changes, not unrelated/local settings saves.
// Leaves a live session or an in-progress device flow untouched.
gdrive_state_t gdrive_reconfigure(const config_t* cfg);

// Begin the device flow. Caller takes ownership of the returned struct
// (stored internally; pointer is valid until gdrive_device_flow_cancel
// or completion). NULL on hard failure.
const gdrive_device_flow_t* gdrive_device_flow_start(void);

// Last automatic-Drive sign-in failure, for /api/status and the setup UI.
void gdrive_get_diagnostic(gdrive_diagnostic_t* out);

// Probe Google's device endpoint from the PS5. Any HTTP response proves DNS,
// TLS, and HTTPS connectivity; no token or device flow is retained.
bool gdrive_test_connectivity(gdrive_diagnostic_t* out);

// User-facing end-to-end test: refresh token, Drive API, and configured root
// folder. Returns one actionable message without exposing transport internals.
bool gdrive_test_ready(gdrive_diagnostic_t* out);

// No network work: a temporary ERROR with saved credentials and expired
// provider backoff can be scheduled alongside a due persistent backup retry.
bool gdrive_recovery_due(void);

// Backup-worker only. Reuses the ready test on demand; credentials/permission
// errors wait for settings or explicit reconnect instead of automatic polling.
bool gdrive_ensure_ready(void);

// Poll Google's token endpoint. Returns the new state. When this
// returns GDRIVE_STATE_READY the access + refresh tokens have been
// written to tokens.json.
gdrive_state_t gdrive_device_flow_poll(void);

// Abort an in-progress device flow (user clicked Cancel in the UI).
void gdrive_device_flow_cancel(void);

// Forget the refresh token and delete tokens.json. After this the
// state returns to GDRIVE_STATE_NOT_SIGNED_IN.
void gdrive_sign_out(void);

// Current state, for the Settings UI.
gdrive_state_t gdrive_get_state(void);

// Passive metadata only: "present", "absent", or "unknown". A saved file is
// not proof of valid credentials; unknown must not authorize browser fallback.
// Never reads tokens/account data, activates Drive, or performs network work.
const char* gdrive_get_session_presence(void);

// Latest known account info. Returns false if not signed in.
bool gdrive_get_account(gdrive_account_t* out);

// Force a refresh of the access token. Returns true on success.
bool gdrive_refresh(void);

// Refresh the cached quota by calling about.get. Returns true on
// success; updates the value returned by gdrive_get_account.
bool gdrive_refresh_quota(void);

// Read-only complete, bounded ZIP count under configured root/UID/title.
// The same hierarchy is used inside appDataFolder when use_appdata=true.
// False means unknown/incomplete, never a partial authoritative estimate.
bool gdrive_estimate_backup_usage(uint64_t* out_bytes, size_t* out_files);
// Compatibility wrapper for callers that only need bytes.
bool gdrive_estimate_backup_bytes(uint64_t* out_bytes);

size_t gdrive_individual_scan(const char* user, const char* title,
        individual_backup_t* out, size_t cap, catalog_scan_t* scan);
bool gdrive_individual_revalidate(const individual_backup_t* item);
bool gdrive_individual_download_bounded(const individual_backup_t* item,
        const char* local_path, char* err, size_t err_sz);

// ---- Backup operations ----

// Upload a zip into Drive at the path
//   <root_folder> / <readable-user - UID> / <readable-game - Title ID> / <filename>
// user_alias is retained as an API name for compatibility, but callers pass
// the stable PS5 UID. title_id is something like "CUSA00000".
// Bare legacy codes remain readable. A sole legacy folder is renamed in its
// parent, preserving its ID; an unconfirmed rename reuses it without a second
// folder. Duplicate code folders choose a deterministic physical write target.
// On writes, a sole readable user folder follows console configuration; a sole
// readable game folder changes only for an explicit local game-name alias.
// filename should already include a timestamp,
// e.g. "save_20260610T204500Z.zip".
// On success, writes the new file's Drive file ID into out_file_id
// (buffer of size GDRIVE_FILEID_MAX). On failure, returns false and
// sets the daemon log entry; the caller may retry per the policy.
bool gdrive_upload(const char* user_alias,
                   const char* title_id,
                   const char* filename,
                   const char* local_zip_path,
                   char        out_file_id[GDRIVE_FILEID_MAX]);

// Read-only, fresh account/folder resolution. Unknown or unreachable targets
// return false and an empty identity; callers must not deduplicate them.
bool gdrive_backup_identity(const char* user_alias, const char* title_id,
                            char out_identity[65]);

// On-demand receipt verification: the exact ZIP must still exist, untrashed,
// with its recorded size in the currently resolved account/title folder.
// Any missing, malformed, changed, or unreachable proof returns false.
bool gdrive_backup_exists(const char* user_alias, const char* title_id,
                          const char* file_id, uint64_t expected_size,
                          const char* expected_identity);

// Like gdrive_upload, plus the identity of the account/folder actually used by this
// upload. Empty on failed upload or unavailable identity proof. No credentials
// are included. A settings/account change during upload cannot relabel it.
bool gdrive_upload_identified(const char* user_alias, const char* title_id,
                              const char* filename, const char* local_zip_path,
                              char out_file_id[GDRIVE_FILEID_MAX],
                              char out_identity[65]);

// Store in the fixed child "Individual saves", refusing ambiguous/type collisions.
bool gdrive_upload_individual_identified(const char* user_alias, const char* title_id,
                              const char* filename, const char* local_zip_path,
                              char out_file_id[GDRIVE_FILEID_MAX],
                              char out_identity[65]);

// One stored version on Drive.
typedef struct gdrive_version {
    char     file_id[GDRIVE_FILEID_MAX];
    char     name[128];           // the zip filename
    uint64_t size_bytes;
    int64_t  created_unix;        // seconds since epoch
} gdrive_version_t;

// One backup found while scanning the whole TostónSync Drive tree.
typedef struct {
    char     user[32];
    char     title_id[16];
    char     file_id[GDRIVE_FILEID_MAX];
    char     name[128];
    uint64_t size_bytes;
    int64_t  created_unix;
    char     destination_identity[65];
    uint64_t generation;
    char     destination_label[512]; // original folder and identity hint, no tokens/email
    char     observed_root[GDRIVE_FILEID_MAX]; // Root resolved by this explicit catalog scan.
} gdrive_backup_t;

// Read all code-matching physical folders, newest first, without rename/create.
// An incomplete or over-capacity listing returns zero, not a partial inventory.
size_t gdrive_list_versions(const char* user_alias,
                            const char* title_id,
                            gdrive_version_t* out,
                            size_t max_out);

// Destructive retention uses ONE physical folder and a complete listing bound to a real destination
// and this local session. NULL expected_identity captures the current target
// for ordinary cleanup; post-copy callers must pass the upload's actual identity.
// Duplicate physical folders are never aggregated for pruning.
typedef struct {
    char identity[65];
    uint64_t generation;
} gdrive_retention_scope_t;
bool gdrive_retention_list(const char* user_uid, const char* title_id,
                           const char* expected_identity,
                           gdrive_version_t* out, size_t max_out,
                           size_t* out_count, gdrive_retention_scope_t* scope);
bool gdrive_retention_delete(const char* user_uid, const char* title_id,
                             const gdrive_version_t* version,
                             const gdrive_version_t* keep_version,
                             const gdrive_retention_scope_t* scope);

// Scan <root_folder>/<user_uid>/<title_id>/*.zip for every user/title.
// Returns newest-first entries across the configured Drive destination.
size_t gdrive_list_all_versions(gdrive_backup_t* out, size_t max_out);

// Bounded, read-only whole-catalog listing. Readable names resolve canonical
// UID/title codes while keeping each physical folder ID in the identity.
// Cleanup requires COMPLETE or EMPTY;
// PARTIAL/UNAVAILABLE must never grant a destructive preview.
size_t gdrive_catalog_scan(gdrive_backup_t* out, size_t max_out,
                            catalog_scan_t* scan);

// Delete a single version by Drive file ID.
bool gdrive_delete_version(const char* file_id);

// Library deletes revalidate the exact listed file/account/folder/session.
bool gdrive_delete_version_identified(const char* user_uid, const char* title_id,
                                      const gdrive_version_t* version,
                                      const gdrive_retention_scope_t* scope);

// Download a version to a local path. Used by the Restore flow.
bool gdrive_download(const char* file_id, const char* local_path);

#ifdef __cplusplus
}
#endif
#endif // TOSTONSYNC_GDRIVE_H
