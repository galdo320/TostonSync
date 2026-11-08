// TostónSync — restore support for PS5 sdimg_* savedata slots.
//
// PS5 titles that store saves as sdimg_* files are not one PFS image per
// title. Each sdimg_<dir_name> is a savedata slot that the system also tracks
// in /system_data/savedata_prospero/<uid>/db/user/savedata.db. A valid restore
// must therefore copy the raw image(s) and update that database together.

#ifndef TOSTONSYNC_SDIMG_RESTORE_H
#define TOSTONSYNC_SDIMG_RESTORE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "sfo.h"
#include "restore_sources.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    char     dir_name[64];
    char     status[32];
    char     detail[160];
    int      stat_errno; // Captured failed container stat; zero is not proof of access.
    char     registry_status[16]; // ROW_FOUND, ROW_ABSENT, SQLITE_ERROR; empty if not checked.
    int      sqlite_code;
    int      sqlite_extended_code;
    char     sqlite_message[160];
    int64_t  registry_rowid; // Meaningful only when registry_status is ROW_FOUND.
    uint64_t container_bytes;
    char     key_fingerprint[17];
} sdimg_target_slot_report_t;

typedef enum {
    SDIMG_TARGET_PREFLIGHT_BLOCKED = 0,
    SDIMG_TARGET_PREFLIGHT_READY = 1,
    SDIMG_TARGET_PREFLIGHT_UNMOUNT_UNCERTAIN = 2
} sdimg_target_preflight_result_t;

// Update savedata.db for a single-slot save (savedata0.bin titles). Upserts the
// row for `title_id`/`dir_name` with `bytes` (and authentic fields from `sfo`
// when non-NULL), and prunes stale/sce_bu rows for the title — the same
// transactional logic the sdimg path uses. Returns false on error.
bool savedata_db_update_single(const char* user_uid, const char* title_id,
                               const char* dir_name, uint64_t bytes,
                               const sfo_info_t* sfo,
                               char* err, size_t err_sz);

// Import a decrypted single-slot save folder (Garlic-style export:
// data files + sce_sys/param.sfo) into an existing
// sdimg_<SAVEDATA_DIRECTORY>. The slot and savedata.db row must already have
// been created by the destination PS5; its container/key/DB identity remain.
bool sdimg_restore_plain_slot_from_payload(const char* plain_dir,
                                           const char* user_uid,
                                           const char* title_id,
                                           const char* target_title_dir,
                                           const char* stage_base,
                                          const restore_sources_t* originals,
                                           char* err,
                                           size_t err_sz);

// Restore a plain-sdimg-v1 backup created by TostónSync. It contains
// decrypted folders in slots/ and optional service/ folders. Only active slot
// payloads are imported; destination service images and DB rows are preserved.
bool sdimg_restore_plain_set_from_payload(const char* payload_dir,
                                          const char* user_uid,
                                          const char* title_id,
                                          const char* target_title_dir,
                                          const char* stage_base,
                                          const restore_sources_t* originals,
                                          char* err,
                                          size_t err_sz);

// Same container-preserving engine with a literal, immutable slot allowlist.
// NULL/0 alone means the historical all-slots behavior; explicit lists must
// be nonempty, unique, and completely present before snapshot/writeback.
// Explicit lists alone are no longer publication authority; use the approved
// Portable scope entry below. Historical NULL/0 admission remains unchanged.
// written_count counts completed writebacks that passed image verification,
// even if a later failure rolls them back; it is NOT proof of final commit.
bool sdimg_restore_plain_set_selected_from_payload(
    const char* payload_dir, const char* user_uid, const char* title_id,
    const char* target_title_dir, const char* stage_base,
    const char selected_slots[][64], size_t selected_count,
    size_t* written_count, const restore_sources_t* originals, char* err, size_t err_sz);

#include "portable_transaction.h"
// Same Portable engine, approved selection-only durable preimages/publication.
// No inferred services, title-wide snapshot/pruning or automatic rollback.
bool sdimg_restore_portable_scope_from_payload(
    const char* payload_dir, const char* user_uid, const char* title_id,
    const char* target_title_dir, const char* stage_base,
    const restore_scope_t* scope, const char* canonical_zip_path,
    portable_transaction_report_t* report, const restore_sources_t* originals,
    size_t* written_count, char* err, size_t err_sz);

// Read-only compatibility check for a portable slot set. Verifies that every
// destination image, DB row, local owner and mounted param.sfo already match.
// Checked callers MUST compare the enum explicitly, never use truthiness.
// A durable save-I/O barrier must precede kernel work and remain on uncertain
// unmount. Stop at the first failed validation; never inspect remaining target
// slots. Reports/counts include unattempted slots as not_checked, bounded by
// report_cap. On uncertain unmount, backing images and mount points are retained.
sdimg_target_preflight_result_t sdimg_restore_preflight_target_slots_checked(
                                          const char* user_uid,
                                          const char* title_id,
                                          const char* target_title_dir,
                                          const char slots[][64],
                                          size_t slot_count,
                                          size_t* ready_count,
                                          sdimg_target_slot_report_t* reports,
                                          size_t report_cap,
                                          size_t* report_count,
                                          char* err, size_t err_sz);

// Diagnostic only: exact destination UID/title/slot row and typed owner;
// no owner fallback, defaults or alternate queries after SQLite errors.
// The legacy restore APIs above/below retain their existing admission logic.
// Metadata-only identity reader for the controlled publication diagnostic.
// No mount; no writes. Errors retain SQLite code/message in report.
bool sdimg_diagnostic_target_owner(const char* uid, const char* title_id,
    const char* slot, uint64_t* account_id, uint32_t* user_id,
    sdimg_target_slot_report_t* report);
sdimg_target_preflight_result_t sdimg_diagnose_target_slots_checked(
                                          const char* user_uid,
                                          const char* title_id,
                                          const char* target_title_dir,
                                          const char slots[][64],
                                          size_t slot_count,
                                          size_t* ready_count,
                                          sdimg_target_slot_report_t* reports,
                                          size_t report_cap,
                                          size_t* report_count,
                                          char* err, size_t err_sz);

// Existing bool API: false for both blocked and uncertain results. Restore
// owners must already hold their durable recovery barrier on every failure.
bool sdimg_restore_preflight_target_slots(const char* user_uid,
                                          const char* title_id,
                                          const char* target_title_dir,
                                          const char slots[][64],
                                          size_t slot_count,
                                          size_t* ready_count,
                                          sdimg_target_slot_report_t* reports,
                                          size_t report_cap,
                                          size_t* report_count,
                                          char* err, size_t err_sz);

// A successful exact RAW restore keeps one pre-restore image set. These
// helpers expose that set without weakening the normal restore preflight.
// Unregistered rollback requires exactly matching image names/keys, preserving
// existing savedata.db rows and undo/redo. Registered expansion recovery instead
// restores the captured originals and removes only its verified new images/rows;
// its journal/evidence remain and it does not offer expansion redo.
bool sdimg_restore_retained_rollback_available(const char* rollback_dir,
                                               size_t* image_count);
// Any unfinished snapshot/rotation blocks a new write, even after restart.
bool sdimg_restore_recovery_pending(const char* rollback_dir);
bool sdimg_restore_apply_retained_rollback(const char* target_title_dir,
                                           const char* rollback_dir,
                                           char* err, size_t err_sz);

// Transaction foundation for a FUTURE validated native creator, not called by
// current restore or UI. The caller must hold the shared exclusive save-I/O gate
// and durable restore barrier, freshly resolve UID and verify the game is closed.
// approved_images/approved_rows_db must already have passed the native key,
// owner, HMAC, metadata and integrity checks; this journal cannot replace them.
// Begin snapshots before arming and never publishes containers or inserts rows.
// Any failure leaves recovery evidence; stop, do not invoke an old helper.
bool sdimg_restore_expansion_begin_held(
    const char* uid, const char* title, const char* target,
    const char* rollback, const char* approved_images,
    const char* approved_rows_db, const char added_names[][128], size_t added_count,
    char* err, size_t err_sz);
bool sdimg_restore_expansion_commit_held(const char* uid, const char* title,
    const char* target, const char* rollback, char* err, size_t err_sz);
// The commit checkpoint intentionally leaves the barrier active; native
// completion/activation is outside this release. Explicit verified recovery
// can clear it, preserving the journal and snapshots.

// Shared verified image replacement and sealed-key lineage, no creation/resign.
bool sdimg_restore_copy_verified(const char* src, const char* dst);
bool sdimg_restore_images_share_key(const char* a, const char* b);

// Restore every sdimg_* regular file found directly in `payload_dir` into
// `target_title_dir`, updating the owning user's savedata.db in one SQLite
// transaction. Existing target files are snapshotted per file and rolled back
// on copy/DB failure. `stage_base` is used only for temporary rollback files.
//
// `user_uid` must be the real PS5 user directory name (for example
// "1234abcd"), not a friendly alias.
// `fix_zeroed_sfo` (crypto.fix_zeroed_sfo) enables the EXPERIMENTAL re-seal
// pass that rebuilds a restored slot's zeroed sce_sys/param.sfo. Off = safe
// default (raw restore only).
bool sdimg_restore_from_payload(const char* payload_dir,
                                const char* user_uid,
                                const char* title_id,
                                const char* target_title_dir,
                                const char* stage_base,
                                const restore_sources_t* originals,
                                bool promote_service_backups,
                                bool fix_zeroed_sfo,
                                char* err,
                                size_t err_sz);

#ifdef __cplusplus
}
#endif
#endif // TOSTONSYNC_SDIMG_RESTORE_H
