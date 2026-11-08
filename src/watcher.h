// TostónSync — save watcher and upload queue.
//
// Three jobs in one module:
//
//   1. Watch the saves root for changes. On FreeBSD-derived systems
//      we use kqueue with EVFILT_VNODE / NOTE_WRITE on each user's
//      savedata_prospero directory. Falls back to polling if kqueue
//      cannot be set up for some reason.
//
//   2. Decide *when* to actually upload, based on config.triggers:
//        - on_change     → fires `change_settle_seconds` after the last
//                          NOTE_WRITE; near-real-time live backup
//        - on_game_close → fires when the watched title's process exits
//        - on_idle       → fires N seconds after the last NOTE_WRITE
//        - on_shutdown   → fires on SIGTERM (the daemon's shutdown path)
//        - interval      → fires every N seconds regardless
//        - manual        → never fires automatically
//
//   3. Run the upload pipeline: zip → CRC32 dedup check → gdrive_upload
//      → retention_enforce_title. One pool of N worker threads.

#ifndef TOSTONSYNC_WATCHER_H
#define TOSTONSYNC_WATCHER_H

#include <stdbool.h>
#include <stdint.h>
#include "config.h"
#include "sdimg_restore.h"
#include "restore_selection.h"
#include "import_session.h"
#include "save_metadata.h"
#include "session_saves.h"
#include "pfs_attributes.h"
#include "pfs_mode_trial.h"
#include "pfs_candidate_publish.h"
#include "lifecycle.h"
#include "paired_backup.h"
#include "backup_failure.h"
#include "jobs.h"

#ifdef __cplusplus
extern "C" {
#endif

bool watcher_start(const config_t* cfg);
void watcher_stop(void);
// Accepted local stop only: checked joins, no shutdown flush or queue cleanup.
bool watcher_stop_checked(void);
// Pure, non-waiting lifecycle observation; never expires imports, hashes ZIPs,
// repairs checkpoints, mounts images or takes a full configuration snapshot.
bool watcher_lifecycle_snapshot(life_snapshot_t* out);
// Explicit app-owned staging/mount cleanup. Rejects while save I/O or transient
// ZIP delivery is active; recovery snapshots/imports are never removed.
// Background maintenance never runs from a GET or UI navigation.
void watcher_maintenance(void);
bool watcher_cleanup_scratch(bool mounts, char* err, size_t err_sz);

// One metadata-only observation; never opens images, imports or recovery
// journals. UNKNOWN game/recovery state is not a read-only inventory veto.
typedef struct {
    char title_id[16], uid[16];
    save_metadata_check_t uid_check, gate, recovery_clear, game_closed;
    int recovery_errno;
    char uid_detail[192], gate_detail[192], recovery_detail[192], game_detail[192];
    save_metadata_report_t inventory;
    session_saves_report_t session;
    int8_t session_active[SAVE_METADATA_MAX_ENTRIES];
    int8_t session_service[SAVE_METADATA_MAX_ENTRIES];
} watcher_save_metadata_t;
bool watcher_inspect_save_metadata(const char* title_id, watcher_save_metadata_t* out);
bool watcher_inspect_save_metadata_for_uid(const char* uid, const char* title_id,
                                          watcher_save_metadata_t* out);
// Adds observations only; never grants a capture/Restore owner or reads images.
void watcher_copy_save_session(watcher_save_metadata_t* out);

// Finish exactly one successful make_*_zip/prepare_backup_file call after the
// file consumer closes it (including HTTP failures/disconnects). Removes the
// file only when temporary=true, then releases its cleanup protection.
void watcher_release_backup_file(const char* path, bool temporary);

// Stats exposed to the UI / status endpoint.
// Explicit owned-file USB diagnostic, excluded from concurrent save work.
bool watcher_test_usb(jobs_ref_t* admitted, char* detail,size_t detail_sz);
bool   watcher_is_running(void);
int    watcher_queue_depth(void);
int    watcher_active_jobs(void);
int64_t watcher_last_sync_unix(void);

// Last backup outcome for the UI. state: -1 none, 2 running, 1 ok,
// 3 skipped (unchanged/excluded), 0 failed.
void watcher_last_backup(char* title, size_t tn, int* state,
                         char* msg, size_t mn, int64_t* when);

// Record a backup performed outside the daemon (browser Google Drive upload)
// so the Home "Last backup" tile reflects it. `label` is the friendly name.
void watcher_note_external_backup(const char* label, const char* dests);

// Last restore outcome for the UI. state: -1 none, 2 running, 1 ok, 0 failed.
void watcher_last_restore(char* title, size_t tn, int* state,
                          char* msg, size_t mn, int64_t* when);
// Counts are normal verified slot writebacks; a reported rollback can undo them.
void watcher_last_restore_scope(bool* selective, size_t* available,
                                 size_t* selected, size_t* written);
// Counts distinguish durable published images from an uncertain rename.
void watcher_last_portable_transaction(portable_transaction_report_t* report);

// Caller holds the target-check/save-I/O gate. Only literal selected image
// hashes and no-follow identity metadata; no mounts or source ZIP inspector.
bool watcher_portable_target_state_held(const restore_scope_t* scope,
    char out_sha256[65], char* err, size_t err_sz);

// Manual sync — drain *every* title regardless of triggers.
int watcher_kick_sync_now(void);
typedef struct { jobs_ref_t id; bool coalesced, tracked; } watcher_job_admission_t;
typedef struct {
    size_t count;
    bool complete;
    watcher_job_admission_t items[128];
} watcher_jobs_admission_t;
int watcher_kick_sync_now_observed(watcher_jobs_admission_t* out);

// Back up a single title right now, to every enabled destination.
// `user_uid` may be NULL/"" to target the first user that owns the title.
// Returns true if a matching save was found and queued (or was already
// queued); false if the title isn't known to the watcher.
bool watcher_backup_title_async(const char* user_uid, const char* title_id);

// Manual backup with an optional destination override: usb, ftp, drive, all,
// or all-local. Empty/default preserves the configured destination mode.
bool watcher_backup_title_to_async(const char* user_uid, const char* title_id,
                                   const char* destination);
bool watcher_backup_title_to_async_observed(const char* user_uid, const char* title_id,
    const char* destination, watcher_job_admission_t* out);

// Download (when needed) and inspect a catalog backup without restoring it.
// `out_report_json` receives the same report shape used by Import Review.
bool watcher_verify_backup(const char* file_id, const char* title_hint,
                           char* out_report_json, size_t out_report_json_sz,
                           char* err, size_t err_sz);

// Build a ZIP for direct browser download. `raw_encrypted=false` attempts a
// kernel-decrypted TostónSync/Garlic-style ZIP; `true` zips the live encrypted
// save folder as-is. The caller must watcher_release_backup_file(path, true)
// after serving. Synchronous; intended for explicit UI downloads, not polling.
typedef struct {
    char raw_completeness[40];
    size_t active_images;
    size_t service_images;
    size_t missing_service_images;
    char first_missing_service_image[128];
    // Set only by the explicit manual partial RAW download; never a full backup.
    bool selected_partial;
    char uid[16], title_id[16], zip_sha256[65];
    size_t available_slots, selected_slots;
} watcher_raw_info_t;

bool watcher_make_download_zip(const char* user_uid, const char* title_id,
                               bool raw_encrypted,
                               char* out_zip_path, size_t out_zip_path_sz,
                               watcher_raw_info_t* raw_info,
                               char* err, size_t err_sz);

// Explicit active selection only. service_slots contains the literal selected
// names whose service companions were declared in review, separated by '\n'.
// An empty string declares no companions; absence/UNKNOWN is not a wildcard.
// On success retains the existing scratch lease until HTTP delivery releases it.
// On failure retains any new partial ZIP as evidence, never as a valid backup.
bool watcher_make_raw_selected_zip(const char* uid, const char* title,
    const restore_selection_t* requested, const char* service_slots,
    bool game_closed_confirmed, char* out_path, size_t path_sz,
    watcher_raw_info_t* out, char* err, size_t err_sz);

// New explicit manual capture only. Returns a paired Portable+RAW artifact or
// clearly labelled RAW_ONLY; failure/uncertainty preserves workspace evidence.
// A successful call retains the scratch lease until release_backup_file().
bool watcher_make_container_selected_backup(const char* uid, const char* title,
    const restore_selection_t* requested, const char* service_slots,
    bool game_closed_confirmed, paired_backup_report_t* out,
    char* err, size_t err_sz);

typedef struct {
    const char* status; // saved, not_attempted, failed
    backup_destination_failure_t failure;
} watcher_individual_destination_t;

typedef struct {
    bool ok;
    char filename[128], game[96], error[64];
    int thread_error;
    uint64_t size_bytes;
    // Stable response order: drive, usb, ftp; never a new destination policy.
    watcher_individual_destination_t destinations[3];
} watcher_individual_backup_t;

// One joined storage thread with an explicit 1 MiB stack; never HTTP fallback.
// Capture has already released save I/O. Caller retains/releases its scratch lease.
void watcher_store_container_selected(const paired_backup_report_t* capture,
    const char* container, watcher_individual_backup_t* out);

// Build a Garlic-compatible decrypted ZIP for manual import/debugging:
//   <TITLE_ID>/sdimg_<SAVEDATA_DIRECTORY>/{data*.bin,sce_sys/...}
// This is not TostónSync's native restore package; it is intentionally shaped
// like Garlic's browser download/export layout.
bool watcher_make_garlic_zip(const char* user_uid, const char* title_id,
                             char* out_zip_path, size_t out_zip_path_sz,
                             char* err, size_t err_sz);

// Build TostónSync's formal portable format. It keeps the same decrypted
// slot layout but adds manifest.json and SHA-256 checksums.json.
bool watcher_make_migration_zip(const char* user_uid, const char* title_id,
                                char* out_zip_path, size_t out_zip_path_sz,
                                char* err, size_t err_sz);

// Explicit preparation only: decrypt disposable images from the owned RAW
// import, build/verify a portable sidecar, never select or write a live save.
// Caller owns publication through import_session_finish_recovery().
bool watcher_recover_raw_import(const import_session_info_t* info,
                                char* candidate, size_t candidate_sz,
                                char* title, size_t title_sz,
                                char* err, size_t err_sz);

typedef void (*watcher_slot_cb_t)(const char* dir_name,
                                  const char* subtitle,
                                  const char* detail,
                                  const char* image_name,
                                  uint64_t bytes,
                                  bool system_slot,
                                  void* ud);

// Inspect the live save's individual slots by reading each slot's
// sce_sys/param.sfo through the kernel mount path. This is used only on demand
// from the UI; the game must be closed and kstuff must be loaded.
bool watcher_enumerate_save_slots(const char* user_uid,
                                  const char* title_id,
                                  watcher_slot_cb_t cb,
                                  void* ud,
                                  char* err,
                                  size_t err_sz);

// Trigger called from outside on shutdown (SIGTERM handler).
void watcher_on_shutdown(void);

// Restore: download `file_id` and unzip back into the (user, title)'s
// savedata_prospero path. `user_alias` may be NULL/"" to target the
// first user that owns the title — the v0.4 single-user behavior.
// Asynchronous; returns true if accepted.
// Explicit UID requests bypass aliases and require one current local profile.
bool watcher_restore_uid_is_local(const char* uid);
bool watcher_restore_async(const char* user_alias,
                           const char* title_id, const char* file_id);
// A server-approved immutable import scope, never a caller-supplied slot filter.
bool watcher_restore_selected_async(const restore_scope_t* scope,
                                    const char* file_id);
bool watcher_restore_async_observed(const char* user_alias, const char* title_id,
    const char* file_id, watcher_job_admission_t* out, bool uid_explicit, const char* claimed_import_id);
bool watcher_restore_selected_async_observed(const restore_scope_t* scope,
    const char* file_id, watcher_job_admission_t* out);

bool watcher_retained_rollback_available(const char* user_alias,
                                         const char* title_id,
                                         size_t* image_count, bool uid_explicit);
typedef void (*watcher_rollback_cb)(const char* id, int64_t date, uint64_t bytes, size_t images, void* context);
bool watcher_list_rollbacks(const char* user,const char* title,watcher_rollback_cb cb,void* context, bool uid_explicit);
bool watcher_delete_archived_rollback(const char* user,const char* title,const char* id,char* err,size_t n, bool uid_explicit);
bool watcher_delete_retained_rollback(const char* user_alias,
                                      const char* title_id,
                                      char* err, size_t err_sz, bool uid_explicit);

// Fresh local resolution only; no PFS/key access. The UID is confirmation,
// never authority supplied by an imported manifest or friendly alias.
// Each HTTP resolve/check request takes this exclusive lease before reviewing
// its import, releases before replying, and never spans human confirmation.
// begin: 1 admitted, 0 busy (no wait/mount), -1 recovery/config unavailable.
int watcher_target_check_begin(char* err, size_t err_sz);
void watcher_target_check_end(void);

// RAW-selected read-only preflight adapters. The caller already owns the same
// exclusive lease; no recursive acquisition, aliases or mutation of live saves.
bool watcher_raw_selected_workspace_held(char* work, size_t work_sz,
    char* err, size_t err_sz);
bool watcher_raw_selected_target_held(const char* expected_uid, const char* title,
    char* uid, size_t uid_sz, char* target, size_t target_sz,
    char* err, size_t err_sz);
bool watcher_raw_selected_barrier_held(bool create, const char* work,
    char* err, size_t err_sz);

// Fixed forensic PRE/current 1Slot pair. Owns one exclusive lease; native
// operations use new private copies only, with the existing durable barrier.
void watcher_inspect_pfs_attributes(pfs_attributes_report_t* report);
// Explicit private experiment only. No live image can be published by this path.
void watcher_private_mode_trial(pfs_mode_trial_report_t* report);
// One pinned closed candidate only; never a normal Restore or retry path.
void watcher_publish_mode_candidate(pfs_candidate_publication_t* report);

// Caller already owns the lease; these helpers never acquire it recursively.
bool watcher_resolve_portable_target_held(const char* title_id,
                                          char* resolved_uid, size_t resolved_uid_sz,
                                          char* err, size_t err_sz);
bool watcher_preflight_portable_target_held(const char* expected_uid,
                                            const char* title_id,
                                            const char slots[][64],
                                            size_t slot_count,
                                            size_t* ready_count,
                                            sdimg_target_slot_report_t* reports,
                                            size_t report_cap,
                                            size_t* report_count,
                                            char* resolved_uid, size_t resolved_uid_sz,
                                            char* err, size_t err_sz);

bool watcher_resolve_portable_target(const char* title_id,
                                     char* resolved_uid, size_t resolved_uid_sz,
                                     char* err, size_t err_sz);

bool watcher_preflight_portable_target(const char* expected_uid,
                                       const char* title_id,
                                       const char slots[][64],
                                       size_t slot_count,
                                       size_t* ready_count,
                                       sdimg_target_slot_report_t* reports,
                                       size_t report_cap,
                                       size_t* report_count,
                                       char* resolved_uid, size_t resolved_uid_sz,
                                       char* err, size_t err_sz);

// Explicit import removal must not discard recovery evidence while a target
// check is mounting copies or its durable recovery barrier is still present.
bool watcher_cancel_import(const char* id, char* err, size_t err_sz);

// Explicit READY -> historical record, under the existing exclusive gate.
// No native mount, Restore claim, worker or historical reactivation occurs.
bool watcher_preserve_import(const char* id, import_preserved_info_t* out,
                             char* err, size_t err_sz);

// Resolve a validated catalog reference to a readable ZIP. Remote FTP/Drive
// refs use an exclusive private folder (including provider sidecars). Failed
// residues and the folder are retained. After success, callers must
// watcher_release_backup_file(path, temporary), even for non-temporary files.
// Upload-session refs are intentionally rejected.
bool watcher_prepare_backup_file(const char* ref,
                                 char* out_path, size_t out_path_sz,
                                 bool* temporary,
                                 char* err, size_t err_sz);

// UI-friendly local save discovery. This does not query Drive; it only
// reports titles found under saves_root. `included` reflects the current
// title filters. `game_name` may be empty until the game has run once.
void watcher_enumerate_saves(
    void (*cb)(const char* user_alias, const char* user_uid,
               const char* title_id, const char* game_name,
               bool included, void* ud),
    void* ud);

bool watcher_title_is_backed_up(const char* title_id);

#ifdef __cplusplus
}
#endif
#endif
