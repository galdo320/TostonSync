// TostónSync — configuration model.
//
// Mirrors config.ini.example. Loaded once at startup with config_load(),
// mutated through the Settings UI (config_apply_json from the httpd),
// and persisted back to disk with config_save(). The model is plain
// flat C structs so every other module can read it without locking.

#ifndef TOSTONSYNC_CONFIG_H
#define TOSTONSYNC_CONFIG_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define CFG_MAX_LIST       64
#define CFG_MAX_PATH       256
#define CFG_MAX_TITLE_ID   16
#define CFG_MAX_TRIG_LEN   24
#define CFG_MAX_SIZE_STR   16

#define NOTIFY_IMPORTANT 0
#define NOTIFY_BALANCED  1
#define NOTIFY_ALL       2

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    int  http_port;
    char http_hostname[254]; // Optional exact LAN hostname, configured in the INI.
    bool notifications;
    bool update_auto_check; // Signed release checks only, never automatic installation.
    int  notification_level;
    char log_level[16];
    int  log_max_bytes;
    // UI language and localized game-name preference. English is the default; the
    // first browser visit can ask the owner to switch to Spanish.
    // Ingles es el valor por defecto; la primera visita puede preguntar.
    char language[8]; // "en" or "es"
    char time_format[8]; // "auto", "12h", or "24h"
    char display_timezone[64]; // "auto", IANA zone, or "offset:+HH:MM"
    // Optional browser-resolved offset for backup names; empty means UTC fallback.
    char backup_timezone_offset[14]; // "offset:+HH:MM" or "offset:-HH:MM"
    bool language_prompt_seen;
    // Optional UI access protection. The switch is intentionally separate
    // from the stored code so stale config files cannot lock the owner out.
    bool ui_auth_enabled;
    // Optional UI access code (PIN or password). Only used when enabled.
    char ui_password[64];
    // When true, the access code is wiped on every boot (one of the
    // "forgot my code" escape hatches).
    bool ui_auth_reset_on_boot;
    // Open the PS5's own web browser to the Settings UI at startup, so
    // you can configure everything from the console itself (like Payload
    // Manager). Default true.
    bool open_browser;
} cfg_general_t;

typedef struct {
    char provider[16];   // currently "gdrive"
} cfg_cloud_t;

typedef struct {
    char name[32];       // friendly local console name, e.g. "PS5 OG"
    char type[16];       // "PS5", "PS5 Pro", or custom short label
    char role[16];       // source, target, main, secondary
} cfg_console_t;

typedef struct {
    char client_id[128];
    char client_secret[128];
    char root_folder[64];
    bool use_appdata;
    // EXPERIMENTAL: load a custom CA bundle at init via sceSslLoadRootCACert.
    // Default false — that call destabilised the daemon on hardware, so normal
    // startup must never touch it. Only advanced users who proved it opt in.
    bool custom_ca;
} cfg_gdrive_t;

typedef struct {
    bool enabled;          // copy each backup to a plugged-in USB drive
    char mount_path[64];   // "auto" (best free space) or /mnt/usbN
    char folder[64];       // subfolder on the USB (default "TostónSync")
} cfg_usb_t;

// Backup destination policy. Each backup can go to USB and/or Google
// Drive. `order` is the priority list (e.g. {"drive","usb"}). When
// `fallback` is true (cascade) we try destinations in order and STOP at the
// first one that succeeds — so "if USB isn't there, go to Drive" works. When
// false we copy to EVERY enabled destination (the original behaviour). A
// destination still only runs when its own enable switch is on (usb.enabled,
// Drive signed in).
#define CFG_MAX_DESTS 3
typedef struct {
    char   order[CFG_MAX_DESTS][8]; // subset/permutation of usb,drive
    size_t order_count;
    bool order_explicit;          // An explicit empty order must not enable defaults.
    bool   fallback;                // true = cascade (first success wins)
} cfg_destinations_t;

typedef struct {
    char modes[8][CFG_MAX_TRIG_LEN];
    size_t modes_count;
    char live_backup_mode[16]; // balanced, aggressive, game_close
    int  idle_seconds;
    int  interval_seconds;
    // "on_change": near-real-time. Back up this many seconds after the
    // save stops being written (so we never grab a half-written save,
    // but you're always nearly up to date while playing).
    int  change_settle_seconds;
} cfg_triggers_t;

typedef struct {
    int     max_versions;
    char    max_total_size_per_title_str[CFG_MAX_SIZE_STR];
    char    max_total_size_global_str[CFG_MAX_SIZE_STR];
    int     min_change_bytes;
    bool    dedup_by_hash;
} cfg_retention_t;

typedef struct {
    char   exclude[CFG_MAX_LIST][CFG_MAX_TITLE_ID];
    size_t exclude_count;
    char   include_only[CFG_MAX_LIST][CFG_MAX_TITLE_ID];
    size_t include_only_count;
    // Titles the user chose to hide from the Saves list (e.g. apps like
    // YouTube). Independent of backup inclusion — hiding only affects the
    // UI listing, not whether a title is backed up.
    char   hidden[CFG_MAX_LIST][CFG_MAX_TITLE_ID];
    size_t hidden_count;
    // One-time migration marker for built-in non-game app defaults.
    bool   app_defaults_applied;
} cfg_titles_t;

// PS5 console users. Each PS5 stores its users' saves under
// /user/home/<UID>/savedata_prospero/<TITLE_ID>/, where <UID> is an
// opaque hex-like string (e.g. "1230fa00" or "user93736i"). The owner
// of the console can attach a friendly alias to each UID via the UI
// so backups for "Alex" and "Juan" land in clearly-labelled folders
// rather than under cryptic IDs. When no alias is set we fall back to
// the UID itself.
#define CFG_MAX_USERS 8
typedef struct {
    char uid[16];
    char alias[32];
} cfg_user_alias_t;
typedef struct {
    cfg_user_alias_t entries[CFG_MAX_USERS];
    size_t           count;
} cfg_users_t;

// Manual game-name aliases. When a save's TITLE_ID has no readable metadata
// (the title isn't installed/mounted, so titlename_lookup fails), the owner can
// type a friendly name here, e.g. PPSA01411 -> "Resident Evil 4". Display only;
// the backup identity is always the TITLE_ID.
#define CFG_MAX_TITLE_ALIASES 64
typedef struct {
    char title_id[CFG_MAX_TITLE_ID];
    char name[64];
} cfg_title_alias_t;
typedef struct {
    cfg_title_alias_t entries[CFG_MAX_TITLE_ALIASES];
    size_t            count;
} cfg_title_aliases_t;

typedef struct {
    char saves_root[CFG_MAX_PATH];
    char state_dir[CFG_MAX_PATH];
    char staging_dir[CFG_MAX_PATH];
} cfg_paths_t;

typedef struct {
    bool zip_mode_deflate;   // true = deflate, false = store
    int  upload_workers;
    int  retry_max_attempts;
    int  retry_backoff_ms;
} cfg_advanced_t;

// Reserved kernel-mediated save handling. Hardware tests showed that the
// re-sealed result may be rejected as corrupt, so config_sanitize() forces
// these experimental write paths off. Read-only mounts remain available for
// inspection/export; normal backups and restores use verified raw images.
typedef struct {
    bool use_kernel_resign;        // reserved; forced off after hardware tests
    bool auto_fallback_on_failure; // if mount fails, fall back to the
                                   // encrypted-blob path with a warning
    bool fix_zeroed_sfo;           // reserved; forced off with re-sealing
} cfg_crypto_t;

typedef struct config {
    cfg_general_t   general;
    cfg_console_t   console;
    cfg_cloud_t     cloud;
    cfg_gdrive_t    gdrive;
    cfg_usb_t       usb;
    cfg_destinations_t destinations;
    cfg_triggers_t  triggers;
    cfg_retention_t retention;
    cfg_titles_t    titles;
    cfg_users_t     users;
    cfg_users_t     display_users; // Presentation only; never consumed by backup naming.
    cfg_title_aliases_t title_aliases;
    cfg_paths_t     paths;
    cfg_advanced_t  advanced;
    cfg_crypto_t    crypto;
    char            ini_path[CFG_MAX_PATH];
} config_t;

// Load from disk. Falls back to safe defaults when the file is missing.
bool config_load(config_t* cfg, const char* ini_path);
// Validation delivery: existing stable literal INI only, explicit manual-only;
// no creation, default migration or persistence. Normal load is unchanged.
bool config_load_observational(config_t* cfg, const char* ini_path);

// Persist changed or already explicit settings to ini_path; untouched defaults
// remain absent. Atomic write through a temp file + rename.
bool config_save(void);

// JSON helpers used by the httpd.
void config_to_json(const config_t* cfg, char* out, size_t out_sz);
bool config_validate_json(const char* patch, size_t length);
bool config_apply_json(const char* json_patch);

typedef enum {
    CFG_BACKUP_TIMEZONE_OK, CFG_BACKUP_TIMEZONE_INVALID,
    CFG_BACKUP_TIMEZONE_STALE, CFG_BACKUP_TIMEZONE_UNAVAILABLE,
    CFG_BACKUP_TIMEZONE_SAVE_FAILED
} cfg_backup_timezone_result_t;
// Local-only offset synchronization; no OAuth authority and no write if unchanged.
cfg_backup_timezone_result_t config_backup_timezone_sync(const char* timezone,
                                                        const char* offset,
                                                        bool* changed);

// Borrowed pointer to the active config. Stable for the daemon's
// lifetime. Read-only — mutations go through config_apply_json.
const config_t* config_get(void);

// --- UI access protection ------------------------------------------------
// Effective access protection state (enabled and a non-empty code exists).
bool config_ui_auth_enabled(void);
// Current access code ("" when no code is stored).
const char* config_ui_password(void);
// Whether the access code is wiped on every boot.
bool config_ui_reset_on_boot(void);
// Enable/disable the access code and persist. Disabling clears any stored
// code so a stale config.ini cannot start locking again later.
bool config_set_ui_auth(bool enabled, const char* code, bool reset_on_boot);
// Forgot-code escape hatch: clear the access code and persist.
bool config_reset_ui_auth(void);

// Briefly hold the config lock so a reader can take a consistent snapshot
// of several fields at once without racing a UI settings write.
void config_lock(void);
void config_unlock(void);

// Copy the whole live config under the config lock into `out`. Worker threads
// use this to read a consistent snapshot for the duration of a job instead of
// racing in-place mutations from a concurrent Settings save. Returns false if
// no config is loaded yet.
bool config_snapshot(config_t* out);

// --- Per-user alias map --------------------------------------------------
// Resolve a PS5 UID to its friendly alias (e.g. "1230fa00" -> "Alex").
// Returns the UID itself when no alias is set, so callers can always
// build a path with the returned string. Output stable for the daemon's
// lifetime; do not store the pointer across config_set_user_alias().
const char* config_alias_for_uid(const char* uid);

// Add/update the alias for `uid`. Persists. Pass empty alias to clear.
// Returns true on success. UID is normalized as-is; no validation
// beyond fitting in the buffer.
bool config_set_user_alias(const char* uid, const char* alias);
bool config_set_display_alias(const char* uid, const char* alias);

// Manual game name for a TITLE_ID, or "" when none is set. Stable for the
// daemon's lifetime; do not store across config_set_title_alias().
const char* config_title_alias_for(const char* title_id);

// Add/update the manual name for `title_id`. Persists. Empty name clears it.
bool config_set_title_alias(const char* title_id, const char* name);

// Build a JSON array of {uid, alias} pairs for the UI. Truncates to
// fit `out_sz`.
void config_users_to_json(char* out, size_t out_sz);

// Title filter helpers used by the local-saves UI. Exclude wins over
// include_only; when include_only is empty, every non-excluded title is
// backed up. config_set_title_backup() persists the change.
bool config_title_is_backed_up(const char* title_id);
bool config_set_title_backup(const char* title_id, bool backup);

// Hide/unhide a title from the Saves list. Purely cosmetic — a hidden
// title is still backed up if it is included. Persists.
bool config_title_is_hidden(const char* title_id);
bool config_set_title_hidden(const char* title_id, bool hidden);

#ifdef __cplusplus
}
#endif
#endif
