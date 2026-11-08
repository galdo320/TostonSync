// TostónSync — config: INI load, JSON snapshot / patch, persist.

#include "config.h"
#include "settings_input.h"
#include "log.h"
#include "fs.h"
#include "gdrive_default_creds.h"

#include <ctype.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

// Bounded append: advances *pp by what was written, never past end-1, so a
// long titles list can only truncate the JSON rather than run the cursor
// past the buffer (which would make the next `end - p` a huge size_t).
static void jappendf(char** pp, char* end, const char* fmt, ...) {
    char* p = *pp;
    if (!p || p >= end) return;
    size_t avail = (size_t)(end - p);
    va_list ap;
    va_start(ap, fmt);
    int n = vsnprintf(p, avail, fmt, ap);
    va_end(ap);
    if (n < 0) return;
    *pp = (size_t)n >= avail ? end - 1 : p + n;
}

static void jappendc(char** pp, char* end, char c) {
    char* p = *pp;
    if (!p || p >= end - 1) return;
    *p++ = c;
    *p = '\0';
    *pp = p;
}

static void jappend_json_string(char** pp, char* end, const char* s) {
    jappendc(pp, end, '"');
    for (size_t i = 0; s && s[i]; i++) {
        unsigned char c = (unsigned char)s[i];
        switch (c) {
            case '"':  jappendf(pp, end, "\\\""); break;
            case '\\': jappendf(pp, end, "\\\\"); break;
            case '\n': jappendf(pp, end, "\\n");  break;
            case '\r': jappendf(pp, end, "\\r");  break;
            case '\t': jappendf(pp, end, "\\t");  break;
            default:
                if (c < 0x20) jappendf(pp, end, "\\u%04x", c);
                else          jappendc(pp, end, (char)c);
                break;
        }
    }
    jappendc(pp, end, '"');
}


// Serializes config mutations + persistence. The HTTP server spawns a
// thread per connection, so two POST /api/config requests could
// otherwise interleave inside config_apply_json / config_save.
static pthread_mutex_t s_cfg_lock = PTHREAD_MUTEX_INITIALIZER;

// Pointer to the single live config instance owned by main(). Every
// module (gdrive, watcher, httpd) holds this same pointer, so mutations
// from the UI (config_apply_json) take effect immediately for the whole
// daemon. (Previously config kept a private copy here, so UI edits —
// including the Google credentials — were silently ignored until a
// reboot re-read config.ini.)
static config_t* s_live = NULL;

static bool backup_timezone_offset_minutes(const char* value, int* out) {
    if (!value || strlen(value) != 13 || strncmp(value, "offset:", 7) ||
        (value[7] != '+' && value[7] != '-') || value[10] != ':' ||
        value[8] < '0' || value[8] > '9' || value[9] < '0' || value[9] > '9' ||
        value[11] < '0' || value[11] > '9' || value[12] < '0' || value[12] > '9') return false;
    int hours = (value[8] - '0') * 10 + value[9] - '0';
    int minutes = (value[11] - '0') * 10 + value[12] - '0';
    if (minutes > 59) return false;
    int result = (value[7] == '-' ? -1 : 1) * (hours * 60 + minutes);
    if (result < -720 || result > 840) return false;
    if (out) *out = result;
    return true;
}

static void set_defaults(config_t* c) {
    memset(c, 0, sizeof(*c));
    c->general.http_port     = 1993;
    c->general.notifications = true;
    c->general.update_auto_check = true;
    c->general.notification_level = NOTIFY_IMPORTANT;
    strcpy(c->general.log_level, "info");
    c->general.log_max_bytes = 1024 * 1024;
    strcpy(c->general.language, "en");
    strcpy(c->general.time_format, "auto");
    strcpy(c->general.display_timezone, "auto");
    c->general.language_prompt_seen = false;
    c->general.ui_auth_enabled        = false;  // protection off by default
    c->general.ui_password[0]         = '\0';
    c->general.ui_auth_reset_on_boot  = false;
    c->general.open_browser           = true;   // open the PS5 browser on boot

    strcpy(c->console.name, "This PS5");
    strcpy(c->console.type, "PS5");
    strcpy(c->console.role, "main");

    strcpy(c->cloud.provider, "gdrive");

    strcpy(c->gdrive.root_folder, "TostónSync");
    c->gdrive.use_appdata = false;

    // Optional built-in OAuth client (see gdrive_default_creds.h). When
    // the publisher fills these in, users sign in with zero setup; when
    // empty, each user pastes their own in the UI.
    strncpy(c->gdrive.client_id, GDRIVE_DEFAULT_CLIENT_ID,
            sizeof(c->gdrive.client_id) - 1);
    strncpy(c->gdrive.client_secret, GDRIVE_DEFAULT_CLIENT_SECRET,
            sizeof(c->gdrive.client_secret) - 1);

    c->usb.enabled = true;   // ON by default: a plugged-in USB is the simplest
                             // backup destination and avoids "No enabled
                             // destination succeeded" out of the box.
    strcpy(c->usb.mount_path, "auto");
    strcpy(c->usb.folder, "TostónSync");

    // Default destination policy: cascade in the order Drive, USB and
    // stop at the first that works. Disabled/unavailable destinations are
    // skipped, so this also means "if Drive can't upload, fall back to USB".
    strcpy(c->destinations.order[0], "drive");
    strcpy(c->destinations.order[1], "usb");

    c->destinations.order_count = 2;
    c->destinations.fallback    = true;

    // Balanced is the daily-use default: one live backup per title every
    // 15 minutes at most, plus a final deduplicated backup on game close.
    strcpy(c->triggers.modes[0], "on_change");
    strcpy(c->triggers.modes[1], "on_game_close");
    strcpy(c->triggers.modes[2], "on_shutdown");
    c->triggers.modes_count        = 3;
    strcpy(c->triggers.live_backup_mode, "balanced");
    c->triggers.idle_seconds       = 120;
    c->triggers.interval_seconds   = 600;
    c->triggers.change_settle_seconds = 30;

    c->retention.max_versions      = 10;
    strcpy(c->retention.max_total_size_per_title_str, "5GB");
    strcpy(c->retention.max_total_size_global_str,    "13GB");
    c->retention.min_change_bytes  = 0; // deprecated; content CRC decides
    c->retention.dedup_by_hash     = true;

    strcpy(c->paths.saves_root,   "/user/home");
    strcpy(c->paths.state_dir,    "/data/tostonsync");
    strcpy(c->paths.staging_dir,  "/data/tostonsync/staging");

    c->advanced.zip_mode_deflate     = true;
    // One worker => backups run one at a time (sequential). Extra simultaneous
    // backups wait in the queue (visible as "N queued") instead of all showing
    // as "active". Bump this in config.ini to parallelize if you ever want to.
    c->advanced.upload_workers       = 1;
    c->advanced.retry_max_attempts   = 5;
    c->advanced.retry_backoff_ms     = 2000;

    // Kernel-mediated decrypt/resign is OFF by default.
    //
    // WHY OFF: on the SAME console the only safe restore is a byte-for-byte
    // copy of the encrypted sdimg images (exactly what PS5 Payload Manager
    // does, confirmed working on hardware). Decrypting at backup forces a PFS
    // re-seal at restore, and that re-seal produces a save the game reads as
    // CORRUPT even when param.sfo verifies — observed on hardware (RE Requiem,
    // June 2026). So we capture the raw encrypted images and restore them
    // verbatim. The same-lineage byte-copy path in sdimg_restore handles this.
    //
    // Resign is ONLY needed to move a save to a DIFFERENT console/account
    // (different sealed key). Turn it on deliberately for that case; it is
    // experimental and known to risk corruption on same-console saves.
    c->crypto.use_kernel_resign        = false;
    c->crypto.auto_fallback_on_failure = true;
    c->crypto.fix_zeroed_sfo           = false; // experimental, opt-in
}

// Trim whitespace in place.
static char* trim(char* s) {
    while (*s && isspace((unsigned char)*s)) s++;
    char* end = s + strlen(s);
    while (end > s && isspace((unsigned char)end[-1])) *--end = '\0';
    return s;
}

// Safe as a single path component: no separators, no control chars, and not
// "." or ".." (which would walk out of the intended backup folder). Used for
// user aliases and the USB folder name. Aliases are display-only now, but the
// same conservative validation keeps config.ini and UI output predictable.
static bool alias_is_safe(const char* s) {
    if (!settings_text_valid(s ? s : "")) return false;
    if (s && (strcmp(s, ".") == 0 || strcmp(s, "..") == 0)) return false;
    for (size_t i = 0; s && s[i]; i++) {
        unsigned char c = (unsigned char)s[i];
        if (c == '/' || c == '\\' || c < 0x20) return false;
    }
    return true;
}

static bool usb_mount_value_safe(const char* s) {
    if (!s || !s[0] || strcmp(s, "auto") == 0) return true;
    const char prefix[] = "/mnt/usb";
    size_t n = sizeof(prefix) - 1;
    return strncmp(s, prefix, n) == 0 &&
           s[n] >= '0' && s[n] <= '7' &&
           s[n + 1] == '\0';
}

// Split "a, b, c" into list of trimmed tokens.
static void split_csv(const char* s, char list[][CFG_MAX_TITLE_ID],
                      size_t* count, size_t cap) {
    *count = 0;
    char buf[512];
    snprintf(buf, sizeof(buf), "%s", s ? s : "");
    char* tok = strtok(buf, ",");
    while (tok && *count < cap) {
        char* t = trim(tok);
        if (*t) {
            strncpy(list[*count], t, CFG_MAX_TITLE_ID - 1);
            list[*count][CFG_MAX_TITLE_ID - 1] = '\0';
            (*count)++;
        }
        tok = strtok(NULL, ",");
    }
}

static void apply_kv(config_t* c, const char* section,
                     const char* key, const char* val) {
    #define IS(s,k) (strcmp(section,s) == 0 && strcmp(key,k) == 0)

    if (IS("general","http_hostname")) { snprintf(c->general.http_hostname,sizeof(c->general.http_hostname),"%s",val); return; }
    if (IS("general","http_port"))      c->general.http_port = atoi(val);
    else if (IS("general","notifications"))
        c->general.notifications = (strcmp(val,"true") == 0);
    else if (IS("general","update_auto_check"))
        c->general.update_auto_check = (strcmp(val,"true") == 0);
    else if (IS("general","notification_level"))
        c->general.notification_level = strcmp(val, "all") == 0 ? NOTIFY_ALL :
                                        strcmp(val, "balanced") == 0 ? NOTIFY_BALANCED :
                                        NOTIFY_IMPORTANT;
    else if (IS("general","log_level"))
        strncpy(c->general.log_level, val, sizeof(c->general.log_level)-1);
    else if (IS("general","log_max_bytes"))
        c->general.log_max_bytes = atoi(val);
    else if (IS("general","language"))
        snprintf(c->general.language, sizeof(c->general.language), "%s", val);
    else if (IS("general","time_format") || IS("display","time_format"))
        snprintf(c->general.time_format, sizeof(c->general.time_format), "%s", val);
    else if (IS("display","display_timezone"))
        snprintf(c->general.display_timezone,
                 sizeof(c->general.display_timezone), "%s", val);
    else if (IS("display","backup_timezone_offset")) {
        if (backup_timezone_offset_minutes(val, NULL))
            snprintf(c->general.backup_timezone_offset,
                     sizeof(c->general.backup_timezone_offset), "%s", val);
    }
    else if (IS("general","language_prompt_seen"))
        c->general.language_prompt_seen = (strcmp(val,"true") == 0);
    else if (IS("general","ui_auth_enabled"))
        c->general.ui_auth_enabled = (strcmp(val,"true") == 0);
    else if (IS("general","ui_password"))
        strncpy(c->general.ui_password, val, sizeof(c->general.ui_password)-1);
    else if (IS("general","ui_auth_reset_on_boot"))
        c->general.ui_auth_reset_on_boot = (strcmp(val,"true") == 0);
    else if (IS("general","open_browser"))
        c->general.open_browser = (strcmp(val,"true") == 0);
    else if (IS("console","console_name") || IS("console","name"))
        snprintf(c->console.name, sizeof(c->console.name), "%s", val);
    else if (IS("console","console_type") || IS("console","type"))
        snprintf(c->console.type, sizeof(c->console.type), "%s", val);
    else if (IS("console","console_role") || IS("console","role"))
        snprintf(c->console.role, sizeof(c->console.role), "%s", val);
    else if (IS("triggers","live_backup_mode"))
        snprintf(c->triggers.live_backup_mode,
                 sizeof(c->triggers.live_backup_mode), "%s", val);

    else if (IS("cloud","provider"))
        strncpy(c->cloud.provider, val, sizeof(c->cloud.provider)-1);

    // Only override the embedded default when the INI actually provides
    // a value — an empty client_id= line (as in config.ini.example) must
    // not wipe a built-in credential from gdrive_default_creds.h.
    else if (IS("gdrive","client_id")) {
        if (*val) strncpy(c->gdrive.client_id, val, sizeof(c->gdrive.client_id)-1);
    }
    else if (IS("gdrive","client_secret")) {
        if (*val) strncpy(c->gdrive.client_secret, val, sizeof(c->gdrive.client_secret)-1);
    }
    else if (IS("gdrive","root_folder"))
        strncpy(c->gdrive.root_folder, val, sizeof(c->gdrive.root_folder)-1);
    else if (IS("gdrive","use_appdata"))
        c->gdrive.use_appdata = (strcmp(val,"true") == 0);
    else if (IS("gdrive","custom_ca"))
        c->gdrive.custom_ca = (strcmp(val,"true") == 0);

    else if (IS("usb","enabled"))
        c->usb.enabled = (strcmp(val,"true") == 0);
    else if (IS("usb","mount")) {
        if (usb_mount_value_safe(val))
            strncpy(c->usb.mount_path, *val ? val : "auto",
                    sizeof(c->usb.mount_path)-1);
    }
    else if (IS("usb","folder")) {
        // Reject path-traversal in the folder name (it is spliced into the USB
        // destination path); ignore an unsafe value and keep the current one.
        if (val[0] && alias_is_safe(val)) {
            strncpy(c->usb.folder, val, sizeof(c->usb.folder)-1);
            c->usb.folder[sizeof(c->usb.folder)-1] = '\0';
        }
    }

    else if (IS("destinations","order")) {
        c->destinations.order_explicit = true;
        c->destinations.order_count = 0;
        char buf[64]; snprintf(buf, sizeof(buf), "%s", val);
        char* tok = strtok(buf, ",");
        while (tok && c->destinations.order_count < CFG_MAX_DESTS) {
            char* t = trim(tok);
            if (strcmp(t,"usb")==0 || strcmp(t,"drive")==0) {
                strncpy(c->destinations.order[c->destinations.order_count],
                        t, 7);
                c->destinations.order[c->destinations.order_count][7] = '\0';
                c->destinations.order_count++;
            }
            tok = strtok(NULL, ",");
        }
    }
    else if (IS("destinations","fallback"))
        c->destinations.fallback = (strcmp(val,"true") == 0);

    else if (IS("triggers","modes")) {
        c->triggers.modes_count = 0;
        char buf[256]; snprintf(buf, sizeof(buf), "%s", val);
        char* tok = strtok(buf, ",");
        while (tok && c->triggers.modes_count < 8) {
            char* t = trim(tok);
            if (*t) {
                strncpy(c->triggers.modes[c->triggers.modes_count],
                        t, CFG_MAX_TRIG_LEN - 1);
                c->triggers.modes_count++;
            }
            tok = strtok(NULL, ",");
        }
    }
    else if (IS("triggers","idle_seconds"))     c->triggers.idle_seconds = atoi(val);
    else if (IS("triggers","interval_seconds")) c->triggers.interval_seconds = atoi(val);
    else if (IS("triggers","change_settle_seconds"))
        c->triggers.change_settle_seconds = atoi(val);

    else if (IS("retention","max_versions"))    c->retention.max_versions = atoi(val);
    else if (IS("retention","max_total_size_per_title"))
        strncpy(c->retention.max_total_size_per_title_str, val,
                sizeof(c->retention.max_total_size_per_title_str)-1);
    else if (IS("retention","max_total_size_global"))
        strncpy(c->retention.max_total_size_global_str, val,
                sizeof(c->retention.max_total_size_global_str)-1);
    else if (IS("retention","min_change_bytes"))
        c->retention.min_change_bytes = atoi(val);
    else if (IS("retention","dedup_by_hash"))
        c->retention.dedup_by_hash = (strcmp(val,"true") == 0);

    else if (IS("titles","exclude"))
        split_csv(val, c->titles.exclude, &c->titles.exclude_count, CFG_MAX_LIST);
    else if (IS("titles","include_only"))
        split_csv(val, c->titles.include_only, &c->titles.include_only_count, CFG_MAX_LIST);
    else if (IS("titles","hidden"))
        split_csv(val, c->titles.hidden, &c->titles.hidden_count, CFG_MAX_LIST);
    else if (IS("titles","app_defaults_applied"))
        c->titles.app_defaults_applied = (strcmp(val,"true") == 0);

    // [users] holds free-form key=value pairs where the key is a PS5
    // UID (the directory name under /user/home/) and the value is the
    // friendly alias the owner chose. Unknown sections are silently
    // ignored elsewhere, so we handle the whole section right here.
    else if (strcmp(section,"display_users")==0) {
        bool valid=strlen(key)==8;
        for(size_t i=0;key[i];i++)if(!isxdigit((unsigned char)key[i]))valid=false;
        if(valid&&alias_is_safe(val)&&strlen(val)<sizeof(c->display_users.entries[0].alias)&&c->display_users.count<CFG_MAX_USERS) {
            cfg_user_alias_t* e=&c->display_users.entries[c->display_users.count++];
            snprintf(e->uid,sizeof(e->uid),"%s",key);snprintf(e->alias,sizeof(e->alias),"%s",val);
        }
    }
    else if (strcmp(section, "users") == 0) {
        if (alias_is_safe(val) && c->users.count < CFG_MAX_USERS) {
            cfg_user_alias_t* e = &c->users.entries[c->users.count++];
            strncpy(e->uid,   key, sizeof(e->uid)   - 1);
            strncpy(e->alias, val, sizeof(e->alias) - 1);
        }
    }

    // [title_names] maps a TITLE_ID to a manual game name the owner typed when
    // no metadata was readable. Same free-form key=value handling as [users].
    else if (strcmp(section, "title_names") == 0) {
        if (alias_is_safe(val) && c->title_aliases.count < CFG_MAX_TITLE_ALIASES) {
            cfg_title_alias_t* e =
                &c->title_aliases.entries[c->title_aliases.count++];
            strncpy(e->title_id, key, sizeof(e->title_id) - 1);
            strncpy(e->name,     val, sizeof(e->name)     - 1);
        }
    }

    else if (IS("paths","saves_root"))
        strncpy(c->paths.saves_root, val, sizeof(c->paths.saves_root)-1);
    else if (IS("paths","state_dir"))
        strncpy(c->paths.state_dir, val, sizeof(c->paths.state_dir)-1);
    else if (IS("paths","staging_dir"))
        strncpy(c->paths.staging_dir, val, sizeof(c->paths.staging_dir)-1);

    else if (IS("advanced","zip_mode"))
        c->advanced.zip_mode_deflate = (strcmp(val,"deflate") == 0);
    else if (IS("advanced","upload_workers"))
        c->advanced.upload_workers = atoi(val);
    else if (IS("advanced","retry_max_attempts"))
        c->advanced.retry_max_attempts = atoi(val);
    else if (IS("advanced","retry_backoff_ms"))
        c->advanced.retry_backoff_ms = atoi(val);

    else if (IS("crypto","use_kernel_resign"))
        c->crypto.use_kernel_resign = (strcmp(val,"true") == 0);
    else if (IS("crypto","auto_fallback_on_failure"))
        c->crypto.auto_fallback_on_failure = (strcmp(val,"true") == 0);
    else if (IS("crypto","fix_zeroed_sfo"))
        c->crypto.fix_zeroed_sfo = (strcmp(val,"true") == 0);

    #undef IS
}

static bool trigger_mode_known(const char* mode) {
    static const char* known[] = {
        "on_change", "on_game_close", "on_shutdown",
        "on_idle", "interval", "manual"
    };
    for (size_t i = 0; i < sizeof(known) / sizeof(known[0]); i++)
        if (strcmp(mode, known[i]) == 0) return true;
    return false;
}

static void sanitize_trigger_modes(cfg_triggers_t* triggers) {
    if (!triggers) return;
    char clean[8][CFG_MAX_TRIG_LEN] = {{0}};
    size_t count = 0;
    bool has_automatic = false;

    for (size_t i = 0; i < triggers->modes_count && i < 8; i++) {
        const char* mode = triggers->modes[i];
        if (!trigger_mode_known(mode)) continue;
        bool duplicate = false;
        for (size_t j = 0; j < count; j++)
            if (strcmp(clean[j], mode) == 0) duplicate = true;
        if (duplicate) continue;
        snprintf(clean[count], sizeof(clean[count]), "%s", mode);
        if (strcmp(mode, "manual") != 0) has_automatic = true;
        count++;
    }

    memset(triggers->modes, 0, sizeof(triggers->modes));
    triggers->modes_count = 0;
    for (size_t i = 0; i < count; i++) {
        if (has_automatic && strcmp(clean[i], "manual") == 0) continue;
        snprintf(triggers->modes[triggers->modes_count], CFG_MAX_TRIG_LEN,
                 "%s", clean[i]);
        triggers->modes_count++;
    }
    if (triggers->modes_count == 0) {
        strcpy(triggers->modes[0], "manual");
        triggers->modes_count = 1;
    }
}

static void config_sanitize(config_t* c) {
    if (!c) return;
    if (c->general.http_port <= 0 || c->general.http_port > 65535)
        c->general.http_port = 1993;
    if (c->general.notification_level < NOTIFY_IMPORTANT ||
        c->general.notification_level > NOTIFY_ALL)
        c->general.notification_level = NOTIFY_IMPORTANT;
    if (c->triggers.idle_seconds <= 0)
        c->triggers.idle_seconds = 120;
    if (c->triggers.interval_seconds <= 0)
        c->triggers.interval_seconds = 600;
    if (c->triggers.change_settle_seconds <= 0)
        c->triggers.change_settle_seconds = 30;
    if (strcmp(c->triggers.live_backup_mode, "aggressive") != 0 &&
        strcmp(c->triggers.live_backup_mode, "game_close") != 0)
        strcpy(c->triggers.live_backup_mode, "balanced");
    sanitize_trigger_modes(&c->triggers);
    if ((!c->destinations.order_count && !c->destinations.order_explicit) ||
        c->destinations.order_count > CFG_MAX_DESTS) {
        strcpy(c->destinations.order[0], "drive");
        strcpy(c->destinations.order[1], "usb");

        c->destinations.order_count = 2;
    }
    if (c->retention.max_versions < 0)
        c->retention.max_versions = 0;
    if (c->retention.min_change_bytes < 0)
        c->retention.min_change_bytes = 0;
    if (c->advanced.upload_workers < 1)
        c->advanced.upload_workers = 1;
    if (c->advanced.upload_workers > 8)
        c->advanced.upload_workers = 8;
    if (!c->usb.mount_path[0] || !usb_mount_value_safe(c->usb.mount_path))
        strcpy(c->usb.mount_path, "auto");
    if (!c->usb.folder[0])
        strcpy(c->usb.folder, "TostónSync");
    if (!c->gdrive.root_folder[0])
        strcpy(c->gdrive.root_folder, "TostónSync");
    if (strcmp(c->general.language, "es") != 0)
        strcpy(c->general.language, "en");
    if (strcmp(c->general.time_format, "12h") != 0 &&
        strcmp(c->general.time_format, "24h") != 0)
        strcpy(c->general.time_format, "auto");
    size_t tz_len = strlen(c->general.display_timezone);
    for (size_t i = 0; i < tz_len; i++) {
        unsigned char ch = (unsigned char)c->general.display_timezone[i];
        if (!isalnum(ch) && ch != '/' && ch != '_' && ch != '-' &&
            ch != '+' && ch != ':' && ch != '.') {
            strcpy(c->general.display_timezone, "auto");
            break;
        }
    }
    if (!tz_len) strcpy(c->general.display_timezone, "auto");
    if (!backup_timezone_offset_minutes(c->general.backup_timezone_offset, NULL))
        c->general.backup_timezone_offset[0] = '\0';
    if (!c->console.name[0]) strcpy(c->console.name, "This PS5");
    if (!c->console.type[0]) strcpy(c->console.type, "PS5");
    if (!c->console.role[0]) strcpy(c->console.role, "main");

    // SAFETY: force the kernel decrypt/re-seal path OFF, regardless of what a
    // previously-saved config.ini holds. On the same console the only safe
    // backup/restore is a raw byte-for-byte copy of the encrypted images (what
    // PS5 Payload Manager does). Decrypt+re-seal rewrites the PFS header and
    // the game reads the restored save as CORRUPT — it destroyed a real save.
    c->crypto.use_kernel_resign = false;
    c->crypto.fix_zeroed_sfo    = false;
}


// Keep absence distinct from an explicit choice, including choices equal to defaults.
typedef enum { INI_STRING, INI_INT, INI_BOOL, INI_NOTIFY, INI_ZIP, INI_CSV } ini_type_t;
typedef struct {
    const char* section;
    const char* key;
    size_t offset, count_offset, stride;
    ini_type_t type;
} ini_field_t;
#define FIELD(s,k,m,t) {s,k,offsetof(config_t,m),0,sizeof(((config_t*)0)->m),t}
#define CSV(s,k,m,n) {s,k,offsetof(config_t,m),offsetof(config_t,n),sizeof(((config_t*)0)->m[0]),INI_CSV}
static const ini_field_t s_fields[] = {
    FIELD("general","http_port",general.http_port,INI_INT),
    FIELD("general","http_hostname",general.http_hostname,INI_STRING),
    FIELD("general","notifications",general.notifications,INI_BOOL),
    FIELD("general","update_auto_check",general.update_auto_check,INI_BOOL),
    FIELD("general","notification_level",general.notification_level,INI_NOTIFY),
    FIELD("general","log_level",general.log_level,INI_STRING),
    FIELD("general","log_max_bytes",general.log_max_bytes,INI_INT),
    FIELD("general","language",general.language,INI_STRING),
    FIELD("general","language_prompt_seen",general.language_prompt_seen,INI_BOOL),
    FIELD("general","ui_auth_enabled",general.ui_auth_enabled,INI_BOOL),
    FIELD("general","ui_password",general.ui_password,INI_STRING),
    FIELD("general","ui_auth_reset_on_boot",general.ui_auth_reset_on_boot,INI_BOOL),
    FIELD("general","open_browser",general.open_browser,INI_BOOL),
    FIELD("display","time_format",general.time_format,INI_STRING),
    FIELD("display","display_timezone",general.display_timezone,INI_STRING),
    FIELD("display","backup_timezone_offset",general.backup_timezone_offset,INI_STRING),
    FIELD("console","console_name",console.name,INI_STRING),
    FIELD("console","console_type",console.type,INI_STRING),
    FIELD("console","console_role",console.role,INI_STRING),
    FIELD("cloud","provider",cloud.provider,INI_STRING),
    FIELD("gdrive","client_id",gdrive.client_id,INI_STRING),
    FIELD("gdrive","client_secret",gdrive.client_secret,INI_STRING),
    FIELD("gdrive","root_folder",gdrive.root_folder,INI_STRING),
    FIELD("gdrive","use_appdata",gdrive.use_appdata,INI_BOOL),
    FIELD("gdrive","custom_ca",gdrive.custom_ca,INI_BOOL),
    FIELD("usb","enabled",usb.enabled,INI_BOOL),
    FIELD("usb","mount",usb.mount_path,INI_STRING),
    FIELD("usb","folder",usb.folder,INI_STRING),
    CSV("destinations","order",destinations.order,destinations.order_count),
    FIELD("destinations","fallback",destinations.fallback,INI_BOOL),
    CSV("triggers","modes",triggers.modes,triggers.modes_count),
    FIELD("triggers","live_backup_mode",triggers.live_backup_mode,INI_STRING),
    FIELD("triggers","idle_seconds",triggers.idle_seconds,INI_INT),
    FIELD("triggers","interval_seconds",triggers.interval_seconds,INI_INT),
    FIELD("triggers","change_settle_seconds",triggers.change_settle_seconds,INI_INT),
    FIELD("retention","max_versions",retention.max_versions,INI_INT),
    FIELD("retention","max_total_size_per_title",retention.max_total_size_per_title_str,INI_STRING),
    FIELD("retention","max_total_size_global",retention.max_total_size_global_str,INI_STRING),
    FIELD("retention","min_change_bytes",retention.min_change_bytes,INI_INT),
    FIELD("retention","dedup_by_hash",retention.dedup_by_hash,INI_BOOL),
    CSV("titles","exclude",titles.exclude,titles.exclude_count),
    CSV("titles","include_only",titles.include_only,titles.include_only_count),
    CSV("titles","hidden",titles.hidden,titles.hidden_count),
    FIELD("titles","app_defaults_applied",titles.app_defaults_applied,INI_BOOL),
    FIELD("paths","saves_root",paths.saves_root,INI_STRING),
    FIELD("paths","state_dir",paths.state_dir,INI_STRING),
    FIELD("paths","staging_dir",paths.staging_dir,INI_STRING),
    FIELD("advanced","zip_mode",advanced.zip_mode_deflate,INI_ZIP),
    FIELD("advanced","upload_workers",advanced.upload_workers,INI_INT),
    FIELD("advanced","retry_max_attempts",advanced.retry_max_attempts,INI_INT),
    FIELD("advanced","retry_backoff_ms",advanced.retry_backoff_ms,INI_INT),
    FIELD("crypto","use_kernel_resign",crypto.use_kernel_resign,INI_BOOL),
    FIELD("crypto","auto_fallback_on_failure",crypto.auto_fallback_on_failure,INI_BOOL),
    FIELD("crypto","fix_zeroed_sfo",crypto.fix_zeroed_sfo,INI_BOOL),
};
#undef FIELD
#undef CSV
#define INI_FIELD_COUNT (sizeof(s_fields) / sizeof(s_fields[0]))
static bool s_explicit[INI_FIELD_COUNT];
static config_t s_saved;

static void config_note_explicit(const char* section, const char* key) {
    if (!strcmp(section,"general") && !strcmp(key,"time_format")) section="display";
    if (!strcmp(section,"console")) {
        if (!strcmp(key,"name")) key="console_name";
        else if (!strcmp(key,"type")) key="console_type";
        else if (!strcmp(key,"role")) key="console_role";
    }
    for (size_t i=0; i<INI_FIELD_COUNT; i++)
        if (!strcmp(section,s_fields[i].section) && !strcmp(key,s_fields[i].key)) {
            s_explicit[i]=true;
            return;
        }
}

static bool config_field_changed(const ini_field_t* field) {
    const char* now=(const char*)s_live+field->offset;
    const char* before=(const char*)&s_saved+field->offset;
    if (field->type==INI_STRING) return strcmp(now,before)!=0;
    if (field->type!=INI_CSV) return memcmp(now,before,field->stride)!=0;
    size_t count=*(const size_t*)((const char*)s_live+field->count_offset);
    if (count!=*(const size_t*)((const char*)&s_saved+field->count_offset)) return true;
    for (size_t i=0; i<count; i++)
        if (strcmp(now+i*field->stride,before+i*field->stride)) return true;
    return false;
}

// Quote only values that legacy INI whitespace/comment parsing would change.
static void config_write_text(FILE* f,const char* text) {
    size_t n=strlen(text);bool quoted=strchr(text,';')||text[0]=='"'||(n&&(isspace((unsigned char)text[0])||isspace((unsigned char)text[n-1])));
    if(!quoted){fputs(text,f);return;}
    fputc('"',f);for(size_t i=0;i<n;i++){if(text[i]=='"'||text[i]=='\\')fputc('\\',f);fputc(text[i],f);}fputc('"',f);
}
static bool config_read_text(char* text,size_t capacity) {
    if(text[0]!='"')return true;
    settings_json_t* d=calloc(1,sizeof(*d));if(!d)return false;
    d->p=text;d->end=text+strlen(text);char decoded[CFG_MAX_PATH];
    bool ok=settings_string(d,decoded,sizeof(decoded));settings_space(d);
    ok=ok&&(d->p==d->end||*d->p==';')&&strlen(decoded)<capacity;
    if(ok)strcpy(text,decoded);free(d);return ok;
}

static void config_write_field(FILE* f, const ini_field_t* field) {
    const char* value=(const char*)s_live+field->offset;
    fprintf(f,"%s = ",field->key);
    switch (field->type) {
        case INI_STRING: config_write_text(f,value); break;
        case INI_INT: fprintf(f,"%d",*(const int*)value); break;
        case INI_BOOL: fputs(*(const bool*)value?"true":"false",f); break;
        case INI_ZIP: fputs(*(const bool*)value?"deflate":"store",f); break;
        case INI_NOTIFY:
            fputs(*(const int*)value==NOTIFY_ALL?"all":
                  *(const int*)value==NOTIFY_BALANCED?"balanced":"important",f);
            break;
        case INI_CSV: {
            size_t count=*(const size_t*)((const char*)s_live+field->count_offset);
            for (size_t i=0; i<count; i++) fprintf(f,"%s%s",i?", ":"",value+i*field->stride);
            break;
        }
    }
    fputc('\n',f);
}

static void title_list_add_once(char list[][CFG_MAX_TITLE_ID], size_t* count,
                                const char* title_id) {
    if (!list || !count || !title_id || !title_id[0]) return;
    for (size_t i = 0; i < *count; i++)
        if (strcmp(list[i], title_id) == 0) return;
    if (*count >= CFG_MAX_LIST) return;
    snprintf(list[*count], CFG_MAX_TITLE_ID, "%s", title_id);
    (*count)++;
}

// YouTube owns save-like data but is not a game. Apply these defaults once,
// then preserve any explicit choice the user makes afterwards.
static bool apply_known_app_defaults(config_t* c) {
    if (!c || c->titles.app_defaults_applied) return false;
    title_list_add_once(c->titles.exclude, &c->titles.exclude_count,
                        "PPSA01650");
    title_list_add_once(c->titles.hidden, &c->titles.hidden_count,
                        "PPSA01650");
    c->titles.app_defaults_applied = true;
    return true;
}

static bool config_stat_same(const struct stat* a, const struct stat* b) {
#ifdef __APPLE__
    bool times = a->st_mtimespec.tv_nsec == b->st_mtimespec.tv_nsec &&
                 a->st_ctimespec.tv_nsec == b->st_ctimespec.tv_nsec;
#else
    bool times = a->st_mtim.tv_nsec == b->st_mtim.tv_nsec &&
                 a->st_ctim.tv_nsec == b->st_ctim.tv_nsec;
#endif
    return S_ISREG(b->st_mode) && a->st_dev == b->st_dev && a->st_ino == b->st_ino &&
        a->st_size == b->st_size && a->st_mtime == b->st_mtime && a->st_ctime == b->st_ctime && times;
}

static bool config_load_internal(config_t* cfg, const char* ini_path, bool observe) {
    if (!cfg || !ini_path) return false;
    set_defaults(cfg);
    config_sanitize(cfg);
    s_saved=*cfg;
    memset(s_explicit,0,sizeof(s_explicit));
    strncpy(cfg->ini_path, ini_path, sizeof(cfg->ini_path) - 1);
    s_live = cfg;   // share the caller's instance with the whole daemon

    struct stat before, opened, after;
    FILE* f = NULL;
    if (observe) {
        if (lstat(ini_path, &before) || !S_ISREG(before.st_mode) ||
            before.st_size <= 0 || before.st_size > 1024 * 1024) return false;
        int fd = open(ini_path, O_RDONLY | O_NOFOLLOW | O_NONBLOCK);
        if (fd < 0) return false;
        if (fstat(fd, &opened) || !config_stat_same(&before, &opened)) {
            close(fd); return false;
        }
        f = fdopen(fd, "r");
        if (!f) { close(fd); return false; }
    } else f = fopen(ini_path, "r");
    if (!f) {
        if (observe) return false;
        // First run: persist only the one-time app migration, not untouched defaults.
        apply_known_app_defaults(cfg);
        return config_save();
    }

    char line[1024];
    char section[64] = "";
    bool quoted_ini = false; unsigned line_number = 0;
    while (fgets(line, sizeof(line), f)) {
        if (observe && !strchr(line, '\n') && !feof(f)) {
            fclose(f); return false;
        }
        char* first = trim(line);
        if (line_number++ == 0 && !strcmp(first, "; tostonsync-string-encoding:json-v1")) {
            quoted_ini = true; continue;
        }
        if (*first == ';' || !*first) continue;
        // Legacy INIs retain literal quotes; only our explicit header enables decoding.
        char* assignment=strchr(line,'=');char* raw=assignment?assignment+1:NULL;
        while(raw&&(*raw==' '||*raw=='\t'))raw++;
        if(!quoted_ini||!raw||*raw!='"'){char* comment=strchr(line,';');if(comment)*comment=0;}
        char* trimmed = trim(line);
        if (!*trimmed) continue;
        if (*trimmed == '[') {
            char* end = strchr(trimmed, ']');
            if (!end) continue;
            *end = '\0';
            strncpy(section, trimmed + 1, sizeof(section) - 1);
            continue;
        }
        char* eq = strchr(trimmed, '=');
        if (!eq) continue;
        *eq = '\0';
        char* key = trim(trimmed);
        char* val = trim(eq + 1);
        if(quoted_ini&&!config_read_text(val,sizeof(line)-(size_t)(val-line))){fclose(f);return false;}
        apply_kv(cfg, section, key, val);
        config_note_explicit(section,key);
    }
    if (observe) {
        bool stable = !ferror(f) && !fstat(fileno(f), &after) &&
            config_stat_same(&before, &after) && !lstat(ini_path, &opened) &&
            config_stat_same(&after, &opened);
        if (fclose(f)) stable = false;
        // Check before sanitization: missing/unknown modes must not become manual.
        if (!stable || cfg->triggers.modes_count != 1 ||
            strcmp(cfg->triggers.modes[0], "manual")) return false;
    } else fclose(f);
    config_sanitize(cfg);
    s_saved=*cfg;
    if (observe) return true;
    if (apply_known_app_defaults(cfg)) return config_save();
    return true;
}

bool config_load(config_t* cfg, const char* ini_path) {
    return config_load_internal(cfg, ini_path, false);
}

bool config_load_observational(config_t* cfg, const char* ini_path) {
    return config_load_internal(cfg, ini_path, true);
}

static bool config_ini_safe(const config_t* c) {
    for(size_t i=0;i<INI_FIELD_COUNT;i++) {
        const ini_field_t* f=&s_fields[i];const char* p=(const char*)c+f->offset;
        size_t count=f->type==INI_CSV?*(const size_t*)((const char*)c+f->count_offset):1;
        if(f->type!=INI_STRING&&f->type!=INI_CSV)continue;
        size_t limit=!strcmp(f->section,"triggers")?8:!strcmp(f->section,"destinations")?CFG_MAX_DESTS:CFG_MAX_LIST;
        if(count>limit)return false;
        for(size_t j=0;j<count;j++)if(!memchr(p+j*f->stride,0,f->stride)||!settings_text_valid(p+j*f->stride))return false;
    }
    const cfg_users_t* maps[]={&c->users,&c->display_users};
    for(unsigned m=0;m<2;m++)for(size_t i=0;i<maps[m]->count;i++)
        if(!settings_text_valid(maps[m]->entries[i].uid)||strpbrk(maps[m]->entries[i].uid,"=[];#")||!settings_text_valid(maps[m]->entries[i].alias))return false;
    for(size_t i=0;i<c->title_aliases.count;i++)
        if(!settings_text_valid(c->title_aliases.entries[i].title_id)||strpbrk(c->title_aliases.entries[i].title_id,"=[];#")||!settings_text_valid(c->title_aliases.entries[i].name))return false;
    return true;
}

static bool config_save_locked(void) {
    if (!s_live || !config_ini_safe(s_live)) return false;
    config_sanitize(s_live);
    char dir[CFG_MAX_PATH];
    snprintf(dir, sizeof(dir), "%s", s_live->ini_path);
    char* slash = strrchr(dir, '/');
    if (slash && slash != dir) { *slash = '\0'; fs_mkdir_p(dir); }

    char tmp[300];
    snprintf(tmp, sizeof(tmp), "%s.tmp", s_live->ini_path);
    int fd=open(tmp,O_WRONLY|O_CREAT|O_TRUNC,0600);
    if (fd<0) return false;
    FILE* f=fdopen(fd,"w");
    if (!f) { close(fd); unlink(tmp); return false; }
    fputs("; tostonsync-string-encoding:json-v1\n",f);
    bool written[INI_FIELD_COUNT]={false};
    const char* section="";
    for (size_t i=0; i<INI_FIELD_COUNT; i++) {
        if (!s_explicit[i] && !config_field_changed(&s_fields[i])) continue;
        if (strcmp(section,s_fields[i].section)) {
            section=s_fields[i].section;
            fprintf(f,"%s[%s]\n",i?"\n":"",section);
        }
        config_write_field(f,&s_fields[i]);
        written[i]=true;
    }
    // These maps have no defaults: each existing entry is an explicit user value.
    const cfg_users_t* maps[]={&s_live->users,&s_live->display_users};
    const char* sections[]={"users","display_users"};
    for (size_t m=0; m<2; m++) {
        if (maps[m]->count) fprintf(f,"\n[%s]\n",sections[m]);
        for (size_t i=0; i<maps[m]->count; i++)
            if (maps[m]->entries[i].uid[0])
                { fprintf(f,"%s = ",maps[m]->entries[i].uid);config_write_text(f,maps[m]->entries[i].alias);fputc('\n',f); }
    }
    if (s_live->title_aliases.count) fprintf(f,"\n[title_names]\n");
    for (size_t i=0; i<s_live->title_aliases.count; i++)
        if (s_live->title_aliases.entries[i].title_id[0] && s_live->title_aliases.entries[i].name[0])
            { fprintf(f,"%s = ",s_live->title_aliases.entries[i].title_id);config_write_text(f,s_live->title_aliases.entries[i].name);fputc('\n',f); }

    bool write_ok = !ferror(f);
    if (fclose(f)) write_ok = false;
    if (!write_ok) { unlink(tmp); return false; }
    chmod(tmp, 0600);
    if (rename(tmp, s_live->ini_path) != 0) return false;
    chmod(s_live->ini_path, 0600);
    memcpy(s_explicit,written,sizeof(s_explicit));
    s_saved=*s_live;
    return true;
}

bool config_save(void) {
    pthread_mutex_lock(&s_cfg_lock);
    bool ok = config_save_locked();
    pthread_mutex_unlock(&s_cfg_lock);
    return ok;
}

cfg_backup_timezone_result_t config_backup_timezone_sync(const char* timezone,
                                                        const char* offset,
                                                        bool* changed) {
    if (changed) *changed = false;
    int minutes, configured;
    if (!timezone || !backup_timezone_offset_minutes(offset, &minutes))
        return CFG_BACKUP_TIMEZONE_INVALID;
    pthread_mutex_lock(&s_cfg_lock);
    cfg_backup_timezone_result_t result = CFG_BACKUP_TIMEZONE_OK;
    if (!s_live) result = CFG_BACKUP_TIMEZONE_UNAVAILABLE;
    else if (strcmp(timezone, s_live->general.display_timezone)) result = CFG_BACKUP_TIMEZONE_STALE;
    else if ((!strcmp(timezone, "UTC") || !strcmp(timezone, "Etc/UTC") || !strcmp(timezone, "GMT")) && minutes)
        result = CFG_BACKUP_TIMEZONE_INVALID;
    else if (!strncmp(timezone, "offset:", 7) &&
             (!backup_timezone_offset_minutes(timezone, &configured) || configured != minutes))
        result = CFG_BACKUP_TIMEZONE_INVALID;
    else if (strcmp(offset, s_live->general.backup_timezone_offset)) {
        char previous[sizeof(s_live->general.backup_timezone_offset)];
        memcpy(previous, s_live->general.backup_timezone_offset, sizeof(previous));
        snprintf(s_live->general.backup_timezone_offset,
                 sizeof(s_live->general.backup_timezone_offset), "%s", offset);
        if (!config_save_locked()) {
            memcpy(s_live->general.backup_timezone_offset, previous, sizeof(previous));
            result = CFG_BACKUP_TIMEZONE_SAVE_FAILED;
        } else if (changed) *changed = true;
    }
    pthread_mutex_unlock(&s_cfg_lock);
    return result;
}

const config_t* config_get(void) { return s_live; }

// Copy the whole live config under the lock into `out`. Workers call this
// once at the start of a job so they read a CONSISTENT snapshot instead of
// dereferencing the shared s_live while a Settings save mutates its strings
// in place (which could otherwise yield a torn host/path/credential read).
bool config_snapshot(config_t* out) {
    if (!out) return false;
    pthread_mutex_lock(&s_cfg_lock);
    if (s_live) *out = *s_live;
    pthread_mutex_unlock(&s_cfg_lock);
    return s_live != NULL;
}

// --- UI access protection -------------------------------------------------

void config_lock(void)   { pthread_mutex_lock(&s_cfg_lock); }
void config_unlock(void) { pthread_mutex_unlock(&s_cfg_lock); }

bool config_ui_auth_enabled(void) {
    config_t cfg;
    return config_snapshot(&cfg) && cfg.general.ui_auth_enabled
           && cfg.general.ui_password[0];
}

const char* config_ui_password(void) {
    static _Thread_local char password[64];
    config_t cfg;
    password[0] = '\0';
    if (config_snapshot(&cfg))
        snprintf(password, sizeof(password), "%s", cfg.general.ui_password);
    return password;
}

bool config_ui_reset_on_boot(void) {
    config_t cfg;
    return config_snapshot(&cfg) && cfg.general.ui_auth_reset_on_boot;
}

bool config_set_ui_auth(bool enabled, const char* code, bool reset_on_boot) {
    if (!s_live || (code && (!settings_text_valid(code) || strlen(code) >= sizeof(s_live->general.ui_password)))) return false;
    pthread_mutex_lock(&s_cfg_lock);
    cfg_general_t before = s_live->general;
    if (!enabled) {
        s_live->general.ui_auth_enabled = false;
        s_live->general.ui_password[0] = '\0';
    } else if (code && code[0]) {
        s_live->general.ui_auth_enabled = true;
        strncpy(s_live->general.ui_password, code,
                sizeof(s_live->general.ui_password) - 1);
        s_live->general.ui_password[sizeof(s_live->general.ui_password) - 1] = '\0';
    } else {
        // Enabling without a code would create a confusing half-locked state.
        // Keep the old code if one exists; otherwise reject the change.
        if (!s_live->general.ui_password[0]) {
            pthread_mutex_unlock(&s_cfg_lock);
            return false;
        }
        s_live->general.ui_auth_enabled = true;
    }
    s_live->general.ui_auth_reset_on_boot = reset_on_boot;
    bool ok = config_save_locked();
    if (!ok) s_live->general = before;
    pthread_mutex_unlock(&s_cfg_lock);
    return ok;
}

bool config_reset_ui_auth(void) {
    if (!s_live) return false;
    pthread_mutex_lock(&s_cfg_lock);
    cfg_general_t before = s_live->general;
    s_live->general.ui_auth_enabled = false;
    s_live->general.ui_password[0] = '\0';
    bool ok = config_save_locked();
    if (!ok) s_live->general = before;
    pthread_mutex_unlock(&s_cfg_lock);
    return ok;
}

// --- Per-user alias map --------------------------------------------------

const char* config_alias_for_uid(const char* uid) {
    static _Thread_local char value[32];
    snprintf(value, sizeof(value), "%s", (uid && uid[0]) ? uid : "default");
    config_t cfg;
    if (!config_snapshot(&cfg) || !uid || !uid[0]) return value;
    for (size_t i = 0; i < cfg.users.count; i++) {
        if (strcmp(cfg.users.entries[i].uid, uid) == 0
            && cfg.users.entries[i].alias[0]) {
            snprintf(value, sizeof(value), "%s", cfg.users.entries[i].alias);
            break;
        }
    }
    return value;
}

bool config_set_user_alias(const char* uid, const char* alias) {
    if (!s_live || !uid || strlen(uid) != 8 || strspn(uid,"0123456789abcdefABCDEF") != 8) return false;
    if (!alias_is_safe(alias ? alias : "")) return false;
    pthread_mutex_lock(&s_cfg_lock);
    // Update in place if known.
    for (size_t i = 0; i < s_live->users.count; i++) {
        if (strcmp(s_live->users.entries[i].uid, uid) == 0) {
            strncpy(s_live->users.entries[i].alias, alias ? alias : "",
                    sizeof(s_live->users.entries[i].alias) - 1);
            s_live->users.entries[i].alias[
                sizeof(s_live->users.entries[i].alias) - 1] = '\0';
            bool ok = config_save_locked();
            pthread_mutex_unlock(&s_cfg_lock);
            return ok;
        }
    }
    if (s_live->users.count >= CFG_MAX_USERS) {
        pthread_mutex_unlock(&s_cfg_lock);
        return false;
    }
    cfg_user_alias_t* e = &s_live->users.entries[s_live->users.count++];
    strncpy(e->uid,   uid,             sizeof(e->uid)   - 1);
    strncpy(e->alias, alias ? alias : "", sizeof(e->alias) - 1);
    e->uid[sizeof(e->uid) - 1]     = '\0';
    e->alias[sizeof(e->alias) - 1] = '\0';
    bool ok = config_save_locked();
    pthread_mutex_unlock(&s_cfg_lock);
    return ok;
}

bool config_set_display_alias(const char* uid,const char* alias) {
    if(!s_live||!uid||strlen(uid)!=8||!alias||strlen(alias)>=sizeof(s_live->display_users.entries[0].alias)||!alias_is_safe(alias))return false;
    for(size_t i=0;i<8;i++)if(!isxdigit((unsigned char)uid[i]))return false;
    pthread_mutex_lock(&s_cfg_lock);
    cfg_users_t before=s_live->display_users;
    size_t i=0;for(;i<before.count;i++)if(!strcasecmp(before.entries[i].uid,uid))break;
    if(i==CFG_MAX_USERS){pthread_mutex_unlock(&s_cfg_lock);return false;}
    if(i==before.count)s_live->display_users.count++;
    cfg_user_alias_t* entry=&s_live->display_users.entries[i];
    for(size_t j=0;j<8;j++)entry->uid[j]=(char)tolower((unsigned char)uid[j]);entry->uid[8]=0;
    snprintf(entry->alias,sizeof(entry->alias),"%s",alias);
    bool ok=config_save_locked();if(!ok)s_live->display_users=before;
    pthread_mutex_unlock(&s_cfg_lock);return ok;
}

// --- Manual title (game) name map ----------------------------------------

const char* config_title_alias_for(const char* title_id) {
    static _Thread_local char value[64];
    value[0] = '\0';
    if (!title_id || !title_id[0]) return value;
    config_t cfg;
    if (!config_snapshot(&cfg)) return value;
    for (size_t i = 0; i < cfg.title_aliases.count; i++) {
        if (strcmp(cfg.title_aliases.entries[i].title_id, title_id) == 0
            && cfg.title_aliases.entries[i].name[0]) {
            snprintf(value, sizeof(value), "%s",
                     cfg.title_aliases.entries[i].name);
            break;
        }
    }
    return value;
}

static bool title_id_safe(const char* t);

bool config_set_title_alias(const char* title_id, const char* name) {
    if (!s_live || !title_id_safe(title_id)) return false;
    if (!alias_is_safe(name ? name : "")) return false;
    pthread_mutex_lock(&s_cfg_lock);
    for (size_t i = 0; i < s_live->title_aliases.count; i++) {
        if (strcmp(s_live->title_aliases.entries[i].title_id, title_id) == 0) {
            strncpy(s_live->title_aliases.entries[i].name, name ? name : "",
                    sizeof(s_live->title_aliases.entries[i].name) - 1);
            s_live->title_aliases.entries[i].name[
                sizeof(s_live->title_aliases.entries[i].name) - 1] = '\0';
            bool ok = config_save_locked();
            pthread_mutex_unlock(&s_cfg_lock);
            return ok;
        }
    }
    if (s_live->title_aliases.count >= CFG_MAX_TITLE_ALIASES) {
        pthread_mutex_unlock(&s_cfg_lock);
        return false;
    }
    cfg_title_alias_t* e =
        &s_live->title_aliases.entries[s_live->title_aliases.count++];
    strncpy(e->title_id, title_id,        sizeof(e->title_id) - 1);
    strncpy(e->name,     name ? name : "", sizeof(e->name)     - 1);
    e->title_id[sizeof(e->title_id) - 1] = '\0';
    e->name[sizeof(e->name) - 1]         = '\0';
    bool ok = config_save_locked();
    pthread_mutex_unlock(&s_cfg_lock);
    return ok;
}

static bool title_id_safe(const char* t) {
    if (!t || !t[0]) return false;
    for (size_t i = 0; t[i]; i++) {
        unsigned char c = (unsigned char)t[i];
        bool ok = (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
                  (c >= '0' && c <= '9') || c == '_';
        if (!ok) return false;
    }
    return true;
}

static int title_index(char list[][CFG_MAX_TITLE_ID], size_t count,
                       const char* title_id) {
    for (size_t i = 0; i < count; i++)
        if (strcmp(list[i], title_id) == 0) return (int)i;
    return -1;
}

static void title_remove(char list[][CFG_MAX_TITLE_ID], size_t* count,
                         const char* title_id) {
    int idx = title_index(list, *count, title_id);
    if (idx < 0) return;
    for (size_t i = (size_t)idx; i + 1 < *count; i++)
        memcpy(list[i], list[i + 1], CFG_MAX_TITLE_ID);
    (*count)--;
    memset(list[*count], 0, CFG_MAX_TITLE_ID);
}

static bool title_add(char list[][CFG_MAX_TITLE_ID], size_t* count,
                      const char* title_id) {
    if (title_index(list, *count, title_id) >= 0) return true;
    if (*count >= CFG_MAX_LIST) return false;
    strncpy(list[*count], title_id, CFG_MAX_TITLE_ID - 1);
    list[*count][CFG_MAX_TITLE_ID - 1] = '\0';
    (*count)++;
    return true;
}

bool config_title_is_backed_up(const char* title_id) {
    config_t cfg;
    if (!title_id_safe(title_id) || !config_snapshot(&cfg)) return false;
    if (title_index(cfg.titles.exclude,
                    cfg.titles.exclude_count, title_id) >= 0)
        return false;
    if (cfg.titles.include_only_count == 0) return true;
    return title_index(cfg.titles.include_only,
                       cfg.titles.include_only_count, title_id) >= 0;
}

bool config_set_title_backup(const char* title_id, bool backup) {
    if (!s_live || !title_id_safe(title_id)) return false;
    pthread_mutex_lock(&s_cfg_lock);
    if (backup) {
        title_remove(s_live->titles.exclude,
                     &s_live->titles.exclude_count, title_id);
        if (s_live->titles.include_only_count > 0 &&
            !title_add(s_live->titles.include_only,
                       &s_live->titles.include_only_count, title_id)) {
            pthread_mutex_unlock(&s_cfg_lock);
            return false;
        }
    } else {
        if (!title_add(s_live->titles.exclude,
                       &s_live->titles.exclude_count, title_id)) {
            pthread_mutex_unlock(&s_cfg_lock);
            return false;
        }
        title_remove(s_live->titles.include_only,
                     &s_live->titles.include_only_count, title_id);
    }
    bool ok = config_save_locked();
    pthread_mutex_unlock(&s_cfg_lock);
    return ok;
}

bool config_title_is_hidden(const char* title_id) {
    config_t cfg;
    if (!title_id_safe(title_id) || !config_snapshot(&cfg)) return false;
    return title_index(cfg.titles.hidden,
                       cfg.titles.hidden_count, title_id) >= 0;
}

bool config_set_title_hidden(const char* title_id, bool hidden) {
    if (!s_live || !title_id_safe(title_id)) return false;
    pthread_mutex_lock(&s_cfg_lock);
    if (hidden) {
        if (!title_add(s_live->titles.hidden,
                       &s_live->titles.hidden_count, title_id)) {
            pthread_mutex_unlock(&s_cfg_lock);
            return false;
        }
    } else {
        title_remove(s_live->titles.hidden,
                     &s_live->titles.hidden_count, title_id);
    }
    bool ok = config_save_locked();
    pthread_mutex_unlock(&s_cfg_lock);
    return ok;
}

void config_users_to_json(char* out, size_t out_sz) {
    if (!out || out_sz < 4) return;
    config_t cfg;
    if (!config_snapshot(&cfg)) { snprintf(out, out_sz, "[]"); return; }
    char* p = out;
    char* end = out + out_sz;
    jappendf(&p, end, "[");
    for (size_t i = 0; i < cfg.users.count && p + 4 < end; i++) {
        jappendf(&p, end, "%s{\"uid\":", i ? "," : "");
        jappend_json_string(&p, end, cfg.users.entries[i].uid);
        jappendf(&p, end, ",\"alias\":");
        jappend_json_string(&p, end, cfg.users.entries[i].alias);
        jappendf(&p, end, "}");
    }
    if (p < end - 1) { *p++ = ']'; *p = '\0'; }
    else out[out_sz - 1] = '\0';
}

// --------------------------------------------------------------------
// JSON snapshot for the UI.
// --------------------------------------------------------------------

void config_to_json(const config_t* cfg, char* out, size_t out_sz) {
    char  triggers[256] = "[";
    char* tp = triggers + 1;
    char* tend = triggers + sizeof(triggers);
    for (size_t i = 0; i < cfg->triggers.modes_count; i++) {
        jappendf(&tp, tend, "%s", i ? "," : "");
        jappend_json_string(&tp, tend, cfg->triggers.modes[i]);
    }
    jappendf(&tp, tend, "]");

    // Build exclude / include arrays.
    char excl[1024] = "[", incl[1024] = "[";
    char *ep = excl + 1, *eend = excl + sizeof(excl);
    char *ip = incl + 1, *iend = incl + sizeof(incl);
    for (size_t i = 0; i < cfg->titles.exclude_count; i++) {
        jappendf(&ep, eend, "%s", i ? "," : "");
        jappend_json_string(&ep, eend, cfg->titles.exclude[i]);
    }
    for (size_t i = 0; i < cfg->titles.include_only_count; i++) {
        jappendf(&ip, iend, "%s", i ? "," : "");
        jappend_json_string(&ip, iend, cfg->titles.include_only[i]);
    }
    jappendf(&ep, eend, "]");
    jappendf(&ip, iend, "]");

    char* p = out;
    char* end = out + out_sz;
    jappendf(&p, end,
        "{\"general\":{\"http_port\":%d,\"notifications\":%s,\"notification_level\":",
        cfg->general.http_port,
        cfg->general.notifications ? "true" : "false");
    jappend_json_string(&p, end,
        cfg->general.notification_level == NOTIFY_ALL ? "all" :
        cfg->general.notification_level == NOTIFY_BALANCED ? "balanced" :
                                                             "important");
    jappendf(&p, end, ",\"update_auto_check\":%s", cfg->general.update_auto_check ? "true" : "false");
    jappendf(&p, end, ",\"log_level\":");
    jappend_json_string(&p, end, cfg->general.log_level);
    jappendf(&p, end, ",\"language\":");
    jappend_json_string(&p, end, cfg->general.language);
    jappendf(&p, end, ",\"time_format\":");
    jappend_json_string(&p, end, cfg->general.time_format);
    jappendf(&p, end,
        ",\"language_prompt_seen\":%s,"
        "\"ui_auth_enabled\":%s,\"ui_auth_has_code\":%s,"
        "\"ui_auth_reset_on_boot\":%s},\"display\":{\"time_format\":",
        cfg->general.language_prompt_seen ? "true" : "false",
        cfg->general.ui_auth_enabled ? "true" : "false",
        cfg->general.ui_password[0] ? "true" : "false",
        cfg->general.ui_auth_reset_on_boot ? "true" : "false");
    jappend_json_string(&p, end, cfg->general.time_format);
    jappendf(&p, end, ",\"display_timezone\":");
    jappend_json_string(&p, end, cfg->general.display_timezone);
    jappendf(&p,end,"},\"display_users\":[");
    for(size_t i=0;i<cfg->display_users.count;i++) {
        jappendf(&p,end,"%s{\"uid\":",i?",":"");jappend_json_string(&p,end,cfg->display_users.entries[i].uid);
        jappendf(&p,end,",\"alias\":");jappend_json_string(&p,end,cfg->display_users.entries[i].alias);jappendf(&p,end,"}");
    }
    jappendf(&p, end, "],\"console\":{\"name\":");
    jappend_json_string(&p, end, cfg->console.name);
    jappendf(&p, end, ",\"type\":");
    jappend_json_string(&p, end, cfg->console.type);
    jappendf(&p, end, ",\"role\":");
    jappend_json_string(&p, end, cfg->console.role);
    jappendf(&p, end, "},\"cloud\":{\"provider\":");
    jappend_json_string(&p, end, cfg->cloud.provider);
    jappendf(&p, end, "},\"gdrive\":{\"client_id\":");
    jappend_json_string(&p, end, cfg->gdrive.client_id);
    jappendf(&p, end, ",\"client_secret\":\"\",\"client_secret_set\":%s",
             cfg->gdrive.client_secret[0] ? "true" : "false");
    jappendf(&p, end, ",\"root_folder\":");
    jappend_json_string(&p, end, cfg->gdrive.root_folder);
    jappendf(&p, end, ",\"use_appdata\":%s,\"custom_ca\":%s},\"usb\":{\"enabled\":%s,\"mount\":",
             cfg->gdrive.use_appdata ? "true" : "false",
             cfg->gdrive.custom_ca ? "true" : "false",
             cfg->usb.enabled ? "true" : "false");
    jappend_json_string(&p, end,
                        cfg->usb.mount_path[0] ? cfg->usb.mount_path : "auto");
    jappendf(&p, end, ",\"folder\":");
    jappend_json_string(&p, end, cfg->usb.folder);
    jappendf(&p, end, "},\"destinations\":{\"order\":[");
    for (size_t i = 0; i < cfg->destinations.order_count; i++) {
        if (i) jappendf(&p, end, ",");
        jappend_json_string(&p, end, cfg->destinations.order[i]);
    }
    jappendf(&p, end, "],\"fallback\":%s}",
             cfg->destinations.fallback ? "true" : "false");
    jappendf(&p, end,
        ",\"triggers\":{\"modes\":%s,\"live_backup_mode\":",
        triggers);
    jappend_json_string(&p, end, cfg->triggers.live_backup_mode);
    jappendf(&p, end,
        ","
        "\"idle_seconds\":%d,\"interval_seconds\":%d,"
        "\"change_settle_seconds\":%d},\"retention\":{\"max_versions\":%d,"
        "\"max_total_size_per_title\":",
        cfg->triggers.idle_seconds,
        cfg->triggers.interval_seconds,
        cfg->triggers.change_settle_seconds,
        cfg->retention.max_versions);
    jappend_json_string(&p, end, cfg->retention.max_total_size_per_title_str);
    jappendf(&p, end, ",\"max_total_size_global\":");
    jappend_json_string(&p, end, cfg->retention.max_total_size_global_str);
    jappendf(&p, end,
        ",\"min_change_bytes\":%d,\"dedup_by_hash\":%s},"
        "\"titles\":{\"exclude\":%s,\"include_only\":%s},"
        "\"crypto\":{\"use_kernel_resign\":%s,"
        "\"auto_fallback_on_failure\":%s,\"fix_zeroed_sfo\":%s}}",
        cfg->retention.min_change_bytes,
        cfg->retention.dedup_by_hash ? "true" : "false",
        excl, incl,
        cfg->crypto.use_kernel_resign ? "true" : "false",
        cfg->crypto.auto_fallback_on_failure ? "true" : "false",
        cfg->crypto.fix_zeroed_sfo ? "true" : "false");
}

// --------------------------------------------------------------------
// Patch application from the UI. Accepts the same shape as
// config_to_json. Anything not present is left alone.
// --------------------------------------------------------------------

#include "json.h"

static const ini_field_t* config_patch_field(const char* section,const char* key) {
    if(!strcmp(section,"console")) {
        if(!strcmp(key,"name"))key="console_name";
        else if(!strcmp(key,"type"))key="console_type";
        else if(!strcmp(key,"role"))key="console_role";
    }
    if(!strcmp(section,"general")&&!strcmp(key,"time_format"))section="display";
    for(size_t i=0;i<INI_FIELD_COUNT;i++)if(!strcmp(section,s_fields[i].section)&&!strcmp(key,s_fields[i].key))return &s_fields[i];
    return NULL;
}
static bool config_patch_writable(const ini_field_t* f) {
    const char* s=f->section,*k=f->key;
    if(!strcmp(s,"general"))return !strcmp(k,"notifications")||!strcmp(k,"update_auto_check")||!strcmp(k,"notification_level")||!strcmp(k,"language")||!strcmp(k,"language_prompt_seen");
    if(!strcmp(s,"display"))return strcmp(k,"backup_timezone_offset")!=0;
    return !strcmp(s,"console")||!strcmp(s,"gdrive")||!strcmp(s,"usb")||!strcmp(s,"destinations")||!strcmp(s,"triggers")||!strcmp(s,"retention")||!strcmp(s,"crypto")||(!strcmp(s,"titles")&&(!strcmp(k,"exclude")||!strcmp(k,"include_only")));
}
static bool config_patch_decode(const char* patch,size_t length,config_t* next) {
    settings_json_t* d=settings_parse(patch,length);if(!d)return false;
    bool ok=true;bool seen[INI_FIELD_COUNT]={0};
    for(int si=d->values[0].first;si>=0&&ok;si=d->values[si].next) {
        const settings_value_t* section=&d->values[si];
        if(section->kind!=SET_OBJECT){ok=false;break;}
        bool known=false;for(size_t f=0;f<INI_FIELD_COUNT;f++)if(!strcmp(section->key,s_fields[f].section))known=true;
        if(!known)continue; // Preserve ignored extension objects without searching their fields.
        for(int ki=section->first;ki>=0&&ok;ki=d->values[ki].next) {
            const settings_value_t* v=&d->values[ki];const ini_field_t* f=config_patch_field(section->key,v->key);
            if(!f||seen[f-s_fields]){ok=false;break;}seen[f-s_fields]=true;
            char* out=(char*)next+f->offset;bool writable=config_patch_writable(f);
            if(f->type==INI_STRING||f->type==INI_NOTIFY||f->type==INI_ZIP) {
                size_t cap=f->type==INI_STRING?f->stride:24;
                if(v->kind!=SET_STRING||strlen(v->text)>=cap){ok=false;break;}
                if(!writable)continue;
                if(f->type==INI_NOTIFY){next->general.notification_level=!strcmp(v->text,"all")?NOTIFY_ALL:!strcmp(v->text,"balanced")?NOTIFY_BALANCED:NOTIFY_IMPORTANT;continue;}
                if(!strcmp(f->section,"gdrive")&&(!strcmp(f->key,"client_id")||!strcmp(f->key,"client_secret"))&&!v->text[0])continue;
                if(!strcmp(f->section,"usb")&&((!strcmp(f->key,"mount")&&!usb_mount_value_safe(v->text))||(!strcmp(f->key,"folder")&&!alias_is_safe(v->text)))){ok=false;break;}
                if(!strcmp(f->section,"display")&&!strcmp(f->key,"display_timezone")&&strcmp(out,v->text))next->general.backup_timezone_offset[0]=0;
                strcpy(out,v->text);
                if((!strcmp(f->section,"gdrive")&&!strcmp(f->key,"root_folder"))||(!strcmp(f->section,"usb")&&!strcmp(f->key,"folder")))if(!out[0])strcpy(out,"TostónSync");
                if(!strcmp(f->section,"usb")&&!strcmp(f->key,"mount")&&!out[0])strcpy(out,"auto");
            } else if(f->type==INI_BOOL) {
                if(v->kind!=SET_BOOL){ok=false;break;}if(writable)*(bool*)out=v->boolean;
            } else if(f->type==INI_INT) {
                if(v->kind!=SET_INT||v->number<INT_MIN||v->number>INT_MAX){ok=false;break;}
                if(writable&&(!strcmp(f->section,"retention")||v->number>0))*(int*)out=(int)v->number;
            } else if(f->type==INI_CSV) {
                if(v->kind!=SET_ARRAY){ok=false;break;}size_t count=0;
                size_t limit=!strcmp(f->section,"triggers")?8:!strcmp(f->section,"destinations")?CFG_MAX_DESTS:CFG_MAX_LIST;
                for(int vi=v->first;vi>=0;vi=d->values[vi].next) {
                    const settings_value_t* item=&d->values[vi];
                    if(item->kind!=SET_STRING||strlen(item->text)>=f->stride||count>=limit){ok=false;break;}
                    if(!strcmp(f->section,"titles")&&!title_id_safe(item->text)){ok=false;break;}
                    if(!strcmp(f->section,"destinations")&&strcmp(item->text,"usb")&&strcmp(item->text,"drive"))continue;
                    if(writable)strcpy(out+count*f->stride,item->text);count++;
                }
                if(writable){*(size_t*)((char*)next+f->count_offset)=count;if(!strcmp(f->section,"destinations"))next->destinations.order_explicit=true;}
            }
        }
    }
    free(d);return ok&&config_ini_safe(next);
}
bool config_validate_json(const char* patch,size_t length) {
    config_t candidate;if(!config_snapshot(&candidate))return false;
    return config_patch_decode(patch,length,&candidate);
}
bool config_apply_json(const char* patch) {
    if(!patch||!s_live)return false;
    pthread_mutex_lock(&s_cfg_lock);
    config_t next=*s_live,before=*s_live;
    bool ok=config_patch_decode(patch,strlen(patch),&next);
    if(ok){*s_live=next;ok=config_save_locked();if(!ok)*s_live=before;}
    pthread_mutex_unlock(&s_cfg_lock);return ok;
}
