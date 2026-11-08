#include "backup_names.h"
#ifndef BACKUP_NAMES_PURE_TEST
#include "config.h"
#include "metacache.h"
#endif

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static bool ascii_digit(unsigned char c) { return c >= '0' && c <= '9'; }
static bool ascii_alnum(unsigned char c) {
    return ascii_digit(c) || (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z');
}

// Strict UTF-8, with no reads past the known byte count and no split characters.
static size_t codepoint(const unsigned char* p, size_t n, uint32_t* value) {
    if (!n) return 0;
    unsigned char a = p[0];
    if (a < 0x80) { *value = a; return 1; }
    size_t width = a >= 0xc2 && a <= 0xdf ? 2 : a >= 0xe0 && a <= 0xef ? 3 :
        a >= 0xf0 && a <= 0xf4 ? 4 : 0;
    if (!width || n < width) return 0;
    uint32_t v = a & (width == 2 ? 0x1f : width == 3 ? 0x0f : 0x07);
    for (size_t i = 1; i < width; i++) {
        if ((p[i] & 0xc0) != 0x80) return 0;
        v = (v << 6) | (p[i] & 0x3f);
    }
    if ((width == 2 && v < 0x80) || (width == 3 && v < 0x800) ||
        (width == 4 && v < 0x10000) || v > 0x10ffff ||
        (v >= 0xd800 && v <= 0xdfff)) return 0;
    *value = v;
    return width;
}

static bool utf8_valid(const char* in) {
    if (!in) return false;
    size_t n = strlen(in), i = 0;
    while (i < n) {
        uint32_t v;
        size_t width = codepoint((const unsigned char*)in + i, n - i, &v);
        if (!width || v < 0x20 || (v >= 0x7f && v <= 0x9f)) return false;
        i += width;
    }
    return true;
}

static bool clean(const char* in, char* out, size_t cap) {
    if (!out || !cap) return false;
    out[0] = '\0';
    if (!in) return true;
    size_t n = strlen(in), used = 0;
    bool space = false, truncated = false;
    for (size_t i = 0; i < n;) {
        uint32_t v;
        size_t width = codepoint((const unsigned char*)in + i, n - i, &v);
        if (!width) { out[0] = '\0'; return false; }
        bool whitespace = v == ' ' || v == 0xa0 || (v >= 0x2000 && v <= 0x200a) ||
            v == 0x202f || v == 0x205f || v == 0x3000;
        bool excluded = v < 0x20 || (v >= 0x7f && v <= 0x9f) ||
            v == 0x2122 || v == 0xae || v == 0xa9 ||
            (v < 0x80 && strchr("\\/:*?\"<>|", (int)v));
        if (whitespace) space = used > 0;
        else if (!excluded && !truncated) {
            size_t required = width + (space ? 1 : 0);
            if (required >= cap - used) truncated = true;
            else {
                if (space) out[used++] = ' ';
                memcpy(out + used, in + i, width); used += width;
                space = false;
            }
        }
        i += width;
    }
    while (used && (out[used - 1] == '.' || out[used - 1] == ' ')) used--;
    out[used] = '\0';
    return true;
}

static bool bare_code(const char* value, bool title, char* out, size_t cap) {
    if (!value || !out) return false;
    size_t n = strlen(value);
    if (n + 1 > cap || (title ? n < 5 || n > 15 : n != 8)) return false;
    char canonical[16];
    for (size_t i = 0; i < n; i++) {
        unsigned char c = (unsigned char)value[i];
        if (title) {
            if (!ascii_alnum(c)) return false;
            canonical[i] = c >= 'a' && c <= 'z' ? (char)(c - 'a' + 'A') : (char)c;
        } else {
            if (!ascii_digit(c) && !(c >= 'a' && c <= 'f') && !(c >= 'A' && c <= 'F')) return false;
            canonical[i] = c >= 'A' && c <= 'F' ? (char)(c - 'A' + 'a') : (char)c;
        }
    }
    canonical[n] = '\0';
    if (title && strncmp(canonical, "PPSA", 4) && strncmp(canonical, "CUSA", 4) &&
        strncmp(canonical, "PCSA", 4) && strncmp(canonical, "NPXS", 4)) return false;
    memcpy(out, canonical, n + 1);
    return true;
}

bool backup_folder_code(const char* name, bool title, char* out, size_t cap) {
    if (out && cap) out[0] = '\0';
    if (!name || !out || !cap || !utf8_valid(name) || strchr(name, '/') || strchr(name, '\\')) return false;
    if (bare_code(name, title, out, cap)) return true;
    const char* suffix = NULL;
    for (const char* p = strstr(name, " - "); p; p = strstr(p + 3, " - ")) suffix = p;
    return suffix && suffix != name && bare_code(suffix + 3, title, out, cap);
}

static const char* canonical_trigger(const char* trigger) {
    if (trigger && !strcmp(trigger, "Interval")) return "Scheduled";
    if (trigger && !strcmp(trigger, "SAFETY")) return "Safety";
    static const char* allowed[] = {"Manual", "Auto", "GameClose", "Live", "Idle", "Startup",
        "Shutdown", "BeforeRestore", "Scheduled", "Imported", "Converted", "Safety"};
    for (size_t i = 0; trigger && i < sizeof(allowed) / sizeof(allowed[0]); i++)
        if (!strcmp(trigger, allowed[i])) return allowed[i];
    return NULL;
}

static int timezone_minutes(const char* zone, char effective[64]) {
    snprintf(effective, 64, "UTC");
    if (!zone || !strcmp(zone, "UTC") || !strcmp(zone, "Etc/UTC") || !strcmp(zone, "GMT")) return 0;
    if (strlen(zone) == 13 && !strncmp(zone, "offset:", 7) &&
        (zone[7] == '+' || zone[7] == '-') && zone[10] == ':' &&
        ascii_digit(zone[8]) && ascii_digit(zone[9]) && ascii_digit(zone[11]) && ascii_digit(zone[12])) {
        int hours = (zone[8] - '0') * 10 + zone[9] - '0';
        int minutes = (zone[11] - '0') * 10 + zone[12] - '0';
        if (hours <= 23 && minutes <= 59) {
            snprintf(effective, 64, "%s", zone);
            return (zone[7] == '-' ? -1 : 1) * (hours * 60 + minutes);
        }
    }
    // No process-wide TZ changes or guessed IANA rules. Unknown/auto uses UTC.
    return 0;
}

static bool folder_name(const char* readable, const char* code, char out[128]) {
    if (!readable[0] || !strcmp(readable, code)) {
        snprintf(out, 128, "%s", code); return true;
    }
    char clipped[128];
    if (!clean(readable, clipped, 128 - strlen(code) - 3)) return false;
    if (!clipped[0]) snprintf(out, 128, "%s", code);
    else snprintf(out, 128, "%s - %s", clipped, code);
    return true;
}

static unsigned char ascii_fold(unsigned char c) {
    return c >= 'A' && c <= 'Z' ? (unsigned char)(c - 'A' + 'a') : c;
}

static bool same_text(const char* a, const char* b) {
    while (*a && *b) {
        if (ascii_fold((unsigned char)*a++) != ascii_fold((unsigned char)*b++)) return false;
    }
    return *a == *b;
}

static bool contains_type(const char* console, const char* type) {
    size_t n = strlen(console), width = strlen(type);
    if (!width || width > n) return false;
    for (size_t i = 0; i <= n - width; i++) {
        if ((i && ascii_alnum((unsigned char)console[i - 1])) ||
            (i + width < n && ascii_alnum((unsigned char)console[i + width]))) continue;
        size_t j = 0;
        while (j < width && ascii_fold((unsigned char)console[i + j]) == ascii_fold((unsigned char)type[j])) j++;
        if (j == width) return true;
    }
    return false;
}

bool backup_names_build(const char* console_name, const char* console_type,
                        const char* user_alias, const char* uid,
                        const char* title, const char* game,
                        const char* trigger, const char* timezone,
                        time_t now, backup_names_t* out) {
    if (!out) return false;
    memset(out, 0, sizeof(*out));
    char user_code[16], title_code[16];
    if (!bare_code(uid, false, user_code, sizeof(user_code)) ||
        !bare_code(title, true, title_code, sizeof(title_code))) return false;
    char console[96], type[32], alias[64], user[256];
    if (!clean(console_name, console, sizeof(console)) || !clean(console_type, type, sizeof(type)) ||
        !clean(user_alias, alias, sizeof(alias)) || !clean(game, out->game, sizeof(out->game))) return false;
    if (!strcmp(out->game, title_code)) out->game[0] = '\0';
    bool append_type = type[0] && !contains_type(console, type);
    snprintf(user, sizeof(user), "%s%s%s", console, console[0] && append_type ? " " : "", append_type ? type : "");
    if (alias[0] && !same_text(alias, user_code) && !same_text(alias, console) && !same_text(alias, user)) {
        size_t n = strlen(user);
        snprintf(user + n, sizeof(user) - n, "%s(%s)", n ? " " : "", alias);
    }
    if (!folder_name(user, user_code, out->user_folder) ||
        !folder_name(out->game, title_code, out->title_folder)) return false;
    const char* normalized = canonical_trigger(trigger);
    if (!normalized) normalized = "Auto";
    int minutes = timezone_minutes(timezone, out->timezone);
    int64_t t = (int64_t)now, delta = (int64_t)minutes * 60;
    if ((delta > 0 && t > INT64_MAX - delta) || (delta < 0 && t < INT64_MIN - delta)) return false;
    time_t shifted = (time_t)(t + delta);
    if ((int64_t)shifted != t + delta) return false;
    struct tm tm;
    char date[24], offset[8];
    if (!gmtime_r(&shifted, &tm) || tm.tm_year < 0 || tm.tm_year > 8099 ||
        strftime(date, sizeof(date), "%Y-%m-%d %H.%M.%S", &tm) != 19) return false;
    int absolute = minutes < 0 ? -minutes : minutes;
    snprintf(offset, sizeof(offset), "%c%02d%02d", minutes < 0 ? '-' : '+', absolute / 60, absolute % 60);
    char suffix[100];
    int suffix_length = snprintf(suffix, sizeof(suffix), "%s - Full - %s - %s %s.zip",
        title_code, normalized, date, offset);
    if (suffix_length < 0 || (size_t)suffix_length >= sizeof(suffix) || (size_t)suffix_length >= sizeof(out->filename)) return false;
    if (!out->game[0]) snprintf(out->filename, sizeof(out->filename), "%s", suffix);
    else {
        char clipped[96];
        size_t cap = sizeof(out->filename) - (size_t)suffix_length - 3;
        if (!clean(out->game, clipped, cap)) return false;
        if (!clipped[0]) snprintf(out->filename, sizeof(out->filename), "%s", suffix);
        else snprintf(out->filename, sizeof(out->filename), "%s - %s", clipped, suffix);
    }
    return backup_names_limit(out, 177);
}

#ifndef BACKUP_NAMES_PURE_TEST
bool backup_names_current(const char* uid, const char* title, const char* fallback,
                          const char* trigger, time_t now, backup_names_t* out) {
    config_t cfg;
    if (!config_snapshot(&cfg)) return false;
    const char* alias = "";
    const char* manual = "";
    for (size_t i = 0; i < cfg.users.count && i < CFG_MAX_USERS; i++)
        if (uid && !strcmp(cfg.users.entries[i].uid, uid)) alias = cfg.users.entries[i].alias;
    for (size_t i = 0; i < cfg.title_aliases.count && i < CFG_MAX_TITLE_ALIASES; i++)
        if (title && !strcmp(cfg.title_aliases.entries[i].title_id, title)) manual = cfg.title_aliases.entries[i].name;
    char resolved[96] = {0};
    if (manual[0]) snprintf(resolved, sizeof(resolved), "%s", manual);
    else (void)metacache_resolve_name(title, fallback, resolved, sizeof(resolved));
    const char* timezone = cfg.general.display_timezone;
    if (strcmp(timezone, "UTC") && strcmp(timezone, "Etc/UTC") && strcmp(timezone, "GMT")) {
        if (strncmp(timezone, "offset:", 7)) timezone = cfg.general.backup_timezone_offset;
        char effective[64];
        int minutes = timezone_minutes(timezone, effective);
        if (strcmp(effective, timezone) || minutes < -720 || minutes > 840) timezone = "UTC";
    }
    if (!backup_names_build(cfg.console.name, cfg.console.type, alias, uid, title,
        resolved, trigger, timezone, now, out)) return false;
    out->title_rename_requested = manual[0] != '\0';
    return true;
}
#endif

static const char* last_separator(const char* begin, const char* end, const char* separator) {
    const char* found = NULL;
    size_t width = strlen(separator);
    for (const char* p = begin; end - p >= (ptrdiff_t)width; p++)
        if (!memcmp(p, separator, width)) found = p;
    return found;
}

static bool copy_piece(char* out, size_t cap, const char* begin, const char* end) {
    if (end < begin || (size_t)(end - begin) >= cap) return false;
    memcpy(out, begin, (size_t)(end - begin)); out[end - begin] = '\0';
    return true;
}

static int decimal(const char* p, size_t n) {
    int result = 0;
    for (size_t i = 0; i < n; i++) { if (!ascii_digit(p[i])) return -1; result = result * 10 + p[i] - '0'; }
    return result;
}

static bool calendar_time(int y, int month, int day, int hour, int minute, int second,
                          int offset, time_t* out) {
    if (y < 1900 || y > 9999 || month < 1 || month > 12 || day < 1 ||
        hour < 0 || hour > 23 || minute < 0 || minute > 59 || second < 0 || second > 59) return false;
    static const int days[] = {31,28,31,30,31,30,31,31,30,31,30,31};
    bool leap = y % 4 == 0 && (y % 100 != 0 || y % 400 == 0);
    if (day > days[month - 1] + (month == 2 && leap ? 1 : 0)) return false;
    int64_t total = 0;
    if (y >= 1970) for (int i = 1970; i < y; i++) total += i % 4 == 0 && (i % 100 != 0 || i % 400 == 0) ? 366 : 365;
    else for (int i = y; i < 1970; i++) total -= i % 4 == 0 && (i % 100 != 0 || i % 400 == 0) ? 366 : 365;
    for (int i = 1; i < month; i++) total += days[i - 1] + (i == 2 && leap ? 1 : 0);
    int64_t epoch = ((total + day - 1) * 24 + hour) * 3600 + minute * 60 + second - (int64_t)offset * 60;
    *out = (time_t)epoch;
    return (int64_t)*out == epoch;
}

static bool parse_new(const char* name, size_t n, backup_filename_info_t* out) {
    if (n < 29 || strcmp(name + n - 4, ".zip")) return false;
    const char* date = name + n - 29;
    if (date[4] != '-' || date[7] != '-' || date[10] != ' ' || date[13] != '.' ||
        date[16] != '.' || date[19] != ' ' || (date[20] != '+' && date[20] != '-')) return false;
    int oh = decimal(date + 21, 2), om = decimal(date + 23, 2);
    if (oh < 0 || oh > 23 || om < 0 || om > 59 ||
        !calendar_time(decimal(date, 4), decimal(date + 5, 2), decimal(date + 8, 2),
            decimal(date + 11, 2), decimal(date + 14, 2), decimal(date + 17, 2),
            (date[20] == '-' ? -1 : 1) * (oh * 60 + om), &out->created_unix)) return false;
    if (date - name < 3 || memcmp(date - 3, " - ", 3)) return false;
    const char* trigger_end = date - 3;
    const char* trigger_sep = last_separator(name, trigger_end, " - ");
    if (!trigger_sep || !copy_piece(out->trigger, sizeof(out->trigger), trigger_sep + 3, trigger_end) ||
        !canonical_trigger(out->trigger)) return false;
    const char* scope_sep = last_separator(name, trigger_sep, " - ");
    if (!scope_sep || !copy_piece(out->scope, sizeof(out->scope), scope_sep + 3, trigger_sep) ||
        strcmp(out->scope, "Full")) return false;
    const char* title_sep = last_separator(name, scope_sep, " - ");
    const char* title_begin = title_sep ? title_sep + 3 : name;
    char code[16];
    if (!copy_piece(code, sizeof(code), title_begin, scope_sep) ||
        !bare_code(code, true, out->title_id, sizeof(out->title_id))) return false;
    if (title_sep) {
        char game[512];
        if (!copy_piece(game, sizeof(game), name, title_sep) || !clean(game, out->game, sizeof(out->game))) return false;
    }
    snprintf(out->type, sizeof(out->type), "RAW");
    out->safety = !strcmp(canonical_trigger(out->trigger), "Safety");
    out->recognized = true;
    return true;
}

static bool parse_legacy(const char* name, size_t n, backup_filename_info_t* out) {
    if (n < 21 || strcmp(name + n - 4, ".zip")) return false;
    const char* date = name + n - 20;
    if (date == name || date[-1] != '_' || date[8] != 'T' || date[15] != 'Z' ||
        !calendar_time(decimal(date, 4), decimal(date + 4, 2), decimal(date + 6, 2),
            decimal(date + 9, 2), decimal(date + 11, 2), decimal(date + 13, 2), 0, &out->created_unix)) return false;
    const char* trigger_sep = last_separator(name, date - 1, "_");
    if (!trigger_sep || !copy_piece(out->trigger, sizeof(out->trigger), trigger_sep + 1, date - 1) ||
        !canonical_trigger(out->trigger)) return false;
    const char* type_sep = last_separator(name, trigger_sep, "_");
    if (!type_sep || !copy_piece(out->type, sizeof(out->type), type_sep + 1, trigger_sep)) return false;
    if (strcmp(out->type, "RAW") && strcmp(out->type, "PORTABLE") && strcmp(out->type, "MIGRATION") &&
        strcmp(out->type, "SAFETY") && strcmp(out->type, "CONVERTED")) return false;
    const char* title_sep = last_separator(name, type_sep, "_");
    char title[16];
    if (!title_sep || !copy_piece(title, sizeof(title), title_sep + 1, type_sep) ||
        !bare_code(title, true, out->title_id, sizeof(out->title_id))) return false;
    char game[512];
    if (!copy_piece(game, sizeof(game), name, title_sep)) return false;
    for (size_t i = 0; game[i]; i++) if (game[i] == '_') game[i] = ' ';
    if (!clean(game, out->game, sizeof(out->game))) return false;
    if (!strcmp(out->type, "MIGRATION")) snprintf(out->type, sizeof(out->type), "PORTABLE");
    snprintf(out->scope, sizeof(out->scope), "Full");
    out->safety = strstr(name, "_SAFETY_") != NULL;
    out->legacy = out->recognized = true;
    return true;
}

bool backup_filename_parse(const char* name, backup_filename_info_t* out) {
    if (!out) return false;
    memset(out, 0, sizeof(*out));
    if (!name || !utf8_valid(name) || strchr(name, '/') || strchr(name, '\\')) return false;
    if (parse_new(name, strlen(name), out)) return true;
    memset(out, 0, sizeof(*out));
    if (parse_legacy(name, strlen(name), out)) return true;
    memset(out, 0, sizeof(*out));
    return false;
}

static bool shrink_readable(char value[128], const char* suffix, size_t remove) {
    size_t n = strlen(value), tail = strlen(suffix);
    if (n == tail) return !strcmp(value, suffix);
    if (n < tail + 3 || strcmp(value + n - tail, suffix) ||
        memcmp(value + n - tail - 3, " - ", 3)) return false;
    size_t prefix = n - tail - 3;
    char readable[128], clipped[128];
    memcpy(readable, value, prefix); readable[prefix] = '\0';
    size_t keep = remove < prefix ? prefix - remove : 0;
    if (!clean(readable, clipped, keep + 1)) return false;
    if (clipped[0]) snprintf(value, 128, "%s - %s", clipped, suffix);
    else snprintf(value, 128, "%s", suffix);
    return true;
}

bool backup_names_limit(backup_names_t* names, size_t component_budget) {
    if (!names || !memchr(names->user_folder, '\0', sizeof(names->user_folder)) ||
        !memchr(names->title_folder, '\0', sizeof(names->title_folder)) ||
        !memchr(names->filename, '\0', sizeof(names->filename)) ||
        !memchr(names->game, '\0', sizeof(names->game)) || !utf8_valid(names->game)) return false;
    char uid[16], title[16]; backup_filename_info_t parsed;
    if (!backup_folder_code(names->user_folder, false, uid, sizeof(uid)) ||
        !backup_folder_code(names->title_folder, true, title, sizeof(title)) ||
        !backup_filename_parse(names->filename, &parsed) || parsed.legacy ||
        strcmp(parsed.title_id, title)) return false;
    char marker[96];
    int mn = snprintf(marker, sizeof(marker), "%s - Full - %s - ", title, parsed.trigger);
    if (mn <= 0 || (size_t)mn >= sizeof(marker)) return false;
    const char* suffix = NULL;
    for (const char* p = strstr(names->filename, marker); p; p = strstr(p + 1, marker)) suffix = p;
    if (!suffix) return false;
    char file_suffix[128]; snprintf(file_suffix, sizeof(file_suffix), "%s", suffix);
    // Reserve the longest canonical trigger independently of this operation's
    // trigger. User/title proposals must stay identical across all backups.
    // The fixed trailer is date(19), space(1), UTC offset(5), and .zip(4).
    size_t tail = strlen(file_suffix);
    if (tail < 29) return false;
    char maximum_suffix[128];
    int maximum = snprintf(maximum_suffix, sizeof(maximum_suffix),
                           "%s - Full - BeforeRestore - %s", title, file_suffix + tail - 29);
    if (maximum <= 0 || (size_t)maximum >= sizeof(maximum_suffix)) return false;
    size_t reserved = (size_t)maximum + (names->game[0] ? 3 + strlen(names->game) : 0);
    if (reserved > sizeof(names->filename) - 1) reserved = sizeof(names->filename) - 1;
    if (component_budget < strlen(uid) + strlen(title) + reserved) return false;
    backup_names_t candidate = *names;
    // 177 - maximum filename(127) - maximum title code(15): the user label
    // must depend only on Settings, never on the game or this backup's trigger.
    if (strlen(candidate.user_folder) > 35 &&
        !shrink_readable(candidate.user_folder, uid, strlen(candidate.user_folder) - 35)) return false;
    size_t folder_budget = component_budget - reserved;
    size_t total = strlen(candidate.user_folder) + strlen(candidate.title_folder);
    if (total > folder_budget &&
        !shrink_readable(candidate.title_folder, title, total - folder_budget)) return false;
    if (strlen(candidate.user_folder) + strlen(candidate.title_folder) > folder_budget) return false;
    size_t filename_budget = component_budget - strlen(candidate.user_folder) - strlen(candidate.title_folder);
    if (strlen(candidate.filename) > filename_budget &&
        !shrink_readable(candidate.filename, file_suffix, strlen(candidate.filename) - filename_budget)) return false;
    if (strlen(candidate.user_folder) + strlen(candidate.title_folder) +
        strlen(candidate.filename) > component_budget) return false;
    *names = candidate;
    return true;
}

bool backup_filename_safety(const char* name) {
    if (!name) return false;
    const char* basename = strrchr(name, '/');
    basename = basename ? basename + 1 : name;
    backup_filename_info_t info;
    if (backup_filename_parse(basename, &info) && !info.legacy) return info.safety;
    return strstr(basename, "_SAFETY_") != NULL;
}

static void save_names_neutralize_safety(char* label) {
    // A display label must not trigger the unchanged legacy SAFETY fallback.
    char* marker;
    while ((marker = strstr(label, "_SAFETY_")) != NULL) {
        marker[0] = '-'; marker[7] = '-';
    }
}

static bool save_names_finish(backup_names_t* names, const char* container) {
    if (!names || !container) return false;
    backup_filename_info_t full;
    if (!backup_filename_parse(names->filename, &full) || full.legacy ||
        strcmp(full.trigger, "Manual")) return false;
    size_t raw_length = strlen(container);
    if (raw_length == SIZE_MAX) return false;
    char* label = malloc(raw_length + 1);
    if (!label) return false;
    bool ok = clean(container, label, raw_length + 1);
    if (!ok) { free(label); return false; }
    save_names_neutralize_safety(label);
    char game[96]; snprintf(game, sizeof(game), "%s", names->game);
    save_names_neutralize_safety(game);
    const char* readable = label[0] ? label : "container";
    char trailer[30];
    size_t original_length = strlen(names->filename);
    if (original_length < 29) { free(label); return false; }
    memcpy(trailer, names->filename + original_length - 29, 30);
    size_t fixed = strlen(full.title_id) + strlen(" - Save -  - Manual - ") + 29;
    if (fixed >= sizeof(names->filename) - 1) { free(label); return false; }
    size_t label_budget = sizeof(names->filename) - 1 - fixed;
    char clipped_label[128], clipped_game[96];
    if (!clean(readable, clipped_label, label_budget + 1) || !clipped_label[0]) {
        free(label); return false;
    }
    // Keep the complete label before shortening it: the game is removed first.
    size_t game_budget = strlen(readable) + fixed + 3 < sizeof(names->filename)
        ? sizeof(names->filename) - 1 - fixed - strlen(readable) - 3 : 0;
    if (!clean(game, clipped_game, game_budget + 1)) { free(label); return false; }
    int written = snprintf(names->filename, sizeof(names->filename),
        "%s%s%s - Save - %s - Manual - %s", clipped_game,
        clipped_game[0] ? " - " : "", full.title_id, clipped_label, trailer);
    free(label);
    backup_filename_info_t forbidden_full;
    backup_save_filename_info_t parsed_save;
    return written > 0 && (size_t)written < sizeof(names->filename) &&
        !strstr(names->filename, "_SAFETY_") && !backup_filename_safety(names->filename) &&
        !backup_filename_parse(names->filename, &forbidden_full) &&
        backup_save_filename_parse(names->filename, &parsed_save) &&
        !strcmp(parsed_save.title_id, full.title_id);
}

bool backup_save_names_build(const char* console_name, const char* console_type,
                            const char* user_alias, const char* uid,
                            const char* title, const char* game,
                            const char* container, const char* timezone,
                            time_t now, backup_names_t* out) {
    if (!out) return false;
    backup_names_t candidate;
    if (!backup_names_build(console_name, console_type, user_alias, uid, title,
            game, "Manual", timezone, now, &candidate) ||
        !save_names_finish(&candidate, container)) {
        memset(out, 0, sizeof(*out)); return false;
    }
    *out = candidate; return true;
}

#ifndef BACKUP_NAMES_PURE_TEST
bool backup_save_names_current(const char* uid, const char* title,
                              const char* fallback, const char* container,
                              time_t now, backup_names_t* out) {
    if (!out) return false;
    backup_names_t candidate;
    if (!backup_names_current(uid, title, fallback, "Manual", now, &candidate) ||
        !save_names_finish(&candidate, container)) {
        memset(out, 0, sizeof(*out)); return false;
    }
    *out = candidate; return true;
}
#endif

bool backup_save_filename_parse(const char* name, backup_save_filename_info_t* out) {
    if (!out) return false;
    memset(out, 0, sizeof(*out));
    if (!name || !utf8_valid(name) || strchr(name, '/') || strchr(name, '\\') ||
        strstr(name, "_SAFETY_")) return false;
    size_t n = strlen(name);
    if (n > 127 || n < 29 || strcmp(name + n - 4, ".zip")) return false;
    const char* date = name + n - 29;
    if (date[4] != '-' || date[7] != '-' || date[10] != ' ' || date[13] != '.' ||
        date[16] != '.' || date[19] != ' ' || (date[20] != '+' && date[20] != '-')) return false;
    int hours = decimal(date + 21, 2), minutes = decimal(date + 23, 2);
    time_t created;
    if (hours < 0 || hours > 23 || minutes < 0 || minutes > 59 ||
        !calendar_time(decimal(date, 4), decimal(date + 5, 2), decimal(date + 8, 2),
            decimal(date + 11, 2), decimal(date + 14, 2), decimal(date + 17, 2),
            (date[20] == '-' ? -1 : 1) * (hours * 60 + minutes), &created)) return false;
    static const char manual[] = " - Manual - ";
    if (date - name < (ptrdiff_t)(sizeof(manual) - 1) ||
        memcmp(date - (sizeof(manual) - 1), manual, sizeof(manual) - 1)) return false;
    const char* label_end = date - (sizeof(manual) - 1);
    backup_save_filename_info_t candidate = {0};
    size_t matches = 0;
    for (const char* marker = strstr(name, " - Save - "); marker && marker < label_end;
            marker = strstr(marker + 1, " - Save - ")) {
        const char* title_sep = last_separator(name, marker, " - ");
        const char* title_begin = title_sep ? title_sep + 3 : name;
        char title[16], label[128], game[96] = {0};
        backup_save_filename_info_t item = {0};
        if (!copy_piece(title, sizeof(title), title_begin, marker) ||
            !bare_code(title, true, item.title_id, sizeof(item.title_id)) ||
            !copy_piece(label, sizeof(label), marker + 10, label_end) || !label[0] ||
            !clean(label, item.container, sizeof(item.container)) ||
            strcmp(label, item.container)) continue;
        if (title_sep && (!copy_piece(game, sizeof(game), name, title_sep) ||
                !clean(game, item.game, sizeof(item.game)) ||
                strcmp(game, item.game))) continue;
        if (++matches != 1) return false; // Ambiguous display fields grant no identity.
        candidate = item;
    }
    if (matches != 1) return false;
    candidate.created_unix = created;
    snprintf(candidate.trigger, sizeof(candidate.trigger), "Manual");
    candidate.recognized = true;
    *out = candidate; return true;
}
