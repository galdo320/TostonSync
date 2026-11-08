// TostónSync — backup history / audit log. See history.h.

#include "history.h"
#include "log.h"
#include "json.h"

#include <ctype.h>
#include <errno.h>
#include <limits.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>

#define HISTORY_MAX_RECORDS 300   // how many to keep / return

static const config_t* s_cfg = NULL;
static pthread_mutex_t  s_lock = PTHREAD_MUTEX_INITIALIZER;
static history_last_backup_t s_last;

static void history_path(char* out, size_t out_sz) {
    snprintf(out, out_sz, "%s/history.jsonl", s_cfg->paths.state_dir);
}

// Keep the file from growing without bound: if it has more than
// 2*HISTORY_MAX_RECORDS lines, rewrite it with only the most recent
// HISTORY_MAX_RECORDS.
static void history_trim_locked(void) {
    char path[300];
    history_path(path, sizeof(path));
    FILE* f = fopen(path, "r");
    if (!f) return;

    // Count lines.
    size_t total = 0;
    char line[2048];
    while (fgets(line, sizeof(line), f)) total++;
    if (total <= (size_t)HISTORY_MAX_RECORDS * 2) { fclose(f); return; }

    rewind(f);
    size_t skip = total - HISTORY_MAX_RECORDS;
    char tmp[320];
    snprintf(tmp, sizeof(tmp), "%s.tmp", path);
    FILE* out = fopen(tmp, "w");
    if (!out) { fclose(f); return; }
    size_t idx = 0;
    while (fgets(line, sizeof(line), f)) {
        if (idx++ < skip) continue;
        fputs(line, out);
    }
    fclose(f);
    fclose(out);
    chmod(tmp, 0600);
    if (rename(tmp, path) == 0) chmod(path, 0600);
}

static const char* history_ws(const char* p) {
    while (*p == ' ' || *p == '\t' || *p == '\r' || *p == '\n') p++;
    return p;
}

// Validate this writer's flat JSON shape before using its permissive getters.
static bool history_last_parse(const char* line, history_last_backup_t* out) {
    const char* p = history_ws(line);
    char keys[32][64], dests[64] = "";
    size_t count = 0;
    unsigned seen = 0;
    history_last_backup_t value = { .state = HISTORY_LAST_FOUND };
    snprintf(value.outcome, sizeof(value.outcome), "ok");
    if (*p++ != '{') return false;
    for (;;) {
        p = history_ws(p);
        const char* field = p;
        if (*p++ != '"' || count == 32) return false;
        size_t len = 0;
        while (*p && *p != '"') {
            if (!((*p >= 'a' && *p <= 'z') || *p == '_') || len + 1 >= sizeof(keys[0]))
                return false;
            keys[count][len++] = *p++;
        }
        keys[count][len] = 0;
        if (!len || *p++ != '"') return false;
        for (size_t i = 0; i < count; i++)
            if (!strcmp(keys[i], keys[count])) return false;
        const char* key = keys[count++];
        if (*(p = history_ws(p)) != ':') return false;
        p = history_ws(p + 1);
        const char* raw = p;
        bool string = *p == '"';
        if (string) {
            p++;
            while (*p && *p != '"') {
                if ((unsigned char)*p < 32) return false;
                if (*p == '\\') {
                    p++;
                    if (*p == 'u') {
                        for (unsigned i = 0; i < 4; i++)
                            if (!isxdigit((unsigned char)*++p)) return false;
                    } else if (!*p || !strchr("\"\\/bfnrt", *p)) return false;
                }
                p++;
            }
            if (*p++ != '"') return false;
        } else if (!strcmp(key, "canceled") || !strcmp(key, "cancel_unknown")) {
            if (!strncmp(p, "true", 4)) p += 4;
            else if (!strncmp(p, "false", 5)) p += 5;
            else return false;
        } else {
            if (*p < '0' || *p > '9') return false;
            if (*p == '0') p++;
            else while (*p >= '0' && *p <= '9') p++;
        }
        if (string && (!strcmp(key, "canceled") || !strcmp(key, "cancel_unknown")))
            return false;
        size_t raw_len = (size_t)(p - raw);
        if (!strcmp(key, "ts")) {
            if (string) return false;
            errno = 0;
            unsigned long long timestamp = strtoull(raw, NULL, 10);
            if (errno || !timestamp || timestamp > INT64_MAX) return false;
            value.when = (int64_t)timestamp;
            seen |= 1;
        } else if (!strcmp(key, "title") || !strcmp(key, "status") || !strcmp(key, "dests")) {
            char* target = !strcmp(key, "title") ? value.title :
                           !strcmp(key, "status") ? value.outcome : dests;
            size_t cap = target == value.title ? sizeof(value.title) :
                         target == value.outcome ? sizeof(value.outcome) : sizeof(dests);
            if (!string || raw_len < 2 || raw_len - 2 >= cap ||
                memchr(raw + 1, '\\', raw_len - 2) ||
                !json_get_string(field, key, target, cap)) return false;
            if (target == value.title) seen |= 2;
            if (target == dests) seen |= 4;
        }
        p = history_ws(p);
        if (*p != ',') break;
        p++;
    }
    if (*p++ != '}' || *history_ws(p) || seen != 7 || !value.title[0]) return false;
    for (size_t i = 0; value.title[i]; i++)
        if (!isalnum((unsigned char)value.title[i]) && value.title[i] != '_') return false;
    if (strcmp(value.outcome, "ok") && strcmp(value.outcome, "warning") &&
        strcmp(value.outcome, "partial") && strcmp(value.outcome, "failed")) return false;
    const char* d = dests;
    while (*d) {
        size_t n = strcspn(d, ",");
        if (!((n == 3 && (!strncmp(d, "usb", n) || !strncmp(d, "ftp", n))) ||
              (n == 5 && !strncmp(d, "drive", n)))) return false;
        d += n;
        if (*d && !*++d) return false;
    }
    if (!dests[0] && strcmp(value.outcome, "failed")) return false;
    *out = value;
    return true;
}

static void history_last_load_locked(void) {
    memset(&s_last, 0, sizeof(s_last));
    char path[300];
    history_path(path, sizeof(path));
    FILE* f = fopen(path, "r");
    if (!f) {
        if (errno != ENOENT) {
            s_last.state = HISTORY_LAST_UNREADABLE;
            s_last.error = errno;
        }
        return;
    }
    char line[2048];
    size_t used = 0, total = 0;
    bool invalid = false;
    int c;
    while ((c = fgetc(f)) != EOF) {
        if (++total > 2 * 1024 * 1024) {
            memset(&s_last, 0, sizeof(s_last));
            s_last.state = HISTORY_LAST_CORRUPT;
            break;
        }
        if (c != '\n') {
            if (!c || used + 1 >= sizeof(line)) invalid = true;
            else line[used++] = (char)c;
            continue;
        }
        line[used] = 0;
        if (invalid || *history_ws(line)) {
            memset(&s_last, 0, sizeof(s_last));
            if (invalid || !history_last_parse(line, &s_last))
                s_last.state = HISTORY_LAST_CORRUPT;
        }
        used = 0;
        invalid = false;
    }
    if (used || invalid) {
        memset(&s_last, 0, sizeof(s_last));
        s_last.state = HISTORY_LAST_CORRUPT;
    }
    int error = ferror(f) ? (errno ? errno : EIO) : 0;
    if (fclose(f) != 0 && !error) error = errno ? errno : EIO;
    if (error) {
        memset(&s_last, 0, sizeof(s_last));
        s_last.state = HISTORY_LAST_UNREADABLE;
        s_last.error = error;
    }
}

void history_last_backup(history_last_backup_t* out) {
    if (!out) return;
    pthread_mutex_lock(&s_lock);
    *out = s_last;
    pthread_mutex_unlock(&s_lock);
}

void history_init(const config_t* cfg) {
    s_cfg = cfg;
    pthread_mutex_lock(&s_lock);
    history_trim_locked();
    history_last_load_locked();
    pthread_mutex_unlock(&s_lock);
}

// Escape a string for embedding in a JSON value (quotes, backslashes,
// control chars). The game name comes from a game's param.json/sfo and
// can contain anything, so it must be escaped.
static void json_escape(const char* in, char* out, size_t out_sz) {
    size_t j = 0;
    for (size_t i = 0; in && in[i] && j + 2 < out_sz; i++) {
        unsigned char c = (unsigned char)in[i];
        if (c == '"' || c == '\\') { out[j++] = '\\'; out[j++] = (char)c; }
        else if (c == '\n') { out[j++] = '\\'; if (j+1<out_sz) out[j++]='n'; }
        else if (c == '\r') { out[j++] = '\\'; if (j+1<out_sz) out[j++]='r'; }
        else if (c == '\t') { out[j++] = '\\'; if (j+1<out_sz) out[j++]='t'; }
        else if (c < 0x20)  { /* drop other control chars */ }
        else out[j++] = (char)c;
    }
    out[j] = '\0';
}

void history_record(const char* user_alias,
                    const char* title_id, const char* game,
                    const char* filename, const char* backup_type,
                    const char* trigger, uint64_t size_bytes,
                    uint32_t crc, const char* dests,
                    const history_meta_t* meta) {
    if (!s_cfg || !title_id || !filename) return;
    char path[300];
    history_path(path, sizeof(path));

    char game_esc[160];
    json_escape(game ? game : "", game_esc, sizeof(game_esc));

    // user_alias is config-controlled (UID or friendly name) — escape
    // it just like the game name so a tampered config can't break the
    // JSON line.
    char user_esc[64];
    json_escape(user_alias ? user_alias : "default", user_esc, sizeof(user_esc));

    char name_esc[192], type_esc[32], trigger_esc[32], dests_esc[96];
    char raw_esc[48], missing_esc[160], status_esc[24], failed_esc[96], canceled_esc[96];
    json_escape(filename, name_esc, sizeof(name_esc));
    json_escape(backup_type ? backup_type : "RAW", type_esc, sizeof(type_esc));
    json_escape(trigger ? trigger : "Auto", trigger_esc, sizeof(trigger_esc));
    json_escape(dests ? dests : "", dests_esc, sizeof(dests_esc));
    json_escape(meta ? meta->raw_completeness : "", raw_esc, sizeof(raw_esc));
    json_escape(meta ? meta->first_missing_service_image : "",
                missing_esc, sizeof(missing_esc));
    json_escape(meta && meta->status[0] ? meta->status : "ok",
                status_esc, sizeof(status_esc));
    json_escape(meta ? meta->failed_dests : "", failed_esc, sizeof(failed_esc));

    json_escape(meta ? meta->canceled_dests : "",canceled_esc,sizeof(canceled_esc));
    pthread_mutex_lock(&s_lock);
    FILE* f = fopen(path, "a");
    if (f) {
        fprintf(f,
            "{\"ts\":%lld,\"user\":\"%s\","
            "\"title\":\"%s\",\"game\":\"%s\",\"name\":\"%s\","
            "\"type\":\"%s\",\"trigger\":\"%s\","
            "\"size\":%llu,\"crc\":\"%08x\",\"dests\":\"%s\","
            "\"status\":\"%s\",\"failed_dests\":\"%s\","
            "\"canceled\":%s,\"cancel_unknown\":%s,\"canceled_dests\":\"%s\","
            "\"raw_completeness\":\"%s\",\"active_images\":%zu,"
            "\"service_images\":%zu,\"missing_service_images\":%zu,"
            "\"first_missing_service_image\":\"%s\"}\n",
            (long long)time(NULL), user_esc,
            title_id, game_esc, name_esc, type_esc, trigger_esc,
            (unsigned long long)size_bytes, crc, dests_esc,
            status_esc, failed_esc, meta&&meta->canceled?"true":"false",meta&&meta->cancel_unknown?"true":"false",canceled_esc,raw_esc,
            meta ? meta->active_images : 0,
            meta ? meta->service_images : 0,
            meta ? meta->missing_service_images : 0,
            missing_esc);
        fclose(f);
        chmod(path, 0600);
    }
    pthread_mutex_unlock(&s_lock);
}

size_t history_to_json(char* out, size_t out_sz) {
    if (!out || out_sz < 16) return 0;
    char path[300];
    history_path(path, sizeof(path));

    // Load the last HISTORY_MAX_RECORDS lines into a ring buffer.
    // Must be a local (not static): the HTTP server calls this from a
    // per-connection thread, so two concurrent /api/history requests
    // would otherwise share — and double-free — the same array.
    char* ring[HISTORY_MAX_RECORDS] = {0};
    size_t count = 0, head = 0;

    pthread_mutex_lock(&s_lock);
    FILE* f = fopen(path, "r");
    if (f) {
        char line[2048];
        while (fgets(line, sizeof(line), f)) {
            size_t L = strlen(line);
            while (L && (line[L-1] == '\n' || line[L-1] == '\r')) line[--L] = '\0';
            if (!L) continue;
            if (ring[head]) free(ring[head]);
            ring[head] = strdup(line);
            head = (head + 1) % HISTORY_MAX_RECORDS;
            if (count < HISTORY_MAX_RECORDS) count++;
        }
        fclose(f);
    }
    pthread_mutex_unlock(&s_lock);

    char* p = out;
    char* end = out + out_sz;
    p += snprintf(p, end - p, "{\"items\":[");
    // Emit newest first. The newest is at (head-1); walk backwards.
    for (size_t i = 0; i < count; i++) {
        size_t idx = (head + HISTORY_MAX_RECORDS - 1 - i) % HISTORY_MAX_RECORDS;
        if (!ring[idx]) continue;
        int w = snprintf(p, end - p, "%s%s", i ? "," : "", ring[idx]);
        if (w < 0 || p + w >= end) break;   // out of room; stop cleanly
        p += w;
    }
    // Free the ring.
    for (size_t i = 0; i < HISTORY_MAX_RECORDS; i++) {
        if (ring[i]) { free(ring[i]); ring[i] = NULL; }
    }
    if (p < end - 2) { *p++ = ']'; *p++ = '}'; *p = '\0'; }
    else { out[out_sz - 3] = ']'; out[out_sz - 2] = '}'; out[out_sz - 1] = '\0'; }
    return (size_t)(p - out);
}
