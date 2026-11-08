// TostónSync — tiny JSON reader.
//
// Not a real parser. Scans for "<key>": <value> pairs and extracts the
// value as a string or number. Sufficient for the known response shapes
// from Google Drive and OAuth endpoints.

#include "json.h"
#include "gdrive.h"

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Skip whitespace.
static const char* skip_ws(const char* s) {
    while (s && *s && (*s == ' ' || *s == '\t' || *s == '\n' || *s == '\r')) s++;
    return s;
}

// Find the first occurrence of "key" (as a JSON key, i.e. inside double
// quotes followed by ':'). Returns a pointer past the ':' or NULL.
//
// `start` is the original buffer base, used to bound the s[-1] read so
// we never underflow when the match happens at offset 0.
static const char* find_key(const char* s, const char* key) {
    if (!s || !key) return NULL;
    const char* start = s;
    size_t klen = strlen(key);
    while ((s = strstr(s, key)) != NULL) {
        // Must be inside quotes: a `"` immediately before the key
        // (and we need at least one char of headroom for s[-1]) and a
        // `"` immediately after.
        if (s > start && s[-1] == '"' && s[klen] == '"') {
            const char* p = s + klen + 1;
            p = skip_ws(p);
            if (*p == ':') return skip_ws(p + 1);
        }
        s += klen;
    }
    return NULL;
}

bool json_get_string(const char* json, const char* key,
                     char* out, size_t out_sz) {
    if (!out || out_sz == 0) return false;
    out[0] = '\0';
    const char* p = find_key(json, key);
    if (!p || *p != '"') return false;
    p++;
    size_t i = 0;
    while (*p && *p != '"' && i + 1 < out_sz) {
        if (*p == '\\' && p[1]) {
            switch (p[1]) {
                case 'n': out[i++] = '\n'; break;
                case 't': out[i++] = '\t'; break;
                case 'r': out[i++] = '\r'; break;
                case '"': out[i++] = '"';  break;
                case '\\': out[i++] = '\\'; break;
                case '/': out[i++] = '/'; break;
                default:  out[i++] = p[1]; break;
            }
            p += 2;
        } else {
            out[i++] = *p++;
        }
    }
    out[i] = '\0';
    return true;
}

double json_get_number(const char* json, const char* key) {
    const char* p = find_key(json, key);
    if (!p) return 0;
    // Drive returns large integers as quoted strings (e.g. "15000000000").
    if (*p == '"') p++;
    return strtod(p, NULL);
}

bool json_get_first_array_string(const char* json, const char* arr_key,
                                 const char* field,
                                 char* out, size_t out_sz) {
    const char* p = find_key(json, arr_key);
    if (!p || *p != '[') return false;
    p = strchr(p, '{');
    if (!p) return false;
    return json_get_string(p, field, out, out_sz);
}

size_t json_parse_versions(const char* json,
                           gdrive_version_t* out, size_t max_out) {
    const char* p = strstr(json, "\"files\"");
    if (!p) return 0;
    p = strchr(p, '[');
    if (!p) return 0;

    size_t n = 0;
    while (n < max_out) {
        const char* obj = strchr(p, '{');
        if (!obj) break;
        const char* end = strchr(obj, '}');
        if (!end) break;

        // Carve the object into a temp NUL-terminated buffer so the
        // key-finder doesn't run past it.
        size_t olen = (size_t)(end - obj + 1);
        char   tmp[2048];
        if (olen >= sizeof(tmp)) { p = end + 1; continue; }
        memcpy(tmp, obj, olen); tmp[olen] = '\0';

        gdrive_version_t* v = &out[n];
        memset(v, 0, sizeof(*v));
        json_get_string(tmp, "id",   v->file_id, sizeof(v->file_id));
        json_get_string(tmp, "name", v->name,    sizeof(v->name));
        v->size_bytes = (uint64_t)json_get_number(tmp, "size");

        // createdTime is ISO 8601: 2026-06-10T20:45:00.000Z
        char ts[40] = {0};
        json_get_string(tmp, "createdTime", ts, sizeof(ts));
        if (ts[0]) {
            int Y, M, D, h, m, s;
            if (sscanf(ts, "%d-%d-%dT%d:%d:%d", &Y, &M, &D, &h, &m, &s) == 6) {
                // Lightweight UTC conversion (no DST).
                static const int mday[] = {31,28,31,30,31,30,31,31,30,31,30,31};
                int64_t days = 0;
                for (int y = 1970; y < Y; y++)
                    days += ((y % 4 == 0 && y % 100 != 0) || y % 400 == 0) ? 366 : 365;
                for (int mi = 0; mi < M - 1; mi++) days += mday[mi];
                if (M > 2 && ((Y % 4 == 0 && Y % 100 != 0) || Y % 400 == 0)) days++;
                days += D - 1;
                v->created_unix = days * 86400 + h * 3600 + m * 60 + s;
            }
        }
        if (v->file_id[0]) n++;
        p = end + 1;
    }
    return n;
}
