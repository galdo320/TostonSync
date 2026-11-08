#include "public_metadata.h"
#include "config.h"
#include "fs.h"
#include "http_client.h"
#include "titlename.h"
#include "title_catalog.h"
#include "public_artwork.h"

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <limits.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#define PUBLIC_HTML_LIMIT (512 * 1024)
#define PUBLIC_RETRY_SECONDS 86400
#define CACHE_LIMIT 2048
#define PATH_LIMIT 400
#define PUBLIC_TRUST_POLICY "public-roots-v2"

// ponytail: one in-flight public lookup globally; per-title locks only if
// explicit lookup throughput ever warrants them. Offline readers never wait.
static pthread_mutex_t s_lookup_lock = PTHREAD_MUTEX_INITIALIZER;

static bool valid_id(const char* id) {
    if (!id || strlen(id) != 9 || strncmp(id, "PPSA", 4)) return false;
    for (size_t i = 4; i < 9; i++) if (id[i] < '0' || id[i] > '9') return false;
    return true;
}

static bool init_result(const char* id, public_metadata_t* out) {
    if (!out) return false;
    memset(out, 0, sizeof(*out));
    strcpy(out->status, "unavailable");
    strcpy(out->reason, "none");
    strcpy(out->cache_state, "miss");
    if (!valid_id(id)) { strcpy(out->reason, "invalid_title_id"); return false; }
    strcpy(out->title_id, id);
    strcpy(out->source, "ProsperoPatches");
    snprintf(out->source_url, sizeof(out->source_url),
             "https://prosperopatches.com/%s", id);
    return true;
}

static bool content_matches(const char* content, const char* id) {
    if (strlen(content) != 36 || content[6] != '-' ||
        strncmp(content + 7, id, 9) || strncmp(content + 16, "_00-", 4)) return false;
    for (size_t i = 0; i < 2; i++) if (content[i] < 'A' || content[i] > 'Z') return false;
    for (size_t i = 2; i < 6; i++) if (content[i] < '0' || content[i] > '9') return false;
    for (size_t i = 20; i < 36; i++)
        if (!((content[i] >= 'A' && content[i] <= 'Z') ||
              (content[i] >= '0' && content[i] <= '9'))) return false;
    return true;
}

static bool plain_utf8(const char* s, bool allow_empty) {
    size_t len = strlen(s);
    if (!allow_empty && !len) return false;
    char copy[256];
    if (len >= sizeof(copy) || titlename_copy_utf8(copy, sizeof(copy), s) != len) return false;
    for (const unsigned char* p = (const unsigned char*)s; *p; p++)
        if (*p < 0x20 || *p == 0x7f || *p == '<' || *p == '>') return false;
    return true;
}

static bool valid_region(const char* region) {
    size_t n = strlen(region);
    if (n < 2 || n > 12) return false;
    for (size_t i = 0; i < n; i++) if (region[i] < 'A' || region[i] > 'Z') return false;
    return true;
}

static const char* find_ci(const char* s, const char* needle) {
    size_t n = strlen(needle);
    for (; *s; s++) if (!strncasecmp(s, needle, n)) return s;
    return NULL;
}

static const char* markup_end(const char* p) {
    char quote = 0;
    for (; *p; p++) {
        if (quote) { if (*p == quote) quote = 0; }
        else if (*p == '\'' || *p == '"') quote = *p;
        else if (*p == '>') return p;
    }
    return NULL;
}

static bool tag_name(const char* p, const char* name) {
    size_t n = strlen(name);
    if (strncasecmp(p + 1, name, n)) return false;
    return p[n + 1] == '>' || isspace((unsigned char)p[n + 1]);
}

static const char* tag_before(const char* start, const char* name, const char* limit) {
    const char* p = start;
    while ((!limit || p < limit) &&
           (p = limit ? memchr(p, '<', (size_t)(limit - p)) : strchr(p, '<'))) {
        // Server-rendered values only: examples in comments, JS, styles or
        // quoted attributes are not metadata and cannot satisfy the parser.
        if (!strncmp(p, "<!--", 4)) {
            const char* end = strstr(p + 4, "-->");
            if (!end || (limit && end >= limit)) return NULL;
            p = end + 3; continue;
        }
        const char* end = markup_end(p);
        if (!end || (limit && end >= limit)) return NULL;
        if (tag_name(p, "script") || tag_name(p, "style")) {
            const char* close = find_ci(end + 1, tag_name(p, "script") ? "</script" : "</style");
            end = close ? markup_end(close) : NULL;
            if (!end || (limit && end >= limit)) return NULL;
        } else if (tag_name(p, name)) return p;
        p = end + 1;
    }
    return NULL;
}

static const char* tag(const char* start, const char* name) {
    return tag_before(start, name, NULL);
}

static bool append_scalar(char* out, size_t cap, size_t* n, uint32_t cp) {
    if (!cp || cp > 0x10ffff || (cp >= 0xd800 && cp <= 0xdfff)) return false;
    unsigned char bytes[4]; size_t count;
    if (cp < 0x80) { bytes[0] = (unsigned char)cp; count = 1; }
    else if (cp < 0x800) { bytes[0] = 0xc0 | (cp >> 6); bytes[1] = 0x80 | (cp & 63); count = 2; }
    else if (cp < 0x10000) {
        bytes[0] = 0xe0 | (cp >> 12); bytes[1] = 0x80 | ((cp >> 6) & 63);
        bytes[2] = 0x80 | (cp & 63); count = 3;
    } else {
        bytes[0] = 0xf0 | (cp >> 18); bytes[1] = 0x80 | ((cp >> 12) & 63);
        bytes[2] = 0x80 | ((cp >> 6) & 63); bytes[3] = 0x80 | (cp & 63); count = 4;
    }
    if (*n + count >= cap) return false;
    memcpy(out + *n, bytes, count); *n += count; return true;
}

// No markup is accepted within a value, even if encoded as &lt;script&gt;.
static bool decode(const char* p, const char* end, char* out, size_t cap) {
    while (p < end && isspace((unsigned char)*p)) p++;
    while (end > p && isspace((unsigned char)end[-1])) end--;
    size_t n = 0;
    while (p < end) {
        if (*p == '<' || *p == '>') return false;
        if (*p != '&') {
            if (n + 1 >= cap) return false;
            out[n++] = *p++; continue;
        }
        const char* semi = memchr(p, ';', (size_t)(end - p));
        if (!semi || semi - p > 12) return false;
        uint32_t cp = 0;
        size_t entity_len = (size_t)(semi - p + 1);
        const struct { const char* text; uint32_t cp; } entities[] = {
            {"&amp;", '&'}, {"&quot;", '"'}, {"&apos;", '\''}, {"&reg;", 0xae},
            {"&trade;", 0x2122}, {"&nbsp;", ' '}, {"&lt;", '<'}, {"&gt;", '>'}
        };
        if (p + 1 < semi && p[1] == '#') {
            const char* q = p + 2; unsigned base = 10;
            if (q < semi && (*q == 'x' || *q == 'X')) { base = 16; q++; }
            if (q == semi) return false;
            for (; q < semi; q++) {
                unsigned digit;
                if (*q >= '0' && *q <= '9') digit = (unsigned)(*q - '0');
                else if (*q >= 'a' && *q <= 'f') digit = (unsigned)(*q - 'a' + 10);
                else if (*q >= 'A' && *q <= 'F') digit = (unsigned)(*q - 'A' + 10);
                else return false;
                if (digit >= base || cp > (0x10ffff - digit) / base) return false;
                cp = cp * base + digit;
            }
        } else {
            for (size_t i = 0; i < sizeof(entities) / sizeof(entities[0]); i++)
                if (strlen(entities[i].text) == entity_len &&
                    !memcmp(p, entities[i].text, entity_len)) cp = entities[i].cp;
        }
        if (!append_scalar(out, cap, &n, cp)) return false;
        p = semi + 1;
    }
    out[n] = '\0';
    return plain_utf8(out, false);
}

static bool field(const char* html, const char* label, char* out, size_t cap, bool required) {
    const char* p = html; bool found = false;
    while ((p = tag(p, "li"))) {
        const char* end = tag(p, "/li");
        if (!end) return false;
        const char* strong = tag_before(p, "strong", end);
        if (strong && strong < end) {
            const char* begin = markup_end(strong);
            const char* close = tag(strong, "/strong");
            if (!begin || !close || close > end) return false;
            const char* label_end = memchr(begin + 1, '<', (size_t)(close - begin - 1));
            if (!label_end) label_end = close;
            char text[48];
            if (decode(begin + 1, label_end, text, sizeof(text)) && !strcmp(text, label)) {
                const char* value = markup_end(close);
                if (found || !value || value >= end || !decode(value + 1, end, out, cap)) return false;
                found = true;
            }
        }
        p = end + 1;
    }
    return found || !required;
}

// Attribute values only, not scripts/styles/examples. Quoted HTML used by
// the public page; unknown syntax supplies no artwork, not guessed URLs.
static bool attribute(const char* tag_start, const char* key, char* out, size_t cap) {
    const char* end = markup_end(tag_start);
    if (!end) return false;
    const char* p = tag_start + 1;
    while (p < end && !isspace((unsigned char)*p)) p++;
    bool found = false;
    while (p < end) {
        while (p < end && isspace((unsigned char)*p)) p++;
        const char* name = p;
        while (p < end && (isalnum((unsigned char)*p) || *p == '-' || *p == ':')) p++;
        size_t len = (size_t)(p - name);
        if (!len) break;
        while (p < end && isspace((unsigned char)*p)) p++;
        if (p == end || *p++ != '=') return false;
        while (p < end && isspace((unsigned char)*p)) p++;
        if (p == end || (*p != '\'' && *p != '"')) return false;
        char quote = *p++;
        const char* value = p;
        while (p < end && *p != quote) p++;
        if (p == end) return false;
        if (len == strlen(key) && !strncasecmp(name, key, len)) {
            if (found || !decode(value, p, out, cap)) return false;
            found = true;
        }
        p++;
    }
    return found;
}

static void announced_artwork(const char* id, const char* html, char* out, size_t cap) {
    const char* p = html;
    while ((p = tag(p, "meta"))) {
        char key[48], url[256];
        bool image = (attribute(p, "name", key, sizeof(key)) && !strcmp(key, "twitter:image")) ||
                     (attribute(p, "property", key, sizeof(key)) && !strcmp(key, "og:image"));
        if (image && attribute(p, "content", url, sizeof(url))) {
            if (!public_artwork_valid_url(id, url) || (out[0] && strcmp(out, url))) {
                out[0] = '\0'; return;
            }
            snprintf(out, cap, "%s", url);
        }
        p = markup_end(p) + 1;
    }
}

bool public_metadata_parse(const char* id, const char* html, public_metadata_t* out) {
    if (!init_result(id, out) || !html || strnlen(html, PUBLIC_HTML_LIMIT + 1) > PUBLIC_HTML_LIMIT)
        return false;
    if (find_ci(html, "cf-chl-") || find_ci(html, "challenge-platform") ||
        find_ci(html, "Just a moment...") || find_ci(html, "Attention Required!")) return false;
    const char* h1 = tag(html, "h1");
    const char* begin = h1 ? markup_end(h1) : NULL;
    const char* end = h1 ? tag(h1, "/h1") : NULL;
    public_metadata_t parsed = *out; char observed_id[16];
    if (!begin || !end || begin >= end || tag(h1 + 1, "h1") ||
        !decode(begin + 1, end, parsed.name, sizeof(parsed.name)) || !strcmp(parsed.name, id) ||
        !field(html, "Title ID", observed_id, sizeof(observed_id), true) || strcmp(observed_id, id) ||
        !field(html, "Content ID", parsed.content_id, sizeof(parsed.content_id), true) ||
        !content_matches(parsed.content_id, id) ||
        !field(html, "Region", parsed.region, sizeof(parsed.region), false) ||
        (parsed.region[0] && !valid_region(parsed.region))) return false;
    strcpy(parsed.status, "available");
    announced_artwork(id, html, parsed.artwork_url, sizeof(parsed.artwork_url));
    time_t now = time(NULL); parsed.checked_unix = now > 0 ? (int64_t)now : 0;
    *out = parsed; return true;
}

static bool cache_path(const char* id, char* out, size_t cap) {
    const config_t* cfg = config_get();
    const char* state = cfg && cfg->paths.state_dir[0] ? cfg->paths.state_dir : "/data/tostonsync";
    int n = snprintf(out, cap, "%s/metadata/%s/public.json", state, id);
    if (n <= 0 || (size_t)n >= cap) { errno = ENAMETOOLONG; return false; }
    return true;
}

static bool cache_dirs_safe(const char* path, bool allow_missing) {
    char dir[PATH_LIMIT]; strcpy(dir, path); *strrchr(dir, '/') = '\0';
    // The configured state root may be relocated, but metadata and title
    // subdirectories must not redirect cache operations through symlinks.
    for (int i = 0; i < 2; i++) {
        struct stat st;
        if (lstat(dir, &st)) {
            if (!allow_missing || errno != ENOENT) return false;
        } else if (!S_ISDIR(st.st_mode)) { errno = ENOTDIR; return false; }
        *strrchr(dir, '/') = '\0';
    }
    return true;
}

static void skip_ws(const char** p) { while (isspace((unsigned char)**p)) (*p)++; }
static bool literal(const char** p, const char* text) {
    skip_ws(p); size_t n = strlen(text);
    if (strncmp(*p, text, n)) return false;
    *p += n; return true;
}

// Only the canonical flat JSON written below is accepted; no truncation,
// duplicate keys, missing delimiters, unrelated nested values or extra fields.
static bool cache_string(const char** p, const char* key, char* out, size_t cap) {
    char prefix[64]; snprintf(prefix, sizeof(prefix), "\"%s\":", key);
    if (!literal(p, prefix) || !literal(p, "\"")) return false;
    size_t n = 0;
    while (**p && **p != '"') {
        unsigned char c = (unsigned char)*(*p)++;
        if (c == '\\') {
            c = (unsigned char)*(*p)++;
            if (c != '\\' && c != '"') return false;
        }
        if (c < 0x20 || n + 1 >= cap) return false;
        out[n++] = (char)c;
    }
    if (**p != '"') return false;
    (*p)++; out[n] = '\0'; return true;
}

static bool cache_integer(const char** p, const char* key, int64_t* out, bool signed_value) {
    char prefix[64]; snprintf(prefix, sizeof(prefix), "\"%s\":", key);
    if (!literal(p, prefix)) return false;
    skip_ws(p);
    if ((**p < '0' || **p > '9') && !(signed_value && **p == '-')) return false;
    errno = 0; char* end;
    long long n = strtoll(*p, &end, 10);
    if (errno || end == *p || (!signed_value && n < 0)) return false;
    *p = end; *out = (int64_t)n; return true;
}

static bool cache_number(const char** p, const char* key, int64_t* out) {
    return cache_integer(p, key, out, false);
}

static bool cache_code(const char** p, const char* key, int* out) {
    int64_t value;
    if (!cache_integer(p, key, &value, true) || value < INT_MIN || value > INT_MAX) return false;
    *out = (int)value; return true;
}

static bool cache_ssl_detail(const char** p, unsigned long* out) {
    char text[32];
    if (!cache_string(p, "ssl_detail", text, sizeof(text)) ||
        strncmp(text, "0x", 2) || !text[2]) return false;
    for (const char* q = text + 2; *q; q++) if (!isxdigit((unsigned char)*q)) return false;
    errno = 0; char* end;
    *out = strtoul(text + 2, &end, 16);
    return !errno && !*end;
}

static bool cache_failure(public_metadata_t* out, const char* state, int error) {
    strcpy(out->reason, "cache_error");
    snprintf(out->cache_state, sizeof(out->cache_state), "%s", state);
    out->cache_errno = error;
    return false;
}

static bool read_cache(const char* id, public_metadata_t* out) {
    char path[PATH_LIMIT], body[CACHE_LIMIT + 1];
    if (!cache_path(id, path, sizeof(path)) || !cache_dirs_safe(path, false))
        return errno == ENOENT ? false : cache_failure(out, "read_error", errno);
    int fd = open(path, O_RDONLY | O_NOFOLLOW);
    if (fd < 0) return errno == ENOENT ? false : cache_failure(out, "read_error", errno);
    struct stat st;
    int error = fstat(fd, &st) ? errno : 0;
    if (!error && (!S_ISREG(st.st_mode) || st.st_size <= 0 || st.st_size > CACHE_LIMIT))
        error = EINVAL;
    bool ok = !error;
    ssize_t n = ok ? read(fd, body, sizeof(body) - 1) : -1;
    if (ok && n != st.st_size) error = n < 0 ? errno : EIO;
    if (close(fd) && !error) error = errno;
    if (error) return cache_failure(out, "read_error", error);
    if (memchr(body, '\0', (size_t)n)) return cache_failure(out, "corrupt", EINVAL);
    body[n] = '\0'; const char* p = body; public_metadata_t cached;
    char trust_policy[48] = "";
    memset(&cached, 0, sizeof(cached));
    if (!literal(&p, "{") ||
        !cache_string(&p, "title_id", cached.title_id, sizeof(cached.title_id)) || !literal(&p, ",") ||
        !cache_string(&p, "name", cached.name, sizeof(cached.name)) || !literal(&p, ",") ||
        !cache_string(&p, "region", cached.region, sizeof(cached.region)) || !literal(&p, ",") ||
        !cache_string(&p, "content_id", cached.content_id, sizeof(cached.content_id)) || !literal(&p, ",") ||
        !cache_string(&p, "source_url", cached.source_url, sizeof(cached.source_url)) || !literal(&p, ",") ||
        !cache_string(&p, "status", cached.status, sizeof(cached.status)) || !literal(&p, ",") ||
        !cache_number(&p, "checked_unix", &cached.checked_unix) || !literal(&p, ",") ||
        !cache_number(&p, "retry_after_unix", &cached.retry_after_unix)) goto corrupt;
    skip_ws(&p);
    bool legacy = *p == '}';
    if (legacy) {
        strcpy(cached.reason, !strcmp(cached.status, "available") ? "none" : "previous_failure_unknown");
    } else if (!literal(&p, ",") ||
        !cache_string(&p, "reason", cached.reason, sizeof(cached.reason)) || !literal(&p, ",") ||
        !cache_code(&p, "http_status", &cached.http_status) || !literal(&p, ",") ||
        !cache_code(&p, "transport_error", &cached.transport_error) || !literal(&p, ",") ||
        !cache_code(&p, "ssl_error", &cached.ssl_error) || !literal(&p, ",") ||
        !cache_ssl_detail(&p, &cached.ssl_detail)) goto corrupt;
    skip_ws(&p);
    if (*p == ',' && (!literal(&p, ",") ||
        !cache_string(&p, "artwork_url", cached.artwork_url, sizeof(cached.artwork_url)))) goto corrupt;
    skip_ws(&p);
    if (*p == ',' && (!literal(&p, ",") ||
        !cache_string(&p, "trust_policy", trust_policy, sizeof(trust_policy)))) goto corrupt;
    if (!literal(&p, "}")) goto corrupt;
    skip_ws(&p);
    if (*p || strcmp(cached.title_id, id) || strcmp(cached.source_url, out->source_url) ||
        !plain_utf8(cached.name, true) ||
        (cached.artwork_url[0] && !public_artwork_valid_url(id, cached.artwork_url))) goto corrupt;
    if (!strcmp(cached.status, "available")) {
        if (!cached.name[0] || !strcmp(cached.name, id) || (cached.region[0] && !valid_region(cached.region)) ||
            !content_matches(cached.content_id, id)) goto corrupt;
        if (!strcmp(cached.reason, "none")) {
            if (cached.retry_after_unix) goto corrupt;
        } else if (cached.artwork_url[0] || cached.checked_unix > INT64_MAX - PUBLIC_RETRY_SECONDS ||
                   cached.retry_after_unix != cached.checked_unix + PUBLIC_RETRY_SECONDS) goto corrupt;
    } else if (strcmp(cached.status, "unavailable") || cached.name[0] || cached.region[0] ||
               cached.content_id[0] || cached.checked_unix > INT64_MAX - PUBLIC_RETRY_SECONDS ||
               cached.retry_after_unix != cached.checked_unix + PUBLIC_RETRY_SECONDS) goto corrupt;
    if (strcmp(cached.reason, "none") && strcmp(cached.reason, "previous_failure_unknown") &&
        strcmp(cached.reason, "refresh_pending") &&
        strcmp(cached.reason, "transport_error") && strcmp(cached.reason, "tls_error") &&
        strcmp(cached.reason, "http_status") && strcmp(cached.reason, "page_unrecognized")) goto corrupt;
    if (!strcmp(cached.status, "unavailable") && !strcmp(cached.reason, "none")) goto corrupt;
    strcpy(cached.cache_state, legacy ? "legacy" : "hit");
    if (!strcmp(cached.status, "unavailable") && !strcmp(cached.reason, "tls_error") &&
        strcmp(trust_policy, PUBLIC_TRUST_POLICY)) strcpy(cached.cache_state, "old_tls_policy");
    strcpy(cached.source, "ProsperoPatches");
    cached.cached = true;
    *out = cached; return true;
corrupt:
    return cache_failure(out, "corrupt", EINVAL);
}

static void write_string(FILE* f, const char* text) {
    fputc('"', f);
    for (const char* p = text; *p; p++) {
        if (*p == '"' || *p == '\\') fputc('\\', f);
        fputc(*p, f);
    }
    fputc('"', f);
}

static bool write_cache(const public_metadata_t* data) {
    char path[PATH_LIMIT], tmp[PATH_LIMIT + 8], dir[PATH_LIMIT];
    if (!cache_path(data->title_id, path, sizeof(path)) || !cache_dirs_safe(path, true)) return false;
    strcpy(dir, path); *strrchr(dir, '/') = '\0';
    if (!fs_mkdir_p(dir) || !cache_dirs_safe(path, false)) return false;
    snprintf(tmp, sizeof(tmp), "%s.tmp", path);
    int fd = open(tmp, O_WRONLY | O_CREAT | O_TRUNC | O_NOFOLLOW, 0600);
    if (fd < 0) return false;
    FILE* f = fdopen(fd, "wb");
    if (!f) { int error = errno; close(fd); remove(tmp); errno = error; return false; }
    const char* keys[] = {"title_id", "name", "region", "content_id", "source_url", "status"};
    const char* values[] = {data->title_id, data->name, data->region, data->content_id, data->source_url, data->status};
    fputc('{', f);
    for (size_t i = 0; i < 6; i++) {
        if (i) fputc(',', f);
        fprintf(f, "\"%s\":", keys[i]); write_string(f, values[i]);
    }
    fprintf(f, ",\"checked_unix\":%" PRId64 ",\"retry_after_unix\":%" PRId64 ",\"reason\":",
            data->checked_unix, data->retry_after_unix);
    write_string(f, data->reason);
    fprintf(f, ",\"http_status\":%d,\"transport_error\":%d,\"ssl_error\":%d,\"ssl_detail\":\"0x%lx\",\"artwork_url\":",
            data->http_status, data->transport_error, data->ssl_error, data->ssl_detail);
    write_string(f, data->artwork_url); fputs(",\"trust_policy\":", f);
    write_string(f, PUBLIC_TRUST_POLICY); fputs("}\n", f);
    bool ok = !ferror(f) && !fflush(f) && !fsync(fd);
    int error = ok ? 0 : (errno ? errno : EIO);
    if (fclose(f)) { if (!error) error = errno; ok = false; }
    if (ok && !rename(tmp, path)) return true;
    if (!error) error = errno;
    remove(tmp); errno = error ? error : EIO; return false;
}

static bool prospero_cached(const char* id, public_metadata_t* out) {
    if (!init_result(id, out)) return false;
    return read_cache(id, out) && !strcmp(out->status, "available");
}

bool public_metadata_cached(const char* id, public_metadata_t* out) {
    if (!init_result(id, out)) return false;
    if (title_catalog_lookup(id, out)) return true;
    return prospero_cached(id, out);
}

static bool obsolete_failure(const public_metadata_t* data) {
    return !strcmp(data->status, "unavailable") &&
           (!strcmp(data->reason, "previous_failure_unknown") ||
            !strcmp(data->cache_state, "old_tls_policy"));
}

bool public_metadata_lookup(const char* id, public_metadata_t* out) {
    if (!init_result(id, out)) return false;
    int64_t now = (int64_t)time(NULL); if (now < 0) now = 0;
    bool hit = prospero_cached(id, out);
    if (hit && (out->artwork_url[0] || now < out->checked_unix || now - out->checked_unix < PUBLIC_RETRY_SECONDS)) return true;
    // Unknown legacy failures and failures under old TLS trust can be replaced
    // once, not on every release. All current failures retain normal backoff.
    if (out->retry_after_unix > now && !obsolete_failure(out)) return false;
    if (pthread_mutex_trylock(&s_lookup_lock)) {
        strcpy(out->status, "busy"); strcpy(out->reason, "busy"); return false;
    }
    // A peer may have finished and persisted between our first read and lock.
    hit = prospero_cached(id, out);
    if ((hit && (out->artwork_url[0] || now < out->checked_unix || now - out->checked_unix < PUBLIC_RETRY_SECONDS)) ||
        (out->retry_after_unix > now && !obsolete_failure(out))) {
        pthread_mutex_unlock(&s_lookup_lock); return !strcmp(out->status, "available");
    }
    if (obsolete_failure(out)) {
        // Persist admission first: a crash mid-request must not retry on every
        // restart. This records no transport/TLS cause until one is observed.
        strcpy(out->reason, "refresh_pending");
        out->checked_unix = now;
        out->retry_after_unix = now <= INT64_MAX - PUBLIC_RETRY_SECONDS ? now + PUBLIC_RETRY_SECONDS : INT64_MAX;
        out->cached = false;
        if (!write_cache(out)) {
            cache_failure(out, "write_error", errno);
            pthread_mutex_unlock(&s_lookup_lock); return false;
        }
        strcpy(out->cache_state, "stored");
    }
    public_metadata_t last_good = *out;
    http_response_t response = {0}; public_metadata_t parsed;
    bool fetched = http_get_public_limited(out->source_url, PUBLIC_HTML_LIMIT, &response);
    bool ok = fetched && response.status == 200 && response.body &&
              response.body_len <= PUBLIC_HTML_LIMIT &&
              strnlen(response.body, response.body_len + 1) == response.body_len &&
              public_metadata_parse(id, response.body, &parsed);
    char cache_state[sizeof(out->cache_state)];
    strcpy(cache_state, out->cache_state);
    int cache_errno = out->cache_errno;
    if (ok) *out = parsed;
    else {
        if (hit) *out = last_good;
        strcpy(out->reason, !fetched ?
                (response.ssl_error || response.ssl_detail ? "tls_error" : "transport_error") :
                response.status != 200 ? "http_status" : "page_unrecognized");
    }
    // http_response_free() zeroes these fields. Capture only this request's
    // evidence now; a generic transport failure is not a DNS diagnosis.
    out->http_status = response.status;
    out->transport_error = response.transport_error;
    out->ssl_error = response.ssl_error;
    out->ssl_detail = response.ssl_detail;
    http_response_free(&response);
    if (!ok) {
        out->checked_unix = now;
        out->retry_after_unix = now <= INT64_MAX - PUBLIC_RETRY_SECONDS ? now + PUBLIC_RETRY_SECONDS : INT64_MAX;
    }
    out->cached = false;
    out->cache_errno = cache_errno;
    if (write_cache(out)) strcpy(out->cache_state, cache_errno ? cache_state : "stored");
    else {
        strcpy(out->cache_state, "write_error");
        out->cache_errno = errno;
        if (ok) strcpy(out->reason, "cache_error");
    }
    pthread_mutex_unlock(&s_lookup_lock); return ok || hit;
}
