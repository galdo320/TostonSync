// Source: https://github.com/andshrew/PlayStation-Titles (MIT, andshrew 2022).
// Only its public TSV metadata is cached; no Sony services or artwork fetched.
#include "title_catalog.h"
#include "config.h"
#include "fs.h"
#include "http_client.h"
#include "titlename.h"

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

#define CATALOG_TTL 86400
#define CATALOG_PATH_MAX 400
// ponytail: one bounded TSV scan per offline lookup; index only if measured
// UI lookup latency warrants one. Atomic replacement keeps readers independent.
static pthread_mutex_t s_catalog_lock = PTHREAD_MUTEX_INITIALIZER;
static const char s_header[] = "titleId\tconceptId\tname\tcontentId\tregion\tpublisherId\n";

static bool id_valid(const char* id) {
    if (!id || strlen(id) != 9 || strncmp(id, "PPSA", 4)) return false;
    for (size_t i = 4; i < 9; i++) if (id[i] < '0' || id[i] > '9') return false;
    return true;
}

static bool text_valid(const char* text, size_t cap, bool empty) {
    size_t n = strlen(text); char copy[128];
    if ((!empty && !n) || n >= cap || n >= sizeof(copy) ||
        titlename_copy_utf8(copy, sizeof(copy), text) != n) return false;
    for (const unsigned char* p = (const unsigned char*)text; *p; p++)
        if (*p < 0x20 || *p == 0x7f) return false;
    return true;
}

static bool content_valid(const char* content, const char* id) {
    if (!*content) return true;
    if (strlen(content) != 36 || content[6] != '-' ||
        strncmp(content + 7, id, 9) || strncmp(content + 16, "_00-", 4)) return false;
    for (size_t i = 0; i < 2; i++) if (content[i] < 'A' || content[i] > 'Z') return false;
    for (size_t i = 2; i < 6; i++) if (content[i] < '0' || content[i] > '9') return false;
    for (size_t i = 20; i < 36; i++) if (!((content[i] >= 'A' && content[i] <= 'Z') ||
                                         (content[i] >= '0' && content[i] <= '9'))) return false;
    return true;
}

static const char* region_label(const char* region) {
    if (!strcmp(region, "EP")) return "EU";
    if (!strcmp(region, "UP")) return "AMERICAS";
    if (!strcmp(region, "JP")) return "JP";
    if (!strcmp(region, "HP")) return "ASIA";
    return ""; // Explicit source codes only; no inference from PPSA numbers.
}

static bool paths(char* table, char* state) {
    const config_t* cfg = config_get();
    const char* root = cfg && cfg->paths.state_dir[0] ? cfg->paths.state_dir : "/data/tostonsync";
    if (snprintf(table, CATALOG_PATH_MAX, "%s/metadata/title-catalog.tsv", root) >= CATALOG_PATH_MAX ||
        snprintf(state, CATALOG_PATH_MAX, "%s/metadata/title-catalog.state", root) >= CATALOG_PATH_MAX) {
        errno = ENAMETOOLONG; return false;
    }
    return true;
}

static bool safe_parent(const char* path, bool create) {
    char dir[CATALOG_PATH_MAX]; snprintf(dir, sizeof(dir), "%s", path);
    char* slash = strrchr(dir, '/'); if (!slash) { errno = EINVAL; return false; }
    *slash = 0; struct stat st;
    if (lstat(dir, &st)) {
        if (!create || errno != ENOENT || !fs_mkdir_p(dir) || lstat(dir, &st)) return false;
    }
    if (!S_ISDIR(st.st_mode)) { errno = ENOTDIR; return false; }
    return true;
}

static char* read_file(const char* path, size_t limit, size_t* length, int64_t* modified) {
    if (!safe_parent(path, false)) return NULL;
    int fd = open(path, O_RDONLY | O_NOFOLLOW); if (fd < 0) return NULL;
    struct stat before, after; int error = fstat(fd, &before) ? errno : 0;
    if (!error && (!S_ISREG(before.st_mode) || before.st_size <= 0 ||
                   (uint64_t)before.st_size > limit)) error = EINVAL;
    char* body = error ? NULL : malloc((size_t)before.st_size + 1);
    if (!body && !error) error = ENOMEM;
    size_t used = 0;
    while (!error && used < (size_t)before.st_size) {
        ssize_t n = read(fd, body + used, (size_t)before.st_size - used);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) { error = n < 0 ? errno : EIO; break; }
        used += (size_t)n;
    }
    if (!error && (fstat(fd, &after) || before.st_dev != after.st_dev ||
                   before.st_ino != after.st_ino || before.st_size != after.st_size)) error = EIO;
    if (close(fd) && !error) error = errno;
    if (error) { free(body); errno = error; return NULL; }
    body[used] = 0; *length = used;
    if (modified) *modified = (int64_t)before.st_mtime;
    return body;
}

static bool atomic_write(const char* path, const char* body, size_t length) {
    if (!safe_parent(path, true)) return false;
    char tmp[CATALOG_PATH_MAX + 8]; snprintf(tmp, sizeof(tmp), "%s.tmp", path);
    int fd = open(tmp, O_WRONLY | O_CREAT | O_TRUNC | O_NOFOLLOW, 0600);
    if (fd < 0) return false;
    size_t done = 0; int error = 0;
    while (done < length) {
        ssize_t n = write(fd, body + done, length - done);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) { error = n < 0 ? errno : EIO; break; }
        done += (size_t)n;
    }
    if (!error && fsync(fd)) error = errno;
    if (close(fd) && !error) error = errno;
    if (!error && rename(tmp, path)) error = errno;
    if (error) { unlink(tmp); errno = error; return false; }
    char dir[CATALOG_PATH_MAX]; snprintf(dir, sizeof(dir), "%s", path); *strrchr(dir, '/') = 0;
    fd = open(dir, O_RDONLY);
    if (fd < 0) return false;
    error = fsync(fd) ? errno : 0;
    if (close(fd) && !error) error = errno;
    if (error) { errno = error; return false; }
    return true;
}

// Six canonical columns and complete newline-terminated rows. Unsupported IDs
// and unusable fields are not metadata; malformed structure rejects the update.
static bool parse_table(const char* body, size_t length, const char* id,
                        public_metadata_t* out, size_t* usable_rows) {
    *usable_rows = 0;
    if (!body || length > TITLE_CATALOG_LIMIT || length <= sizeof(s_header) - 1 ||
        memchr(body, 0, length) || body[length - 1] != '\n' ||
        memcmp(body, s_header, sizeof(s_header) - 1)) return false;
    bool found = false, conflict = false, unusable_match = false;
    const char* p = body + sizeof(s_header) - 1; const char* end = body + length;
    while (p < end) {
        const char* newline = memchr(p, '\n', (size_t)(end - p));
        if (!newline || newline - p > 4096) return false;
        const char* values[6]; size_t sizes[6]; const char* q = p;
        for (size_t i = 0; i < 6; i++) {
            const char* tab = memchr(q, '\t', (size_t)(newline - q));
            if ((i < 5 && !tab) || (i == 5 && tab)) return false;
            const char* stop = i < 5 ? tab : newline;
            values[i] = q; sizes[i] = (size_t)(stop - q); q = stop + 1;
        }
        p = newline + 1;
        if (sizes[0] != 12 || memcmp(values[0] + 9, "_00", 3)) continue;
        char row_id[16], name[96], content[64], region[16];
        memcpy(row_id, values[0], 9); row_id[9] = 0;
        if (!id_valid(row_id)) continue;
        bool relevant = id && !strcmp(row_id, id);
        if (sizes[2] >= 96 || sizes[3] >= 64 || sizes[4] >= 16) {
            if (relevant) unusable_match = true;
            continue;
        }
        memcpy(name, values[2], sizes[2]); name[sizes[2]] = 0;
        memcpy(content, values[3], sizes[3]); content[sizes[3]] = 0;
        memcpy(region, values[4], sizes[4]); region[sizes[4]] = 0;
        if (!text_valid(name, sizeof(name), false) ||
            !content_valid(content, row_id) || !text_valid(region, sizeof(region), true) ||
            (*content && *region && (strlen(region) != 2 || strncmp(content, region, 2)))) {
            if (relevant) unusable_match = true;
            continue;
        }
        (*usable_rows)++;
        if (!relevant) continue;
        const char* label = region_label(region);
        if (found && (strcmp(out->name, name) || strcmp(out->content_id, content) ||
                      strcmp(out->region, label))) conflict = true;
        if (!found) {
            strcpy(out->name, name); strcpy(out->content_id, content); strcpy(out->region, label);
            found = true;
        }
    }
    if (id && (!found || conflict || unusable_match)) {
        out->name[0] = out->content_id[0] = out->region[0] = 0;
        strcpy(out->reason, conflict ? "catalog_conflict" : unusable_match ? "catalog_unusable" : "catalog_not_found");
    }
    return *usable_rows != 0;
}

static bool etag_valid(const char* text) {
    if (!text || strlen(text) >= 128) return false;
    size_t n = strlen(text), begin = n > 2 && !strncmp(text, "W/", 2) ? 2 : 0;
    if (!n) return true;
    if (n < begin + 2 || text[begin] != '"' || text[n - 1] != '"') return false;
    for (size_t i = begin + 1; i < n - 1; i++)
        if ((unsigned char)text[i] < 0x21 || (unsigned char)text[i] > 0x7e || text[i] == '"') return false;
    return true;
}

static void response_etag(const http_response_t* response, char* out) {
    if (!response->headers || response->headers_len > 65536) return;
    const char* p = response->headers; const char* end = p + response->headers_len;
    while (p < end) {
        const char* newline = memchr(p, '\n', (size_t)(end - p));
        if (!newline) newline = end;
        if (newline - p > 5 && !strncasecmp(p, "ETag:", 5)) {
            const char* value = p + 5; while (value < newline && (*value == ' ' || *value == '\t')) value++;
            const char* finish = newline; while (finish > value && (finish[-1] == '\r' || finish[-1] == ' ')) finish--;
            char etag[128]; size_t n = (size_t)(finish - value);
            if (n < sizeof(etag)) { memcpy(etag, value, n); etag[n] = 0; if (etag_valid(etag)) strcpy(out, etag); }
            return;
        }
        p = newline < end ? newline + 1 : end;
    }
}

static bool write_state(const char* path, const title_catalog_status_t* state) {
    char body[640];
    int n = snprintf(body, sizeof(body), "v2\t%" PRId64 "\t%" PRId64 "\t%s\t%s\t%d\t%d\t%d\t%lx\t%d\t%zu\t%s\n",
        state->checked_unix, state->retry_after_unix, state->status, state->reason,
        state->http_status, state->transport_error, state->ssl_error, state->ssl_detail,
        state->cache_errno, state->rows, state->etag[0] ? state->etag : "-");
    return n > 0 && (size_t)n < sizeof(body) && atomic_write(path, body, (size_t)n);
}

static bool state_number(const char* text, int64_t min, int64_t max, int64_t* out) {
    if (!*text || ((*text < '0' || *text > '9') && *text != '-')) return false;
    errno = 0; char* end; long long n = strtoll(text, &end, 10);
    if (errno || end == text || *end || n < min || n > max) return false;
    *out = (int64_t)n; return true;
}

static bool read_state(const char* path, title_catalog_status_t* state) {
    size_t length; char* body = read_file(path, 639, &length, NULL); if (!body) return false;
    char* fields[12]; char* p = body; bool ok = !memchr(body, 0, length);
    for (size_t i = 0; ok && i < 12; i++) {
        fields[i] = p; char* stop = strchr(p, i == 11 ? '\n' : '\t');
        if (!stop || (i == 11 && stop != body + length - 1)) { ok = false; break; }
        *stop = 0; p = stop + 1;
    }
    title_catalog_status_t value = {0}; int64_t number;
    if (ok) ok = (!strcmp(fields[0], "v1") || !strcmp(fields[0], "v2")) &&
        state_number(fields[1], 0, INT64_MAX - CATALOG_TTL, &value.checked_unix) &&
        state_number(fields[2], 0, INT64_MAX, &value.retry_after_unix) &&
        value.retry_after_unix == value.checked_unix + CATALOG_TTL &&
        text_valid(fields[3], sizeof(value.status), false) &&
        text_valid(fields[4], sizeof(value.reason), false) &&
        (strcmp(fields[11], "-") == 0 || etag_valid(fields[11]));
    if (ok) {
        strcpy(value.status, fields[3]); strcpy(value.reason, fields[4]);
        int* codes[] = {&value.http_status, &value.transport_error, &value.ssl_error, &value.cache_errno};
        const size_t columns[] = {5, 6, 7, 9};
        for (size_t i = 0; ok && i < 4; i++) {
            ok = state_number(fields[columns[i]], INT_MIN, INT_MAX, &number);
            if (ok) *codes[i] = (int)number;
        }
        if (ok) ok = state_number(fields[10], 0, TITLE_CATALOG_LIMIT, &number);
        if (ok) value.rows = (size_t)number;
        if (!*fields[8]) ok = false;
        for (const char* q = fields[8]; ok && *q; q++)
            if (!((*q >= '0' && *q <= '9') || (*q >= 'a' && *q <= 'f'))) ok = false;
        if (ok) {
            errno = 0; char* end; value.ssl_detail = strtoul(fields[8], &end, 16);
            ok = !errno && !*end;
        }
        if (ok) {
            if (strcmp(fields[11], "-")) strcpy(value.etag, fields[11]);
            ok = (!strcmp(value.status, "available") && (!strcmp(value.reason, "updated") || !strcmp(value.reason, "not_modified"))) ||
                 (!strcmp(value.status, "pending") && !strcmp(value.reason, "refresh_pending")) ||
                 (!strcmp(value.status, "unavailable") && (!strcmp(value.reason, "transport_error") ||
                    !strcmp(value.reason, "tls_error") || !strcmp(value.reason, "http_status") ||
                    !strcmp(value.reason, "catalog_unrecognized") || !strcmp(value.reason, "not_modified_without_table") ||
                    !strcmp(value.reason, "cache_error")));
        }
    }
    // v2 uses the approved direct GitHub trust anchor. Revalidate only a TLS
    // failure from the old policy once, without removing the last-good table.
    // refresh() persists a v2 pending marker before transport, so interruption
    // or a new failure cannot replay this migration after restart.
    if (ok && !strcmp(fields[0], "v1") && !strcmp(value.status, "unavailable") &&
        !strcmp(value.reason, "tls_error")) value.retry_after_unix = 0;
    free(body);
    if (!ok) { errno = EINVAL; return false; }
    *state = value; return true;
}

bool title_catalog_lookup(const char* id, public_metadata_t* out) {
    if (!out) return false;
    memset(out, 0, sizeof(*out)); strcpy(out->status, "unavailable");
    strcpy(out->reason, "catalog_not_found"); strcpy(out->cache_state, "catalog_miss");
    if (!id_valid(id)) { strcpy(out->reason, "invalid_title_id"); return false; }
    strcpy(out->title_id, id); strcpy(out->source, "PlayStation-Titles");
    strcpy(out->source_url, TITLE_CATALOG_URL);
    char table[CATALOG_PATH_MAX], state[CATALOG_PATH_MAX];
    if (!paths(table, state)) { out->cache_errno = errno; return false; }
    size_t length, rows; int64_t modified;
    char* body = read_file(table, TITLE_CATALOG_LIMIT, &length, &modified);
    if (!body) { if (errno != ENOENT) { out->cache_errno = errno; strcpy(out->reason, "cache_error"); } return false; }
    bool valid = parse_table(body, length, id, out, &rows); free(body);
    if (!valid) { out->cache_errno = EINVAL; strcpy(out->reason, "cache_error"); return false; }
    out->cached = true; out->checked_unix = modified; strcpy(out->cache_state, "catalog_hit");
    if (!out->name[0]) return false;
    strcpy(out->status, "available"); strcpy(out->reason, "none"); return true;
}

bool title_catalog_refresh(title_catalog_status_t* out) {
    if (!out) return false;
    memset(out, 0, sizeof(*out)); strcpy(out->status, "unavailable"); strcpy(out->reason, "cache_error");
    if (pthread_mutex_trylock(&s_catalog_lock)) { strcpy(out->status, "busy"); strcpy(out->reason, "busy"); return false; }
    bool ok = false; char table[CATALOG_PATH_MAX], state_path[CATALOG_PATH_MAX];
    if (!paths(table, state_path)) { out->cache_errno = errno; goto done; }
    title_catalog_status_t previous = {0};
    if (!read_state(state_path, &previous) && errno != ENOENT) { out->cache_errno = errno; goto done; }
    int64_t now = (int64_t)time(NULL); if (now < 0) now = 0;
    if (previous.retry_after_unix > now) {
        *out = previous; out->cached = true;
        ok = !strcmp(previous.status, "available"); goto done;
    }
    *out = previous; out->checked_unix = now;
    if (now > INT64_MAX - CATALOG_TTL) { out->cache_errno = EOVERFLOW; strcpy(out->reason, "cache_error"); goto done; }
    out->retry_after_unix = now + CATALOG_TTL; out->cached = false;
    size_t length = 0, rows = 0; char* old = read_file(table, TITLE_CATALOG_LIMIT, &length, NULL);
    bool have_table = old && parse_table(old, length, NULL, NULL, &rows); free(old);
    if (!have_table) out->etag[0] = 0;
    out->rows = have_table ? rows : 0;
    strcpy(out->status, "pending"); strcpy(out->reason, "refresh_pending");
    out->http_status = out->transport_error = out->ssl_error = out->cache_errno = 0;
    out->ssl_detail = 0;
    // Persist before contacting the public source: restart cannot make a
    // failed/interrupted request loop or discard the last-good table.
    if (!write_state(state_path, out)) { out->cache_errno = errno; strcpy(out->reason, "cache_error"); goto done; }
    http_response_t response = {0};
    bool fetched = http_get_public_catalog(TITLE_CATALOG_URL, out->etag, TITLE_CATALOG_LIMIT, &response);
    out->http_status = response.status; out->transport_error = response.transport_error;
    out->ssl_error = response.ssl_error; out->ssl_detail = response.ssl_detail; out->cache_errno = 0;
    strcpy(out->status, "unavailable");
    if (!fetched) strcpy(out->reason, response.ssl_error || response.ssl_detail ? "tls_error" : "transport_error");
    else if (response.status == 304 && have_table) {
        ok = true; strcpy(out->reason, "not_modified"); response_etag(&response, out->etag);
    } else if (response.status == 200 && response.body &&
               parse_table(response.body, response.body_len, NULL, NULL, &rows)) {
        if (atomic_write(table, response.body, response.body_len)) {
            ok = true; out->rows = rows; out->etag[0] = 0;
            strcpy(out->reason, "updated"); response_etag(&response, out->etag);
        } else { out->cache_errno = errno; strcpy(out->reason, "cache_error"); }
    } else strcpy(out->reason, response.status == 200 ? "catalog_unrecognized" :
                                response.status == 304 ? "not_modified_without_table" : "http_status");
    http_response_free(&response);
    if (ok) strcpy(out->status, "available");
    if (!write_state(state_path, out)) { out->cache_errno = errno; if (ok) strcpy(out->reason, "cache_error"); ok = false; }
done:
    pthread_mutex_unlock(&s_catalog_lock); return ok;
}
