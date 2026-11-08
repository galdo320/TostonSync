#include "public_artwork.h"
#include "config.h"
#include "fs.h"
#include "http_client.h"

#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <limits.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#define ARTWORK_LIMIT (512 * 1024)
#define ARTWORK_DIMENSION_LIMIT 4096
#define ARTWORK_RETRY_SECONDS 86400
#define META_LIMIT 2048

// ponytail: one in-flight public cover globally; no queue or background probes.
static pthread_mutex_t s_artwork_lock = PTHREAD_MUTEX_INITIALIZER;

static bool valid_id(const char* id) {
    if (!id || strlen(id) != 9 || strncmp(id, "PPSA", 4)) return false;
    for (size_t i = 4; i < 9; i++) if (id[i] < '0' || id[i] > '9') return false;
    return true;
}

bool public_artwork_valid_url(const char* id, const char* url) {
    if (!valid_id(id) || !url) return false;
    char prefix[80];
    int n = snprintf(prefix, sizeof(prefix), "https://cdn.prosperopatches.com/titles/%s_", id);
    if (n < 0 || strncmp(url, prefix, (size_t)n) ||
        strlen(url) != (size_t)n + 64 + strlen("/icon0.webp")) return false;
    for (size_t i = (size_t)n; i < (size_t)n + 64; i++)
        if (!((url[i] >= '0' && url[i] <= '9') || (url[i] >= 'a' && url[i] <= 'f'))) return false;
    return !strcmp(url + n + 64, "/icon0.webp");
}

static uint32_t le24(const unsigned char* p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16);
}
static uint32_t le32(const unsigned char* p) { return le24(p) | ((uint32_t)p[3] << 24); }

bool public_artwork_validate(const void* body, size_t len, uint32_t* width, uint32_t* height) {
    const unsigned char* b = body;
    if (!b || len < 22 || len > ARTWORK_LIMIT || memcmp(b, "RIFF", 4) ||
        memcmp(b + 8, "WEBP", 4) || le32(b + 4) != len - 8) return false;
    uint32_t w = 0, h = 0; bool image = false;
    for (size_t p = 12; p < len;) {
        if (len - p < 8) return false;
        size_t n = le32(b + p + 4);
        if (n > len - p - 8 || (n & 1) > len - p - 8 - n) return false;
        const unsigned char* data = b + p + 8;
        if (!memcmp(b + p, "VP8X", 4)) {
            if (p != 12 || n != 10 || (data[0] & 0xc3) || data[1] || data[2] || data[3] ||
                (data[0] & 2)) return false; // animated covers are not cached
            w = le24(data + 4) + 1; h = le24(data + 7) + 1;
        } else if (!memcmp(b + p, "VP8 ", 4)) {
            if (image || n <= 10 || (data[0] & 1) || memcmp(data + 3, "\x9d\x01\x2a", 3) ||
                (le24(data) >> 5) < 7 || (le24(data) >> 5) > n - 3) return false;
            uint32_t iw = (data[6] | ((uint32_t)data[7] << 8)) & 0x3fff;
            uint32_t ih = (data[8] | ((uint32_t)data[9] << 8)) & 0x3fff;
            if ((w && w != iw) || (h && h != ih)) return false;
            w = iw; h = ih; image = true;
        } else if (!memcmp(b + p, "VP8L", 4)) {
            if (image || n <= 5 || data[0] != 0x2f || (data[4] & 0xe0)) return false;
            uint32_t packed = le32(data + 1);
            uint32_t iw = (packed & 0x3fff) + 1, ih = ((packed >> 14) & 0x3fff) + 1;
            if ((w && w != iw) || (h && h != ih)) return false;
            w = iw; h = ih; image = true;
        } else if (!memcmp(b + p, "ANIM", 4) || !memcmp(b + p, "ANMF", 4)) return false;
        p += 8 + n + (n & 1);
    }
    if (!image || !w || !h || w > ARTWORK_DIMENSION_LIMIT || h > ARTWORK_DIMENSION_LIMIT) return false;
    if (width) *width = w;
    if (height) *height = h;
    return true;
}

static bool init(const char* id, public_artwork_t* out) {
    if (!out) return false;
    memset(out, 0, sizeof(*out));
    strcpy(out->status, "unavailable"); strcpy(out->reason, "none"); strcpy(out->cache_state, "miss");
    if (!valid_id(id)) { strcpy(out->reason, "invalid_title_id"); return false; }
    strcpy(out->title_id, id);
    const config_t* cfg = config_get();
    const char* root = cfg && cfg->paths.state_dir[0] ? cfg->paths.state_dir : "/data/tostonsync";
    int n = snprintf(out->path, sizeof(out->path), "%s/metadata/%s/public-cover.webp", root, id);
    if (n <= 0 || (size_t)n >= sizeof(out->path)) {
        strcpy(out->reason, "cache_error"); out->cache_errno = ENAMETOOLONG; return false;
    }
    return true;
}

static bool dirs_safe(const char* path, bool allow_missing) {
    char dir[420]; snprintf(dir, sizeof(dir), "%s", path); *strrchr(dir, '/') = '\0';
    for (int i = 0; i < 2; i++) {
        struct stat st;
        if (lstat(dir, &st)) { if (!allow_missing || errno != ENOENT) return false; }
        else if (!S_ISDIR(st.st_mode)) { errno = ENOTDIR; return false; }
        *strrchr(dir, '/') = '\0';
    }
    return true;
}

static bool cache_error(public_artwork_t* out, const char* state, int error) {
    strcpy(out->reason, "cache_error");
    snprintf(out->cache_state, sizeof(out->cache_state), "%s", state);
    out->cache_errno = error; return false;
}

static bool atomic_write(const char* path, const void* body, size_t len) {
    char dir[420], tmp[440]; snprintf(dir, sizeof(dir), "%s", path); *strrchr(dir, '/') = '\0';
    if (!dirs_safe(path, true) || !fs_mkdir_p(dir) || !dirs_safe(path, false)) return false;
    snprintf(tmp, sizeof(tmp), "%s.tmp", path);
    int fd = open(tmp, O_WRONLY | O_CREAT | O_TRUNC | O_NOFOLLOW, 0600);
    if (fd < 0) return false;
    size_t pos = 0; int error = 0;
    while (pos < len) {
        ssize_t n = write(fd, (const char*)body + pos, len - pos);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) { error = n < 0 ? errno : EIO; break; }
        pos += (size_t)n;
    }
    if (!error && fsync(fd)) error = errno;
    if (close(fd) && !error) error = errno;
    if (!error && rename(tmp, path)) error = errno;
    if (!error) {
        fd = open(dir, O_RDONLY | O_DIRECTORY | O_NOFOLLOW);
        if (fd < 0) error = errno;
        else { if (fsync(fd)) error = errno; if (close(fd) && !error) error = errno; }
    }
    if (error) { unlink(tmp); errno = error; return false; }
    return true;
}

static bool read_file(const char* path, void** body, size_t* len, size_t limit) {
    if (!dirs_safe(path, false)) return false;
    int fd = open(path, O_RDONLY | O_NOFOLLOW);
    if (fd < 0) return false;
    struct stat before, after; int error = fstat(fd, &before) ? errno : 0;
    if (!error && (!S_ISREG(before.st_mode) || before.st_size <= 0 ||
                  (uint64_t)before.st_size > limit)) error = EINVAL;
    unsigned char* data = error ? NULL : malloc((size_t)before.st_size + 1);
    if (!data && !error) error = ENOMEM;
    size_t pos = 0;
    while (!error && pos < (size_t)before.st_size) {
        ssize_t n = read(fd, data + pos, (size_t)before.st_size - pos);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) { error = n < 0 ? errno : EIO; break; }
        pos += (size_t)n;
    }
    if (!error && fstat(fd, &after)) error = errno;
    if (!error && (before.st_dev != after.st_dev || before.st_ino != after.st_ino ||
                  before.st_size != after.st_size || before.st_mtime != after.st_mtime ||
                  before.st_ctime != after.st_ctime)) error = EAGAIN;
    if (close(fd) && !error) error = errno;
    if (error) { free(data); errno = error; return false; }
    data[pos] = 0; *body = data; *len = pos; return true;
}

static void meta_path(const public_artwork_t* out, char path[420]) {
    snprintf(path, 420, "%s.meta", out->path);
}

static bool save_meta(const public_artwork_t* out) {
    char path[420], text[META_LIMIT]; meta_path(out, path);
    int n = snprintf(text, sizeof(text),
        "{\"title_id\":\"%s\",\"source_url\":\"%s\",\"status\":\"%s\",\"reason\":\"%s\","
        "\"checked_unix\":%" PRId64 ",\"retry_after_unix\":%" PRId64 ",\"http_status\":%d,"
        "\"transport_error\":%d,\"ssl_error\":%d,\"ssl_detail\":\"0x%lx\"}\n",
        out->title_id, out->source_url, out->status, out->reason, out->checked_unix,
        out->retry_after_unix, out->http_status, out->transport_error, out->ssl_error, out->ssl_detail);
    if (n <= 0 || (size_t)n >= sizeof(text)) { errno = EOVERFLOW; return false; }
    return atomic_write(path, text, (size_t)n);
}

static bool load_meta(public_artwork_t* out) {
    char path[420]; meta_path(out, path); void* data; size_t len;
    if (!read_file(path, &data, &len, META_LIMIT))
        return errno == ENOENT ? false : cache_error(out, "read_error", errno);
    public_artwork_t m = *out; int used = 0;
    int fields = memchr(data, 0, len) ? 0 : sscanf(data,
        "{\"title_id\":\"%15[^\"]\",\"source_url\":\"%255[^\"]\",\"status\":\"%31[^\"]\","
        "\"reason\":\"%31[^\"]\",\"checked_unix\":%" SCNd64 ",\"retry_after_unix\":%" SCNd64 ","
        "\"http_status\":%d,\"transport_error\":%d,\"ssl_error\":%d,\"ssl_detail\":\"0x%lx\"}\n%n",
        m.title_id, m.source_url, m.status, m.reason, &m.checked_unix, &m.retry_after_unix,
        &m.http_status, &m.transport_error, &m.ssl_error, &m.ssl_detail, &used);
    bool ok = fields == 10 && used > 0 && (size_t)used == len &&
        !strcmp(m.title_id, out->title_id) && public_artwork_valid_url(m.title_id, m.source_url) &&
        m.checked_unix >= 0 && m.retry_after_unix >= 0;
    if (ok && !strcmp(m.status, "available")) ok = !strcmp(m.reason, "none") && !m.retry_after_unix;
    else if (ok && !strcmp(m.status, "unavailable")) ok =
        m.checked_unix <= INT64_MAX - ARTWORK_RETRY_SECONDS &&
        m.retry_after_unix == m.checked_unix + ARTWORK_RETRY_SECONDS &&
        (!strcmp(m.reason, "tls_error") || !strcmp(m.reason, "transport_error") ||
         !strcmp(m.reason, "http_status") || !strcmp(m.reason, "image_invalid"));
    else ok = false;
    free(data);
    if (!ok) return cache_error(out, "corrupt", EINVAL);
    m.cached = true; strcpy(m.cache_state, "hit"); *out = m; return true;
}

bool public_artwork_cached(const char* id, public_artwork_t* out) {
    if (!init(id, out)) return false;
    bool meta = load_meta(out);
    void* data; size_t len;
    if (!read_file(out->path, &data, &len, ARTWORK_LIMIT)) {
        if (errno == ENOENT && (!meta || strcmp(out->status, "available"))) return false;
        return cache_error(out, "read_error", errno);
    }
    bool ok = public_artwork_validate(data, len, &out->width, &out->height); free(data);
    if (!ok) return cache_error(out, "corrupt", EINVAL);
    // A crash after image rename but before the small metadata rename does not
    // discard a validated cover. The missing metadata remains explicit.
    if (!meta || strcmp(out->status, "available")) {
        strcpy(out->reason, "cache_error");
        if (!out->cache_errno) out->cache_errno = meta ? EAGAIN : ENOENT;
        strcpy(out->cache_state, "stale_metadata");
    }
    strcpy(out->mime, "image/webp"); strcpy(out->status, "available");
    out->size = len; out->cached = true; return true;
}

bool public_artwork_lookup(const char* id, const char* url, public_artwork_t* out) {
    if (!init(id, out)) return false;
    if (public_artwork_cached(id, out)) return true;
    if (!public_artwork_valid_url(id, url)) { strcpy(out->reason, "invalid_artwork_url"); return false; }
    int64_t now = (int64_t)time(NULL); if (now < 0) now = 0;
    if (out->retry_after_unix > now) return false;
    if (pthread_mutex_trylock(&s_artwork_lock)) {
        strcpy(out->status, "busy"); strcpy(out->reason, "busy"); return false;
    }
    if (public_artwork_cached(id, out) || out->retry_after_unix > now) {
        pthread_mutex_unlock(&s_artwork_lock); return !strcmp(out->status, "available");
    }
    strcpy(out->source_url, url);
    http_response_t response = {0};
    bool fetched = http_get_public_limited(url, ARTWORK_LIMIT, &response);
    bool ok = fetched && response.status == 200 &&
        public_artwork_validate(response.body, response.body_len, &out->width, &out->height);
    strcpy(out->reason, !fetched ? (response.ssl_error || response.ssl_detail ? "tls_error" : "transport_error") :
        response.status != 200 ? "http_status" : ok ? "none" : "image_invalid");
    out->checked_unix = now; out->retry_after_unix = ok ? 0 :
        (now <= INT64_MAX - ARTWORK_RETRY_SECONDS ? now + ARTWORK_RETRY_SECONDS : INT64_MAX);
    out->http_status = response.status; out->transport_error = response.transport_error;
    out->ssl_error = response.ssl_error; out->ssl_detail = response.ssl_detail;
    out->cached = false;
    if (ok) {
        strcpy(out->status, "available"); strcpy(out->mime, "image/webp"); out->size = response.body_len;
        if (!atomic_write(out->path, response.body, response.body_len))
            ok = cache_error(out, "write_error", errno);
    }
    http_response_free(&response);
    if (!out->cache_errno || strcmp(out->cache_state, "write_error")) {
        if (!save_meta(out)) { ok = cache_error(out, "write_error", errno); }
        else if (!out->cache_errno) strcpy(out->cache_state, "stored");
    }
    if (!ok) strcpy(out->status, "unavailable");
    pthread_mutex_unlock(&s_artwork_lock); return ok;
}
