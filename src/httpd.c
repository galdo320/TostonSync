// TostónSync — internal HTTP server.
//
// Hand-rolled HTTP/1.1 server on BSD sockets. Single accept thread,
// one worker thread per connection. No external dependency. The UI is
// embedded at compile time via ui_html.h.

#include "httpd.h"
#include "config.h"
#include "settings_input.h"
#include "http_security.h"
#include "diagnostic_text.h"
#include "backup_names.h"
#include "log.h"
#include "gdrive.h"
#include "http_client.h"
#include "usb.h"
#include "history.h"
#include "protect.h"
#include "metacache.h"
#include "public_metadata.h"
#include "title_catalog.h"
#include "public_artwork.h"
#include "version.h"
#include "zip.h"
#include "qrcode.h"
#include "retention.h"
#include "watcher.h"
#include "ui_html.h"
#include "favicon_data.h"
#include "support_qr.h"
#include "json.h"
#include "fs.h"
#include "pfs_resign.h"
#include "branding.h"
#include "titlename.h"
#include "sfo.h"
#include "import_session.h"
#include "migration_inspect.h"
#include "sha256.h"
#include "dest_dedup.h"
#include "catalog_scan.h"
#include "save_image_hash.h"
#include "raw_selected_preflight.h"
#include "raw_selected_commit.h"
#include "lifecycle.h"
#include "individual_restore.h"
#include "update.h"
#include "github_update.h"
#include "jobs.h"
#include "backup_control.h"

#include <arpa/inet.h>
#include <ctype.h>
#include <ifaddrs.h>
#include <limits.h>
#include <stdatomic.h>
#include <netinet/in.h>
#include <pthread.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

static const config_t* s_cfg = NULL;
static int             s_listen_fd = -1;
static pthread_t       s_accept_thread;
static bool            s_accept_started = false;
static atomic_int      s_running = 0;
static atomic_int      s_active_connections = 0;
static pthread_mutex_t s_large_body_lock = PTHREAD_MUTEX_INITIALIZER;
static char            s_lan_ip[64] = "";
static uint8_t         s_auth_nonce[32];
static bool            s_auth_nonce_ready = false;
// Login revocation is separate from the immutable boot nonce used by B1.
static uint8_t s_login_nonce[32];
static time_t s_login_expires;
static pthread_mutex_t s_auth_lock = PTHREAD_MUTEX_INITIALIZER;

#define HTTP_INITIAL_CAP       (16 * 1024)
#define HTTP_MAX_UPLOAD_BYTES  IMPORT_CHUNK_BYTES
#define HTTP_MAX_CONNECTIONS   32

// Observation responses are published only by explicit actions, never by reads.
#define HTTP_OBSERVATION_SLOTS 32
#define HTTP_OBSERVATION_BYTES (16U * 1024U * 1024U)
typedef struct { char key[1024], type[64]; char* body; size_t size; int status; } http_observation_t;
static http_observation_t s_observations[HTTP_OBSERVATION_SLOTS];
static pthread_mutex_t s_observation_lock = PTHREAD_MUTEX_INITIALIZER;
static size_t s_observation_next, s_observation_bytes;
static _Thread_local char s_observation_key[1024];
static _Thread_local bool s_http_observing, s_prepare_download;
static _Thread_local const char* s_restore_request;

static void observation_key(char out[1024], const char* path, const char* query) {
    int n = snprintf(out, 1024, "%s?%s", path, query ? query : "");
    if (n < 0 || n >= 1024) out[0] = '\0';
}
static void observation_store(int status, const char* type, const void* body, size_t size) {
    if (!s_observation_key[0]) return;
    char* copy = size <= HTTP_OBSERVATION_BYTES ? malloc(size + 1) : NULL;
    if (copy) { if (size) memcpy(copy, body, size); copy[size] = '\0'; }
    pthread_mutex_lock(&s_observation_lock);
    size_t slot = HTTP_OBSERVATION_SLOTS;
    for (size_t i = 0; i < HTTP_OBSERVATION_SLOTS; i++)
        if (!strcmp(s_observations[i].key, s_observation_key)) { slot = i; break; }
    if (slot == HTTP_OBSERVATION_SLOTS) slot = s_observation_next++ % HTTP_OBSERVATION_SLOTS;
    http_observation_t* item = &s_observations[slot];
    s_observation_bytes -= item->size; free(item->body); memset(item, 0, sizeof(*item));
    snprintf(item->key, sizeof(item->key), "%s", s_observation_key);
    if (copy && size <= HTTP_OBSERVATION_BYTES - s_observation_bytes) {
        item->body = copy; item->size = size; item->status = status;
        snprintf(item->type, sizeof(item->type), "%s", type);
        s_observation_bytes += size; copy = NULL;
    }
    pthread_mutex_unlock(&s_observation_lock); free(copy);
}

#define HTTP_PREPARED_MAX 8
#define HTTP_PREPARED_SECONDS (30 * 60)
typedef struct {
    char id[65], path[768], type[64], name[192], extra[1024];
    watcher_raw_info_t raw;
    struct stat identity;
    int file;
    bool active, raw_known;
    unsigned readers;
    time_t expires;
} http_prepared_t;
static http_prepared_t s_prepared[HTTP_PREPARED_MAX];
static pthread_mutex_t s_prepared_lock = PTHREAD_MUTEX_INITIALIZER;
static void reply_prepared(int fd, const char* path, const char* type,
                           const char* name, const watcher_raw_info_t* raw, const char* extra, bool release, bool temporary, bool owned);
static void read_prepared(int fd, const char* id);
static void release_prepared(void);
// --------------------------------------------------------------------
// LAN IP discovery.
// --------------------------------------------------------------------

bool httpd_detect_lan_ip(char* out, size_t out_sz) {
    if (!out || out_sz == 0) return false;
    out[0] = '\0';
    // A connected UDP socket selects the default route without sending data.
    int route_fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (route_fd >= 0) {
        struct sockaddr_in target;
        memset(&target, 0, sizeof(target));
        target.sin_family = AF_INET;
        target.sin_port = htons(9);
        inet_pton(AF_INET, "192.0.2.1", &target.sin_addr); // TEST-NET-1
        if (connect(route_fd, (struct sockaddr*)&target, sizeof(target)) == 0) {
            struct sockaddr_in local;
            socklen_t local_len = sizeof(local);
            if (getsockname(route_fd, (struct sockaddr*)&local, &local_len) == 0 &&
                local.sin_addr.s_addr != htonl(INADDR_LOOPBACK) &&
                local.sin_addr.s_addr != htonl(INADDR_ANY)) {
                inet_ntop(AF_INET, &local.sin_addr, out, out_sz);
            }
        }
        close(route_fd);
        if (out[0]) return true;
    }
    struct ifaddrs* addrs = NULL;
    if (getifaddrs(&addrs) != 0) return false;
    for (struct ifaddrs* a = addrs; a; a = a->ifa_next) {
        if (!a->ifa_addr || a->ifa_addr->sa_family != AF_INET) continue;
        const struct sockaddr_in* sa = (const struct sockaddr_in*)a->ifa_addr;
        uint32_t host = ntohl(sa->sin_addr.s_addr);
        if ((host >> 24) == 127 || (host >> 16) == 0xa9fe || host == 0) continue;
        inet_ntop(AF_INET, &sa->sin_addr, out, out_sz);
        break;
    }
    freeifaddrs(addrs);
    return out[0] != '\0';
}

static void discover_lan_ip(void) {
    (void)httpd_detect_lan_ip(s_lan_ip, sizeof(s_lan_ip));
}

const char* httpd_get_lan_ip(void) { return s_lan_ip; }

// --------------------------------------------------------------------
// Tiny response helpers.
// --------------------------------------------------------------------

static bool send_all(int fd, const void* buf, size_t n) {
    const char* p = (const char*)buf;
    while (n) {
        ssize_t w = send(fd, p, n, 0);
        if (w < 0 && errno == EINTR) continue;
        if (w <= 0) return false;
        p += w; n -= (size_t)w;
    }
    return true;
}

static void observe_restore_request(const char* method, const char* path) {
    s_restore_request = NULL;
    if (strcmp(method, "POST")) return;
    if (!strcmp(path, "/api/restore")) s_restore_request = "/api/restore";
    else if (!strcmp(path, "/api/backup/verify")) s_restore_request = "/api/backup/verify";
}

static void reply(int fd, int status, const char* ctype,
                  const void* body, size_t body_len,
                  const char* extra_headers) {
    if (s_restore_request && status >= 400) {
        char text[512] = {0}, reason[96] = {0};
        size_t n = body_len < sizeof(text) - 1 ? body_len : sizeof(text) - 1;
        if (body) memcpy(text, body, n);
        json_get_string(text, "error", reason, sizeof(reason));
        if (!reason[0]) snprintf(reason, sizeof(reason), "%s", text);
        for (size_t i = 0; reason[i]; i++)
            if ((unsigned char)reason[i] < 32 || (unsigned char)reason[i] == 127) reason[i] = ' ';
        log_warn("http: rejected endpoint=%s status=%d reason=%s", s_restore_request, status,
                 reason[0] ? reason : "empty_error_response");
    }
    observation_store(status, ctype, body, body_len);
    char head[4096];
    int  hn = snprintf(head, sizeof(head),
        // No "Access-Control-Allow-Origin: *": the UI is served from this
        // same origin, so it never needs CORS. Advertising a wildcard let
        // any web page the user happened to be visiting read these
        // responses and (because the API has no auth on the LAN) drive the
        // mutating endpoints — /api/config, /api/restore, /api/oauth/signout
        // — cross-site. Omitting the header makes the browser block those
        // cross-origin reads and preflighted JSON POSTs.
        "HTTP/1.1 %d %s\r\n"
        "Content-Type: %s\r\n"
        "Content-Length: %zu\r\n"
        "Cache-Control: no-store\r\n"
        "X-Content-Type-Options: nosniff\r\n"
        HTTP_SECURITY_HEADERS
        "%s"
        "Connection: close\r\n\r\n",
        status,
        status == 200 ? "OK"
        : status == 204 ? "No Content"
        : status == 400 ? "Bad Request"
        : status == 401 ? "Unauthorized"
        : status == 408 ? "Request Timeout"
        : status == 413 ? "Payload Too Large"
        : status == 503 ? "Service Unavailable"
        : status == 429 ? "Too Many Requests"
        : status == 405 ? "Method Not Allowed"
        : status == 404 ? "Not Found"
        : status == 500 ? "Internal Server Error"
        : "Error",
        ctype, body_len,
        extra_headers ? extra_headers : "");
    if (hn > 0 && (size_t)hn < sizeof(head) && send_all(fd, head, (size_t)hn) && body && body_len)
        (void)send_all(fd, body, body_len);
}

static void reply_json(int fd, int status, const char* json) {
    reply(fd, status, "application/json; charset=utf-8",
          json, strlen(json), NULL);
}

static void reply_text(int fd, int status, const char* text) {
    reply(fd, status, "text/plain; charset=utf-8",
          text, strlen(text), NULL);
}

static void reply_file(int fd, const char* path, const char* ctype) {
    if (s_prepare_download) { reply_prepared(fd, path, ctype, NULL, NULL, NULL, false, false, false); return; }
    struct stat st;
    if (!path || stat(path, &st) != 0 || !S_ISREG(st.st_mode) || st.st_size < 0) {
        reply_text(fd, 404, "not found");
        return;
    }
    FILE* f = fopen(path, "rb");
    if (!f) {
        reply_text(fd, 404, "not found");
        return;
    }

    char head[4096];
    int hn = snprintf(head, sizeof(head),
        "HTTP/1.1 200 OK\r\n"
        "Content-Type: %s\r\n"
        "Content-Length: %llu\r\n"
        "Cache-Control: no-store\r\n"
        "X-Content-Type-Options: nosniff\r\n"
        HTTP_SECURITY_HEADERS
        "Connection: close\r\n\r\n",
        ctype ? ctype : "application/octet-stream",
        (unsigned long long)st.st_size);
    bool sent = hn > 0 && (size_t)hn < sizeof(head) && send_all(fd, head, (size_t)hn);

    char buf[8192];
    size_t n;
    while (sent && (n = fread(buf, 1, sizeof(buf), f)) > 0)
        sent = send_all(fd, buf, n);
    fclose(f);
}

static void reply_download_file_with_headers(int fd, const char* path, const char* ctype,
                                const char* filename,
                                const watcher_raw_info_t* raw_info, const char* extra_headers) {
    struct stat st;
    if (!path || stat(path, &st) != 0 || !S_ISREG(st.st_mode) || st.st_size < 0) {
        reply_text(fd, 404, "not found");
        return;
    }
    FILE* f = fopen(path, "rb");
    if (!f) {
        reply_text(fd, 404, "not found");
        return;
    }

    char safe_name[160] = {0};
    size_t j = 0;
    const char* src = (filename && filename[0]) ? filename : "tostonsync.zip";
    for (size_t i = 0; src[i] && j + 1 < sizeof(safe_name); i++) {
        unsigned char c = (unsigned char)src[i];
        if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
            (c >= '0' && c <= '9') || c == '_' || c == '-' || c == '.')
            safe_name[j++] = (char)c;
        else
            safe_name[j++] = '_';
    }
    if (!safe_name[0]) snprintf(safe_name, sizeof(safe_name), "tostonsync.zip");

    char raw_headers[1024] = {0};
    if (raw_info && raw_info->raw_completeness[0]) {
        snprintf(raw_headers, sizeof(raw_headers),
            "X-Toston-Raw-Completeness: %s\r\n"
            "X-Toston-Active-Images: %zu\r\n"
            "X-Toston-Service-Images: %zu\r\n"
            "X-Toston-Missing-Service-Images: %zu\r\n"
            "X-Toston-First-Missing-Service-Image: %s\r\n",
            raw_info->raw_completeness, raw_info->active_images,
            raw_info->service_images, raw_info->missing_service_images,
            raw_info->first_missing_service_image);
        if (raw_info->selected_partial) {
            size_t used = strlen(raw_headers);
            snprintf(raw_headers + used, sizeof(raw_headers) - used,
                "X-TostonSync-Version: %s\r\n"
                "X-TostonSync-Target-UID: %s\r\n"
                "X-TostonSync-Title-ID: %s\r\n"
                "X-TostonSync-Backup-Scope: selected_containers\r\n"
                "X-TostonSync-Available-Slots: %zu\r\n"
                "X-TostonSync-Selected-Slots: %zu\r\n"
                "X-TostonSync-Service-Images: %zu\r\n"
                "X-TostonSync-Zip-SHA256: %s\r\n",
                TOSTONSYNC_VERSION, raw_info->uid, raw_info->title_id,
                raw_info->available_slots, raw_info->selected_slots,
                raw_info->service_images, raw_info->zip_sha256);
        }
    }

    char head[4096];
    int hn = snprintf(head, sizeof(head),
        "HTTP/1.1 200 OK\r\n"
        "Content-Type: %s\r\n"
        "Content-Length: %llu\r\n"
        "Content-Disposition: attachment; filename=\"%s\"\r\n"
        "%s%s"
        "Cache-Control: no-store\r\n"
        "X-Content-Type-Options: nosniff\r\n"
        HTTP_SECURITY_HEADERS
        "Connection: close\r\n\r\n",
        ctype ? ctype : "application/octet-stream",
        (unsigned long long)st.st_size,
        safe_name, raw_headers, extra_headers ? extra_headers : "");
    if (hn < 0 || (size_t)hn >= sizeof(head)) {
        fclose(f); reply_text(fd, 500, "download headers unavailable"); return;
    }
    bool sent = hn > 0 && (size_t)hn < sizeof(head) && send_all(fd, head, (size_t)hn);

    char buf[8192];
    size_t n;
    while (sent && (n = fread(buf, 1, sizeof(buf), f)) > 0)
        sent = send_all(fd, buf, n);
    fclose(f);
}

static void reply_download_file(int fd, const char* path, const char* ctype,
                                const char* filename, const watcher_raw_info_t* raw_info) {
    reply_download_file_with_headers(fd, path, ctype, filename, raw_info, NULL);
}

// Bounded JSON-builder append. Writes into [*pp, end) and advances *pp by
// the number of bytes actually written, never past `end-1`. The previous
// `p += snprintf(p, end - p, ...)` idiom advanced `p` by snprintf's return
// value — the length it *would* have written — so once a buffer filled, `p`
// moved beyond `end`, `end - p` went negative, and the next call received a
// huge size_t and smashed the stack. This helper can only ever truncate.
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

static void jobs_json_fields(char** p, char* end, jobs_ref_t ref, bool coalesced) {
    jappendf(p, end, ",\"job_id\":");
    if (ref) jappendf(p, end, "\"%llu\"", (unsigned long long)ref);
    else jappendf(p, end, "null");
    jappendf(p, end, ",\"boot_id\":"); jappend_json_string(p, end, update_boot_id());
    jappendf(p, end, ",\"coalesced\":%s,\"tracking_complete\":%s",
             coalesced ? "true" : "false", jobs_tracked(ref) ? "true" : "false");
}

static void jobs_queued_reply(int fd, jobs_ref_t ref, bool coalesced) {
    char body[384], *p = body, *end = body + sizeof(body);
    jappendf(&p, end, "{\"ok\":true,\"status\":\"queued\"");
    jobs_json_fields(&p, end, ref, coalesced); jappendf(&p, end, "}");
    reply_json(fd, 200, body);
}

static jobs_ref_t jobs_import_observe(jobs_ref_t ref, import_state_t state,
    uint64_t received, uint64_t expected, const char* uid, const char* title,
    const char* container, bool uncertain) {
    if (!ref) return 0;
    jobs_queued(ref, JOB_IMPORT, uid, title, container, "ps5");
    const char* phase = state == IMPORT_RECEIVING ? "receiving" :
        state == IMPORT_VERIFYING ? "verifying" : state == IMPORT_RECOVERING ? "recovering" : "ready";
    jobs_phase(ref, "ps5", phase, expected, state == IMPORT_RECEIVING && expected > 0);
    if (state == IMPORT_RECEIVING) {
        jobs_ref_t previous = jobs_bind(ref);
        jobs_progress(received, expected, expected > 0); jobs_bind(previous);
    }
    if (uncertain) jobs_finish(ref, JOB_UNKNOWN, "import_state_unknown");
    else if (state == IMPORT_READY || state == IMPORT_COMMITTED) jobs_finish(ref, JOB_DONE, "");
    else if (state == IMPORT_FAILED) jobs_finish(ref, JOB_FAILED, "import_failed");
    return ref;
}

static atomic_bool s_sessions_observed_complete = ATOMIC_VAR_INIT(false);
static bool jobs_observe_sessions(void) {
    bool complete = true;
    jobs_ref_t import_before = jobs_native_current(JOB_IMPORT);
    import_jobs_snapshot_t imported;
    if (import_session_jobs_snapshot(&imported) != IMPORT_JOBS_OBSERVED) complete = false;
    else if (imported.current_present)
        jobs_import_observe(jobs_native_observe(JOB_IMPORT, imported.native_id, import_before), imported.state, imported.received,
            imported.expected, imported.user_uid, imported.title_id, imported.container,
            imported.uncertain || imported.observation_only);
    else jobs_native_absent(JOB_IMPORT, import_before);
    jobs_ref_t update_before = jobs_native_current(JOB_UPDATE);
    update_jobs_snapshot_t update;
    if (update_jobs_snapshot(&update) != UPDATE_JOBS_OBSERVED) complete = false;
    else if (update.current_present) {
        jobs_ref_t ref = jobs_native_observe(JOB_UPDATE, update.native_id, update_before);
        jobs_queued(ref, JOB_UPDATE, "", "", "", "ps5");
        jobs_phase(ref, "ps5", update.receiving ? "receiving" : "verifying", update.expected,
                   update.receiving && update.expected > 0);
        if (update.receiving) {
            jobs_ref_t previous = jobs_bind(ref);
            jobs_progress(update.received, update.expected, update.expected > 0); jobs_bind(previous);
        }
        if (update.uncertain) jobs_finish(ref, JOB_UNKNOWN, "update_state_unknown");
    } else jobs_native_absent(JOB_UPDATE, update_before);
    return complete;
}

static void jobs_json_number(char** p, char* end, uint64_t number, bool known) {
    if (known) jappendf(p, end, "%llu", (unsigned long long)number);
    else jappendf(p, end, "null");
}

static void handle_backup_cancel(int fd,const char* body) {
    char id[32]={0},boot[65]={0};
    json_get_string(body,"id",id,sizeof(id));json_get_string(body,"boot_id",boot,sizeof(boot));
    uint64_t value=0;
    for (const char* p=id;*p;p++) {
        if (*p<'0'||*p>'9'||value>(UINT64_MAX-(unsigned)(*p-'0'))/10) {
            reply_json(fd,400,"{\"ok\":false,\"error\":\"invalid_job\"}");return;
        }
        value=value*10+(unsigned)(*p-'0');
    }
    if (!value || strcmp(boot,update_boot_id()) || !backup_control_request(value)) {
        reply_json(fd,409,"{\"ok\":false,\"error\":\"backup_not_cancelable\"}");return;
    }
    reply_json(fd,200,"{\"ok\":true,\"cancel_requested\":true,\"finished\":false}");
}

static void handle_jobs(int fd) {
    bool sessions_complete = s_http_observing ? atomic_load(&s_sessions_observed_complete) : jobs_observe_sessions();
    jobs_snapshot_t* snapshot = calloc(1, sizeof(*snapshot));
    // Every string below has a bounded allowlist in the observer; leave room for JSON escaping.
    size_t capacity = 1024 + JOBS_SNAPSHOT_MAX * 3072;
    char* body = malloc(capacity);
    if (!snapshot || !body || !jobs_snapshot(snapshot)) {
        free(snapshot); free(body);
        reply_json(fd, 503, "{\"ok\":false,\"error\":\"jobs_observation_unavailable\"}"); return;
    }
    char* p = body; char* end = body + capacity;
    jappendf(&p, end, "{\"ok\":true,\"version\":\"%s\",\"boot_id\":", TOSTONSYNC_VERSION);
    jappend_json_string(&p, end, update_boot_id());
    jappendf(&p, end, ",\"complete\":%s,\"dropped_observations\":%llu,\"jobs\":[",
        sessions_complete && snapshot->complete ? "true" : "false",
        (unsigned long long)snapshot->dropped_observations);
    for (size_t i = 0; i < snapshot->count; i++) {
        const jobs_record_t* r = &snapshot->items[i];
        jappendf(&p, end, "%s{\"id\":\"%llu\",\"kind\":\"%s\",\"state\":\"%s\",\"uid\":",
            i ? "," : "", (unsigned long long)r->id, jobs_kind_name(r->kind), jobs_state_name(r->state));
        jappend_json_string(&p, end, r->user_uid);
        jappendf(&p, end, ",\"title_id\":"); jappend_json_string(&p, end, r->title_id);
        jappendf(&p, end, ",\"container\":"); jappend_json_string(&p, end, r->container);
        jappendf(&p, end, ",\"destination\":"); jappend_json_string(&p, end, r->destination);
        jappendf(&p, end, ",\"phase\":"); jappend_json_string(&p, end, r->phase);
        jappendf(&p, end, ",\"error\":"); jappend_json_string(&p, end, r->error);
        jappendf(&p, end, ",\"backup_detail\":"); jappend_json_string(&p, end, r->backup_detail);
        jappendf(&p, end, ",\"bytes_done\":"); jobs_json_number(&p, end, r->bytes_done, r->bytes_known);
        jappendf(&p, end, ",\"bytes_total\":"); jobs_json_number(&p, end, r->bytes_total, r->total_known);
        backup_control_status_t control={0};
        bool control_known=backup_control_observe(r->id,&control);
        jappendf(&p,end,",\"saved_destinations\":%u",r->saved_destinations|(control_known?control.saved:0));
        jappendf(&p,end,",\"cancelable\":%s,\"cancel_requested\":%s",
            control_known && control.active && !control.publishing ? "true":"false",
            control_known && control.requested ? "true":"false");
        jappendf(&p, end, ",\"phase_epoch\":%llu,\"started_unix\":", (unsigned long long)r->phase_epoch);
        bool native_session = r->kind == JOB_IMPORT || r->kind == JOB_UPDATE;
        // A recovered session's first observation is not its actual start or finish time.
        jobs_json_number(&p, end, (uint64_t)r->started_unix, !native_session && r->started_unix > 0);
        jappendf(&p, end, ",\"updated_unix\":"); jobs_json_number(&p, end, (uint64_t)r->updated_unix, r->updated_unix > 0);
        jappendf(&p, end, ",\"finished_unix\":"); jobs_json_number(&p, end, (uint64_t)r->finished_unix, !native_session && r->finished_unix > 0);
        jappendf(&p, end, "}");
    }
    jappendf(&p, end, "]}"); reply_json(fd, 200, body);
    free(body); free(snapshot);
}

// --------------------------------------------------------------------
// Routing.
// --------------------------------------------------------------------

static const char* state_to_str(gdrive_state_t s) {
    switch (s) {
        case GDRIVE_STATE_NOT_CONFIGURED: return "not_configured";
        case GDRIVE_STATE_NOT_SIGNED_IN:  return "not_signed_in";
        case GDRIVE_STATE_DEVICE_PENDING: return "device_pending";
        case GDRIVE_STATE_DEVICE_DENIED:  return "device_denied";
        case GDRIVE_STATE_READY:          return "ready";
        case GDRIVE_STATE_ERROR:          return "error";
    }
    return "unknown";
}

static void append_usb_observation(char** p, char* end,
                                   const usb_mount_t* mount, const char* prefix) {
    const char* keys[] = {"state", "reason", "fs_type", "device", "volume_id", "selection_reason"};
    const char* values[] = {usb_state_name(mount->state), mount->reason,
        mount->fs_type, mount->device, mount->volume_id, mount->selection_reason};
    for (size_t i = 0; i < sizeof(keys) / sizeof(keys[0]); i++) {
        jappendf(p, end, ",\"%s%s\":", prefix, keys[i]);
        jappend_json_string(p, end, values[i]);
    }
    jappendf(p, end, ",\"%smount_flags\":%llu,\"%sidentity_confirmed\":%s,"
        "\"%susable_count\":%zu,\"%smax_file_bytes\":%llu",
        prefix, (unsigned long long)mount->mount_flags,
        prefix, mount->identity_confirmed ? "true" : "false",
        prefix, (size_t)mount->usable_count, prefix, (unsigned long long)mount->max_file_bytes);
}

static void append_usb_mount(char** p, char* end, const usb_mount_t* mount) {
    jappendf(p, end, "{\"path\":"); jappend_json_string(p, end, mount->path);
    jappendf(p, end, ",\"name\":"); jappend_json_string(p, end, mount->display_name);
    jappendf(p, end, ",\"label_source\":"); jappend_json_string(p, end, mount->label_source);
    jappendf(p, end, ",\"free\":%llu,\"total\":%llu,\"space_known\":%s,"
        "\"writable\":%s,\"selected\":%s",
        (unsigned long long)mount->free_bytes, (unsigned long long)mount->total_bytes,
        mount->space_known ? "true" : "false", mount->writable ? "true" : "false",
        mount->selected ? "true" : "false");
    append_usb_observation(p, end, mount, "");
    jappendf(p, end, "}");
}

static void handle_status(int fd) {
    gdrive_account_t acc = {0};
    gdrive_diagnostic_t oauth_diag = {0};
    gdrive_get_account(&acc);
    gdrive_get_diagnostic(&oauth_diag);
    usb_mount_t usb_observation = {0}, usb_volumes[8] = {{0}};
    size_t usb_count = usb_observe_snapshot(&usb_observation, usb_volumes, 8);
    bool usb_present = usb_observation.path[0] != '\0';
    const char* usb_mount = usb_observation.path;
    const char* usb_name = usb_observation.display_name;
    const char* usb_label_source = usb_observation.label_source;
    uint64_t usb_free = usb_observation.free_bytes;
    uint64_t usb_total = usb_observation.total_bytes;
    int64_t usb_observed_unix = (int64_t)time(NULL);
    const char* usb_observation_reason = usb_observation.reason;
    char restore_title[16] = {0};
    char restore_msg[128] = {0};
    int restore_state = -1;
    int64_t restore_unix = 0;
    watcher_last_restore(restore_title, sizeof(restore_title),
                         &restore_state, restore_msg, sizeof(restore_msg),
                         &restore_unix);
    bool restore_selective = false;
    size_t restore_available = 0, restore_selected = 0, restore_written = 0;
    watcher_last_restore_scope(&restore_selective, &restore_available,
                               &restore_selected, &restore_written);
    portable_transaction_report_t restore_transaction = {0};
    if (restore_selective) watcher_last_portable_transaction(&restore_transaction);
    char backup_title[64] = {0};
    char backup_msg[768] = {0};
    int backup_state = -1;
    int64_t backup_unix = 0;
    watcher_last_backup(backup_title, sizeof(backup_title),
                        &backup_state, backup_msg, sizeof(backup_msg),
                        &backup_unix);
    history_last_backup_t history_backup;
    history_last_backup(&history_backup);
    const char* backup_source = backup_state >= 0 ? "memory" : "none";
    const char* history_state = history_backup.state == HISTORY_LAST_FOUND ? "found" :
        history_backup.state == HISTORY_LAST_CORRUPT ? "corrupt" :
        history_backup.state == HISTORY_LAST_UNREADABLE ? "unreadable" : "empty";
    if (backup_state < 0 && history_backup.state == HISTORY_LAST_FOUND) {
        backup_source = "history";
        snprintf(backup_title, sizeof(backup_title), "%s", history_backup.title);
        backup_unix = history_backup.when;
        backup_state = !strcmp(history_backup.outcome, "failed") ? 0 :
            !strcmp(history_backup.outcome, "partial") ? 6 : 1;
    }
    char google_cert_status[24] = {0};
    int google_cert_blocks = 0;
    int64_t google_cert_verified = 0;
    http_google_cert_status(google_cert_status, sizeof(google_cert_status),
                            &google_cert_blocks, &google_cert_verified);
    const char* drive_session = gdrive_get_session_presence();
    char buf[32768] = {0};
    char* p = buf;
    char* end = buf + sizeof(buf);
    // Hold the config lock for the snapshot so we never serialize a
    // half-applied settings write (config_apply_json mutates under the same
    // lock). Cheap: this runs only on a status poll, not the hot path.
    config_lock();
    jappendf(&p, end, "{\"app\":\"TostónSync\",\"ip\":");
    jappend_json_string(&p, end, s_lan_ip);
    jappendf(&p, end, ",\"console\":{\"name\":");
    jappend_json_string(&p, end, s_cfg->console.name);
    jappendf(&p, end, ",\"type\":");
    jappend_json_string(&p, end, s_cfg->console.type);
    jappendf(&p, end, ",\"role\":");
    jappend_json_string(&p, end, s_cfg->console.role);
    jappendf(&p, end, "}");
    jappendf(&p, end,
             ",\"port\":%d,\"pid\":%d,\"server_unix\":%lld,\"oauth_state\":",
             s_cfg->general.http_port, (int)getpid(),
             (long long)time(NULL));
    jappend_json_string(&p, end, state_to_str(gdrive_get_state()));
    jappendf(&p, end, ",\"drive_session\":");
    jappend_json_string(&p, end, drive_session);
    jappendf(&p, end, ",\"email\":");
    jappend_json_string(&p, end, acc.email);
    jappendf(&p, end, ",\"oauth_error\":");
    jappend_json_string(&p, end, oauth_diag.code);
    jappendf(&p, end, ",\"oauth_error_detail\":");
    jappend_json_string(&p, end, oauth_diag.detail);
    jappendf(&p, end,
             ",\"oauth_http_status\":%d,\"oauth_transport_error\":%d",
             oauth_diag.http_status, oauth_diag.transport_error);
    jappendf(&p, end,
        ",\"drive_used\":%llu,"
        "\"drive_total\":%llu,"
        "\"last_sync_unix\":%lld,"
        "\"queued_uploads\":%d,"
        "\"active_jobs\":%d,"
        "\"watcher\":",
        (unsigned long long)acc.quota_used_bytes,
        (unsigned long long)acc.quota_total_bytes,
        (long long)watcher_last_sync_unix(),
        watcher_queue_depth(),
        watcher_active_jobs());
    jappend_json_string(&p, end, watcher_is_running() ? "running" : "stopped");
    jappendf(&p, end,
        ",\"retention_max_versions\":%d,"
        "\"retention_max_size\":",
        s_cfg->retention.max_versions);
    jappend_json_string(&p, end, s_cfg->retention.max_total_size_per_title_str);
    jappendf(&p, end,
        ",\"usb_enabled\":%s,"
        "\"usb_present\":%s,"
        "\"usb_mount\":",
        s_cfg->usb.enabled ? "true" : "false",
        usb_present ? "true" : "false");
    jappend_json_string(&p, end, usb_mount);
    jappendf(&p, end, ",\"usb_name\":");
    jappend_json_string(&p, end, usb_name);
    jappendf(&p, end, ",\"usb_label_source\":");
    jappend_json_string(&p, end, usb_label_source);
    jappendf(&p, end, ",\"usb_space_known\":%s,\"usb_observed_unix\":%lld,"
             "\"usb_partition\":\"unknown\",\"usb_observation_reason\":",
             usb_observation.space_known ? "true" : "false", (long long)usb_observed_unix);
    jappend_json_string(&p, end, usb_observation_reason);
    append_usb_observation(&p, end, &usb_observation, "usb_");
    jappendf(&p, end, ",\"usb_volumes\":[");
    for (size_t i = 0; i < usb_count && i < 8; i++) {
        if (i) jappendf(&p, end, ",");
        append_usb_mount(&p, end, &usb_volumes[i]);
    }
    jappendf(&p, end, "]");
    jappendf(&p, end, ",\"usb_selected\":");
    jappend_json_string(&p, end,
                        s_cfg->usb.mount_path[0] ? s_cfg->usb.mount_path : "auto");
    jappendf(&p, end,
        ",\"usb_free\":%llu,"
        "\"usb_total\":%llu,"
        "\"last_backup_state\":%d,"
        "\"last_backup_unix\":%lld,"
        "\"last_backup_title\":",
        (unsigned long long)usb_free,
        (unsigned long long)usb_total,
        backup_state,
        (long long)backup_unix);
    jappend_json_string(&p, end, backup_title);
    jappendf(&p, end, ",\"last_backup_msg\":");
    jappend_json_string(&p, end, backup_msg);
    jappendf(&p, end, ",\"last_backup_source\":");
    jappend_json_string(&p, end, backup_source);
    jappendf(&p, end, ",\"last_backup_history_state\":");
    jappend_json_string(&p, end, history_state);
    jappendf(&p, end, ",\"last_backup_history_errno\":%d,"
             "\"last_backup_history_outcome\":", history_backup.error);
    jappend_json_string(&p, end, history_backup.outcome);
    jappendf(&p, end,
        ",\"last_restore_state\":%d,"
        "\"last_restore_unix\":%lld,"
        "\"last_restore_title\":",
        restore_state,
        (long long)restore_unix);
    jappend_json_string(&p, end, restore_title);
    jappendf(&p, end, ",\"last_restore_msg\":");
    jappend_json_string(&p, end, restore_msg);
    jappendf(&p, end, ",\"last_restore_selective\":%s,"
             "\"last_restore_available_slots\":%zu,\"last_restore_selected_slots\":%zu,"
             "\"last_restore_written_slots\":",
             restore_selective ? "true" : "false", restore_available,
             restore_selected);
    if (restore_selective && restore_transaction.publication_uncertain)
        jappendf(&p, end, "null");
    else jappendf(&p, end, "%zu", restore_written);
    if (restore_selective) {
        jappendf(&p, end, ",\"last_restore_transaction\":{\"restore_mode\":\"portable_selected\",\"result\":");
        jappend_json_string(&p, end, restore_transaction.result);
        jappendf(&p, end, ",\"workspace\":");
        jappend_json_string(&p, end, restore_transaction.workspace);
        jappendf(&p, end, ",\"detail\":");
        jappend_json_string(&p, end, restore_transaction.detail);
        jappendf(&p, end, ",\"plan_sha256\":");
        jappend_json_string(&p, end, restore_transaction.plan_sha256);
        jappendf(&p, end, ",\"authorized_images\":%zu,\"attempted_images\":%zu,\"written_images\":",
                 restore_transaction.authorized_images, restore_transaction.attempted_images);
        // An uncertain rename is not a known zero-write outcome. Keep the
        // durable lower bound separately, never present it as an exact total.
        if (restore_transaction.publication_uncertain) jappendf(&p, end, "null");
        else jappendf(&p, end, "%zu", restore_transaction.written_images);
        jappendf(&p, end, ",\"known_written_images\":%zu,\"verified_images\":%zu,"
                 "\"publication_uncertain\":%s,\"recovery_required\":%s,\"barrier_retained\":%s}",
                 restore_transaction.written_images, restore_transaction.verified_images,
                 restore_transaction.publication_uncertain ? "true" : "false",
                 restore_transaction.recovery_required ? "true" : "false",
                 restore_transaction.barrier_retained ? "true" : "false");
    }
    jappendf(&p, end,
             ",\"google_cert_status\":");
    jappend_json_string(&p, end, google_cert_status);
    jappendf(&p, end,
             ",\"google_cert_blocks\":%d,\"google_cert_last_verified\":%lld",
             google_cert_blocks, (long long)google_cert_verified);
    jappendf(&p, end, ",\"boot_id\":");
    jappend_json_string(&p, end, update_boot_id());
    jappendf(&p, end, ",\"version\":\"%s\",\"build\":\"%s\"}",
             TOSTONSYNC_VERSION, TOSTONSYNC_BUILD);
    config_unlock();
    reply_json(fd, p < end - 1 ? 200 : 503,
        p < end - 1 ? buf : "{\"error\":\"usb_observation_too_large\"}");
}

// Serve the live sync.log over HTTP so it can be read from a browser
// (http://<ps5-ip>:1993/api/log) without an FTP client that may cache stale
// copies. Cache-Control: no-store (set by reply_file) guarantees freshness.
typedef bool (*diagnostic_sink_t)(const char*,size_t,void*);
static bool diagnostic_visit(FILE* file,diagnostic_sink_t sink,void* context) {
    char* line=malloc(65536);if(!line)return false;
    bool ok=true,pem=false;int c;
    for (;;) {
        size_t n=0;bool oversized=false;
        while ((c=fgetc(file))!=EOF) {
            if(n<65535)line[n++]=(char)c;else oversized=true;
            if(c=='\n')break;
        }
        if(!n&&c==EOF)break;
        if(oversized){strcpy(line,"[redacted oversized log line]\n");n=strlen(line);pem=true;}
        else n=diagnostic_redact_state(line,n,&pem);
        if(!sink(line,n,context)){ok=false;break;}
    }
    if(ferror(file))ok=false;free(line);return ok;
}
static FILE* diagnostic_open(const char* path) {
    int fd=open(path,O_RDONLY|O_NOFOLLOW);if(fd<0)return NULL;struct stat st;
    if(fstat(fd,&st)||!S_ISREG(st.st_mode)){close(fd);return NULL;}
    FILE* f=fdopen(fd,"rb");if(!f)close(fd);return f;
}
typedef struct{char* text;size_t used,capacity;bool tail;}diagnostic_buffer_t;
static bool diagnostic_buffer(const char* text,size_t n,void* context) {
    diagnostic_buffer_t* b=context;
    if(b->tail){
        if(n>=b->capacity){text+=n-(b->capacity-1);n=b->capacity-1;b->used=0;}
        if(b->used+n>=b->capacity){size_t drop=b->used+n-(b->capacity-1);memmove(b->text,b->text+drop,b->used-drop);b->used-=drop;}
    }else if(b->used+n>=b->capacity)return false;
    memcpy(b->text+b->used,text,n);b->used+=n;b->text[b->used]=0;return true;
}
static char* diagnostic_read_file(const char* path,bool tail,size_t* length) {
    *length=0;FILE* f=diagnostic_open(path);if(!f)return NULL;
    diagnostic_buffer_t b={.capacity=tail?65537:16*1024*1024+1,.tail=tail};b.text=calloc(b.capacity,1);
    bool ok=b.text&&diagnostic_visit(f,diagnostic_buffer,&b);if(fclose(f))ok=false;
    if(!ok){free(b.text);return NULL;}
    if(tail&&b.used==b.capacity-1){char* newline=strchr(b.text,'\n');size_t skip=newline?(size_t)(newline-b.text)+1:b.used;memmove(b.text,b.text+skip,b.used-skip+1);b.used-=skip;}
    *length=b.used;return b.text;
}
static bool diagnostic_send(const char* text,size_t n,void* context) { return send_all(*(int*)context,text,n); }
static bool diagnostic_write(const char* text,size_t n,void* context) { return fwrite(text,1,n,context)==n; }
static void handle_log(int fd,const char* query) {
    char path[300];snprintf(path,sizeof(path),"%s/sync.log",s_cfg->paths.state_dir);
    if(query&&strstr(query,"tail=1")){
        size_t length;char* text=diagnostic_read_file(path,true,&length);
        if(!text){reply_text(fd,503,"log unavailable");return;}
        reply(fd,200,"text/plain; charset=utf-8",text,length,NULL);free(text);return;
    }
    FILE* f=diagnostic_open(path);if(!f){reply_text(fd,503,"log unavailable");return;}
    static const char head[]="HTTP/1.1 200 OK\r\nContent-Type: text/plain; charset=utf-8\r\nCache-Control: no-store\r\nX-Content-Type-Options: nosniff\r\n" HTTP_SECURITY_HEADERS "Connection: close\r\n\r\n";
    if(send_all(fd,head,sizeof(head)-1))(void)diagnostic_visit(f,diagnostic_send,&fd);
    fclose(f);
}

// Branding (name, accent, logo data URI) — baked in at build time via
// branding.h and changed only with the external branding-kit tool + rebuild.
// There is intentionally NO in-app way to edit it. The logo can be large, so
// the buffer is sized to it.
static void handle_branding(int fd) {
    const char* logo = BRAND_LOGO_DATAURI;
    size_t cap = strlen(logo) + 256;
    char* buf = (char*)malloc(cap);
    if (!buf) {
        reply_json(fd, 200,
            "{\"name\":\"" BRAND_NAME "\",\"accent\":\"" BRAND_ACCENT "\",\"logo\":\"\"}");
        return;
    }
    char* p = buf;
    char* end = buf + cap;
    jappendf(&p, end, "{\"name\":");
    jappend_json_string(&p, end, BRAND_NAME);
    jappendf(&p, end, ",\"accent\":");
    jappend_json_string(&p, end, BRAND_ACCENT);
    jappendf(&p, end, ",\"logo\":");
    jappend_json_string(&p, end, logo);
    jappendf(&p, end, ",\"logo_scale\":%s}", BRAND_LOGO_SCALE);
    reply_json(fd, 200, buf);
    free(buf);
}

static void handle_qr(int fd, const char* query) {
    char text[512] = {0};
    if (query) {
        const char* t = strstr(query, "text=");
        if (t) {
            t += 5;
            size_t i = 0;
            while (*t && *t != '&' && i + 1 < sizeof(text)) {
                if (*t == '+') text[i++] = ' ';
                else if (*t == '%' && isxdigit((unsigned char)t[1])
                         && isxdigit((unsigned char)t[2])) {
                    char h[3] = {t[1], t[2], 0};
                    text[i++] = (char)strtol(h, NULL, 16);
                    t += 2;
                } else text[i++] = *t;
                t++;
            }
        }
    }
    if (!text[0]) { reply_text(fd, 400, "missing text"); return; }
    char svg[16384];
    size_t n = qr_render_svg(text, 6, svg, sizeof(svg));
    if (!n) { reply_text(fd, 500, "qr render failed"); return; }
    reply(fd, 200, "image/svg+xml", svg, n, NULL);
}

static void handle_oauth_start(int fd) {
    const gdrive_device_flow_t* f = gdrive_device_flow_start();
    if (!f) {
        gdrive_diagnostic_t d = {0};
        gdrive_get_diagnostic(&d);
        char buf[768] = {0};
        char* p = buf;
        char* end = buf + sizeof(buf);
        jappendf(&p, end, "{\"ok\":false,\"error\":");
        jappend_json_string(&p, end, d.code[0] ? d.code : "oauth_start_failed");
        jappendf(&p, end, ",\"detail\":");
        jappend_json_string(&p, end, d.detail);
        jappendf(&p, end,
                 ",\"http_status\":%d,\"transport_error\":%d}",
                 d.http_status, d.transport_error);
        reply_json(fd, d.code[0] && strcmp(d.code, "not_configured") == 0
                       ? 400 : 503,
                   buf);
        return;
    }
    char buf[1024] = {0};
    char* p = buf;
    char* end = buf + sizeof(buf);
    jappendf(&p, end, "{\"ok\":true,\"state\":\"device_pending\",\"user_code\":");
    jappend_json_string(&p, end, f->user_code);
    jappendf(&p, end, ",\"verification_url\":");
    jappend_json_string(&p, end, f->verification_url);
    jappendf(&p, end, ",\"verification_url_complete\":");
    jappend_json_string(&p, end, f->verification_url_complete);
    jappendf(&p, end, ",\"interval\":%d,\"expires_in\":%d}",
             f->interval_seconds, f->expires_in_seconds);
    reply_json(fd, 200, buf);
}

static void handle_oauth_poll(int fd) {
    gdrive_state_t state = gdrive_device_flow_poll();
    gdrive_account_t account = {0};
    gdrive_diagnostic_t d = {0};
    gdrive_get_account(&account);
    gdrive_get_diagnostic(&d);
    char buf[768] = {0};
    char* p = buf;
    char* end = buf + sizeof(buf);
    jappendf(&p, end, "{\"ok\":true,\"state\":");
    jappend_json_string(&p, end, state_to_str(state));
    jappendf(&p, end, ",\"email\":");
    jappend_json_string(&p, end, account.email);
    jappendf(&p, end, ",\"error\":");
    jappend_json_string(&p, end, d.code);
    jappendf(&p, end, ",\"detail\":");
    jappend_json_string(&p, end, d.detail);
    jappendf(&p, end, ",\"http_status\":%d", d.http_status);
    jappendf(&p, end, "}");
    reply_json(fd, 200, buf);
}

static void handle_oauth_cancel(int fd) {
    gdrive_device_flow_cancel();
    reply_json(fd, 200, "{\"ok\":true}");
}

static void handle_signout(int fd) {
    gdrive_sign_out();
    reply_json(fd, 200, "{\"ok\":true}");
}

static void handle_sync(int fd) {
    watcher_jobs_admission_t observed = {0};
    int accepted = watcher_kick_sync_now_observed(&observed);
    if (accepted <= 0) {
        reply_json(fd, 503,
                   "{\"ok\":false,\"error\":\"no_backup_jobs_accepted\"}");
        return;
    }
    char body[4096], *p = body, *end = body + sizeof(body);
    jappendf(&p, end, "{\"ok\":true,\"accepted\":%d,\"boot_id\":", accepted);
    jappend_json_string(&p, end, update_boot_id());
    jappendf(&p, end, ",\"tracking_complete\":%s,\"job_ids\":[", observed.complete ? "true" : "false");
    for (size_t i = 0; i < observed.count; i++)
        jappendf(&p, end, "%s\"%llu\"", i ? "," : "", (unsigned long long)observed.items[i].id);
    jappendf(&p, end, "]}");
    reply_json(fd, 200, body);
}

typedef struct { const char* name; int kind; size_t capacity; bool required; } http_setting_field_t;
static bool http_settings_flat(const settings_json_t* d,const http_setting_field_t* fields,size_t count) {
    unsigned seen=0;
    for(int i=d->values[0].first;i>=0;i=d->values[i].next) {
        const settings_value_t* v=&d->values[i];size_t f=0;
        for(;f<count;f++)if(!strcmp(fields[f].name,v->key))break;
        if(f==count||v->kind!=fields[f].kind||(v->kind==SET_STRING&&strlen(v->text)>=fields[f].capacity))return false;
        seen|=1u<<f;
    }
    for(size_t i=0;i<count;i++)if(fields[i].required&&!(seen&(1u<<i)))return false;
    return true;
}
static bool http_settings_request(const char* path,const char* body,size_t length) {
    if(!strcmp(path,"/api/config"))return config_validate_json(body,length);
    static const http_setting_field_t alias[]={{"uid",SET_STRING,16,true},{"alias",SET_STRING,32,true}};
    static const http_setting_field_t title[]={{"title_id",SET_STRING,16,true},{"name",SET_STRING,64,true}};
    static const http_setting_field_t toggle[]={{"title_id",SET_STRING,16,true},{"backup",SET_BOOL,0,true}};
    static const http_setting_field_t hidden[]={{"title_id",SET_STRING,16,true},{"hidden",SET_BOOL,0,true}};
    static const http_setting_field_t auth[]={{"code",SET_STRING,64,false},{"enabled",SET_BOOL,0,false},{"reset_on_boot",SET_BOOL,0,false}};
    static const http_setting_field_t login[]={{"code",SET_STRING,64,true}};
    static const http_setting_field_t timezone[]={{"timezone",SET_STRING,64,true},{"offset",SET_STRING,14,true}};
    const http_setting_field_t* fields=NULL;size_t count=2;
    if(!strcmp(path,"/api/users/alias")||!strcmp(path,"/api/users/display-alias"))fields=alias;
    else if(!strcmp(path,"/api/titles/alias"))fields=title;
    else if(!strcmp(path,"/api/saves/toggle"))fields=toggle;
    else if(!strcmp(path,"/api/saves/hide"))fields=hidden;
    else if(!strcmp(path,"/api/auth/set")){fields=auth;count=3;}
    else if(!strcmp(path,"/api/login")){fields=login;count=1;}
    else if(!strcmp(path,"/api/backup-timezone"))fields=timezone;
    if(!fields)return true;
    settings_json_t* d=settings_parse(body,length);if(!d)return false;
    bool ok=http_settings_flat(d,fields,count);
    const settings_value_t* id=settings_member(d,&d->values[0],"title_id");
    if(id)ok=ok&&id->text[0]&&strspn(id->text,"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-")==strlen(id->text);
    const settings_value_t* uid=settings_member(d,&d->values[0],"uid");
    if(uid)ok=ok&&restore_uid_valid(uid->text);
    free(d);return ok;
}
static bool http_setting_text(const char* body,const char* key,char* out,size_t capacity) {
    if(!out||!capacity)return false;out[0]=0;settings_json_t* d=settings_parse(body,body?strlen(body):0);
    const settings_value_t* v=d?settings_member(d,&d->values[0],key):NULL;
    bool ok=v&&v->kind==SET_STRING&&strlen(v->text)<capacity;
    if(ok)strcpy(out,v->text);free(d);return ok;
}
static bool http_setting_bool(const char* body,const char* key) {
    settings_json_t* d=settings_parse(body,body?strlen(body):0);
    const settings_value_t* v=d?settings_member(d,&d->values[0],key):NULL;
    bool result=v&&v->kind==SET_BOOL&&v->boolean;free(d);return result;
}

static void handle_config_get(int fd) {
    char buf[8192];
    config_t cfg;
    if (!config_snapshot(&cfg)) {
        reply_json(fd, 503, "{\"ok\":false,\"error\":\"config_unavailable\"}");
        return;
    }
    config_to_json(&cfg, buf, sizeof(buf));
    reply_json(fd, 200, buf);
}

static bool backup_timezone_json_string(const char** cursor, char* out, size_t cap) {
    const char* p = *cursor;
    while (isspace((unsigned char)*p)) p++;
    if (*p++ != '"') return false;
    size_t n = 0;
    while (*p && *p != '"') {
        if ((unsigned char)*p < 0x20 || *p == '\\' || n + 1 >= cap) return false;
        out[n++] = *p++;
    }
    if (*p++ != '"') return false;
    out[n] = '\0'; *cursor = p;
    return true;
}

static bool backup_timezone_request(const char* body, char timezone[64], char offset[14]) {
    if (!body) return false;
    const char* p = body;
    bool have_timezone = false, have_offset = false;
    while (isspace((unsigned char)*p)) p++;
    if (*p++ != '{') return false;
    for (int i = 0; i < 2; i++) {
        char key[16];
        if (!backup_timezone_json_string(&p, key, sizeof(key))) return false;
        while (isspace((unsigned char)*p)) p++;
        if (*p++ != ':') return false;
        if (!strcmp(key, "timezone") && !have_timezone) {
            if (!backup_timezone_json_string(&p, timezone, 64)) return false;
            have_timezone = true;
        } else if (!strcmp(key, "offset") && !have_offset) {
            if (!backup_timezone_json_string(&p, offset, 14)) return false;
            have_offset = true;
        } else return false;
        while (isspace((unsigned char)*p)) p++;
        if (*p++ != (i == 0 ? ',' : '}')) return false;
    }
    while (isspace((unsigned char)*p)) p++;
    return !*p && have_timezone && have_offset;
}

static void handle_backup_timezone(int fd, const char* body) {
    char timezone[64], offset[14];
    if (!backup_timezone_request(body, timezone, offset)) {
        reply_json(fd, 400, "{\"ok\":false,\"error\":\"invalid_backup_timezone\"}"); return;
    }
    bool changed = false;
    cfg_backup_timezone_result_t result = config_backup_timezone_sync(timezone, offset, &changed);
    if (result == CFG_BACKUP_TIMEZONE_OK)
        reply_json(fd, 200, changed ? "{\"ok\":true,\"changed\":true}" : "{\"ok\":true,\"changed\":false}");
    else if (result == CFG_BACKUP_TIMEZONE_INVALID)
        reply_json(fd, 400, "{\"ok\":false,\"error\":\"invalid_backup_timezone\"}");
    else if (result == CFG_BACKUP_TIMEZONE_STALE)
        reply_json(fd, 409, "{\"ok\":false,\"error\":\"timezone_changed\"}");
    else if (result == CFG_BACKUP_TIMEZONE_UNAVAILABLE)
        reply_json(fd, 503, "{\"ok\":false,\"error\":\"config_unavailable\"}");
    else reply_json(fd, 500, "{\"ok\":false,\"error\":\"backup_timezone_save_failed\"}");
}

static void handle_config_post(int fd, const char* body) {
    if (!body || !*body) { reply_text(fd, 400, "empty body"); return; }
    config_t before, after;
    if (!config_snapshot(&before)) {
        reply_json(fd, 503, "{\"ok\":false,\"error\":\"config_unavailable\"}");
        return;
    }
    if (config_apply_json(body)) {
        if (!config_snapshot(&after)) {
            reply_json(fd, 503, "{\"ok\":false,\"error\":\"config_unavailable\"}");
            return;
        }
        // Only an actual Drive-settings change grants provider work. Trigger,
        // language and other local saves must not load/refresh stored tokens.
        if (memcmp(&before.gdrive, &after.gdrive, sizeof(before.gdrive)) != 0)
            gdrive_reconfigure(&after);
        bool selected_usb = strcmp(before.usb.mount_path, after.usb.mount_path) != 0 &&
            after.usb.mount_path[0] && strcmp(after.usb.mount_path, "auto") != 0;
        if (selected_usb) {
            bool identified = usb_select_volume_identity(after.usb.mount_path);
            reply_json(fd, 200, identified
                ? "{\"ok\":true,\"usb_identity_confirmed\":true}"
                : "{\"ok\":true,\"usb_identity_confirmed\":false}");
        } else reply_json(fd, 200, "{\"ok\":true}");
    } else {
        reply_text(fd, 400, "invalid config patch");
    }
}

static void handle_restore(int fd, const char* body) {
    if (!restore_selection_legacy_request(body)) {
        reply_json(fd, 400, "{\"ok\":false,\"error\":\"selective_restore_requires_import_commit\"}");
        return;
    }
    char uid[16]; bool uid_explicit;
    if (!restore_request_uid(body, uid, &uid_explicit)) {
        reply_json(fd, 400, "{\"ok\":false,\"error\":\"invalid_restore_uid\"}");
        return;
    }
    // file_id may be a Drive id OR a full USB path, so size generously.
    char title[16] = {0}, file_id[320] = {0}, user[32] = {0};
    json_get_string(body, "title_id", title, sizeof(title));
    json_get_string(body, "file_id",  file_id, sizeof(file_id));
    // user is a hint, not portable overwrite authority. The shared worker
    // requires a verified local owner and refuses ambiguous automatic selection.
    json_get_string(body, "user", user, sizeof(user));
    if (!title[0] || !file_id[0]) {
        reply_text(fd, 400, "missing title_id or file_id");
        return;
    }
    watcher_job_admission_t observed = {0};
    if (watcher_restore_async_observed(uid_explicit ? uid : (user[0] ? user : NULL),
                                       title, file_id, &observed, uid_explicit, NULL)) {
        jobs_queued_reply(fd, observed.id, observed.coalesced);
    } else {
        reply_text(fd, 500, "restore queue failed");
    }
}

static void url_decode_inplace(char* s) {
    if (!s) return;
    char* r = s;
    char* w = s;
    while (*r) {
        if (*r == '%' && isxdigit((unsigned char)r[1]) &&
            isxdigit((unsigned char)r[2])) {
            char h[3] = { r[1], r[2], 0 };
            *w++ = (char)strtol(h, NULL, 16);
            r += 3;
        } else if (*r == '+') {
            *w++ = ' ';
            r++;
        } else {
            *w++ = *r++;
        }
    }
    *w = '\0';
}

static bool query_get_decoded(const char* query, const char* key,
                              char* out, size_t out_sz) {
    if (!out || out_sz == 0) return false;
    out[0] = '\0';
    if (!query || !key || !key[0]) return false;
    size_t kl = strlen(key);
    const char* p = query;
    while (*p) {
        const char* eq = strchr(p, '=');
        const char* amp = strchr(p, '&');
        if (!amp) amp = p + strlen(p);
        if (eq && eq < amp && (size_t)(eq - p) == kl &&
            strncmp(p, key, kl) == 0) {
            size_t n = (size_t)(amp - eq - 1);
            if (n >= out_sz) n = out_sz - 1;
            memcpy(out, eq + 1, n);
            out[n] = '\0';
            url_decode_inplace(out);
            return true;
        }
        p = *amp ? amp + 1 : amp;
    }
    return false;
}

static bool title_id_candidate(const char* s) {
    if (!s) return false;
    for (size_t i = 0; i < 4; i++) {
        if (!(s[i] >= 'A' && s[i] <= 'Z')) return false;
    }
    for (size_t i = 4; i < 9; i++) {
        if (!(s[i] >= '0' && s[i] <= '9')) return false;
    }
    return s[9] == '\0';
}

// Shared builder state for /api/titles enumeration.
typedef struct {
    char* p;
    char* end;
    int   first;
} titles_ctx_t;

static void titles_cb(const char* user_alias,
                      const char* user_uid,
                      const char* title_id,
                      const char* game_name,
                      bool included,
                      void* ud) {
    (void)game_name;
    (void)included;
    titles_ctx_t* c = (titles_ctx_t*)ud;
    // Legacy endpoint: keep it local and cheap. Backup versions are exposed by
    // /api/backups/catalog; querying Drive once per title could monopolize the
    // global Drive lock and make an old client stall the daemon for minutes.
    jappendf(&c->p, c->end, "%s{\"user\":", c->first ? "" : ",");
    jappend_json_string(&c->p, c->end, user_alias ? user_alias : "default");
    jappendf(&c->p, c->end, ",\"uid\":");
    jappend_json_string(&c->p, c->end, user_uid ? user_uid : "");
    jappendf(&c->p, c->end, ",\"title_id\":");
    jappend_json_string(&c->p, c->end, title_id);
    jappendf(&c->p, c->end,
        ",\"versions\":0,\"size_bytes\":0,\"last_unix\":0}");
    c->first = 0;
}

static void handle_titles(int fd) {
    enum { CAP = 128 * 1024 };
    char* buf = (char*)calloc(1, CAP);
    if (!buf) { reply_text(fd, 503, "out of memory"); return; }
    titles_ctx_t c = { buf, buf + CAP, 1 };
    jappendf(&c.p, c.end, "{\"titles\":[");
    watcher_enumerate_saves(titles_cb, &c);
    jappendf(&c.p, c.end, "]}");
    reply_json(fd, 200, buf);
    free(buf);
}

// Region is catalogue metadata, not save compatibility or account identity.
static void append_public_metadata(char** p, char* end,
                                   const public_metadata_t* metadata) {
    bool available = strcmp(metadata->status, "available") == 0;
    jappendf(p, end, ",\"region\":");
    jappend_json_string(p, end, available ? metadata->region : "");
    jappendf(p, end, ",\"region_source\":");
    jappend_json_string(p, end,
                        available && metadata->region[0] ?
                        (metadata->source[0] ? metadata->source : "ProsperoPatches") : "");
    jappendf(p, end, ",\"source\":");
    jappend_json_string(p, end, available ? metadata->source : "");
    jappendf(p, end, ",\"source_url\":");
    jappend_json_string(p, end, available ? metadata->source_url : "");
    jappendf(p, end, ",\"content_id\":");
    jappend_json_string(p, end, available ? metadata->content_id : "");
}

static void append_public_metadata_diagnostic(char** p, char* end,
                                              const public_metadata_t* metadata) {
    jappendf(p, end, ",\"diagnostic\":{\"reason\":");
    jappend_json_string(p, end, metadata->reason[0] ? metadata->reason : "previous_failure_unknown");
    jappendf(p, end, ",\"http_status\":%d,\"transport_error\":%d,\"ssl_error\":%d,"
             "\"ssl_detail\":\"0x%lx\",\"cache_state\":",
             metadata->http_status, metadata->transport_error, metadata->ssl_error, metadata->ssl_detail);
    jappend_json_string(p, end, metadata->cache_state);
    jappendf(p, end, ",\"cache_errno\":%d,\"cached\":%s}",
             metadata->cache_errno, metadata->cached ? "true" : "false");
}

static void append_public_catalog(char** p, char* end, const title_catalog_status_t* c) {
    jappendf(p, end, ",\"catalog\":{\"status\":"); jappend_json_string(p, end, c->status);
    jappendf(p, end, ",\"reason\":"); jappend_json_string(p, end, c->reason);
    jappendf(p, end, ",\"rows\":%zu,\"checked_unix\":%lld,\"retry_after_unix\":%lld,"
             "\"http_status\":%d,\"transport_error\":%d,\"ssl_error\":%d,\"ssl_detail\":\"0x%lx\","
             "\"cache_errno\":%d,\"cached\":%s}", c->rows,
             (long long)c->checked_unix, (long long)c->retry_after_unix, c->http_status,
             c->transport_error, c->ssl_error, c->ssl_detail, c->cache_errno, c->cached ? "true" : "false");
}

static void append_public_artwork(char** p, char* end, const public_artwork_t* a) {
    jappendf(p, end, ",\"artwork\":{\"status\":"); jappend_json_string(p, end, a->status);
    jappendf(p, end, ",\"reason\":"); jappend_json_string(p, end, a->reason);
    jappendf(p, end, ",\"source_url\":"); jappend_json_string(p, end, a->source_url);
    jappendf(p, end, ",\"mime\":"); jappend_json_string(p, end, a->mime);
    jappendf(p, end, ",\"width\":%u,\"height\":%u,\"checked_unix\":%lld,\"retry_after_unix\":%lld,"
             "\"http_status\":%d,\"transport_error\":%d,\"ssl_error\":%d,\"ssl_detail\":\"0x%lx\","
             "\"cache_errno\":%d,\"cached\":%s}", a->width, a->height,
             (long long)a->checked_unix, (long long)a->retry_after_unix, a->http_status,
             a->transport_error, a->ssl_error, a->ssl_detail, a->cache_errno, a->cached ? "true" : "false");
}

static void saves_cb(const char* user_alias,
                     const char* user_uid,
                     const char* title_id,
                     const char* game_name,
                     bool included,
                     void* ud) {
    titles_ctx_t* c = (titles_ctx_t*)ud;
    jappendf(&c->p, c->end, "%s{\"user\":", c->first ? "" : ",");
    jappend_json_string(&c->p, c->end, user_alias ? user_alias : "default");
    jappendf(&c->p, c->end, ",\"uid\":");
    jappend_json_string(&c->p, c->end, user_uid ? user_uid : "");
    jappendf(&c->p, c->end, ",\"title_id\":");
    jappend_json_string(&c->p, c->end, title_id);
    // Watcher names may be cached or from an earlier app language. Only the
    // fresh metadata resolver may re-seed the automatic cache as "live".
    const char* manual = config_title_alias_for(title_id);
    char automatic[96];
    bool real_name = (s_http_observing ? metacache_resolve_name_readonly : metacache_resolve_name)
        (title_id, game_name, automatic, sizeof(automatic));
    if (manual[0]) titlename_copy_utf8(automatic, sizeof(automatic), manual);
    jappendf(&c->p, c->end, ",\"game\":");
    jappend_json_string(&c->p, c->end, automatic);
    // Orphan = no name from anywhere (manual/metadata/cache). The save still exists
    // and backs up normally; the UI shows a hint + a "Name" button.
    jappendf(&c->p, c->end, ",\"orphan\":%s",
             (!manual[0] && !real_name) ? "true" : "false");
    public_metadata_t metadata;
    public_metadata_cached(title_id, &metadata);
    append_public_metadata(&c->p, c->end, &metadata);

    // On-disk size of the live save folder, so the UI can show how much
    // each game's save weighs. Cheap metadata walk; /api/saves is only
    // hit on a manual refresh, not the status poll.
    uint64_t size_bytes = 0;
    int64_t  modified_unix = 0;
    fs_backup_estimate_t backup_estimate = { .reason = "unavailable" };
    bool backup_estimate_known = false;
    int64_t backup_estimate_unix = 0;
    config_t cfg;
    if (config_snapshot(&cfg) && user_uid && user_uid[0] &&
        title_id && title_id[0]) {
        char sp[300];
        int path_len = snprintf(sp, sizeof(sp), "%s/%s/savedata_prospero/%s",
                 cfg.paths.saves_root, user_uid, title_id);
        size_bytes = fs_dir_size(sp);
        modified_unix = fs_dir_newest_mtime(sp);  // for "needs backup" compare
        if (path_len >= 0 && (size_t)path_len < sizeof(sp)) {
            backup_estimate_known = fs_backup_size_estimate(sp, &backup_estimate);
            backup_estimate_unix = (int64_t)time(NULL);
        }
    }
    jappendf(&c->p, c->end,
             ",\"backup_estimate_known\":%s,\"backup_estimate_bytes\":%llu,"
             "\"backup_estimate_unix\":%lld,\"backup_estimate_errno\":%d,"
             "\"backup_estimate_reason\":",
             backup_estimate_known ? "true" : "false",
             (unsigned long long)backup_estimate.estimated_bytes,
             (long long)backup_estimate_unix, backup_estimate.error);
    jappend_json_string(&c->p, c->end, backup_estimate.reason);
    size_t rollback_images = 0;
    bool rollback_available = watcher_retained_rollback_available(
        user_uid, title_id, &rollback_images, true);
    jappendf(&c->p, c->end,
             ",\"size_bytes\":%llu,\"modified_unix\":%lld,"
             "\"included\":%s,\"hidden\":%s,"
             "\"rollback_available\":%s,\"rollback_images\":%zu}",
             (unsigned long long)size_bytes, (long long)modified_unix,
             included ? "true" : "false",
             config_title_is_hidden(title_id) ? "true" : "false",
             rollback_available ? "true" : "false", rollback_images);
    c->first = 0;
}

typedef struct { const char* uid; const char* title; char game[96]; } naming_title_t;
static void naming_title_cb(const char* alias, const char* uid, const char* title,
                            const char* game, bool included, void* userdata) {
    (void)alias; (void)included;
    naming_title_t* n = userdata;
    if (uid && title && !strcmp(uid, n->uid) && !strcmp(title, n->title))
        snprintf(n->game, sizeof(n->game), "%s", game ? game : "");
}

static void handle_backup_names(int fd, const char* query) {
    char uid[16], title[16], checked[16];
    if (!query_get_decoded(query, "uid", uid, sizeof(uid)) ||
        !query_get_decoded(query, "title_id", title, sizeof(title)) ||
        !backup_folder_code(uid, false, checked, sizeof(checked)) || strcmp(uid, checked) ||
        !backup_folder_code(title, true, checked, sizeof(checked)) || strcmp(title, checked)) {
        reply_text(fd, 400, "invalid backup identity"); return;
    }
    naming_title_t source = { .uid = uid, .title = title };
    watcher_enumerate_saves(naming_title_cb, &source);
    backup_names_t names;
    if (!backup_names_current(uid, title, source.game, "Manual", time(NULL), &names)) {
        reply_text(fd, 503, "backup naming unavailable"); return;
    }
    char buf[2048], *p = buf, *end = buf + sizeof(buf);
    jappendf(&p, end, "{\"schema\":1,\"uid\":"); jappend_json_string(&p, end, uid);
    jappendf(&p, end, ",\"title_id\":"); jappend_json_string(&p, end, title);
    jappendf(&p, end, ",\"user_folder\":"); jappend_json_string(&p, end, names.user_folder);
    jappendf(&p, end, ",\"title_folder\":"); jappend_json_string(&p, end, names.title_folder);
    jappendf(&p, end, ",\"filename\":"); jappend_json_string(&p, end, names.filename);
    jappendf(&p, end, ",\"game\":"); jappend_json_string(&p, end, names.game);
    jappendf(&p, end, ",\"timezone\":"); jappend_json_string(&p, end, names.timezone);
    jappendf(&p, end, ",\"title_rename_requested\":%s", names.title_rename_requested ? "true" : "false");
    jappendf(&p, end, "}"); reply_json(fd, 200, buf);
}

static void handle_saves(int fd) {
    enum { CAP = 128 * 1024 };
    char* buf = (char*)calloc(1, CAP);
    if (!buf) { reply_text(fd, 503, "out of memory"); return; }
    titles_ctx_t c = { buf, buf + CAP, 1 };
    jappendf(&c.p, c.end, "{\"saves\":[");
    watcher_enumerate_saves(saves_cb, &c);
    jappendf(&c.p, c.end, "]}");
    reply_json(fd, 200, buf);
    free(buf);
}

static void handle_title_metadata(int fd, const char* query) {
    // One literal identifier, no arbitrary URL, encoded path or duplicate key.
    if (!query || strlen(query) != 18 ||
        strncmp(query, "title_id=PPSA", 13) != 0) {
        reply_text(fd, 400, "expected title_id=PPSA followed by five digits");
        return;
    }
    for (size_t i = 13; i < 18; ++i) {
        if (query[i] < '0' || query[i] > '9') {
            reply_text(fd, 400, "invalid Title ID");
            return;
        }
    }
    const char* title_id = query + 9;
    title_catalog_status_t catalog;
    title_catalog_refresh(&catalog); // bounded lazy refresh; never a status-poll task
    public_metadata_t metadata, page;
    bool catalog_found = title_catalog_lookup(title_id, &metadata);
    public_artwork_t artwork = {0};
    bool local_icon = metacache_has_icon(title_id);
    if (local_icon && catalog_found) public_metadata_cached(title_id, &page);
    else public_metadata_lookup(title_id, &page);
    if (!catalog_found) metadata = page;
    if (local_icon) {
        strcpy(artwork.status, "local"); strcpy(artwork.reason, "none"); artwork.cached = true;
    } else {
        public_artwork_lookup(title_id, page.artwork_url, &artwork);
        if (!page.artwork_url[0] && !strcmp(artwork.status, "unavailable")) {
            // A missing image is independent of the catalogue name/region.
            snprintf(artwork.reason, sizeof(artwork.reason), "%s",
                     strcmp(page.reason, "none") ? page.reason : "image_not_announced");
            artwork.http_status = page.http_status; artwork.transport_error = page.transport_error;
            artwork.ssl_error = page.ssl_error; artwork.ssl_detail = page.ssl_detail;
            artwork.cache_errno = page.cache_errno; artwork.cached = page.cached;
            artwork.checked_unix = page.checked_unix; artwork.retry_after_unix = page.retry_after_unix;
        }
    }
    char game[96];
    bool known = metacache_resolve_name(title_id, NULL, game, sizeof(game));
    // A verified response is usable even if its best-effort cache could not be
    // persisted. Local metadata/cache still takes precedence.
    if (!known && strcmp(metadata.status, "available") == 0 && metadata.name[0]) {
        titlename_copy_utf8(game, sizeof(game), metadata.name);
        known = game[0] != '\0';
    }
    const char* manual = config_title_alias_for(title_id);
    if (manual[0]) titlename_copy_utf8(game, sizeof(game), manual);
    char buf[8192], *p = buf, *end = buf + sizeof(buf);
    jappendf(&p, end, "{\"version\":\"%s\",\"title_id\":", TOSTONSYNC_VERSION);
    jappend_json_string(&p, end, title_id);
    jappendf(&p, end, ",\"game\":");
    jappend_json_string(&p, end, game);
    jappendf(&p, end, ",\"orphan\":%s,\"status\":",
             !manual[0] && !known ? "true" : "false");
    jappend_json_string(&p, end,
                        metadata.status[0] ? metadata.status : "unavailable");
    append_public_metadata(&p, end, &metadata);
    append_public_metadata_diagnostic(&p, end, &metadata);
    append_public_catalog(&p, end, &catalog);
    append_public_artwork(&p, end, &artwork);
    jappendf(&p, end, ",\"checked_unix\":%lld,\"retry_after_unix\":%lld}",
             (long long)metadata.checked_unix,
             (long long)metadata.retry_after_unix);
    reply_json(fd, 200, buf);
}

static void slots_cb(const char* dir_name,
                     const char* subtitle,
                     const char* detail,
                     const char* image_name,
                     uint64_t bytes,
                     bool system_slot,
                     void* ud) {
    titles_ctx_t* c = (titles_ctx_t*)ud;
    jappendf(&c->p, c->end, "%s{\"dir\":", c->first ? "" : ",");
    jappend_json_string(&c->p, c->end, dir_name ? dir_name : "");
    jappendf(&c->p, c->end, ",\"subtitle\":");
    jappend_json_string(&c->p, c->end, subtitle ? subtitle : "");
    jappendf(&c->p, c->end, ",\"detail\":");
    jappend_json_string(&c->p, c->end, detail ? detail : "");
    jappendf(&c->p, c->end,
             ",\"detail_source_timezone\":\"console/local\"");
    jappendf(&c->p, c->end, ",\"image\":");
    jappend_json_string(&c->p, c->end, image_name ? image_name : "");
    jappendf(&c->p, c->end, ",\"size_bytes\":%llu,\"system\":%s}",
             (unsigned long long)bytes, system_slot ? "true" : "false");
    c->first = 0;
}

static void handle_slots(int fd, const char* user_uid, const char* title_id) {
    if (!title_id || !title_id[0]) {
        reply_text(fd, 400, "missing title id");
        return;
    }
    enum { CAP = 128 * 1024 };
    char* buf = (char*)calloc(1, CAP);
    if (!buf) { reply_text(fd, 503, "out of memory"); return; }
    char err[160] = {0};
    titles_ctx_t c = { buf, buf + CAP, 1 };
    jappendf(&c.p, c.end, "{\"slots\":[");
    bool ok = watcher_enumerate_save_slots(user_uid, title_id, slots_cb, &c,
                                           err, sizeof(err));
    jappendf(&c.p, c.end, "]}");
    if (!ok) {
        char eb[256];
        snprintf(eb, sizeof(eb), "{\"ok\":false,\"error\":");
        char* p = eb + strlen(eb);
        char* end = eb + sizeof(eb);
        jappend_json_string(&p, end, err[0] ? err : "slot inspection failed");
        jappendf(&p, end, "}");
        reply_json(fd, 500, eb);
        free(buf);
        return;
    }
    reply_json(fd, 200, buf);
    free(buf);
}

static void handle_saves_toggle(int fd, const char* body) {
    if (!body) { reply_text(fd, 400, "missing body"); return; }
    char title[32] = {0};
    http_setting_text(body, "title_id", title, sizeof(title));
    bool backup = http_setting_bool(body,"backup");
    if (!title[0]) { reply_text(fd, 400, "missing title_id"); return; }
    if (config_set_title_backup(title, backup)) {
        reply_json(fd, 200, "{\"ok\":true}");
    } else {
        reply_text(fd, 500, "title filter update failed");
    }
}

// POST {"title_id":"PPSA01650","hidden":true} — hide/unhide a title from the
// Saves list. Cosmetic only; does not change whether it is backed up.
static void handle_saves_hide(int fd, const char* body) {
    if (!body) { reply_text(fd, 400, "missing body"); return; }
    char title[32] = {0};
    http_setting_text(body, "title_id", title, sizeof(title));
    bool hidden = http_setting_bool(body,"hidden");
    if (!title[0]) { reply_text(fd, 400, "missing title_id"); return; }
    if (config_set_title_hidden(title, hidden)) {
        reply_json(fd, 200, "{\"ok\":true}");
    } else {
        reply_text(fd, 500, "hide update failed");
    }
}

static void rollback_row(const char* id,int64_t date,uint64_t bytes,size_t images,void* context) {
    titles_ctx_t* c=context;jappendf(&c->p,c->end,"%s{\"id\":",c->first?"":",");
    jappend_json_string(&c->p,c->end,id);
    jappendf(&c->p,c->end,",\"date_unix\":%lld,\"size_bytes\":%llu,\"image_count\":%zu}",(long long)date,(unsigned long long)bytes,images);
    c->first=0;
}
static bool rollback_query_uid(const char* query, char uid[16], bool* explicit_uid) {
    uid[0] = '\0'; *explicit_uid = false;
    bool have_user = false;
    if (!query) return false;
    for (const char* p = query; *p;) {
        const char* end = strchr(p, '&'); if (!end) end = p + strlen(p);
        const char* eq = memchr(p, '=', (size_t)(end - p));
        if (!eq) return false;
        char key[64]; size_t n = (size_t)(eq - p);
        if (n >= sizeof(key)) return false;
        memcpy(key, p, n); key[n] = '\0';
        // Encoded keys/NUL must not make a second selector invisible.
        if (strchr(key, '%') || strchr(key, '+')) return false;
        if (!strcmp(key, "source_uid") || !strcmp(key, "target_uid")) return false;
        if (!strcmp(key, "user")) have_user = true;
        if (!strcmp(key, "uid")) {
            if (*explicit_uid || end - eq - 1 != 8) return false;
            memcpy(uid, eq + 1, 8); uid[8] = '\0';
            if (!restore_uid_valid(uid)) return false;
            *explicit_uid = true;
        }
        p = *end ? end + 1 : end;
    }
    return !(*explicit_uid && have_user);
}

static void handle_rollbacks(int fd,const char* query) {
    char user[32]={0},title[16]={0},uid[16]; bool uid_explicit;
    if(!rollback_query_uid(query,uid,&uid_explicit) ||
       (!uid_explicit && !query_get_decoded(query,"user",user,sizeof(user))) ||
       !query_get_decoded(query,"title_id",title,sizeof(title))){reply_text(fd,400,"invalid rollback identity");return;}
    enum{CAP=64*1024};char* buf=calloc(1,CAP);if(!buf){reply_text(fd,503,"out of memory");return;}
    titles_ctx_t c={buf,buf+CAP,1};jappendf(&c.p,c.end,"{\"rollbacks\":[");
    bool ok=watcher_list_rollbacks(uid_explicit?uid:user,title,rollback_row,&c,uid_explicit);
    jappendf(&c.p,c.end,"],\"ok\":%s}",ok?"true":"false");reply_json(fd,ok?200:409,buf);free(buf);
}

static void handle_rollback_delete(int fd, const char* body) {
    char uid[16]; bool uid_explicit;
    if (!restore_request_uid(body, uid, &uid_explicit)) {
        reply_json(fd, 400, "{\"ok\":false,\"error\":\"invalid_restore_uid\"}"); return;
    }
    char title[16] = {0}, user[32] = {0}, err[160] = {0};
    json_get_string(body, "title_id", title, sizeof(title));
    json_get_string(body, "user", user, sizeof(user));
    if (!title[0]) { reply_text(fd, 400, "missing title_id"); return; }
    char archive[256]={0};json_get_string(body,"archive_id",archive,sizeof(archive));
    const char* target = uid_explicit ? uid : (user[0] ? user : NULL);
    if (archive[0] ? watcher_delete_archived_rollback(target,title,archive,err,sizeof(err),uid_explicit) :
        watcher_delete_retained_rollback(target,title,err,sizeof(err),uid_explicit)) {
        reply_json(fd, 200, "{\"ok\":true}");
        return;
    }
    char out[256] = "{\"ok\":false,\"error\":";
    char* p = out + strlen(out);
    char* end = out + sizeof(out);
    jappend_json_string(&p, end, err[0] ? err : "rollback delete failed");
    jappendf(&p, end, "}");
    reply_json(fd, 409, out);
}

// POST {"title_id":"PPSA01650","uid":"1230fa00","destination":"usb"}.
// destination is optional; empty/default preserves the configured mode.
static void handle_backup(int fd, const char* body) {
    if (!body) { reply_text(fd, 400, "missing body"); return; }
    char title[32] = {0}, uid[16], destination[16] = {0}; bool uid_explicit;
    if (!restore_request_uid(body, uid, &uid_explicit)) {
        reply_text(fd, 400, "invalid backup uid"); return;
    }
    json_get_string(body, "title_id", title, sizeof(title));
    json_get_string(body, "destination", destination, sizeof(destination));
    if (!title[0]) { reply_text(fd, 400, "missing title_id"); return; }
    watcher_job_admission_t observed = {0};
    if (watcher_backup_title_to_async_observed(uid_explicit ? uid : NULL, title,
                                      destination[0] ? destination : NULL, &observed)) {
        jobs_queued_reply(fd, observed.id, observed.coalesced);
    } else {
        reply_text(fd, 500, "backup queue failed (title not found)");
    }
}

static void download_game_name(const char* title_id, char* out, size_t out_sz) {
    const char* manual = config_title_alias_for(title_id);
    if (manual && manual[0]) titlename_copy_utf8(out, out_sz, manual);
    else metacache_resolve_name(title_id, NULL, out, out_sz);
}

static void filename_component(const char* input, char* out, size_t out_sz) {
    size_t n = 0;
    bool underscore = false;
    for (const unsigned char* p = (const unsigned char*)input;
         p && *p && n + 1 < out_sz; p++) {
        if (isalnum(*p)) {
            out[n++] = (char)*p;
            underscore = false;
        } else if (!underscore && n) {
            out[n++] = '_';
            underscore = true;
        }
    }
    while (n && out[n - 1] == '_') n--;
    out[n] = '\0';
}

static bool prepared_identity(const struct stat* a, const struct stat* b) {
    return S_ISREG(b->st_mode) && a->st_dev == b->st_dev && a->st_ino == b->st_ino &&
        a->st_size == b->st_size && a->st_mtime == b->st_mtime && a->st_ctime == b->st_ctime &&
#ifdef __APPLE__
        a->st_mtimespec.tv_nsec == b->st_mtimespec.tv_nsec && a->st_ctimespec.tv_nsec == b->st_ctimespec.tv_nsec;
#else
        a->st_mtim.tv_nsec == b->st_mtim.tv_nsec && a->st_ctim.tv_nsec == b->st_ctim.tv_nsec;
#endif
}
static void reply_prepared(int fd, const char* path, const char* type,
                           const char* name, const watcher_raw_info_t* raw, const char* extra, bool release, bool temporary, bool owned) {
    http_prepared_t item = { .file = -1 };
    unsigned char random[32];
    int entropy = open("/dev/urandom", O_RDONLY);
    ssize_t n = entropy >= 0 ? read(entropy, random, sizeof(random)) : -1;
    if (entropy >= 0) close(entropy);
    time_t now = time(NULL);
    if (n != sizeof(random) || now < 0 || !path || strlen(path) >= sizeof(item.path) ||
        (extra && strlen(extra) >= sizeof(item.extra))) {
        if (release) watcher_release_backup_file(path, temporary);
        reply_json(fd, 503, "{\"ok\":false,\"error\":\"download_preparation_unavailable\"}"); return;
    }
    item.file = open(path, O_RDONLY | O_NOFOLLOW);
    if (item.file < 0 || fstat(item.file, &item.identity) ||
        !S_ISREG(item.identity.st_mode) || item.identity.st_size < 0) {
        if (item.file >= 0) close(item.file);
        if (release) watcher_release_backup_file(path, temporary);
        reply_json(fd, 409, "{\"ok\":false,\"error\":\"download_file_unavailable\"}"); return;
    }
    if (owned && unlink(path)) {
        close(item.file); reply_json(fd, 503, "{\"error\":\"support_cleanup_failed\"}"); return;
    }
    // The open descriptor survives temporary-file unlink; release the original scratch lease now.
    if (release) watcher_release_backup_file(path, temporary);
    if (fstat(item.file, &item.identity)) {
        close(item.file); reply_json(fd, 409, "{\"error\":\"download_file_unavailable\"}"); return;
    }
    for (size_t i = 0; i < sizeof(random); i++) snprintf(item.id + i * 2, 3, "%02x", random[i]);
    snprintf(item.path, sizeof(item.path), "%s", path);
    snprintf(item.type, sizeof(item.type), "%s", type ? type : "application/octet-stream");
    snprintf(item.name, sizeof(item.name), "%s", name ? (name[0] ? name : "tostonsync.zip") : "bundle");
    snprintf(item.extra, sizeof(item.extra), "%s", extra ? extra : "");
    if (raw) { item.raw = *raw; item.raw_known = true; }
    item.active = true; item.expires = now + HTTP_PREPARED_SECONDS;
    pthread_mutex_lock(&s_prepared_lock);
    size_t slot = 0;
    while (slot < HTTP_PREPARED_MAX && s_prepared[slot].active) slot++;
    if (slot < HTTP_PREPARED_MAX) s_prepared[slot] = item;
    pthread_mutex_unlock(&s_prepared_lock);
    if (slot == HTTP_PREPARED_MAX) {
        close(item.file); reply_json(fd, 503, "{\"ok\":false,\"error\":\"downloads_busy\"}"); return;
    }
    char response[192];
    snprintf(response, sizeof(response), "{\"ok\":true,\"download_url\":\"/api/download-prepared/%s\"}", item.id);
    reply_json(fd, 200, response);
}
static void read_prepared(int fd, const char* id) {
    if (!id || strlen(id) != 64 || strspn(id, "0123456789abcdef") != 64) {
        reply_text(fd, 404, "not found"); return;
    }
    http_prepared_t item;
    size_t slot = HTTP_PREPARED_MAX;
    pthread_mutex_lock(&s_prepared_lock);
    for (size_t i = 0; i < HTTP_PREPARED_MAX; i++)
        if (s_prepared[i].active && !strcmp(s_prepared[i].id, id)) {
            slot = i; item = s_prepared[i]; s_prepared[i].readers++; break;
        }
    pthread_mutex_unlock(&s_prepared_lock);
    if (slot == HTTP_PREPARED_MAX) { reply_text(fd, 404, "not found"); return; }
    struct stat current;
    if (fstat(item.file, &current) || !prepared_identity(&item.identity, &current)) {
        reply_text(fd, 409, "download changed");
    } else {
        char name[160];
        // Preserve the attachment name and RAW completeness headers without buffering the ZIP.
        size_t j = 0;
        for (size_t i = 0; item.name[i] && j + 1 < sizeof(name); i++) {
            unsigned char c = (unsigned char)item.name[i];
            name[j++] = ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
                (c >= '0' && c <= '9') || c == '_' || c == '-' || c == '.') ? (char)c : '_';
        }
        name[j] = '\0';
        char raw[1024] = "";
        if (item.raw_known && item.raw.raw_completeness[0])
            snprintf(raw, sizeof(raw), "X-Toston-Raw-Completeness: %s\r\nX-Toston-Active-Images: %zu\r\n"
                "X-Toston-Service-Images: %zu\r\nX-Toston-Missing-Service-Images: %zu\r\n"
                "X-Toston-First-Missing-Service-Image: %s\r\n", item.raw.raw_completeness,
                item.raw.active_images, item.raw.service_images, item.raw.missing_service_images,
                item.raw.first_missing_service_image);
        char header[4096];
        int count = snprintf(header, sizeof(header), "HTTP/1.1 200 OK\r\nContent-Type: %s\r\n"
            "Content-Length: %llu\r\nContent-Disposition: attachment; filename=\"%s\"\r\n"
            "%s%sCache-Control: no-store\r\nX-Content-Type-Options: nosniff\r\n" HTTP_SECURITY_HEADERS "Connection: close\r\n\r\n",
            item.type, (unsigned long long)item.identity.st_size, name, raw, item.extra);
        bool sent = count > 0 && (size_t)count < sizeof(header) && send_all(fd, header, (size_t)count);
        char buf[8192]; off_t offset = 0;
        while (sent && offset < item.identity.st_size) {
            size_t want = (uint64_t)(item.identity.st_size - offset) < sizeof(buf)
                ? (size_t)(item.identity.st_size - offset) : sizeof(buf);
            ssize_t got = pread(item.file, buf, want, offset);
            if (got < 0 && errno == EINTR) continue;
            if (got <= 0) break;
            sent = send_all(fd, buf, (size_t)got); offset += got;
        }
    }
    pthread_mutex_lock(&s_prepared_lock); s_prepared[slot].readers--; pthread_mutex_unlock(&s_prepared_lock);
}
static void release_prepared(void) {
    time_t now = time(NULL);
    for (size_t i = 0; i < HTTP_PREPARED_MAX; i++) {
        http_prepared_t item = {0};
        pthread_mutex_lock(&s_prepared_lock);
        if (s_prepared[i].active && !s_prepared[i].readers && now >= s_prepared[i].expires) {
            item = s_prepared[i]; memset(&s_prepared[i], 0, sizeof(s_prepared[i]));
        }
        pthread_mutex_unlock(&s_prepared_lock);
        if (item.active) close(item.file);
    }
}

static void handle_download(int fd, const char* mode,
                            const char* user_uid, const char* title_id) {
    if (!mode || !title_id || !title_id[0]) {
        reply_text(fd, 400, "missing download target");
        return;
    }
    bool raw = false;
    const char* label = "decrypted";
    if (strcmp(mode, "raw") == 0 || strcmp(mode, "encrypted") == 0) {
        raw = true;
        label = "raw";
    } else if (strcmp(mode, "garlic") == 0 || strcmp(mode, "migration") == 0) {
        label = "garlic";
    } else if (strcmp(mode, "decrypted") != 0 && strcmp(mode, "smart") != 0) {
        reply_text(fd, 400, "invalid download mode");
        return;
    }

    char zip_path[320] = {0};
    char err[160] = {0};
    watcher_raw_info_t raw_info;
    memset(&raw_info, 0, sizeof(raw_info));
    bool ok = strcmp(mode, "migration") == 0
        ? watcher_make_migration_zip(user_uid, title_id,
                                     zip_path, sizeof(zip_path),
                                     err, sizeof(err))
        : (strcmp(label, "garlic") == 0)
        ? watcher_make_garlic_zip(user_uid, title_id,
                                  zip_path, sizeof(zip_path),
                                  err, sizeof(err))
        : watcher_make_download_zip(user_uid, title_id, raw,
                                    zip_path, sizeof(zip_path),
                                    &raw_info,
                                    err, sizeof(err));
    if (!ok) {
        reply_text(fd, 500, err[0] ? err : "download failed");
        return;
    }

    // Download filename: game + exact title + type + trigger + UTC timestamp.
    char dts[24];
    time_t dnow = time(NULL);
    struct tm dtm; gmtime_r(&dnow, &dtm);
    strftime(dts, sizeof(dts), "%Y%m%dT%H%M%SZ", &dtm);
    char game[128] = {0}, safe_game[96] = {0};
    download_game_name(title_id, game, sizeof(game));
    filename_component(game, safe_game, sizeof(safe_game));
    if (!safe_game[0]) snprintf(safe_game, sizeof(safe_game), "%s", title_id);
    char filename[192];
    const char* type = strcmp(mode, "migration") == 0 ? "PORTABLE" :
                       strcmp(label, "garlic") == 0 ? "DECRYPTED" :
                       raw ? "RAW" : "DECRYPTED";
    snprintf(filename, sizeof(filename), "%s_%s_%s_Manual_%s.zip",
             safe_game, title_id, type, dts);
    if (s_prepare_download) {
        reply_prepared(fd, zip_path, "application/zip", filename, raw ? &raw_info : NULL, NULL, true, true, false);
        return;
    }
    reply_download_file(fd, zip_path, "application/zip", filename, raw ? &raw_info : NULL);
    watcher_release_backup_file(zip_path, true);
}

static void handle_raw_selected_download(int fd, const char* body) {
    restore_selection_t selection;
    char uid[64] = {0}, title[16] = {0}, services[2048] = {0}, err[256] = {0};
    if (!body || !restore_selection_parse(body, &selection, err, sizeof(err)) ||
        !selection.specified || !selection.count ||
        !json_get_string(body, "target_uid", uid, sizeof(uid)) ||
        !json_get_string(body, "title_id", title, sizeof(title)) ||
        !json_get_string(body, "service_slots", services, sizeof(services)) ||
        strlen(services) >= sizeof(services) - 1 || !uid[0] || strlen(uid) >= 16 ||
        strlen(title) != 9 || !title_id_candidate(title)) {
        reply_json(fd, 400, "{\"ok\":false,\"error\":\"explicit_raw_selection_required\"}"); return;
    }
    // The complete flat JSON parser above rejects nested/duplicate fields.
    const char* consent = strstr(body, "\"game_closed_confirmed\"");
    consent = consent ? strchr(consent, ':') : NULL;
    if (consent) { consent++; while (isspace((unsigned char)*consent)) consent++; }
    if (!consent || strncmp(consent, "true", 4)) {
        reply_json(fd, 400, "{\"ok\":false,\"error\":\"manual_game_closed_confirmation_required\"}"); return;
    }
    char path[512] = {0}; watcher_raw_info_t info;
    if (!watcher_make_raw_selected_zip(uid, title, &selection, services, true,
            path, sizeof(path), &info, err, sizeof(err))) {
        char response[1400], *p = response, *end = response + sizeof(response);
        jappendf(&p, end, "{\"ok\":false,\"version\":\"%s\",\"error\":\"selected_raw_not_verified\",\"detail\":", TOSTONSYNC_VERSION);
        jappend_json_string(&p, end, err); jappendf(&p, end, ",\"evidence_path\":");
        jappend_json_string(&p, end, path); jappendf(&p, end, "}");
        reply_json(fd, 409, response); return;
    }
    // A separate manual file, never a catalog/automatic/dedupe/retention job.
    const char* filename = strrchr(path, '/'); filename = filename ? filename + 1 : path;
    reply_download_file(fd, path, "application/zip", filename, &info);
    watcher_release_backup_file(path, true);
}

static void handle_container_selected_download(int fd, const char* body) {
    paired_backup_manual_request_t request; char err[256] = {0};
    if (!paired_backup_parse_manual(body, &request, err, sizeof(err))) {
        reply_json(fd, 400, "{\"ok\":false,\"error\":\"explicit_container_selection_required\"}"); return;
    }
    paired_backup_report_t* r = calloc(1, sizeof(*r));
    if (!r) { reply_json(fd, 500, "{\"ok\":false,\"error\":\"capture_memory_unavailable\"}"); return; }
    jobs_ref_t observed = jobs_begin(JOB_INDIVIDUAL_BACKUP, request.uid, request.title_id,
                                     request.active.slots[0], "browser");
    jobs_phase(observed, "browser", "preparing_copy", 0, false);
    if (!watcher_make_container_selected_backup(request.uid, request.title_id, &request.active,
            request.service_slots, true, r, err, sizeof(err))) {
        char response[2400], *p = response, *end = response + sizeof(response);
        jappendf(&p, end, "{\"ok\":false,\"version\":\"%s\",\"outcome\":", TOSTONSYNC_VERSION);
        jappend_json_string(&p, end, r->outcome); jappendf(&p, end, ",\"detail\":");
        jappend_json_string(&p, end, err); jappendf(&p, end, ",\"evidence_path\":");
        jappend_json_string(&p, end, r->workspace);
        jappendf(&p, end, ",\"raw_verified\":%s,\"migration_ready\":false,\"barrier_retained\":%s,\"unmount_uncertain\":%s",
            r->raw_verified ? "true" : "false", r->barrier_retained ? "true" : "false", r->unmount_uncertain ? "true" : "false");
        jobs_finish(observed, r->unmount_uncertain ? JOB_UNKNOWN : JOB_FAILED, "capture_failed");
        jobs_json_fields(&p, end, observed, false); jappendf(&p, end, "}");
        reply_json(fd, 409, response); free(r); return;
    }
    char headers[4096], diagnostic[2048]; bool paired = r->migration_ready;
    size_t diagnostic_length = paired_backup_diagnostic_summary(r, diagnostic, sizeof(diagnostic));
    if (diagnostic_length >= sizeof(diagnostic)) snprintf(diagnostic, sizeof(diagnostic), "{\"report_unavailable\":true}");
    int length = snprintf(headers, sizeof(headers),
        "X-TostonSync-Version: %s\r\nX-TostonSync-Target-UID: %s\r\nX-TostonSync-Title-ID: %s\r\n"
        "X-TostonSync-Backup-Scope: selected_containers\r\nX-TostonSync-Backup-Outcome: %s\r\n"
        "X-TostonSync-Migration-Ready: %s\r\nX-TostonSync-Capture-ID: %s\r\n"
        "X-TostonSync-Selected-Slots: %zu\r\nX-TostonSync-Service-Images: %zu\r\n"
        "X-TostonSync-Raw-Zip-SHA256: %s\r\nX-TostonSync-Zip-SHA256: %s\r\n"
        "X-TostonSync-Capture-Diagnostic: %s\r\nX-TostonSync-Barrier-Retained: %s\r\n"
        "X-TostonSync-Unmount-Uncertain: %s\r\nX-Toston-Job-ID: %llu\r\nX-Toston-Boot-ID: %s\r\n",
        TOSTONSYNC_VERSION, r->uid, r->title_id, r->outcome, paired ? "true" : "false", r->capture_id,
        r->selected_active_slots, r->selected_service_images, r->raw_zip_sha256,
        paired ? r->portable_zip_sha256 : r->raw_zip_sha256, diagnostic,
        r->barrier_retained ? "true" : "false", r->unmount_uncertain ? "true" : "false",
        (unsigned long long)observed, update_boot_id());
    if (length < 0 || (size_t)length >= sizeof(headers)) {
        jobs_finish(observed, JOB_FAILED, "capture_headers_unavailable");
        reply_json(fd, 500, "{\"ok\":false,\"error\":\"capture_headers_unavailable\"}");
    } else {
        // This proves preparation, not receipt of the download by a browser.
        jobs_phase(observed, "browser", "copy_prepared", 0, false);
        jobs_finish(observed, JOB_DONE, "");
        char filename[160];
        snprintf(filename, sizeof(filename), "%s_%s_%s.zip", r->title_id, r->capture_id, paired ? "PORTABLE_RAW" : "RAW_ONLY");
        reply_download_file_with_headers(fd, r->artifact, "application/zip", filename, NULL, headers);
    }
    // Retain the acquisition, descriptors and any interrupted download as
    // evidence. No broad staging/forensics cleanup is part of this endpoint.
    watcher_release_backup_file(NULL, false); free(r);
}

static const char* individual_failure_code(backup_failure_code_t code) {
    switch (code) {
        case BACKUP_DEST_OK: return NULL;
        case BACKUP_USB_DISABLED: return "BACKUP_USB_DISABLED";
        case BACKUP_USB_ABSENT: return "BACKUP_USB_ABSENT";
        case BACKUP_USB_FAILED: return "BACKUP_USB_FAILED";
        case BACKUP_USB_IDENTITY_REQUIRED: return "BACKUP_USB_IDENTITY_REQUIRED";
        case BACKUP_USB_READ_ONLY: return "BACKUP_USB_READ_ONLY";
        case BACKUP_USB_NOT_USABLE: return "BACKUP_USB_NOT_USABLE";
        case BACKUP_USB_UNSUPPORTED_FORMAT: return "BACKUP_USB_UNSUPPORTED_FORMAT";
        case BACKUP_USB_FULL: return "BACKUP_USB_FULL";
        case BACKUP_USB_FILE_TOO_LARGE: return "BACKUP_USB_FILE_TOO_LARGE";
        case BACKUP_USB_VOLUME_CHANGED: return "BACKUP_USB_VOLUME_CHANGED";
        case BACKUP_USB_READ_FAILED: return "BACKUP_USB_READ_FAILED";
        case BACKUP_USB_WRITE_FAILED: return "BACKUP_USB_WRITE_FAILED";
        case BACKUP_USB_PUBLICATION_FAILED: return "BACKUP_USB_PUBLICATION_FAILED";
        case BACKUP_FTP_DISABLED: return "BACKUP_FTP_DISABLED";
        case BACKUP_FTP_NO_HOST: return "BACKUP_FTP_NO_HOST";
        case BACKUP_FTP_FAILED: return "BACKUP_FTP_FAILED";
        case BACKUP_DRIVE_SIGNED_OUT: return "BACKUP_DRIVE_SIGNED_OUT";
        case BACKUP_DRIVE_GLOBAL_CAP: return "BACKUP_DRIVE_GLOBAL_CAP";
        case BACKUP_DRIVE_TITLE_CAP: return "BACKUP_DRIVE_TITLE_CAP";
        case BACKUP_DRIVE_NOT_CONFIGURED: return "BACKUP_DRIVE_NOT_CONFIGURED";
        case BACKUP_DRIVE_NOT_READY: return "BACKUP_DRIVE_NOT_READY";
        case BACKUP_DRIVE_FAILED: return "BACKUP_DRIVE_FAILED";
    }
    return NULL;
}

static void individual_backup_response(int fd, int status, const paired_backup_report_t* r,
    const watcher_individual_backup_t* stored, const char* detail) {
    static const char* destinations[] = {"drive", "usb"};
    char response[8192], *p = response, *end = response + sizeof(response);
    jappendf(&p, end, "{\"ok\":%s,\"version\":\"%s\",\"outcome\":", stored->ok ? "true" : "false", TOSTONSYNC_VERSION);
    jappend_json_string(&p, end, r->outcome); jappendf(&p, end, ",\"capture_id\":");
    jappend_json_string(&p, end, r->capture_id); jappendf(&p, end, ",\"filename\":");
    jappend_json_string(&p, end, stored->filename);
    jappendf(&p, end, ",\"size_bytes\":%llu,\"migration_ready\":%s,\"barrier_retained\":%s,\"unmount_uncertain\":%s,\"error\":",
        (unsigned long long)stored->size_bytes, r->migration_ready ? "true" : "false",
        r->barrier_retained ? "true" : "false", r->unmount_uncertain ? "true" : "false");
    if (stored->error[0]) jappend_json_string(&p, end, stored->error); else jappendf(&p, end, "null");
    jappendf(&p, end, ",\"thread_error\":%d,\"detail\":", stored->thread_error);
    jappend_json_string(&p, end, detail); jappendf(&p, end, ",\"destinations\":[");
    for (size_t i = 0; i < 2; i++) {
        const watcher_individual_destination_t* d = &stored->destinations[i];
        char en[512], es[512];
        backup_failure_text(&d->failure, false, en, sizeof(en));
        backup_failure_text(&d->failure, true, es, sizeof(es));
        jappendf(&p, end, "%s{\"destination\":\"%s\",\"status\":", i ? "," : "", destinations[i]);
        jappend_json_string(&p, end, d->status ? d->status : "not_attempted");
        jappendf(&p, end, ",\"cause\":");
        const char* cause = individual_failure_code(d->failure.code);
        if (cause) jappend_json_string(&p, end, cause); else jappendf(&p, end, "null");
        jappendf(&p, end, ",\"detail\":"); jappend_json_string(&p, end, en);
        jappendf(&p, end, ",\"detail_es\":"); jappend_json_string(&p, end, es);
        jappendf(&p, end, "}");
    }
    jappendf(&p, end, "]");
    jobs_json_fields(&p, end, jobs_bound(), false); jappendf(&p, end, "}");
    reply_json(fd, status, response);
}

static void handle_container_selected_backup(int fd, const char* body) {
    paired_backup_manual_request_t request; char err[256] = {0};
    if (!paired_backup_parse_manual(body, &request, err, sizeof(err))) {
        reply_json(fd, 400, "{\"ok\":false,\"error\":\"explicit_container_selection_required\"}"); return;
    }
    paired_backup_report_t* r = calloc(1, sizeof(*r));
    watcher_individual_backup_t stored = {0};
    if (!r) { reply_json(fd, 500, "{\"ok\":false,\"error\":\"capture_memory_unavailable\"}"); return; }
    jobs_ref_t observed = jobs_begin(JOB_INDIVIDUAL_BACKUP, request.uid, request.title_id,
                                     request.active.slots[0], "");
    jobs_ref_t previous = jobs_bind(observed);
    jobs_phase(observed, "", "preparing", 0, false);
    bool captured = watcher_make_container_selected_backup(request.uid, request.title_id, &request.active,
        request.service_slots, true, r, err, sizeof(err));
    log_info("individual-backup[capture=%s key=%s/%s]: capture outcome=%s size_bytes=%llu",
        r->capture_id, request.uid, request.title_id, r->outcome,
        (unsigned long long)(r->migration_ready ? r->portable_zip_size : r->raw_zip_size));
    int status = 409;
    if (captured) {
        watcher_store_container_selected(r, request.active.slots[0], &stored);
        status = !strcmp(stored.error, "selected_capture_not_paired") ? 409 : stored.error[0] ? 500 : 200;
        // Only a successful producer owns a scratch lease; failure already
        // released it internally. Release that lease once, never another user's.
        watcher_release_backup_file(NULL, false);
    } else snprintf(stored.error, sizeof(stored.error), "selected_capture_failed");
    if (stored.error[0]) log_warn("activity:individual_backup_failed|%s",
        stored.game[0] ? stored.game : request.title_id);
    jobs_finish(observed, stored.ok ? JOB_DONE : (r->unmount_uncertain ||
                !strcmp(stored.error, "storage_thread_join_unknown")) ? JOB_UNKNOWN : JOB_FAILED,
                stored.ok ? "" : "individual_backup_failed");
    individual_backup_response(fd, status, r, &stored, err[0] ? err : r->detail);
    jobs_bind(previous);
    free(r);
}

static void handle_import_upload(int fd, const char* query,
                                 const char* body, size_t body_len) {
    (void)query; (void)body; (void)body_len;
    reply_json(fd, 410,
        "{\"ok\":false,\"error\":\"legacy_import_retired\","
        "\"detail\":\"Use the resumable import session API. A restore now requires analysis and review before commit.\"}");
}

static uint64_t query_u64(const char* query, const char* key) {
    char tmp[32] = {0};
    query_get_decoded(query, key, tmp, sizeof(tmp));
    if (!tmp[0]) return 0;
    char* end = NULL;
    unsigned long long value = strtoull(tmp, &end, 10);
    return (end && *end == '\0') ? (uint64_t)value : 0;
}

static uint64_t current_save_bytes(const char* uid, const char* title_id) {
    if (!uid || !uid[0] || !title_id_candidate(title_id)) return 0;
    for (const unsigned char* p = (const unsigned char*)uid; *p; p++)
        if (!(isalnum(*p) || *p == '_' || *p == '-')) return 0;
    config_t cfg;
    if (!config_snapshot(&cfg)) return 0;
    char path[512];
    snprintf(path, sizeof(path), "%s/%s/savedata_prospero/%s",
             cfg.paths.saves_root, uid, title_id);
    return fs_dir_size(path);
}

static void import_info_json(const import_session_info_t* info,
                             char* out, size_t out_sz) {
    char* p = out;
    char* end = out + out_sz;
    jappendf(&p, end, "{\"id\":");
    jappend_json_string(&p, end, info->id);
    jappendf(&p, end, ",\"name\":");
    jappend_json_string(&p, end, info->name);
    jappendf(&p, end, ",\"state\":");
    jappend_json_string(&p, end, import_state_name(info->state));
    jappendf(&p, end,
             ",\"size\":%llu,\"received\":%llu,\"chunk_size\":%u,"
             "\"can_resume\":%s,\"location\":",
             (unsigned long long)info->expected,
             (unsigned long long)info->received,
             IMPORT_CHUNK_BYTES,
             info->state == IMPORT_RECEIVING ? "true" : "false");
    jappend_json_string(&p, end, info->location);
    jappendf(&p, end, ",\"source\":");
    jappend_json_string(&p, end, info->source);
    jappendf(&p, end, ",\"staging_path\":");
    jappend_json_string(&p, end, import_session_selected_path(info));
    jappendf(&p, end, ",\"sha256\":");
    jappend_json_string(&p, end, info->portable_path[0]
                                ? info->portable_sha256 : info->sha256);
    jappendf(&p, end, ",\"recovered\":%s,\"original_sha256\":",
             info->portable_path[0] ? "true" : "false");
    jappend_json_string(&p, end, info->sha256);
    jappendf(&p, end, ",\"error\":");
    jappend_json_string(&p, end, import_session_rejected_uid(info) ? "restore_target_uid_missing" : info->error);
    char raw_uid[16]; int raw_identity = import_session_restore_uid(info->id,raw_uid);
    jappendf(&p,end,",\"raw_target_uid\":"); jappend_json_string(&p,end,raw_uid);
    jappendf(&p,end,",\"raw_target_state\":");
    jappend_json_string(&p,end,raw_identity < 0 ? "unknown" : raw_identity ? "explicit" : "legacy");
    // A delayed serializer must not resurrect an older session over the current one.
    jobs_ref_t observed = 0, before = jobs_native_current(JOB_IMPORT);
    import_jobs_snapshot_t current;
    if (s_http_observing) observed = jobs_native_lookup(JOB_IMPORT, info->id);
    else if (import_session_jobs_snapshot(&current) == IMPORT_JOBS_OBSERVED &&
        current.current_present && !strcmp(current.native_id, info->id))
        observed = jobs_import_observe(jobs_native_observe(JOB_IMPORT, current.native_id, before),
            current.state, current.received, current.expected, current.user_uid,
            current.title_id, current.container, current.uncertain || current.observation_only);
    jobs_json_fields(&p, end, observed, false);
    jappendf(&p, end, "}");
}

static bool import_review(const import_session_info_t* info,
                          migration_report_t* report);
static bool import_review_cached(const import_session_info_t* info,
                                 migration_report_t* report, bool refresh);

typedef struct {
    individual_backup_t item;
    char token[65];
    time_t expires;
    bool available;
} individual_list_entry_t;
static individual_list_entry_t* s_individual_list;
static size_t s_individual_count;
static unsigned long long s_individual_sequence;
static pthread_mutex_t s_individual_lock = PTHREAD_MUTEX_INITIALIZER;

static const char* individual_state_name(catalog_state_t state) {
    return state == CATALOG_COMPLETE ? "complete" : state == CATALOG_EMPTY ? "empty"
        : state == CATALOG_PARTIAL ? "partial" : "unavailable";
}

static void individual_reply_error(int fd, const char* code, const char* detail) {
    import_session_info_t info = {0};
    bool active = import_session_current(&info);
    char item[2048] = "null", response[3072], *p = response, *end = response + sizeof(response);
    if (active) import_info_json(&info, item, sizeof(item));
    jappendf(&p, end, "{\"ok\":false,\"version\":\"%s\",\"error\":", TOSTONSYNC_VERSION);
    jappend_json_string(&p, end, code);
    jappendf(&p, end, ",\"detail\":"); jappend_json_string(&p, end, detail);
    jappendf(&p, end, ",\"import\":%s}", item);
    reply_json(fd, 409, response);
}

static bool individual_list_token(const individual_backup_t* item, char token[65]) {
    unsigned char entropy[32], digest[32];
    int fd = open("/dev/urandom", O_RDONLY);
    ssize_t got = fd >= 0 ? read(fd, entropy, sizeof(entropy)) : -1;
    if (fd >= 0) close(fd);
    if (got != (ssize_t)sizeof(entropy)) return false;
    sha256_ctx_t hash;
    sha256_init(&hash); sha256_update(&hash, entropy, sizeof(entropy));
    sha256_update(&hash, item, sizeof(*item));
    sha256_update(&hash, &s_individual_sequence, sizeof(s_individual_sequence));
    s_individual_sequence++;
    sha256_final(&hash, digest);
    for (size_t i = 0; i < 32; i++) snprintf(token + i * 2, 3, "%02x", digest[i]);
    return true;
}

static void handle_individual_list(int fd, const char* query) {
    char user[32] = {0}, title[16] = {0}, normalized[32];
    if (!query_get_decoded(query, "user", user, sizeof(user)) ||
        !query_get_decoded(query, "title_id", title, sizeof(title)) ||
        !backup_folder_code(user, false, normalized, sizeof(normalized)) ||
        strcmp(user, normalized) || strlen(user) >= 16 || !title_id_candidate(title)) {
        reply_json(fd, 400, "{\"ok\":false,\"error\":\"invalid_individual_identity\"}"); return;
    }
    const size_t capacity = INDIVIDUAL_CATALOG_MAX * 2;
    individual_list_entry_t* entries = calloc(capacity, sizeof(*entries));
    individual_backup_t* items = calloc(INDIVIDUAL_CATALOG_MAX, sizeof(*items));
    const size_t response_cap = 8U * 1024U * 1024U;
    char* response = calloc(1, response_cap);
    if (!entries || !items || !response) {
        free(entries); free(items); free(response);
        reply_json(fd, 503, "{\"ok\":false,\"error\":\"out_of_memory\"}"); return;
    }
    pthread_mutex_lock(&s_individual_lock);
    catalog_scan_t scans[3] = {{0}};
    size_t count = 0;
    for (size_t source = 0; source < 3; source++) {
        if (source == 1) continue; // Retired FTP catalog slot.
        size_t n = source == 0 ? usb_individual_scan(user, title, items, INDIVIDUAL_CATALOG_MAX, &scans[source])
            : gdrive_individual_scan(user, title, items, INDIVIDUAL_CATALOG_MAX, &scans[source]);
        if (n > INDIVIDUAL_CATALOG_MAX) { n = 0; scans[source].state = CATALOG_PARTIAL; }
        for (size_t i = 0; i < n; i++) {
            individual_list_entry_t* entry = &entries[count++];
            entry->item = items[i]; entry->expires = time(NULL) + 1800;
            entry->available = scans[source].state == CATALOG_COMPLETE &&
                individual_catalog_item_valid(&entry->item, entry->item.source) &&
                individual_list_token(&entry->item, entry->token);
        }
    }
    catalog_state_t aggregate = count ? CATALOG_COMPLETE : CATALOG_EMPTY;
    bool any_configured = false;
    for (size_t i = 0; i < 3; i++) {
        any_configured |= scans[i].configured;
        if (scans[i].configured && (scans[i].state == CATALOG_PARTIAL || scans[i].state == CATALOG_UNAVAILABLE))
            aggregate = CATALOG_PARTIAL;
    }
    if (!any_configured) aggregate = CATALOG_UNAVAILABLE;
    char* p = response, *end = response + response_cap;
    jappendf(&p, end, "{\"ok\":true,\"version\":\"%s\",\"state\":\"%s\",\"items\":[",
             TOSTONSYNC_VERSION, individual_state_name(aggregate));
    for (size_t i = 0; i < count; i++) {
        individual_backup_t* item = &entries[i].item;
        jappendf(&p, end, "%s{\"kind\":\"individual\",\"user\":", i ? "," : "");
        jappend_json_string(&p, end, item->user);
        jappendf(&p, end, ",\"title_id\":"); jappend_json_string(&p, end, item->title_id);
        jappendf(&p, end, ",\"source\":"); jappend_json_string(&p, end, item->source);
        jappendf(&p, end, ",\"name\":"); jappend_json_string(&p, end, item->name);
        jappendf(&p, end, ",\"container\":"); jappend_json_string(&p, end, item->container);
        jappendf(&p, end, ",\"file_id\":"); jappend_json_string(&p, end, item->ref);
        jappendf(&p, end, ",\"individual_token\":"); jappend_json_string(&p, end, entries[i].token);
        if (!strcmp(item->source, "usb")) {
            jappendf(&p, end, ",\"usb_volume_id\":"); jappend_json_string(&p, end, item->volume_id);
            jappendf(&p, end, ",\"usb_mount\":"); jappend_json_string(&p, end, item->mount);
        }
        jappendf(&p, end, ",\"size_bytes\":%llu,\"created_unix\":%lld,\"available\":%s}",
            (unsigned long long)item->size_bytes, (long long)item->created_unix,
            entries[i].available ? "true" : "false");
    }
    const char* sources[] = {"usb", NULL, "drive"};
    jappendf(&p, end, "],\"destinations\":[");
    for (size_t i = 0; i < 3; i++) {
        if (!sources[i]) continue;
        jappendf(&p, end, "%s{\"source\":\"%s\",\"state\":\"%s\",\"reason\":",
            i ? "," : "", sources[i], individual_state_name(scans[i].state));
        jappend_json_string(&p, end, scans[i].reason ? scans[i].reason : "unknown");
        jappendf(&p, end, "}");
    }
    jappendf(&p, end, "]}");
    free(s_individual_list); s_individual_list = entries; s_individual_count = count;
    pthread_mutex_unlock(&s_individual_lock);
    reply_json(fd, p < end - 1 ? 200 : 503,
        p < end - 1 ? response : "{\"ok\":false,\"error\":\"individual_list_too_large\"}");
    free(items); free(response);
}

static void individual_reply_review(int fd, const import_session_info_t* info,
    const individual_backup_t* item, const migration_report_t* report, const char* container) {
    char session[2048], review[8192], response[12288], *p = response, *end = response + sizeof(response);
    import_info_json(info, session, sizeof(session));
    migration_report_json(report, review, sizeof(review));
    jappendf(&p, end, "{\"ok\":true,\"version\":\"%s\",\"import\":%s,\"review\":%s,\"individual\":{\"user\":",
        TOSTONSYNC_VERSION, session, review);
    jappend_json_string(&p, end, item->user);
    jappendf(&p, end, ",\"title_id\":"); jappend_json_string(&p, end, item->title_id);
    jappendf(&p, end, ",\"container\":"); jappend_json_string(&p, end, container);
    jappendf(&p, end, ",\"source\":"); jappend_json_string(&p, end, item->source);
    jappendf(&p, end, ",\"created_unix\":%lld}}", (long long)item->created_unix);
    reply_json(fd, 200, response);
}

// Used only by the new individual browser envelope, never by Full imports.
// The existing strict parser validates the flat JSON first. Decode complete
// strings here rather than searching inside unrelated values or truncating.
static bool individual_request_string(const char** cursor, char* out, size_t cap) {
    const unsigned char* p = (const unsigned char*)*cursor;
    size_t n = 0;
    if (*p++ != '"') return false;
    while (*p && *p != '"') {
        uint32_t point = *p++;
        bool unicode = false;
        if (point == '\\') {
            unsigned char escaped = *p++;
            const char* codes = "\"\\/bfnrt", *decoded = "\"\\/\b\f\n\r\t";
            const char* match = escaped ? strchr(codes, escaped) : NULL;
            if (match) point = (unsigned char)decoded[match - codes];
            else if (escaped == 'u') {
                point = 0; unicode = true;
                for (unsigned i = 0; i < 4; i++) {
                    unsigned char c = *p++;
                    unsigned digit = c >= '0' && c <= '9' ? c - '0'
                        : c >= 'a' && c <= 'f' ? c - 'a' + 10
                        : c >= 'A' && c <= 'F' ? c - 'A' + 10 : 16;
                    if (digit == 16) return false;
                    point = point * 16 + digit;
                }
                if (point >= 0xd800 && point <= 0xdbff) {
                    if (*p++ != '\\' || *p++ != 'u') return false;
                    uint32_t low = 0;
                    for (unsigned i = 0; i < 4; i++) {
                        unsigned char c = *p++;
                        unsigned digit = c >= '0' && c <= '9' ? c - '0'
                            : c >= 'a' && c <= 'f' ? c - 'a' + 10
                            : c >= 'A' && c <= 'F' ? c - 'A' + 10 : 16;
                        if (digit == 16) return false;
                        low = low * 16 + digit;
                    }
                    if (low < 0xdc00 || low > 0xdfff) return false;
                    point = 0x10000 + ((point - 0xd800) << 10) + low - 0xdc00;
                } else if (point >= 0xdc00 && point <= 0xdfff) return false;
            } else return false;
        }
        if (!point || point < 32) return false;
        unsigned char bytes[4]; size_t count = 1;
        bytes[0] = (unsigned char)point;
        if (unicode && point >= 0x80) {
            count = point < 0x800 ? 2 : point < 0x10000 ? 3 : 4;
            for (size_t i = count - 1; i; i--) { bytes[i] = 0x80 | (point & 63); point >>= 6; }
            bytes[0] = (count == 2 ? 0xc0 : count == 3 ? 0xe0 : 0xf0) | point;
        }
        if (out) {
            if (n + count >= cap) return false;
            memcpy(out + n, bytes, count); n += count;
        }
    }
    if (*p++ != '"') return false;
    if (out) out[n] = '\0';
    *cursor = (const char*)p; return true;
}

static bool individual_import_start_fields(const char* body, char name[384],
        char user[32], char title[16], uint64_t* size) {
    restore_selection_request_t validated;
    if (!restore_selection_request_parse(body, &validated, NULL, 0) || validated.selection.specified) return false;
    const char* p = body;
    unsigned seen = 0;
    while (isspace((unsigned char)*p)) p++;
    p++;
    while (isspace((unsigned char)*p)) p++;
    while (*p != '}') {
        char key[64];
        if (!individual_request_string(&p, key, sizeof(key))) return false;
        while (isspace((unsigned char)*p)) p++;
        p++;
        while (isspace((unsigned char)*p)) p++;
        char* out = NULL; size_t cap = 0;
        if (!strcmp(key, "name")) { out = name; cap = 384; seen |= 1; }
        else if (!strcmp(key, "user")) { out = user; cap = 32; seen |= 2; }
        else if (!strcmp(key, "title_id")) { out = title; cap = 16; seen |= 4; }
        if (out) {
            if (!individual_request_string(&p, out, cap)) return false;
        } else if (!strcmp(key, "size")) {
            uint64_t number = 0;
            if (*p < '0' || *p > '9') return false;
            do {
                unsigned digit = (unsigned)(*p++ - '0');
                if (number > (IMPORT_MAX_BYTES - digit) / 10) return false;
                number = number * 10 + digit;
            } while (*p >= '0' && *p <= '9');
            if (number < 22 || number > IMPORT_MAX_BYTES || (*p != ',' && *p != '}' && !isspace((unsigned char)*p))) return false;
            *size = number; seen |= 8;
        } else if (*p == '"') {
            if (!individual_request_string(&p, NULL, 0)) return false;
        } else while (*p && *p != ',' && *p != '}') p++;
        while (isspace((unsigned char)*p)) p++;
        if (*p == ',') { p++; while (isspace((unsigned char)*p)) p++; }
    }
    return seen == 15 && individual_catalog_name_safe(name);
}

static void handle_individual_import_start(int fd, const char* body) {
    char name[384] = {0}, user[32] = {0}, title[16] = {0}, uid[32];
    uint64_t size = 0;
    if (!individual_import_start_fields(body, name, user, title, &size) || !title_id_candidate(title) ||
        !backup_folder_code(user, false, uid, sizeof(uid)) || strcmp(uid, user) || strlen(uid) >= 16) {
        individual_reply_error(fd, "individual_invalid", "Invalid individual import identity or size."); return;
    }
    import_session_info_t info = {0};
    if (import_session_current(&info) && info.state != IMPORT_IDLE) {
        individual_reply_error(fd, "import_busy", "Discard the previous import explicitly first."); return;
    }
    if (!fs_title_is_closed(title)) {
        individual_reply_error(fd, "game_not_closed", "Close the game on the PS5 first."); return;
    }
    config_t cfg;
    uint64_t reserve = current_save_bytes(user, title);
    if (!config_snapshot(&cfg) || UINT64_MAX - reserve < size ||
        !import_session_start(&cfg, name, size, reserve + size, title, user, "browser", "", &info) ||
        !import_session_individual_browser_mark(info.id, &info)) {
        individual_reply_error(fd, "individual_import_failed", info.error[0] ? info.error : "Could not checkpoint the individual import."); return;
    }
    char item[2048], response[2304];
    import_info_json(&info, item, sizeof(item));
    snprintf(response, sizeof(response), "{\"ok\":true,\"version\":\"%s\",\"import\":%s}", TOSTONSYNC_VERSION, item);
    reply_json(fd, 200, response);
}

static void handle_individual_import(int fd, const char* body) {
    char token[65] = {0}, id[48] = {0}, error[256] = {0}, container[64] = {0};
    json_get_string(body, "token", token, sizeof(token));
    json_get_string(body, "id", id, sizeof(id));
    individual_backup_t item = {0};
    import_session_info_t info = {0}; migration_report_t report = {0};
    config_t cfg;
    if (!config_snapshot(&cfg)) { individual_reply_error(fd, "config_unavailable", "Configuration unavailable."); return; }
    bool browser = id[0] && !token[0];
    if (browser) {
        json_get_string(body, "user", item.user, sizeof(item.user));
        json_get_string(body, "title_id", item.title_id, sizeof(item.title_id));
        if (!import_session_status(id, &info) || strcmp(info.source, "individual-browser") ||
            info.state != IMPORT_READY || strcmp(info.user_hint, item.user) || strcmp(info.title_hint, item.title_id)) {
            individual_reply_error(fd, "individual_invalid", "This is not a newly owned individual import."); return;
        }
        snprintf(item.source, sizeof(item.source), "browser"); item.size_bytes = info.expected;
        snprintf(item.checksum, sizeof(item.checksum), "%s", info.sha256);
        snprintf(item.name, sizeof(item.name), "%s", info.name);
        snprintf(item.ref, sizeof(item.ref), "browser:%s", info.id);
        snprintf(item.parent_ref, sizeof(item.parent_ref), "%s", info.path);
        snprintf(item.file_stamp, sizeof(item.file_stamp), "%s", info.sha256);
        sha256_ctx_t browser_hash; unsigned char browser_digest[32];
        sha256_init(&browser_hash); sha256_update(&browser_hash, info.id, strlen(info.id));
        sha256_final(&browser_hash, browser_digest);
        for (size_t i = 0; i < 32; i++) snprintf(item.destination_identity + i * 2, 3, "%02x", browser_digest[i]);
        if (!import_session_individual_checkpoint(id, &info)) {
            individual_reply_error(fd, "individual_invalid", "Import checkpoint could not be made durable."); return;
        }
    } else {
        bool found = false;
        pthread_mutex_lock(&s_individual_lock);
        for (size_t i = 0; i < s_individual_count; i++) {
            if (token[0] && !strcmp(token, s_individual_list[i].token) &&
                s_individual_list[i].available && time(NULL) <= s_individual_list[i].expires) {
                item = s_individual_list[i].item; found = true; break;
            }
        }
        pthread_mutex_unlock(&s_individual_lock);
        if (!found) { individual_reply_error(fd, "source_changed", "Individual reference is unavailable or stale."); return; }
    }
    int admitted = watcher_target_check_begin(error, sizeof(error));
    if (admitted != 1) { individual_reply_error(fd, "target_check_busy", error); return; }
    bool ok;
    if (browser) {
        ok = individual_restore_review(&info, &item, &report, container, error, sizeof(error)) &&
            individual_restore_target_exists(&cfg, &item, container, error, sizeof(error)) &&
            import_session_individual_bind(id, &item, container, &info);
    } else {
        ok = individual_restore_prepare(&cfg, &item, current_save_bytes(item.user, item.title_id),
            &info, &report, container, error, sizeof(error));
    }
    watcher_target_check_end();
    if (!ok) {
        const char* code = !strcmp(error, "import_busy") ? "import_busy"
            : !strcmp(error, "game_not_closed") ? "game_not_closed"
            : !strcmp(error, "individual_missing_target") ? "individual_missing_target"
            : !strcmp(error, "source_changed") ? "source_changed" : "individual_invalid";
        individual_reply_error(fd, code, error[0] ? error : "Individual review or checkpoint failed."); return;
    }
    individual_reply_review(fd, &info, &item, &report, container);
}

static bool individual_import_route_admit(int fd, const char* body, bool commit) {
    restore_selection_request_t request;
    if (!restore_selection_request_parse(body, &request, NULL, 0)) return true;
    import_session_info_t info;
    if (!import_session_status(request.id, &info) ||
        (strcmp(info.source, "individual") && strcmp(info.source, "individual-browser"))) return true;
    individual_backup_t item; char container[64], error[256] = {0};
    config_t cfg;
    if (!import_session_individual_get(request.id, &item, container) || !config_snapshot(&cfg) ||
        (request.target_uid[0] && strcmp(request.target_uid, item.user)) ||
        (request.selection.specified && (request.selection.count != 1 || strcmp(request.selection.slots[0], container))) ||
        (commit && !request.selection.specified)) {
        individual_reply_error(fd, "source_changed", "The exact individual import binding changed or is unavailable."); return false;
    }
    if (!individual_restore_target_exists(&cfg, &item, container, error, sizeof(error))) {
        individual_reply_error(fd, !strcmp(error, "game_not_closed") ? "game_not_closed"
            : !strcmp(error, "individual_missing_target") ? "individual_missing_target" : "target_not_ready", error); return false;
    }
    if (commit && strcmp(item.source, "browser") && !individual_restore_source_current(&item)) {
        individual_reply_error(fd, "source_changed", "The source changed after review; no replacement was downloaded."); return false;
    }
    return true;
}

static void handle_import_start(int fd, const char* body) {
    char uid[16]; bool uid_explicit, source_uid;
    if (!import_request_uid(body,uid,&uid_explicit,&source_uid) ||
        (uid_explicit && !watcher_restore_uid_is_local(uid))) {
        reply_json(fd,400,"{\"ok\":false,\"error\":\"invalid_restore_uid\"}"); return;
    }
    char name[128] = {0}, title[16] = {0}, user[16] = {0};
    char source[24] = {0}, resume_id[48] = {0};
    json_get_string(body, "name", name, sizeof(name));
    json_get_string(body, "title_id", title, sizeof(title));
    json_get_string(body, "user", user, sizeof(user));
    json_get_string(body, "source", source, sizeof(source));
    json_get_string(body, "resume_id", resume_id, sizeof(resume_id));
    uint64_t size = (uint64_t)json_get_number(body, "size");
    if (!name[0] || size < 22 || size > IMPORT_MAX_BYTES) {
        reply_json(fd, 400, "{\"ok\":false,\"error\":\"invalid_import_request\"}");
        return;
    }
    if (title[0] && strcmp(title, "auto") != 0 && !title_id_candidate(title)) {
        reply_json(fd, 400, "{\"ok\":false,\"error\":\"invalid_title_id\"}");
        return;
    }
    config_t cfg;
    if (!config_snapshot(&cfg)) {
        reply_json(fd, 503, "{\"ok\":false,\"error\":\"config_unavailable\"}");
        return;
    }
    // Reserve room for the uploaded archive, extracted data, the current save
    // snapshot, and a 512 MB safety margin before accepting the first byte.
    uint64_t reserve = current_save_bytes((uid_explicit || source_uid) ? uid : user, title);
    if (UINT64_MAX - reserve < size) reserve = UINT64_MAX;
    else reserve += size;
    import_session_info_t info = {0};
    // A source UID binds only RAW's literal identity. Portable chooses a local
    // target later through its existing server-held selection approval.
    bool started = (uid_explicit || source_uid)
        ? import_session_start_uid(&cfg,name,size,reserve,title,uid,source,resume_id,&info)
        : import_session_start(&cfg,name,size,reserve,title,user,source,resume_id,&info);
    if (!started) {
        if (import_session_current(&info)) {
            char item[1536], resp[1792];
            import_info_json(&info, item, sizeof(item));
            if (info.state == IMPORT_FAILED && !info.id[0] && info.error[0]) {
                char* p = resp; char* end = resp + sizeof(resp);
                jappendf(&p, end, "{\"ok\":false,\"error\":\"import_checkpoint_invalid\",\"detail\":");
                jappend_json_string(&p, end, info.error);
                jappendf(&p, end, ",\"import\":%s}", item);
                reply_json(fd, 409, resp);
                return;
            }
            snprintf(resp, sizeof(resp),
                "{\"ok\":false,\"error\":\"import_busy\","
                "\"detail\":\"Another import is active. Resume or cancel it before starting another.\","
                "\"import\":%s}", item);
            reply_json(fd, 409, resp);
            return;
        }
        if (info.error[0]) {
            char resp[512], *p = resp, *end = resp + sizeof(resp);
            jappendf(&p, end,
                     "{\"ok\":false,\"error\":\"not_enough_space\",\"detail\":");
            jappend_json_string(&p, end, info.error);
            jappendf(&p, end, "}");
            reply_json(fd, 507, resp);
            return;
        }
        reply_json(fd, 500,
            "{\"ok\":false,\"error\":\"import_start_failed\","
            "\"detail\":\"Could not open temporary storage for this import.\"}");
        return;
    }
    char item[1536], resp[1664];
    import_info_json(&info, item, sizeof(item));
    snprintf(resp, sizeof(resp), "{\"ok\":true,\"import\":%s}", item);
    reply_json(fd, 200, resp);
}

static void handle_import_chunk(int fd, const char* query,
                                const char* body, size_t body_len) {
    struct timeval response_started;
    char id[48] = {0};
    query_get_decoded(query, "id", id, sizeof(id));
    uint64_t offset = query_u64(query, "offset");
    import_session_info_t info = {0};
    bool wrote = id[0] && body && body_len > 0 &&
                 body_len <= IMPORT_CHUNK_BYTES &&
                 import_session_write(id, offset, body, body_len, &info);
    if (!wrote) {
        char item[1536] = "{}", resp[1664];
        if (id[0] && import_session_status(id, &info))
            import_info_json(&info, item, sizeof(item));
        log_warn("ZIP import chunk rejected: id=%s offset=%llu bytes=%zu "
                 "expected_offset=%llu state=%s",
                 id[0] ? id : "missing", (unsigned long long)offset, body_len,
                 (unsigned long long)info.received,
                 import_state_name(info.state));
        snprintf(resp, sizeof(resp),
                 "{\"ok\":false,\"error\":\"invalid_chunk_or_offset\","
                 "\"import\":%s}", item);
        reply_json(fd, 409, resp);
        return;
    }
    char item[1536], resp[1664];
    import_info_json(&info, item, sizeof(item));
    snprintf(resp, sizeof(resp), "{\"ok\":true,\"import\":%s}", item);
    gettimeofday(&response_started, NULL);
    reply_json(fd, 200, resp);
    struct timeval response_done;
    gettimeofday(&response_done, NULL);
    int64_t response_ms =
        (int64_t)(response_done.tv_sec - response_started.tv_sec) * 1000 +
        (response_done.tv_usec - response_started.tv_usec) / 1000;
    log_info("ZIP import chunk response: offset=%llu received=%llu "
             "response_ms=%lld",
             (unsigned long long)offset,
             (unsigned long long)info.received,
             (long long)response_ms);
}

static void handle_import_status(int fd, const char* query) {
    char id[48] = {0};
    query_get_decoded(query, "id", id, sizeof(id));
    import_session_info_t info;
    bool ok = id[0] ? (s_http_observing ? import_session_status_observe : import_session_status)(id, &info)
                    : import_session_current(&info);
    if (!ok) {
        reply_json(fd, 404, "{\"ok\":false,\"error\":\"import_not_found\"}");
        return;
    }
    if (info.state == IMPORT_READY) {
        migration_report_t report;
        const char* target_rejected = import_session_rejected_uid(&info);
        bool valid = import_review_cached(&info, &report, target_rejected && !s_http_observing);
        if (target_rejected && !s_http_observing && valid && !report.needs_kernel) {
            char uid[16]; snprintf(uid,sizeof(uid),"%s",target_rejected);
            valid = watcher_restore_uid_is_local(uid) &&
                import_session_target_reviewed(info.id,uid) && import_session_status(info.id, &info);
        }
        char item[1536], review[4096], resp[5888];
        import_info_json(&info, item, sizeof(item));
        migration_report_json(&report, review, sizeof(review));
        snprintf(resp, sizeof(resp),
                 "{\"ok\":%s,\"import\":%s,\"review\":%s}",
                 valid ? "true" : "false", item, review);
        reply_json(fd, 200, resp);
        return;
    }
    char item[1536], resp[1664];
    import_info_json(&info, item, sizeof(item));
    snprintf(resp, sizeof(resp), "{\"ok\":true,\"import\":%s}", item);
    reply_json(fd, 200, resp);
}

static bool import_preserve_id_valid(const char* id) {
    return id && id[0] && strlen(id) < 48 &&
        strspn(id, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_") == strlen(id);
}

// This mutation accepts exactly {"id":"literal"}; no client metadata,
// nested/shadow IDs, duplicates, escapes, truncation or implicit defaults.
static bool import_preserve_body_id(const char* body, size_t size, char id[48]) {
    id[0] = '\0';
    if (!body || !size || size > 256 || memchr(body, '\0', size)) return false;
    const char* p = body;
    const char* end = body + size;
#define PRESERVE_WS() while (p < end && (*p == ' ' || *p == '\t' || *p == '\r' || *p == '\n')) p++
    PRESERVE_WS();
    if (p == end || *p++ != '{') return false;
    PRESERVE_WS();
    if (end - p < 4 || memcmp(p, "\"id\"", 4)) return false;
    p += 4;
    PRESERVE_WS();
    if (p == end || *p++ != ':') return false;
    PRESERVE_WS();
    if (p == end || *p++ != '"') return false;
    size_t n = 0;
    while (p < end && *p != '"') {
        if (n >= 47) return false;
        id[n++] = *p++;
    }
    id[n] = '\0';
    if (p == end || *p++ != '"' || !import_preserve_id_valid(id)) return false;
    PRESERVE_WS();
    if (p == end || *p++ != '}') return false;
    PRESERVE_WS();
#undef PRESERVE_WS
    return p == end;
}

static void import_preserved_optional_json(char** p, char* end, const char* value) {
    if (value[0]) jappend_json_string(p, end, value);
    else jappendf(p, end, "null");
}

static void import_preserved_artifact_json(char** p, char* end, const char* path,
                                          uint64_t size, const char* sha,
                                          const char* manifest, const char* inventory) {
    jappendf(p, end, "{\"path\":");
    jappend_json_string(p, end, path);
    jappendf(p, end, ",\"size\":%llu,\"sha256\":", (unsigned long long)size);
    jappend_json_string(p, end, sha);
    jappendf(p, end, ",\"manifest_sha256\":");
    import_preserved_optional_json(p, end, manifest);
    jappendf(p, end, ",\"inventory_sha256\":");
    import_preserved_optional_json(p, end, inventory);
    jappendf(p, end, "}");
}

static void reply_import_preserved(int fd, const import_preserved_info_t* record) {
    char* response = calloc(1, 16384);
    if (!response) {
        reply_json(fd, 503, "{\"ok\":false,\"error\":\"preserved_response_unavailable\"}");
        return;
    }
    char* p = response;
    char* end = response + 16384;
    const import_session_info_t* info = &record->historical;
    const import_preserve_metadata_t* meta = &record->metadata;
    jappendf(&p, end, "{\"ok\":true,\"preserved\":{\"id\":");
    jappend_json_string(&p, end, info->id);
    jappendf(&p, end, ",\"status\":\"preserved\",\"operational_authority\":false,"
        "\"claim_allowed\":false,\"restore_allowed\":false,"
        "\"receipt_authority\":\"HISTORICAL_NON_AUTHORIZING\",\"source_format\":");
    jappend_json_string(&p, end, meta->source_format);
    jappendf(&p, end, ",\"title_id\":");
    jappend_json_string(&p, end, meta->title_id);
    jappendf(&p, end, ",\"source_uid\":");
    import_preserved_optional_json(&p, end, meta->source_uid);
    jappendf(&p, end, ",\"user_hint_reference\":");
    jappend_json_string(&p, end, info->user_hint);
    jappendf(&p, end, ",\"prior_state\":");
    jappend_json_string(&p, end, import_state_name(info->state));
    jappendf(&p, end, ",\"raw\":");
    import_preserved_artifact_json(&p, end, info->path, record->raw_size, info->sha256,
        meta->raw_manifest_sha256, meta->raw_inventory_sha256);
    jappendf(&p, end, ",\"portable\":");
    if (info->portable_path[0])
        import_preserved_artifact_json(&p, end, info->portable_path, record->portable_size,
            info->portable_sha256, meta->portable_manifest_sha256, meta->portable_inventory_sha256);
    else jappendf(&p, end, "null");
    jappendf(&p, end, ",\"inventory_scope\":\"inspector-container-inventory\","
        "\"manifest_fingerprint_unavailable\":%s,\"selection_guards\":{"
        "\"required\":%s,\"historical_only\":true,\"available_slots\":%zu,\"slots\":[",
        !meta->raw_manifest_sha256[0] ? "true" : "false",
        info->restore_selection_required ? "true" : "false", info->restore_scope.available_slots);
    for (size_t i = 0; i < info->restore_scope.selection.count && i < RESTORE_SELECTION_MAX; i++) {
        if (i) jappendf(&p, end, ",");
        jappend_json_string(&p, end, info->restore_scope.selection.slots[i]);
    }
    jappendf(&p, end, "]},\"preserved_version\":");
    jappend_json_string(&p, end, record->preserved_version);
    jappendf(&p, end, ",\"preserved_unix\":%lld,\"record_path\":", (long long)record->preserved_unix);
    jappend_json_string(&p, end, record->record_path);
    jappendf(&p, end, ",\"record_sha256\":");
    jappend_json_string(&p, end, record->record_sha256);
    jappendf(&p, end, ",\"checkpoint\":{\"record\":");
    jappend_json_string(&p, end, record->record_path);
    jappendf(&p, end, ",\"section\":\"embedded-import.session\",\"offset\":%llu,\"size\":%llu,\"sha256\":",
        (unsigned long long)record->checkpoint_offset,
        (unsigned long long)record->checkpoint_size);
    jappend_json_string(&p, end, record->checkpoint_sha256);
    jappendf(&p, end, "}}}");
    if (p >= end - 1)
        reply_json(fd, 503, "{\"ok\":false,\"error\":\"preserved_response_overflow\"}");
    else reply_json(fd, 200, response);
    free(response);
}

static void handle_import_preserve(int fd, const char* body, size_t body_len) {
    char id[48], detail[256] = {0};
    if (!import_preserve_body_id(body, body_len, id)) {
        reply_json(fd, 400, "{\"ok\":false,\"error\":\"invalid_preserve_request\"}");
        return;
    }
    import_preserved_info_t* record = calloc(1, sizeof(*record));
    if (!record) {
        reply_json(fd, 503, "{\"ok\":false,\"error\":\"preserve_unavailable\"}");
        return;
    }
    if (!watcher_preserve_import(id, record, detail, sizeof(detail))) {
        char response[1024], *p = response, *end = response + sizeof(response);
        jappendf(&p, end, "{\"ok\":false,\"error\":\"preserve_blocked\",\"detail\":");
        jappend_json_string(&p, end, detail[0] ? detail : "Import is not an active preservable READY session");
        jappendf(&p, end, "}");
        reply_json(fd, 409, response);
    } else reply_import_preserved(fd, record);
    free(record);
}

// Historical lookup is separate from operational /import/status and never
// falls back to the active session, claims a receipt or reactivates an import.
static void handle_import_preserved(int fd, const char* query) {
    const char* id = query && !strncmp(query, "id=", 3) ? query + 3 : NULL;
    if (!import_preserve_id_valid(id)) {
        reply_json(fd, 400, "{\"ok\":false,\"error\":\"invalid_preserved_id\"}");
        return;
    }
    import_preserved_info_t* record = calloc(1, sizeof(*record));
    if (!record) {
        reply_json(fd, 503, "{\"ok\":false,\"error\":\"preserved_lookup_unavailable\"}");
        return;
    }
    if (!(s_http_observing ? import_session_preserved_status_observe : import_session_preserved_status)(id, record))
        reply_json(fd, 409, "{\"ok\":false,\"error\":\"preserved_not_found_or_uncertain\"}");
    else reply_import_preserved(fd, record);
    free(record);
}

static bool import_review(const import_session_info_t* info,
                          migration_report_t* report) {
    if (!import_session_validate_selected(info)) {
        memset(report, 0, sizeof(*report));
        snprintf(report->reason, sizeof(report->reason),
                 "Original or recovery copy failed SHA-256 verification; restore blocked");
        return false;
    }
    bool ok = migration_inspect_zip(import_session_selected_path(info),
                                     info->title_hint, report);
    char raw_uid[16];
    int bound = import_session_restore_uid(info->id, raw_uid);
    if (ok && !report->needs_kernel &&
        (bound < 0 || (bound && !watcher_restore_uid_is_local(raw_uid)))) {
        report->valid = report->strategy_ready = false;
        snprintf(report->restore_strategy, sizeof(report->restore_strategy), "blocked");
        snprintf(report->reason, sizeof(report->reason), "restore_target_uid_missing");
        return false;
    }
    if (ok && !report->title_name[0] && report->title_id[0])
        titlename_lookup(report->title_id, report->title_name,
                         sizeof(report->title_name));
    return ok;
}

// A UI-only cache for the single finalized import. Commit, target preflight
// and the restore worker always perform their own uncached validation.
// Explicit analysis refreshes this cache; status polling does not re-extract.
static bool import_review_same_session(const import_session_info_t* a,
                                       const import_session_info_t* b) {
    return a->state == IMPORT_READY && b->state == IMPORT_READY &&
           a->sha256[0] && strcmp(a->id, b->id) == 0 &&
           strcmp(a->path, b->path) == 0 &&
           strcmp(a->portable_path, b->portable_path) == 0 &&
           strcmp(a->portable_sha256, b->portable_sha256) == 0 &&
           strcmp(a->title_hint, b->title_hint) == 0 &&
           strcmp(a->sha256, b->sha256) == 0;
}

static bool import_review_same_file(const struct stat* a, const struct stat* b) {
    return a->st_dev == b->st_dev && a->st_ino == b->st_ino &&
           a->st_size == b->st_size && a->st_mtime == b->st_mtime &&
           a->st_ctime == b->st_ctime &&
#if defined(__APPLE__)
           a->st_mtimespec.tv_nsec == b->st_mtimespec.tv_nsec &&
           a->st_ctimespec.tv_nsec == b->st_ctimespec.tv_nsec;
#else
           a->st_mtim.tv_nsec == b->st_mtim.tv_nsec &&
           a->st_ctim.tv_nsec == b->st_ctim.tv_nsec;
#endif
}

static bool import_review_cached(const import_session_info_t* info,
                                 migration_report_t* report, bool refresh) {
    static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
    static bool cached = false, cached_ok = false;
    static import_session_info_t cached_info;
    static struct stat cached_stat;
    static migration_report_t cached_report;
    struct stat before, after;
    import_session_info_t current;

    pthread_mutex_lock(&lock);
    bool cacheable = (s_http_observing ? import_session_status_observe : import_session_status)(info->id, &current) &&
        import_review_same_session(info, &current) &&
        !info->portable_path[0] &&
        lstat(info->path, &before) == 0 && S_ISREG(before.st_mode);
    if (!refresh && cacheable && cached && import_review_same_session(info, &cached_info) &&
        import_review_same_file(&before, &cached_stat)) {
        *report = cached_report;
        bool ok = cached_ok;
        pthread_mutex_unlock(&lock);
        return ok;
    }
    if (s_http_observing) {
        memset(report, 0, sizeof(*report));
        pthread_mutex_unlock(&lock); return false;
    }
    cached = false;
    bool ok = import_review(info, report);
    if (cacheable && lstat(info->path, &after) == 0 &&
        import_review_same_file(&before, &after) &&
        import_session_status(info->id, &current) &&
        import_review_same_session(info, &current)) {
        cached_info = *info;
        cached_stat = after;
        cached_report = *report;
        cached_ok = ok;
        cached = true;
    }
    pthread_mutex_unlock(&lock);
    return ok;
}

static void handle_import_finish(int fd, const char* body) {
    char id[48] = {0}, sha[65] = {0}, title[16] = {0};
    json_get_string(body, "id", id, sizeof(id));
    json_get_string(body, "sha256", sha, sizeof(sha));
    json_get_string(body, "title_id", title, sizeof(title));
    if (title[0] && strcmp(title, "auto") != 0) {
        if (!title_id_candidate(title)) {
            reply_json(fd, 400, "{\"ok\":false,\"error\":\"invalid_title_id\"}");
            return;
        }
        (void)import_session_set_title_hint(id, title);
    }
    import_session_info_t info;
    bool already_ready = import_session_status(id, &info) &&
                         info.state == IMPORT_READY;
    if (!already_ready && !import_session_finish(id, sha, &info)) {
        char item[1536] = "{}", resp[1792];
        if (id[0] && import_session_status(id, &info))
            import_info_json(&info, item, sizeof(item));
        snprintf(resp, sizeof(resp),
                 "{\"ok\":false,\"error\":\"import_verification_failed\","
                 "\"import\":%s}", item);
        reply_json(fd, 400, resp);
        return;
    }
    migration_report_t report;
    bool valid = import_review_cached(&info, &report, true);
    char item[1536], review[4096], resp[5888];
    import_info_json(&info, item, sizeof(item));
    migration_report_json(&report, review, sizeof(review));
    snprintf(resp, sizeof(resp),
             "{\"ok\":%s,\"import\":%s,\"review\":%s}",
             valid ? "true" : "false", item, review);
    if (valid) {
        log_info("Restore review ready: %s (%s)",
                 report.title_id[0] ? report.title_id : info.name,
                 migration_format_name(report.format));
    } else {
        log_warn("Restore review blocked: %s (%s): %s",
                 report.title_id[0] ? report.title_id : info.name,
                 migration_format_name(report.format),
                 report.reason[0] ? report.reason : "preflight failed");
    }
    reply_json(fd, valid ? 200 : 400, resp);
}

static void handle_import_compatibility(int fd, const char* body) {
    restore_selection_request_t request;
    char resolved_uid[16] = {0};
    char selection_error[192] = {0};
    if (!restore_selection_request_parse(body, &request, selection_error, sizeof(selection_error))) {
        reply_json(fd, 400, "{\"ok\":false,\"error\":\"invalid_slot_selection\"}");
        return;
    }
    const char* id = request.id;
    const char* phase = request.phase;
    const char* expected_uid = request.target_uid;
    restore_selection_t selection = request.selection;
    if (strcmp(phase, "resolve") &&
        (strcmp(phase, "check") || !expected_uid[0])) {
        reply_json(fd, 409,
                   "{\"ok\":false,\"error\":\"target_confirmation_required\","
                   "\"detail\":\"Resolve and confirm the local target user before checking images.\"}");
        return;
    }
    if (!strcmp(phase, "check") && !selection.specified) {
        reply_json(fd, 409, "{\"ok\":false,\"error\":\"selection_required\"}");
        return;
    }
    char admission_detail[192] = {0};
    int admitted = watcher_target_check_begin(admission_detail, sizeof(admission_detail));
    if (admitted != 1) {
        char resp[512], *p = resp, *end = resp + sizeof(resp);
        jappendf(&p, end, "{\"ok\":false,\"error\":\"%s\",\"detail\":",
                 admitted == 0 ? "target_check_busy" : "recovery_pending");
        jappend_json_string(&p, end, admission_detail[0] ? admission_detail :
            admitted == 0 ? "A save operation is active; wait before checking target compatibility."
                          : "Save recovery state is unavailable; inspect before checking target compatibility.");
        jappendf(&p, end, "}");
        reply_json(fd, 409, resp);
        return;
    }
    import_session_info_t info;
    if (!id[0] || !import_session_status(id, &info) ||
        info.state != IMPORT_READY) {
        watcher_target_check_end();
        reply_json(fd, 409,
                   "{\"ok\":false,\"error\":\"import_not_ready\"}");
        return;
    }
    if (!strcmp(phase, "check") && selection.specified &&
        !import_session_invalidate_restore_scope(id, true)) {
        watcher_target_check_end();
        reply_json(fd, 409, "{\"ok\":false,\"error\":\"selection_checkpoint_failed\"}");
        return;
    }
    migration_report_t report;
    if (!import_review(&info, &report) || !report.needs_kernel ||
        !report.title_id[0] || report.save_dir_count == 0) {
        watcher_target_check_end();
        reply_json(fd, 400,
                   "{\"ok\":false,\"error\":\"not_portable_backup\"}");
        return;
    }
    if (selection.specified && (report.format != MIGRATION_FORMAT_TOSTON_DECRYPTED ||
        !report.has_checksums || !restore_selection_resolve(&selection, report.save_dirs,
                                report.save_dir_count, selection_error, sizeof(selection_error)))) {
        watcher_target_check_end();
        reply_json(fd, 400, "{\"ok\":false,\"error\":\"invalid_slot_selection\"}");
        return;
    }
    import_session_info_t current;
    if (!import_session_status(id, &current) || current.state != IMPORT_READY ||
        strcmp(current.id, info.id) || strcmp(current.path, info.path) ||
        strcmp(current.portable_path, info.portable_path) ||
        strcmp(current.sha256, info.sha256) ||
        strcmp(current.portable_sha256, info.portable_sha256) ||
        strcmp(current.title_hint, info.title_hint) ||
        current.expected != info.expected) {
        watcher_target_check_end();
        reply_json(fd, 409,
                   "{\"ok\":false,\"error\":\"import_changed\","
                   "\"detail\":\"Import changed during review; analyze it again before checking the target.\"}");
        return;
    }
    if (!strcmp(phase, "resolve")) {
        char detail[192] = {0}, resp[512], *p = resp, *end = resp + sizeof(resp);
        bool resolved = watcher_resolve_portable_target_held(
            report.title_id, resolved_uid, sizeof(resolved_uid), detail, sizeof(detail));
        watcher_target_check_end();
        jappendf(&p, end, "{\"ok\":%s,\"phase\":\"target_resolved\",\"target_uid\":",
                 resolved ? "true" : "false");
        jappend_json_string(&p, end, resolved_uid);
        jappendf(&p, end, ",\"detail\":");
        jappend_json_string(&p, end, detail);
        jappendf(&p, end, "}");
        reply_json(fd, resolved ? 200 : 409, resp);
        return;
    }
    const size_t selected_count = selection.specified ? selection.count : report.save_dir_count;
    const char (*selected_dirs)[64] = selection.specified ? selection.slots : report.save_dirs;
    size_t ready = 0, report_count = 0;
    sdimg_target_slot_report_t* slots = (sdimg_target_slot_report_t*)calloc(
        selected_count, sizeof(*slots));
    enum { RESP_CAP = 24 * 1024 };
    char* resp = (char*)calloc(1, RESP_CAP);
    if (!slots || !resp) {
        watcher_target_check_end();
        free(slots); free(resp);
        reply_json(fd, 503, "{\"ok\":false,\"error\":\"out_of_memory\"}");
        return;
    }
    char detail[192] = {0}, *p = resp, *end = resp + RESP_CAP;
    bool compatible = watcher_preflight_portable_target_held(
        expected_uid, report.title_id,
        selected_dirs, selected_count, &ready,
        slots, selected_count, &report_count,
        resolved_uid, sizeof(resolved_uid),
        detail, sizeof(detail));
    restore_scope_t scope = {0};
    if (compatible && selection.specified) {
        scope.selection = selection;
        snprintf(scope.restore_mode, sizeof(scope.restore_mode), "%s", RESTORE_MODE_PORTABLE_SELECTED);
        scope.available_slots = report.save_dir_count;
        snprintf(scope.import_id, sizeof(scope.import_id), "%s", info.id);
        snprintf(scope.title_id, sizeof(scope.title_id), "%s", report.title_id);
        snprintf(scope.target_uid, sizeof(scope.target_uid), "%s", resolved_uid);
        snprintf(scope.source_sha256, sizeof(scope.source_sha256), "%s", info.sha256);
        snprintf(scope.portable_sha256, sizeof(scope.portable_sha256), "%s", info.portable_sha256);
        if (ready != selected_count || report_count != selected_count ||
            !watcher_portable_target_state_held(&scope, scope.target_state_sha256,
                                               detail, sizeof(detail)) ||
            !restore_scope_digest(&scope, scope.receipt) ||
            !import_session_bind_restore_scope(&info, &scope)) {
            compatible = false;
            scope.receipt[0] = '\0';
            snprintf(detail, sizeof(detail), "Could not checkpoint the exact selected restore scope; no restore authorized");
        }
    }
    watcher_target_check_end();
    jappendf(&p, end, "{\"ok\":true,\"version\":\"%s\",\"restore_mode\":\"portable_selected\",\"ready\":%s,\"ready_slots\":%zu,"
             "\"available_slots\":%zu,\"selected_slots\":%zu,\"written_slots\":0,"
             "\"total_slots\":%zu,\"target_uid\":",
             TOSTONSYNC_VERSION, compatible ? "true" : "false", ready,
             report.save_dir_count, selected_count, selected_count);
    jappend_json_string(&p, end, resolved_uid);
    jappendf(&p, end, ",\"title_id\":");
    jappend_json_string(&p, end, report.title_id);
    jappendf(&p, end, ",\"selection_receipt\":");
    jappend_json_string(&p, end, scope.receipt);
    jappendf(&p, end, ",\"target_state_sha256\":");
    jappend_json_string(&p, end, scope.target_state_sha256);
    jappendf(&p, end, ",\"detail\":");
    jappend_json_string(&p, end, detail[0] ? detail :
                        "All target containers passed read-only validation");
    jappendf(&p, end, ",\"slots\":[");
    for (size_t i = 0; i < report_count; i++) {
        jappendf(&p, end, "%s{\"dir_name\":", i ? "," : "");
        jappend_json_string(&p, end, slots[i].dir_name);
        jappendf(&p, end, ",\"status\":");
        jappend_json_string(&p, end, slots[i].status);
        jappendf(&p, end, ",\"detail\":");
        jappend_json_string(&p, end, slots[i].detail);
        jappendf(&p, end, ",\"registry_status\":");
        jappend_json_string(&p, end, slots[i].registry_status);
        jappendf(&p, end, ",\"registry_rowid\":%lld,\"sqlite_code\":%d,"
                 "\"sqlite_extended_code\":%d,\"sqlite_message\":",
                 (long long)slots[i].registry_rowid,
                 slots[i].sqlite_code, slots[i].sqlite_extended_code);
        jappend_json_string(&p, end, slots[i].sqlite_message);
        jappendf(&p, end, ",\"stat_errno\":%d,\"container_bytes\":%llu,\"key_fingerprint\":",
                 slots[i].stat_errno,
                 (unsigned long long)slots[i].container_bytes);
        jappend_json_string(&p, end, slots[i].key_fingerprint);
        jappendf(&p, end, "}");
        log_info("portable-preflight[slot=%s]: status=%s stat_errno=%d bytes=%llu key_fp=%s",
                 slots[i].dir_name, slots[i].status,
                 slots[i].stat_errno,
                 (unsigned long long)slots[i].container_bytes,
                 slots[i].key_fingerprint[0] ? slots[i].key_fingerprint
                                             : "unavailable");
    }
    jappendf(&p, end, "]}");
    log_info("portable-preflight: title=%s ready=%s slots=%zu/%zu detail=%s",
             report.title_id, compatible ? "yes" : "no", ready,
             selected_count, detail[0] ? detail : "ready");
    reply_json(fd, 200, resp);
    free(slots);
    free(resp);
}

static void handle_import_recover(int fd, const char* body) {
    char id[48] = {0};
    json_get_string(body, "id", id, sizeof(id));
    import_session_info_t info;
    migration_report_t raw;
    if (!id[0] || !import_session_status(id, &info) ||
        info.state != IMPORT_READY || info.portable_path[0] ||
        !import_review(&info, &raw) ||
        raw.format != MIGRATION_FORMAT_ENCRYPTED_IMAGE || raw.selected_containers) {
        reply_json(fd, 409,
            "{\"ok\":false,\"error\":\"raw_recovery_not_ready\","
            "\"detail\":\"Choose a verified RAW import first. No saves were changed.\"}");
        return;
    }
    if (!import_session_begin_recovery(id, &info)) {
        reply_json(fd, 409,
            "{\"ok\":false,\"error\":\"raw_recovery_not_ready\","
            "\"detail\":\"Could not checkpoint recovery preparation. No saves were changed.\"}");
        return;
    }
    jobs_ref_t observed = jobs_native_begin(JOB_IMPORT, id);
    jobs_phase(observed, "ps5", "recovering", 0, false);
    char candidate[512], title[16], detail[256] = {0};
    bool prepared = watcher_recover_raw_import(&info, candidate, sizeof(candidate),
                                                title, sizeof(title),
                                                detail, sizeof(detail));
    bool published = import_session_finish_recovery(id,
        prepared ? candidate : NULL, prepared ? title : NULL,
        prepared ? NULL : detail, &info);
    migration_report_t report;
    bool valid = import_review(&info, &report);
    char item[2048], review[4096], resp[6912], *p = resp, *end = resp + sizeof(resp);
    import_info_json(&info, item, sizeof(item));
    migration_report_json(&report, review, sizeof(review));
    jappendf(&p, end, "{\"ok\":%s,\"detail\":",
             published && valid ? "true" : "false");
    jappend_json_string(&p, end, published && valid
        ? "Recovery copy verified. Original retained; no saves changed."
        : info.error[0] ? info.error : "Recovery blocked; original retained. No saves changed.");
    jappendf(&p, end, ",\"import\":%s,\"review\":%s}", item, review);
    log_info("raw-recovery: result=%s original_retained=yes save_writes=no",
             published && valid ? "verified_portable" : "blocked");
    reply_json(fd, published && valid ? 200 : 409, resp);
}

static void handle_import_selected_commit(int fd, const restore_selection_request_t* request) {
    const char* id = request->id;
    const char* uid = request->target_uid;
    const char* receipt = request->selection_receipt;
    restore_selection_t selection = request->selection;
    char detail[192] = {0};
    if (!id[0] || strlen(id) >= 48 || !uid[0] || strlen(uid) >= 16 || strlen(receipt) != 64) {
        reply_json(fd, 409, "{\"ok\":false,\"error\":\"selected_preflight_required\"}");
        return;
    }
    int admission = watcher_target_check_begin(detail, sizeof(detail));
    if (admission != 1) {
        reply_json(fd, 409, admission == 0
            ? "{\"ok\":false,\"error\":\"target_check_busy\"}"
            : "{\"ok\":false,\"error\":\"recovery_pending\"}");
        return;
    }
    import_session_info_t info;
    restore_scope_t scope;
    migration_report_t report;
    bool matched = import_session_status(id, &info) && info.state == IMPORT_READY &&
        !info.error[0] && import_session_get_restore_scope(id, &scope) &&
        !strcmp(scope.target_uid, uid) && !strcmp(scope.receipt, receipt) &&
        import_review(&info, &report) && report.needs_kernel &&
        report.format == MIGRATION_FORMAT_TOSTON_DECRYPTED && report.has_checksums &&
        !strcmp(report.title_id, scope.title_id) && report.save_dir_count == scope.available_slots &&
        restore_selection_resolve(&selection, report.save_dirs, report.save_dir_count,
                                  detail, sizeof(detail)) &&
        restore_selection_equal(&selection, &scope.selection);
    if (!matched) {
        watcher_target_check_end();
        reply_json(fd, 409, "{\"ok\":false,\"error\":\"restore_scope_changed\"}");
        return;
    }
    size_t ready = 0;
    char resolved[16] = {0};
    bool compatible = watcher_preflight_portable_target_held(
        scope.target_uid, scope.title_id, scope.selection.slots, scope.selection.count,
        &ready, NULL, 0, NULL, resolved, sizeof(resolved), detail, sizeof(detail));
    if (!compatible || ready != scope.selection.count || strcmp(resolved, scope.target_uid)) {
        watcher_target_check_end();
        reply_json(fd, 409, "{\"ok\":false,\"error\":\"target_not_ready\"}");
        return;
    }
    char target_state[65] = {0};
    if (!watcher_portable_target_state_held(&scope, target_state, detail, sizeof(detail)) ||
        strcmp(target_state, scope.target_state_sha256)) {
        (void)import_session_invalidate_restore_scope(id, true);
        watcher_target_check_end();
        reply_json(fd, 409, "{\"ok\":false,\"error\":\"target_state_changed\"}");
        return;
    }
    if (!import_session_claim_restore_scope(&scope, &info)) {
        watcher_target_check_end();
        reply_json(fd, 409, "{\"ok\":false,\"error\":\"restore_scope_changed\"}");
        return;
    }
    char ref[560];
    snprintf(ref, sizeof(ref), "upload:%s", import_session_selected_path(&info));
    watcher_job_admission_t observed = {0};
    bool queued = watcher_restore_selected_async_observed(&scope, ref, &observed);
    bool released = queued || import_session_unclaim(id);
    watcher_target_check_end();
    if (!queued) {
        reply_json(fd, 500, released
            ? "{\"ok\":false,\"error\":\"restore_queue_failed\"}"
            : "{\"ok\":false,\"error\":\"selection_checkpoint_uncertain\"}");
        return;
    }
    char response[768];
    snprintf(response, sizeof(response), "{\"ok\":true,\"status\":\"queued\",\"restore_mode\":\"portable_selected\","
             "\"available_slots\":%zu,\"selected_slots\":%zu,\"total_slots\":%zu,"
             "\"ready_slots\":%zu,\"written_slots\":0,\"selection_receipt\":\"%s\"",
             scope.available_slots, scope.selection.count, scope.selection.count,
             ready, scope.receipt);
    char* p = response + strlen(response); char* end = response + sizeof(response);
    jobs_json_fields(&p, end, observed.id, observed.coalesced); jappendf(&p, end, "}");
    reply_json(fd, 200, response);
}

static void handle_import_commit(int fd, const char* body) {
    restore_selection_request_t request;
    if (!restore_selection_request_parse(body, &request, NULL, 0)) {
        reply_json(fd, 400, "{\"ok\":false,\"error\":\"invalid_slot_selection\"}");
        return;
    }
    if (request.selection.specified) {
        handle_import_selected_commit(fd, &request);
        return;
    }
    char uid[16]; bool uid_explicit;
    if (!restore_request_uid(body, uid, &uid_explicit) ||
        (uid_explicit && !watcher_restore_uid_is_local(uid))) {
        reply_json(fd, 400, "{\"ok\":false,\"error\":\"invalid_restore_uid\"}"); return;
    }
    const char* id = request.id;
    const char* user = uid_explicit ? uid : request.user;
    if (strlen(user) >= 16) {
        reply_json(fd, 400, "{\"ok\":false,\"error\":\"invalid_restore_user\"}");
        return;
    }
    import_session_info_t info;
    if (!import_session_status(id, &info) || info.state != IMPORT_READY) {
        reply_json(fd, 409, "{\"ok\":false,\"error\":\"import_not_ready\"}");
        return;
    }
    char bound_uid[16]; int bound = import_session_restore_uid(id,bound_uid);
    if (bound < 0 || (bound && ((uid_explicit && strcmp(uid,bound_uid)) ||
                              (!uid_explicit && request.user[0])))) {
        reply_json(fd,409,"{\"ok\":false,\"error\":\"restore_scope_changed\"}"); return;
    }
    if (bound) { snprintf(uid,sizeof(uid),"%s",bound_uid); uid_explicit=true; user=uid; }
    if (uid_explicit && !watcher_restore_uid_is_local(uid)) {
        reply_json(fd,409,"{\"ok\":false,\"error\":\"restore_target_uid_missing\"}"); return;
    }
    if (info.restore_selection_required) {
        reply_json(fd, 409, "{\"ok\":false,\"error\":\"selection_required\"}");
        return;
    }
    if (info.error[0]) {
        char resp[512], *p = resp, *end = resp + sizeof(resp);
        jappendf(&p, end, "{\"ok\":false,\"error\":\"raw_recovery_blocked\",\"detail\":");
        jappend_json_string(&p, end, info.error);
        jappendf(&p, end, "}");
        reply_json(fd, 409, resp);
        return;
    }
    migration_report_t report;
    // New selected RAW exports are inspectable evidence, not full recovery.
    // This changes admission of that new scope only, never the Restore engine.
    bool reviewed = import_review(&info, &report);
    if (reviewed && report.selected_containers) {
        reply_json(fd, 409, "{\"ok\":false,\"error\":\"partial_raw_restore_blocked\"}");
        return;
    }
    if (!reviewed) {
        char item[1536], review[4096], resp[6400];
        char* p = resp;
        char* end = resp + sizeof(resp);
        import_info_json(&info, item, sizeof(item));
        migration_report_json(&report, review, sizeof(review));
        jappendf(&p, end,
                 "{\"ok\":false,\"error\":\"restore_preflight_failed\","
                 "\"detail\":");
        jappend_json_string(&p, end,
                            report.reason[0] ? report.reason
                            : "Unable to analyze this backup safely.");
        jappendf(&p, end, ",\"import\":%s,\"review\":%s}", item, review);
        reply_json(fd, 400, resp);
        return;
    }
    if (report.needs_kernel) {
        reply_json(fd, 409,
            "{\"ok\":false,\"error\":\"selection_required\","
            "\"detail\":\"Portable restore requires explicit selected slots and a fresh server-held target approval.\"}");
        return;
    }
    if (!import_session_claim(id, &info)) {
        reply_json(fd, 409,
                   "{\"ok\":false,\"error\":\"import_already_committed\"}");
        return;
    }
    char ref[560];
    snprintf(ref, sizeof(ref), "upload:%s", import_session_selected_path(&info));
    const char* target_user = report.needs_kernel ? "" :
                             (user[0] ? user : info.user_hint);
    watcher_job_admission_t observed = {0};
    if (!watcher_restore_async_observed(target_user[0] ? target_user : NULL,
                               report.title_id, ref, &observed, uid_explicit, id)) {
        (void)import_session_unclaim(id);
        reply_json(fd, 500, "{\"ok\":false,\"error\":\"restore_queue_failed\"}");
        return;
    }
    // The queued worker validates this path again before touching save data.
    // Keep the reviewed session alive until that worker completes; releasing
    // it here would make a successfully queued restore fail validation.
    jobs_queued_reply(fd, observed.id, observed.coalesced);
}

// The RAW-selected contract/transaction is an offline foundation only. This
// backend endpoint cannot claim an import, enqueue a worker or touch savedata,
// including when a client manually supplies a valid receipt and durable plan.
__attribute__((unused)) static void handle_raw_selected_commit_disabled(int fd, const char* body) {
    (void)body;
    char response[384];
    snprintf(response, sizeof(response),
             "{\"ok\":false,\"version\":\"%s\","
             "\"restore_mode\":\"raw_selected_exact\","
             "\"error\":\"raw_selected_publication_disabled\","
             "\"publication_enabled\":false,\"published\":false,\"live_writebacks\":0}",
             TOSTONSYNC_VERSION);
    reply_json(fd, 409, response);
}

static void raw_commit_reply(int fd, int code, const raw_selected_commit_report_t* r) {
    char* response = calloc(1, 131072);
    if (!response) { reply_json(fd, 500, "{\"error\":\"allocation_failed\"}"); return; }
    char* p = response; char* end = response + 131072;
    jappendf(&p, end, "{\"ok\":%s,\"version\":\"%s\",\"restore_mode\":\"raw_selected_exact\",\"result\":",
        r->queued || !strcmp(r->result, "PUBLISHED_VERIFIED") ? "true" : "false", r->version);
    jappend_json_string(&p, end, r->result);
    jappendf(&p, end, ",\"id\":"); jappend_json_string(&p, end, r->import_id);
    jappendf(&p, end, ",\"target_uid\":"); jappend_json_string(&p, end, r->target_uid);
    jappendf(&p, end, ",\"title_id\":"); jappend_json_string(&p, end, r->title_id);
    jappendf(&p, end, ",\"zip_sha256\":"); jappend_json_string(&p, end, r->zip_sha256);
    jappendf(&p, end, ",\"selection_receipt\":"); jappend_json_string(&p, end, r->selection_receipt);
    jappendf(&p, end, ",\"authority_sha256\":"); jappend_json_string(&p, end, r->authority_sha256);
    jappendf(&p, end, ",\"detail\":"); jappend_json_string(&p, end, r->detail);
    jappendf(&p, end, ",\"queued\":%s,\"terminal\":%s,\"publication_enabled\":%s,\"destructive_recovery_enabled\":false,"
        "\"recovery_required\":%s,\"barrier_retained\":%s,\"publication_uncertain\":%s,"
        "\"selected_active_slots\":%zu,\"selected_service_images\":%zu,\"authorized_images\":%zu,"
        "\"attempted_images\":%zu,\"written_images\":%zu,\"written_active_slots\":%zu,\"written_service_images\":%zu,"
        "\"verified_images\":%zu,\"uncertain_images\":%zu,\"hmac_cryptographically_validated\":false,\"evidence_workspace\":",
        r->queued ? "true" : "false", r->terminal ? "true" : "false", r->publication_enabled ? "true" : "false",
        r->recovery_required ? "true" : "false", r->barrier_retained ? "true" : "false", r->publication_uncertain ? "true" : "false",
        r->selected_active_slots, r->selected_service_images, r->authorized_images, r->attempted_images,
        r->written_images, r->written_active_slots, r->written_service_images, r->verified_images, r->uncertain_images);
    jappend_json_string(&p, end, r->workspace); jappendf(&p, end, ",\"images\":[");
    for (size_t i = 0; i < r->image_count && i < RAW_SELECTED_MAX_IMAGES; i++) {
        const raw_selected_commit_image_t* e = &r->images[i];
        jappendf(&p, end, "%s{\"role\":\"%s\",\"image_name\":", i ? "," : "",
            e->role == RAW_SELECTED_ROLE_ACTIVE ? "active" : "service");
        jappend_json_string(&p, end, e->image_name);
        jappendf(&p, end, ",\"target\":"); jappend_json_string(&p, end, e->target);
        jappendf(&p, end, ",\"source_sha256\":"); jappend_json_string(&p, end, e->source_sha256);
        jappendf(&p, end, ",\"pre_sha256\":"); jappend_json_string(&p, end, e->pre_sha256);
        jappendf(&p, end, ",\"pre_identity_sfo_key_geometry_unmount_verified\":%s,\"post_identity_sfo_key_geometry_unmount_verified\":%s}",
            e->pre_verified ? "true" : "false", e->post_verified ? "true" : "false");
    }
    jappendf(&p, end, "]}"); reply_json(fd, code, response); free(response);
}
static void handle_raw_selected_commit(int fd, const char* body) {
    raw_selected_preflight_request_t request; char receipt[65], err[256] = {0};
    raw_selected_commit_report_t* r = calloc(1, sizeof(*r));
    if (!r) { reply_json(fd, 500, "{\"error\":\"allocation_failed\"}"); return; }
    if (!raw_selected_commit_parse(body, &request, receipt, err, sizeof(err))) {
        snprintf(r->version, sizeof(r->version), "%s", TOSTONSYNC_VERSION);
        snprintf(r->result, sizeof(r->result), "BLOCKED"); snprintf(r->detail, sizeof(r->detail), "%s", err);
        r->terminal = true; raw_commit_reply(fd, 409, r); free(r); return;
    }
    raw_selected_commit_submit(&request, receipt, r);
    raw_commit_reply(fd, r->queued ? 202 : 409, r); free(r);
}
static void handle_raw_selected_status(int fd, const char* query) {
    char id[48], receipt[65]; raw_selected_commit_report_t* r = calloc(1, sizeof(*r));
    if (!r) { reply_json(fd, 500, "{\"error\":\"allocation_failed\"}"); return; }
    if (!query_get_decoded(query, "id", id, sizeof(id)) ||
        !query_get_decoded(query, "selection_receipt", receipt, sizeof(receipt)) ||
        !raw_selected_commit_status(id, receipt, r)) {
        free(r); reply_json(fd, 409, "{\"ok\":false,\"result\":\"UNKNOWN\",\"detail\":\"Exact RAW job proof unavailable; no replay\"}"); return;
    }
    raw_commit_reply(fd, 200, r); free(r);
}

static const char* raw_check_name(raw_selected_check_t check) {
    return check == RAW_SELECTED_CHECK_PASS ? "PASS" : check == RAW_SELECTED_CHECK_FAIL ? "FAIL" : "UNKNOWN";
}
static void raw_identity_json(char** p, char* end, const raw_selected_identity_t* id) {
    jappendf(p, end, "{\"metadata_complete\":%s,\"hmac_present\":%s,\"hmac_cryptographically_validated\":false,\"title_id\":",
        id->metadata_complete ? "true" : "false", id->hmac_present ? "true" : "false");
    jappend_json_string(p, end, id->title_id);
    jappendf(p, end, ",\"slot\":"); jappend_json_string(p, end, id->slot);
    jappendf(p, end, ",\"game_title_id\":"); jappend_json_string(p, end, id->game_title_id);
    jappendf(p, end, ",\"format\":"); jappend_json_string(p, end, id->format);
    jappendf(p, end, ",\"account_id\":\"%016llx\",\"user_id\":%u,\"user_param\":%u,\"blocks\":%llu,\"system_blocks\":%llu,\"sfo_sha256\":",
        (unsigned long long)id->account_id, id->user_id, id->user_param,
        (unsigned long long)id->blocks, (unsigned long long)id->system_blocks);
    jappend_json_string(p, end, id->sfo_sha256);
    jappendf(p, end, ",\"hmac_fingerprint\":"); jappend_json_string(p, end, id->hmac_sha256);
    jappendf(p, end, "}");
}
// Distinct private RAW contract: no legacy/portable worker or commit admission.
static void handle_raw_selected_preflight(int fd, const char* body) {
    raw_selected_preflight_request_t request; char err[256] = {0};
    if (!raw_selected_preflight_parse(body, &request, err, sizeof(err))) {
        char response[1024], *p = response, *end = response + sizeof(response);
        jappendf(&p, end, "{\"ok\":false,\"version\":\"%s\",\"publication_enabled\":false,\"error\":\"exact_raw_request_required\",\"detail\":", TOSTONSYNC_VERSION);
        jappend_json_string(&p, end, err); jappendf(&p, end, "}"); reply_json(fd, 400, response); return;
    }
    raw_selected_preflight_report_t* r = calloc(1, sizeof(*r));
    char* response = calloc(1, 262144);
    if (!r || !response) { free(r); free(response); reply_json(fd, 500, "{\"error\":\"allocation_failed\"}"); return; }
    raw_selected_preflight_run(&request, r);
    char *p = response, *end = response + 262144;
    jappendf(&p, end, "{\"ok\":%s,\"version\":\"%s\",\"restore_mode\":\"raw_selected_exact\",\"contract_version\":%u,\"result\":",
        r->ready ? "true" : "false", r->version, RAW_SELECTED_CONTRACT_VERSION);
    jappend_json_string(&p, end, r->result);
    jappendf(&p, end, ",\"id\":"); jappend_json_string(&p, end, r->import_id);
    jappendf(&p, end, ",\"target_uid\":"); jappend_json_string(&p, end, r->target_uid);
    jappendf(&p, end, ",\"title_id\":"); jappend_json_string(&p, end, r->title_id);
    jappendf(&p, end, ",\"zip_sha256\":"); jappend_json_string(&p, end, r->zip_sha256);
    jappendf(&p, end, ",\"detail\":"); jappend_json_string(&p, end, r->detail);
    jappendf(&p, end, ",\"source_check\":\"%s\",\"target_check\":\"%s\",\"ready\":%s,\"publication_enabled\":false,\"commit_reachable\":%s,\"destructive_recovery_enabled\":false,",
        raw_check_name(r->source_check), raw_check_name(r->target_check), r->ready ? "true" : "false", r->ready ? "true" : "false");
    jappendf(&p, end, "\"available_backup_slots\":%zu,\"source_title_available_slots\":%zu,\"selected_active_slots\":%zu,\"selected_service_images\":%zu,\"authorized_images\":%zu,\"ready_active_slots\":%zu,\"ready_service_images\":%zu,\"total_slots\":%zu,\"written_slots\":%zu,\"written_images\":%zu,",
        r->available_backup_slots, r->source_title_available_slots, r->selected_active_slots, r->selected_service_images,
        r->authorized_images, r->ready_active_slots, r->ready_service_images, r->total_slots, r->written_slots, r->written_images);
    jappendf(&p, end, "\"barrier_armed\":%s,\"barrier_cleared\":%s,\"barrier_retained\":%s,\"recovery_required\":%s,\"approval_durable\":%s,\"evidence_workspace\":",
        r->barrier_armed ? "true" : "false", r->barrier_cleared ? "true" : "false", r->barrier_retained ? "true" : "false",
        r->recovery_required ? "true" : "false", r->approval_durable ? "true" : "false");
    jappend_json_string(&p, end, r->work);
    jappendf(&p, end, ",\"selection_receipt\":"); jappend_json_string(&p, end, r->selection_receipt);
    jappendf(&p, end, ",\"plan_sha256\":"); jappend_json_string(&p, end, r->plan_sha256);
    jappendf(&p, end, ",\"images\":[");
    for (size_t i = 0; i < r->image_count; i++) {
        const raw_selected_preflight_image_report_t* image = &r->images[i];
        const char* row = image->row.status == RAW_SELECTED_ROW_FOUND ? "ROW_FOUND" :
            image->row.status == RAW_SELECTED_ROW_ABSENT ? "ROW_ABSENT" :
            image->row.status == RAW_SELECTED_ROW_SQLITE_ERROR ? "SQLITE_ERROR" : "UNKNOWN";
        jappendf(&p, end, "%s{\"transport_role\":\"%s\",\"role\":\"%s\",\"role_reliable\":%s,\"future_additional_authorization_required\":%s,\"slot\":",
            i ? "," : "", image->role == RAW_SELECTED_ROLE_SERVICE ? "SERVICE" : "ACTIVE",
            image->save_kind == RAW_SELECTED_SAVE_KIND_SYSTEM ? "SystemSaveData" :
            image->save_kind == RAW_SELECTED_SAVE_KIND_REGULAR ? "GameSaveData" : "UNKNOWN",
            image->save_kind_reliable ? "true" : "false", image->additional_authorization_required ? "true" : "false");
        jappend_json_string(&p, end, image->slot);
        jappendf(&p, end, ",\"image_name\":"); jappend_json_string(&p, end, image->image_name);
        jappendf(&p, end, ",\"result\":"); jappend_json_string(&p, end, image->result);
        jappendf(&p, end, ",\"detail\":"); jappend_json_string(&p, end, image->detail);
        jappendf(&p, end, ",\"registry_status\":\"%s\",\"registry_rowid\":%lld,\"sqlite_code\":%d,\"sqlite_extended_code\":%d,\"owner_verified\":%s,\"source_sha256\":",
            row, (long long)image->row.rowid, image->row.sqlite_code, image->row.sqlite_extended_code,
            image->row.owner_verified ? "true" : "false");
        jappend_json_string(&p, end, image->source_sha256);
        jappendf(&p, end, ",\"target_sha256\":"); jappend_json_string(&p, end, image->target_sha256);
        jappendf(&p, end, ",\"source_key_fingerprint\":"); jappend_json_string(&p, end, image->source_key_fingerprint);
        jappendf(&p, end, ",\"target_key_fingerprint\":"); jappend_json_string(&p, end, image->target_key_fingerprint);
        jappendf(&p, end, ",\"omitted_service\":"); jappend_json_string(&p, end, image->omitted_service_result);
        jappendf(&p, end, ",\"source_identity\":"); raw_identity_json(&p, end, &image->source_identity);
        jappendf(&p, end, ",\"target_identity\":"); raw_identity_json(&p, end, &image->target_identity);
        jappendf(&p, end, "}");
    }
    jappendf(&p, end, "],\"limits\":");
    jappend_json_string(&p, end, "Private RAW preflight only. Canonical ZIP/images and live targets are never mounted or modified. Native mount/unmount may reseal disposable copies. HMAC presence/equality is not cryptographic validation or game acceptance. Semantic role stays UNKNOWN without reliable metadata; no filename inference. Only unchanged active plus a stable privately checked service demonstrates omitted-service coherence. Gate excludes daemon work, not external writers; stability checks are observational. Durable approval is diagnostic evidence, not a commit lease. Publication and destructive recovery remain disabled.");
    jappendf(&p, end, "}");
    if (p >= end - 1) reply_json(fd, 500, "{\"error\":\"raw_preflight_response_overflow\",\"ready\":false,\"publication_enabled\":false}");
    else reply_json(fd, r->ready ? 200 : 409, response);
    free(response); free(r);
}

static void handle_import_cancel(int fd, const char* body) {
    char id[48] = {0};
    json_get_string(body, "id", id, sizeof(id));
    char detail[192] = {0};
    if (!watcher_cancel_import(id, detail, sizeof(detail))) {
        if (detail[0]) {
            char resp[512], *p = resp, *end = resp + sizeof(resp);
            jappendf(&p, end, "{\"ok\":false,\"error\":\"recovery_pending\",\"detail\":");
            jappend_json_string(&p, end, detail);
            jappendf(&p, end, "}");
            reply_json(fd, 409, resp);
            return;
        }
        reply_json(fd, 404, "{\"ok\":false,\"error\":\"import_not_found\"}");
        return;
    }
    reply_json(fd, 200, "{\"ok\":true}");
}

#define BACKUP_CATALOG_MAX 512
#define BACKUP_CATALOG_JSON_CAP (1280 * 1024)

typedef struct {
    char     source[8];     // "drive", "usb", "ftp"
    char     user[32];
    char     raw_user[32];   // provider folder key, never the display alias
    char     title_id[16];
    char     game[64];
    char     ref[320];      // Drive file_id, USB path, or "ftp:<path>"
    char     name[128];
    uint64_t size_bytes;
    int64_t  created_unix;
    bool     local_present;
    bool     is_latest;
    char     destination_identity[65];
    char     file_stamp[65]; // USB file incarnation captured by its listing
    uint64_t generation;    // Drive session used by its listing
    char     delete_proof[65];
    char     destination_label[512];
    char     usb_volume_id[65], usb_mount[64]; // display binding; deletion still revalidates provider proof
    bool     older_unconfirmed; // presentation only
    char     observed_drive_root[GDRIVE_FILEID_MAX]; // Presentation only; not deletion authority.
    bool     cleanup_verified; // complete current scan; never supplied by client
} backup_catalog_item_t;

// A ticket references server-owned listing evidence, not client-supplied paths
// or identities. Restart invalidates it; failed deletion consumes it too.
// ponytail: bounded volatile catalog cache; eviction needs a fresh user scan,
// never a persistence framework or automatic destructive retry.
static pthread_mutex_t s_delete_lock = PTHREAD_MUTEX_INITIALIZER;
// ponytail: serialize bounded, user-driven scans through publication. Parallel
// snapshots need ordered epochs if scan latency ever warrants that complexity.
static pthread_mutex_t s_catalog_lock = PTHREAD_MUTEX_INITIALIZER;
static backup_catalog_item_t s_delete_catalog[BACKUP_CATALOG_MAX];
static uint8_t s_delete_nonce[32];
static bool s_delete_nonce_ready;
static uint64_t s_delete_serial;
static size_t s_delete_next;

static bool catalog_delete_same(const backup_catalog_item_t* a,
                                 const backup_catalog_item_t* b) {
    return !strcmp(a->source, b->source) && !strcmp(a->raw_user, b->raw_user) &&
        !strcmp(a->title_id, b->title_id) && !strcmp(a->ref, b->ref) &&
        !strcmp(a->name, b->name) && a->size_bytes == b->size_bytes &&
        !strcmp(a->destination_identity, b->destination_identity) &&
        !strcmp(a->file_stamp, b->file_stamp) && a->generation == b->generation &&
        !strcmp(a->destination_label, b->destination_label);
}

static void catalog_delete_ticket(backup_catalog_item_t* item) {
    item->delete_proof[0] = '\0';
    if (!item->size_bytes || !dest_fingerprint_hex(item->destination_identity) ||
        (!strcmp(item->source, "usb") && !dest_fingerprint_hex(item->file_stamp))) return;
    pthread_mutex_lock(&s_delete_lock);
    if (!s_delete_nonce_ready) {
        int fd = open("/dev/urandom", O_RDONLY);
        ssize_t n = fd >= 0 ? read(fd, s_delete_nonce, sizeof(s_delete_nonce)) : -1;
        if (fd >= 0) close(fd);
        s_delete_nonce_ready = n == (ssize_t)sizeof(s_delete_nonce);
    }
    if (s_delete_nonce_ready) {
        for (size_t i = 0; i < BACKUP_CATALOG_MAX; i++)
            if (s_delete_catalog[i].delete_proof[0] &&
                catalog_delete_same(item, &s_delete_catalog[i])) {
                memcpy(item->delete_proof, s_delete_catalog[i].delete_proof, 65);
                s_delete_catalog[i].cleanup_verified = item->cleanup_verified;
                pthread_mutex_unlock(&s_delete_lock);
                return;
            }
        sha256_ctx_t ctx;
        uint8_t digest[32];
        ++s_delete_serial;
        sha256_init(&ctx);
        static const char domain[] = "tostonsync-library-delete-v1";
        sha256_update(&ctx, domain, sizeof(domain) - 1);
        sha256_update(&ctx, s_delete_nonce, sizeof(s_delete_nonce));
        sha256_update(&ctx, &s_delete_serial, sizeof(s_delete_serial));
        sha256_final(&ctx, digest);
        for (size_t i = 0; i < sizeof(digest); i++)
            snprintf(item->delete_proof + i * 2, 3, "%02x", digest[i]);
        s_delete_catalog[s_delete_next] = *item;
        s_delete_next = (s_delete_next + 1) % BACKUP_CATALOG_MAX;
    }
    pthread_mutex_unlock(&s_delete_lock);
}

static bool catalog_title_id_ok(const char* t) {
    if (!t || !t[0]) return false;
    for (size_t i = 0; t[i]; i++) {
        unsigned char c = (unsigned char)t[i];
        bool ok = (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
                  (c >= '0' && c <= '9') || c == '_';
        if (!ok) return false;
    }
    return true;
}

static bool catalog_same_key(const backup_catalog_item_t* a,
                             const backup_catalog_item_t* b) {
    return strcmp(a->user, b->user) == 0 &&
           strcmp(a->title_id, b->title_id) == 0;
}

static bool catalog_newer(const backup_catalog_item_t* a,
                          const backup_catalog_item_t* b) {
    if (a->created_unix != b->created_unix)
        return a->created_unix > b->created_unix;
    return strcmp(a->name, b->name) > 0;
}

static bool catalog_source_wanted(const char* filter, const char* source) {
    if (!filter || !filter[0] || strcmp(filter, "best") == 0 ||
        strcmp(filter, "all") == 0) return true;
    return strcmp(filter, source) == 0;
}

// Backup folders created before a friendly alias was configured use the raw
// PS5 UID. Treat that UID and its current alias as one catalog identity while
// keeping the original source path/ref untouched for restore.
static void catalog_canonical_user(const char* user, char* out, size_t out_sz) {
    if (!out || out_sz == 0) return;
    const char* raw = (user && user[0]) ? user : "default";
    const char* alias = config_alias_for_uid(raw);
    snprintf(out, out_sz, "%s", (alias && alias[0]) ? alias : raw);
}

static void catalog_add(backup_catalog_item_t* items, size_t max,
                        size_t* count, const char* source,
                        const char* user, const char* title,
                        const char* ref, const char* name,
                        uint64_t size_bytes, int64_t created_unix,
                        const char* identity, const char* file_stamp,
                        uint64_t generation, const char* destination_label) {
    if (!items || !count || *count >= max || !source || !ref || !ref[0]) return;
    if (strlen(source) >= sizeof(items[0].source) ||
        (user && strlen(user) >= sizeof(items[0].raw_user)) ||
        strlen(ref) >= sizeof(items[0].ref) ||
        (name && strlen(name) >= sizeof(items[0].name))) return;
    if (!catalog_title_id_ok(title) || strlen(title) >= sizeof(items[0].title_id)) return;
    backup_catalog_item_t* it = &items[*count];
    memset(it, 0, sizeof(*it));
    snprintf(it->source, sizeof(it->source), "%s", source);
    snprintf(it->raw_user, sizeof(it->raw_user), "%s", user ? user : "default");
    catalog_canonical_user(user, it->user, sizeof(it->user));
    snprintf(it->title_id, sizeof(it->title_id), "%s", title);
    snprintf(it->ref, sizeof(it->ref), "%s", ref);
    snprintf(it->name, sizeof(it->name), "%s",
             (name && name[0]) ? name : "backup.zip");
    it->size_bytes = size_bytes;
    it->created_unix = created_unix;
    snprintf(it->destination_identity, sizeof(it->destination_identity), "%s",
             identity ? identity : "");
    snprintf(it->file_stamp, sizeof(it->file_stamp), "%s", file_stamp ? file_stamp : "");
    it->generation = generation;
    snprintf(it->destination_label, sizeof(it->destination_label), "%s",
             destination_label ? destination_label : "");
    const char* manual = config_title_alias_for(title);
    if (manual[0]) {
        titlename_copy_utf8(it->game, sizeof(it->game), manual);
    } else {
        metacache_resolve_name(title, NULL, it->game, sizeof(it->game));
    }
    (*count)++;
}

typedef struct {
    char user[32];
    char title_id[16];
} local_save_pair_t;

typedef struct {
    local_save_pair_t* pairs;
    size_t count;
    size_t max;
} local_pair_ctx_t;

static void catalog_local_cb(const char* user_alias,
                             const char* user_uid,
                             const char* title_id,
                             const char* game_name,
                             bool included,
                             void* ud) {
    (void)user_alias; (void)game_name; (void)included;
    local_pair_ctx_t* c = (local_pair_ctx_t*)ud;
    if (!c || !c->pairs || c->count >= c->max || !title_id) return;
    catalog_canonical_user(user_uid, c->pairs[c->count].user,
                           sizeof(c->pairs[c->count].user));
    snprintf(c->pairs[c->count].title_id,
             sizeof(c->pairs[c->count].title_id), "%s", title_id);
    c->count++;
}

static void catalog_scan_gap(catalog_scan_t* scan, const char* reason) {
    if (!scan) return;
    if (scan->state != CATALOG_PARTIAL || !scan->reason || !strcmp(scan->reason,"entry_unconfirmed"))
        scan->reason = reason;
    scan->state = CATALOG_PARTIAL;
}

static void catalog_scan_entry(catalog_scan_t* scan, const backup_catalog_item_t* it) {
    if (!scan) return;
    if (!it || !it->raw_user[0] || !it->name[0] || !it->size_bytes)
        catalog_scan_gap(scan, "invalid_entry");
    else if (!dest_fingerprint_hex(it->destination_identity) ||
             (!strcmp(it->source, "usb") && !dest_fingerprint_hex(it->file_stamp)))
        catalog_scan_gap(scan, !strcmp(it->source,"usb") && !it->older_unconfirmed ? "invalid_entry" : "entry_unconfirmed");
}

static size_t build_backup_catalog_scanned(backup_catalog_item_t* items, size_t max,
                                   const char* source_filter, catalog_scan_t scans[3]) {
    if (!items || max == 0) return 0;
    size_t n = 0;
    if (scans) for (size_t i = 0; i < 3; i++)
        scans[i] = (catalog_scan_t){CATALOG_UNAVAILABLE, "not_selected", false};

    if (catalog_source_wanted(source_filter, "usb")) {
        usb_backup_t* usb = (usb_backup_t*)calloc(BACKUP_CATALOG_MAX, sizeof(*usb));
        if (usb) {
            size_t un = usb_catalog_scan(usb, BACKUP_CATALOG_MAX, scans ? &scans[0] : NULL);
            size_t included = 0;
            for (size_t i = 0; i < un && n < max; i++) {
                size_t before = n;
                catalog_add(items, max, &n, "usb", usb[i].user,
                            usb[i].title_id, usb[i].path, usb[i].name,
                            usb[i].size_bytes, usb[i].created_unix,
                            usb[i].destination_identity, usb[i].file_stamp, 0,
                            usb[i].destination_label);
                if (n > before) {
                    snprintf(items[before].usb_volume_id, sizeof(items[before].usb_volume_id), "%s", usb[i].volume_id);
                    snprintf(items[before].usb_mount, sizeof(items[before].usb_mount), "%s", usb[i].mount);
                    items[before].older_unconfirmed = usb[i].older_unconfirmed;
                }
                catalog_scan_entry(scans ? &scans[0] : NULL, n > before ? &items[before] : NULL);
                included++;
            }
            if (included < un) catalog_scan_gap(scans ? &scans[0] : NULL, "catalog_limit");
            free(usb);
        } else if (scans) scans[0] = (catalog_scan_t){CATALOG_UNAVAILABLE, "memory", true};
    }



    if (catalog_source_wanted(source_filter, "drive")) {
        gdrive_backup_t* gd = (gdrive_backup_t*)calloc(BACKUP_CATALOG_MAX, sizeof(*gd));
        if (gd) {
            // Listing acquires read access without enabling pending backup work.
            size_t gn = gdrive_catalog_scan(gd, BACKUP_CATALOG_MAX, scans ? &scans[2] : NULL);
            size_t included = 0;
            for (size_t i = 0; i < gn && n < max; i++) {
                size_t before = n;
                catalog_add(items, max, &n, "drive", gd[i].user,
                            gd[i].title_id, gd[i].file_id, gd[i].name,
                            gd[i].size_bytes, gd[i].created_unix,
                            gd[i].destination_identity, NULL, gd[i].generation,
                            gd[i].destination_label);
                if(n>before)snprintf(items[before].observed_drive_root,sizeof(items[before].observed_drive_root),"%s",gd[i].observed_root);
                catalog_scan_entry(scans ? &scans[2] : NULL, n > before ? &items[before] : NULL);
                included++;
            }
            if (included < gn) catalog_scan_gap(scans ? &scans[2] : NULL, "catalog_limit");
            free(gd);
        } else if (scans) scans[2] = (catalog_scan_t){CATALOG_UNAVAILABLE, "memory", true};
    }

    local_save_pair_t* locals =
        (local_save_pair_t*)calloc(256, sizeof(*locals));
    if (locals) {
        local_pair_ctx_t lc = { locals, 0, 256 };
        watcher_enumerate_saves(catalog_local_cb, &lc);
        for (size_t i = 0; i < n; i++) {
            for (size_t j = 0; j < lc.count; j++) {
                if (strcmp(items[i].user, locals[j].user) == 0 &&
                    strcmp(items[i].title_id, locals[j].title_id) == 0) {
                    items[i].local_present = true;
                    break;
                }
            }
        }
        free(locals);
    }

    for (size_t i = 0; i < n; i++) items[i].is_latest = false;
    for (size_t i = 0; i < n; i++) {
        size_t best = i;
        for (size_t j = i + 1; j < n; j++) {
            if (catalog_same_key(&items[i], &items[j]) &&
                catalog_newer(&items[j], &items[best]))
                best = j;
        }
        bool already_marked = false;
        for (size_t j = 0; j < i; j++) {
            if (catalog_same_key(&items[i], &items[j])) {
                already_marked = true;
                break;
            }
        }
        if (!already_marked) items[best].is_latest = true;
    }
    return n;
}

static size_t build_backup_catalog(backup_catalog_item_t* items, size_t max,
                                   const char* source_filter) {
    return build_backup_catalog_scanned(items, max, source_filter, NULL);
}

static const char* catalog_state_name(catalog_state_t state) {
    switch (state) {
        case CATALOG_COMPLETE: return "complete";
        case CATALOG_EMPTY: return "empty";
        case CATALOG_PARTIAL: return "partial";
        default: return "unavailable";
    }
}

static catalog_state_t catalog_aggregate(const catalog_scan_t scans[3], size_t n) {
    bool partial = false, unavailable = false;
    for (size_t i = 0; i < 3; i++) if (scans[i].configured) {
        partial |= scans[i].state == CATALOG_PARTIAL;
        unavailable |= scans[i].state == CATALOG_UNAVAILABLE;
    }
    if (partial || (unavailable && n)) return CATALOG_PARTIAL;
    if (unavailable) return CATALOG_UNAVAILABLE;
    return n ? CATALOG_COMPLETE : CATALOG_EMPTY;
}

static void catalog_cleanup_revoke(void) {
    pthread_mutex_lock(&s_delete_lock);
    for (size_t i = 0; i < BACKUP_CATALOG_MAX; i++) s_delete_catalog[i].cleanup_verified = false;
    pthread_mutex_unlock(&s_delete_lock);
}

static void handle_backup_catalog(int fd) {
    pthread_mutex_lock(&s_catalog_lock);
    // An unsuccessful rescan cannot keep authorizing an old cleanup preview.
    // Individual selected-file deletes retain their v169 existence/identity proof.
    catalog_cleanup_revoke();
    backup_catalog_item_t* items =
        (backup_catalog_item_t*)calloc(BACKUP_CATALOG_MAX, sizeof(*items));
    char* buf = (char*)calloc(1, BACKUP_CATALOG_JSON_CAP);
    if (!items || !buf) {
        free(items); free(buf);
        reply_text(fd, 500, "out of memory");
        pthread_mutex_unlock(&s_catalog_lock);
        return;
    }
    catalog_scan_t scans[3];
    size_t n = build_backup_catalog_scanned(items, BACKUP_CATALOG_MAX, "best", scans);
    for (size_t i=0;i<n;i++) usb_note_backup_size(items[i].size_bytes);
    catalog_state_t state = catalog_aggregate(scans, n);
    char* p = buf;
    char* end = buf + BACKUP_CATALOG_JSON_CAP;
    jappendf(&p, end, "{\"items\":[");
    for (size_t i = 0; i < n; i++) {
        backup_catalog_item_t* it = &items[i];
        it->cleanup_verified = state == CATALOG_COMPLETE || state == CATALOG_EMPTY;
        catalog_delete_ticket(it);
        jappendf(&p, end, "%s{\"source\":", i ? "," : "");
        jappend_json_string(&p, end, it->source);
        jappendf(&p, end, ",\"user\":");
        jappend_json_string(&p, end, it->user);
        jappendf(&p, end, ",\"raw_user\":");
        jappend_json_string(&p, end, it->raw_user);
        jappendf(&p, end, ",\"destination_identity\":");
        jappend_json_string(&p, end, it->destination_identity);
        if(!strcmp(it->source,"drive")) {
            jappendf(&p,end,",\"observed_drive_root\":");jappend_json_string(&p,end,it->observed_drive_root);
        }
        if (!strcmp(it->source, "usb")) {
            jappendf(&p, end, ",\"older_unconfirmed\":%s", it->older_unconfirmed ? "true" : "false");
            jappendf(&p, end, ",\"usb_volume_id\":"); jappend_json_string(&p, end, it->usb_volume_id);
            jappendf(&p, end, ",\"usb_mount\":"); jappend_json_string(&p, end, it->usb_mount);
        }
        jappendf(&p, end, ",\"title_id\":");
        jappend_json_string(&p, end, it->title_id);
        jappendf(&p, end, ",\"game\":");
        jappend_json_string(&p, end, it->game);
        jappendf(&p, end, ",\"file_id\":");
        jappend_json_string(&p, end, it->ref);
        jappendf(&p, end, ",\"name\":");
        jappend_json_string(&p, end, it->name);
        jappendf(&p, end, ",\"delete_proof\":");
        jappend_json_string(&p, end, it->delete_proof);
        jappendf(&p, end, ",\"destination_label\":");
        jappend_json_string(&p, end, it->destination_label);
        jappendf(&p, end,
            ",\"size_bytes\":%llu,\"created_unix\":%lld,"
            "\"local_present\":%s,\"is_latest\":%s,\"protected\":%s}",
            (unsigned long long)it->size_bytes,
            (long long)it->created_unix,
            it->local_present ? "true" : "false",
            it->is_latest ? "true" : "false",
            protect_is(it->name) ? "true" : "false");
    }
    jappendf(&p, end, "],\"state\":\"%s\",\"scans\":{", catalog_state_name(state));
    const char* sources[] = {"usb", NULL, "drive"};
    for (size_t i = 0; i < 3; i++) {
        if (!sources[i]) continue;
        jappendf(&p, end, "%s\"%s\":{\"state\":\"%s\",\"configured\":%s,\"reason\":",
                 i ? "," : "", sources[i], catalog_state_name(scans[i].state),
                 scans[i].configured ? "true" : "false");
        jappend_json_string(&p, end, scans[i].reason ? scans[i].reason : "unknown");
        jappendf(&p, end, "}");
    }
    jappendf(&p, end, "}}");
    if (p >= end - 1) {
        catalog_cleanup_revoke();
        reply_json(fd, 503, "{\"detail\":\"Library catalog exceeded its safe response limit. Nothing was deleted.\"}");
    } else reply_json(fd, 200, buf);
    free(items);
    free(buf);
    pthread_mutex_unlock(&s_catalog_lock);
}

static bool catalog_item_selected_for_restore_all(const backup_catalog_item_t* items,
                                                  size_t n, size_t idx,
                                                  const char* source_filter) {
    const backup_catalog_item_t* cur = &items[idx];
    if (!catalog_source_wanted(source_filter, cur->source)) return false;
    for (size_t j = 0; j < n; j++) {
        if (j == idx) continue;
        if (!catalog_source_wanted(source_filter, items[j].source)) continue;
        if (strcmp(cur->raw_user, items[j].raw_user) ||
            strcmp(cur->title_id, items[j].title_id)) continue;
        if (catalog_newer(&items[j], cur)) return false;
        if (!catalog_newer(cur, &items[j]) && !catalog_newer(&items[j], cur) &&
            j < idx) return false;
    }
    return true;
}

typedef struct {
    char source[16];
    jobs_ref_t observed;
} restore_all_catalog_ctx_t;

static void* restore_all_catalog_thread(void* arg) {
    restore_all_catalog_ctx_t* ctx = (restore_all_catalog_ctx_t*)arg;
    const char* source = (ctx && ctx->source[0]) ? ctx->source : "best";
    backup_catalog_item_t* items =
        (backup_catalog_item_t*)calloc(BACKUP_CATALOG_MAX, sizeof(*items));
    if (!items) {
        log_warn("httpd: restore-all catalog thread out of memory");
        jobs_finish(ctx->observed, JOB_FAILED, "catalog_memory_unavailable");
        free(ctx);
        lifecycle_activity_end();
        return NULL;
    }

    jobs_phase(ctx->observed, source, "catalog", 0, false);
    size_t n = build_backup_catalog(items, BACKUP_CATALOG_MAX, source);
    size_t queued = 0, failed = 0;
    for (size_t i = 0; i < n; i++) {
        if (!catalog_item_selected_for_restore_all(items, n, i, source)) continue;
        // Catalog provenance is a UID, never a user-supplied legacy alias.
        if (watcher_restore_async_observed(items[i].raw_user, items[i].title_id,
                                           items[i].ref, NULL, true, NULL))
            queued++;
        else
            failed++;
    }
    log_info("httpd: restore-all from %s queued %zu item(s), failed %zu",
             source, queued, failed);
    // Child workers own their results; admission is not proof of Restore success.
    jobs_phase(ctx->observed, source, "queueing_done", 0, false);
    jobs_finish(ctx->observed, JOB_UNKNOWN, "child_results_separate");
    free(items);
    free(ctx);
    lifecycle_activity_end();
    return NULL;
}

static bool restore_all_catalog_async(const char* source, jobs_ref_t* observed) {
    if (!lifecycle_activity_begin()) return false;
    restore_all_catalog_ctx_t* ctx =
        (restore_all_catalog_ctx_t*)calloc(1, sizeof(*ctx));
    if (!ctx) { lifecycle_activity_end(); return false; }
    snprintf(ctx->source, sizeof(ctx->source), "%s",
             (source && source[0]) ? source : "best");
    ctx->observed = jobs_begin(JOB_RESTORE, "", "", "", source);
    if (observed) *observed = ctx->observed;
    pthread_t t;
    if (pthread_create(&t, NULL, restore_all_catalog_thread, ctx) != 0) {
        jobs_finish(ctx->observed, JOB_FAILED, "restore_worker_unavailable");
        free(ctx);
        lifecycle_activity_end();
        return false;
    }
    pthread_detach(t);
    return true;
}

static void handle_restore_selected(int fd, const char* body) {
    if (!restore_selection_legacy_request(body)) {
        reply_json(fd, 400, "{\"ok\":false,\"error\":\"selective_restore_requires_import_commit\"}");
        return;
    }
    const char* arr;
    if (!restore_batch_request(body, &arr)) {
        reply_json(fd,400,"{\"ok\":false,\"error\":\"invalid_restore_uid\"}"); return;
    }
    // Validate every item before admitting any operation in the batch.
    const char* check = arr; char obj[1024];
    while (restore_batch_item(&check, obj)) {
        char uid[16], title[16] = {0}, ref[320] = {0}; bool explicit_uid;
        if (!json_get_string(obj, "title_id", title, sizeof(title)) || !title[0] ||
            !json_get_string(obj, "file_id", ref, sizeof(ref)) || !ref[0] ||
            !restore_request_uid(obj,uid,&explicit_uid) ||
            (explicit_uid && !watcher_restore_uid_is_local(uid))) {
            reply_json(fd,400,"{\"ok\":false,\"error\":\"invalid_restore_uid\"}"); return;
        }
    }
    const char* p = arr;
    size_t queued = 0, failed = 0;
    jobs_ref_t observed[128] = {0}; bool complete = true;
    while (restore_batch_item(&p, obj)) {
        char title[16] = {0}, user[32] = {0}, ref[320] = {0};
        json_get_string(obj, "title_id", title, sizeof(title));
        json_get_string(obj, "user", user, sizeof(user));
        json_get_string(obj, "file_id", ref, sizeof(ref));
        char uid[16]; bool uid_explicit;
        if (!restore_request_uid(obj,uid,&uid_explicit)) continue;
        watcher_job_admission_t admitted = {0};
        if (watcher_restore_async_observed(uid_explicit ? uid : (user[0] ? user : NULL), title, ref, &admitted, uid_explicit, NULL)) {
            observed[queued++] = admitted.id;
            if (!admitted.tracked) complete = false;
        } else
            failed++;
    }
    if (queued == 0 && failed == 0) {
        reply_text(fd, 400, "no restore items");
        return;
    }
    char buf[4096], *out = buf, *limit = buf + sizeof(buf);
    jappendf(&out, limit, "{\"ok\":%s,\"queued\":%zu,\"failed\":%zu,\"boot_id\":",
             queued > 0 ? "true" : "false", queued, failed);
    jappend_json_string(&out, limit, update_boot_id());
    jappendf(&out, limit, ",\"tracking_complete\":%s,\"job_ids\":[", complete ? "true" : "false");
    for (size_t i = 0; i < queued; i++)
        jappendf(&out, limit, "%s\"%llu\"", i ? "," : "", (unsigned long long)observed[i]);
    jappendf(&out, limit, "]}");
    reply_json(fd, queued > 0 ? 200 : 500, buf);
}

// POST {"source":"best"|"drive"|"usb"} — disaster recovery.
// Restore the newest backup of every backed-up title, even when that title is
// not currently installed or known to the watcher.
static void handle_restore_all(int fd, const char* body) {
    if (!restore_selection_legacy_request(body)) {
        reply_json(fd, 400, "{\"ok\":false,\"error\":\"selective_restore_requires_import_commit\"}");
        return;
    }
    char source[16];
    if (!restore_all_request(body, source)) {
        reply_text(fd, 400, "invalid restore-all request");
        return;
    }

    jobs_ref_t observed = 0;
    if (!restore_all_catalog_async(source, &observed)) {
        reply_text(fd, 500, "restore-all worker failed");
        return;
    }
    char response[384], *p = response, *end = response + sizeof(response);
    jappendf(&p, end, "{\"ok\":true,\"status\":\"started\"");
    jobs_json_fields(&p, end, observed, false); jappendf(&p, end, "}");
    reply_json(fd, 200, response);
}

typedef struct { char source[8], ref[320], proof[65]; } library_delete_request_t;

static const char* library_delete_ws(const char* p) {
    while (*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r') p++;
    return p;
}

// Parse the complete narrow destructive request before acting. The general
// JSON getters accept truncated strings/duplicate keys and cannot authorize it.
static bool library_delete_string(const char** cursor, char* out, size_t cap) {
    const char* p = library_delete_ws(*cursor);
    if (*p++ != '"') return false;
    size_t n = 0;
    while (*p && *p != '"') {
        unsigned char c = (unsigned char)*p++;
        if (c == '\\') {
            c = (unsigned char)*p++;
            if (c != '\\' && c != '"' && c != '/') return false;
        }
        if (c < 32 || n + 1 >= cap) return false;
        out[n++] = (char)c;
    }
    if (*p != '"' || !n) return false;
    out[n] = '\0';
    *cursor = library_delete_ws(p + 1);
    return true;
}

static bool library_delete_parse(const char* body, library_delete_request_t* items,
                                  size_t* count, bool* respect) {
    *count = 0;
    if (!body || strlen(body) > 160 * 1024) return false;
    const char* p = library_delete_ws(body);
    if (*p++ != '{') return false;
    unsigned top = 0;
    bool confirmed = false;
    for (;;) {
        char key[24];
        if (!library_delete_string(&p, key, sizeof(key)) || *p++ != ':') return false;
        p = library_delete_ws(p);
        unsigned bit = !strcmp(key, "confirmed") ? 1 :
                       !strcmp(key, "respect_protection") ? 2 :
                       !strcmp(key, "items") ? 4 : 0;
        if (!bit || (top & bit)) return false;
        top |= bit;
        if (bit != 4) {
            bool value;
            if (!strncmp(p, "true", 4)) { value = true; p += 4; }
            else if (!strncmp(p, "false", 5)) { value = false; p += 5; }
            else return false;
            if (bit == 1) confirmed = value;
            else *respect = value;
            p = library_delete_ws(p);
        } else {
            if (*p++ != '[') return false;
            p = library_delete_ws(p);
            for (;;) {
                if (*count == 256 || *p++ != '{') return false;
                library_delete_request_t* it = &items[*count];
                unsigned fields = 0;
                for (;;) {
                    if (!library_delete_string(&p, key, sizeof(key)) || *p++ != ':') return false;
                    unsigned f = !strcmp(key, "source") ? 1 :
                                 !strcmp(key, "file_id") ? 2 :
                                 !strcmp(key, "delete_proof") ? 4 : 0;
                    if (!f || (fields & f)) return false;
                    fields |= f;
                    char* out = f == 1 ? it->source : f == 2 ? it->ref : it->proof;
                    size_t cap = f == 1 ? sizeof(it->source) : f == 2 ? sizeof(it->ref) : sizeof(it->proof);
                    if (!library_delete_string(&p, out, cap)) return false;
                    if (*p == '}') { p = library_delete_ws(p + 1); break; }
                    if (*p++ != ',') return false;
                }
                if (fields != 7 || !dest_fingerprint_hex(it->proof)) return false;
                for (size_t i = 0; i < *count; i++)
                    if (!strcmp(items[i].proof, it->proof) ||
                        (!strcmp(items[i].source, it->source) && !strcmp(items[i].ref, it->ref)))
                        return false;
                (*count)++;
                if (*p == ']') { p = library_delete_ws(p + 1); break; }
                if (*p++ != ',') return false;
                p = library_delete_ws(p);
            }
        }
        if (*p == '}') break;
        if (*p++ != ',') return false;
        p = library_delete_ws(p);
    }
    return top == 7 && confirmed && *count && (*respect || *count == 1) &&
           !*library_delete_ws(p + 1);
}

static bool library_delete_claim(const library_delete_request_t* requests,
                                  size_t count, backup_catalog_item_t* items, bool cleanup) {
    // Never consume permission while a scan/configuration is still publishing
    // or may reject its response. Release before any provider delete/request.
    pthread_mutex_lock(&s_catalog_lock);
    pthread_mutex_lock(&s_delete_lock);
    size_t indexes[256];
    bool ok = true;
    for (size_t i = 0; i < count && ok; i++) {
        size_t j = 0;
        while (j < BACKUP_CATALOG_MAX &&
               strcmp(s_delete_catalog[j].delete_proof, requests[i].proof)) j++;
        ok = j < BACKUP_CATALOG_MAX &&
             !strcmp(s_delete_catalog[j].source, requests[i].source) &&
             !strcmp(s_delete_catalog[j].ref, requests[i].ref) &&
             (!cleanup || s_delete_catalog[j].cleanup_verified);
        if (ok) { indexes[i] = j; items[i] = s_delete_catalog[j]; }
    }
    // All tickets must be valid before consuming any. Every subsequent outcome
    // needs a fresh scan: never replay a deletion against a replaced filename.
    if (ok) for (size_t i = 0; i < count; i++)
        s_delete_catalog[indexes[i]].delete_proof[0] = '\0';
    pthread_mutex_unlock(&s_delete_lock);
    pthread_mutex_unlock(&s_catalog_lock);
    return ok;
}

static bool delete_backup_by_ref(const backup_catalog_item_t* item) {
    if (!strcmp(item->source, "usb"))
        return usb_delete_backup_identified(item->ref, item->size_bytes,
                                            item->destination_identity, item->file_stamp);
    if (!strcmp(item->source, "drive")) {
        gdrive_version_t version = {0};
        if (strlen(item->ref) >= sizeof(version.file_id) ||
            strlen(item->name) >= sizeof(version.name)) return false;
        snprintf(version.file_id, sizeof(version.file_id), "%s", item->ref);
        snprintf(version.name, sizeof(version.name), "%s", item->name);
        version.size_bytes = item->size_bytes;
        gdrive_retention_scope_t scope = {0};
        memcpy(scope.identity, item->destination_identity, sizeof(scope.identity));
        scope.generation = item->generation;
        return gdrive_delete_version_identified(item->raw_user, item->title_id, &version, &scope);
    }
    return false;
}

static void handle_backup_delete(int fd, const char* body) {
    library_delete_request_t* requests = calloc(256, sizeof(*requests));
    backup_catalog_item_t* items = calloc(256, sizeof(*items));
    size_t count = 0, deleted = 0, failed = 0, protected_skipped = 0;
    bool respect = true;
    int status = 200;
    const char* detail = "";
    if (!requests || !items) {
        status = 503; detail = "Not enough memory to validate deletion. Nothing was deleted.";
    } else if (!library_delete_parse(body, requests, &count, &respect)) {
        status = 400; detail = "Confirm deletion using a fresh Library selection. Nothing was deleted.";
    } else if (!library_delete_claim(requests, count, items, respect)) {
        status = 409; failed = count;
        detail = "Selection expired or changed. Scan backups again and confirm deletion. Nothing was deleted.";
    } else {
        for (size_t i = 0; i < count; i++) {
            if (respect && protect_is(items[i].name)) { protected_skipped++; continue; }
            if (delete_backup_by_ref(&items[i])) deleted++;
            else {
                failed = count - i;
                status = 409;
                detail = "Destination or file changed, is unavailable, or deletion was not confirmed. No further deletions were attempted. Scan backups again to check what remains.";
                break;
            }
        }
    }
    char buf[640], *p = buf, *end = buf + sizeof(buf);
    jappendf(&p, end, "{\"ok\":%s,\"deleted\":%zu,\"failed\":%zu,\"protected_skipped\":%zu,\"detail\":",
             status == 200 ? "true" : "false", deleted, failed, protected_skipped);
    jappend_json_string(&p, end, detail);
    jappendf(&p, end, "}");
    reply_json(fd, status, buf);
    free(items); free(requests);
}

static void handle_backup_verify(int fd, const char* body) {
    if (!body) { reply_text(fd, 400, "no body"); return; }
    char file_id[384] = {0}, title_id[16] = {0};
    json_get_string(body, "file_id", file_id, sizeof(file_id));
    json_get_string(body, "title_id", title_id, sizeof(title_id));
    if (!file_id[0]) { reply_text(fd, 400, "file_id required"); return; }
    char report[8192] = {0}, err[192] = {0};
    if (!watcher_verify_backup(file_id, title_id, report, sizeof(report),
                               err, sizeof(err))) {
        log_warn("backup verify: rejected reason=%s", err[0] ? err : "backup verification failed");
        char out[512], *p = out;
        char* end = out + sizeof(out);
        jappendf(&p, end, "{\"ok\":false,\"error\":\"verify_failed\","
                           "\"detail\":");
        jappend_json_string(&p, end,
                            err[0] ? err : "backup verification failed");
        jappendf(&p, end, "}");
        reply_json(fd, 400, out);
        return;
    }
    char* out = (char*)malloc(strlen(report) + 32);
    if (!out) { reply_text(fd, 500, "out of memory"); return; }
    snprintf(out, strlen(report) + 32, "{\"ok\":true,\"review\":%s}", report);
    reply_json(fd, 200, out);
    free(out);
}

static void handle_backup_export(int fd, const char* query) {
    char ref[384] = {0}, name[160] = {0}, path[768] = {0}, err[192] = {0};
    query_get_decoded(query, "file_id", ref, sizeof(ref));
    query_get_decoded(query, "name", name, sizeof(name));
    if (!ref[0]) { reply_text(fd, 400, "file_id required"); return; }
    bool temporary = false;
    if (!watcher_prepare_backup_file(ref, path, sizeof(path), &temporary,
                                     err, sizeof(err))) {
        reply_text(fd, 400, err[0] ? err : "backup export failed");
        return;
    }
    if (s_prepare_download) {
        reply_prepared(fd, path, "application/zip", name[0] ? name : "TostonSync-backup.zip", NULL, NULL, true, temporary, false);
        return;
    }
    reply_download_file(fd, path, "application/zip", name[0] ? name : "TostonSync-backup.zip", NULL);
    watcher_release_backup_file(path, temporary);
}

static void handle_backup_prune(int fd, const char* body) {
    (void)body;
    reply_json(fd, 410, "{\"error\":\"legacy_prune_retired\"}");
}

// POST /api/backup/protect {name, protected:bool} — mark/unmark a backup
// (by filename) as a protected favorite that auto-retention will never delete.
static void handle_backup_protect(int fd, const char* body) {
    if (!body) { reply_text(fd, 400, "missing body"); return; }
    char name[160] = {0};
    json_get_string(body, "name", name, sizeof(name));
    if (!name[0]) { reply_text(fd, 400, "missing name"); return; }
    bool on = (strstr(body, "\"protected\":true") != NULL);
    if (protect_set(name, on))
        reply_json(fd, 200, on ? "{\"ok\":true,\"protected\":true}"
                               : "{\"ok\":true,\"protected\":false}");
    else
        reply_text(fd, 500, "protect update failed");
}

// GET /api/backup/protected — the set of protected filenames, for the browser
// Drive prune (which runs client-side) to skip them too.
static void handle_backup_protected(int fd) {
    char arr[8192];
    if (!protect_to_json(arr, sizeof(arr))) {
        reply_json(fd, 503, "{\"detail\":\"Backup protection could not be checked. Nothing was deleted.\"}");
        return;
    }
    char buf[8224];
    snprintf(buf, sizeof(buf), "{\"protected\":%s}", arr);
    reply_json(fd, 200, buf);
}

static bool dbg_copy(const char* src,const char* dst) {
    FILE* in=diagnostic_open(src);if(!in)return false;
    int fd=open(dst,O_WRONLY|O_CREAT|O_EXCL|O_NOFOLLOW,0600);if(fd<0){fclose(in);return false;}
    FILE* out=fdopen(fd,"wb");if(!out){close(fd);fclose(in);return false;}
    bool ok=diagnostic_visit(in,diagnostic_write,out);if(fclose(in))ok=false;if(fclose(out))ok=false;return ok;
}

static bool dbg_write(const char* dst, const char* data) {
    int fd = open(dst, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW, 0600);
    if (fd < 0) return false;
    FILE* f = fdopen(fd, "wb");
    if (!f) { close(fd); return false; }
    size_t n = data ? strlen(data) : 0;
    bool ok = fwrite(data, 1, n, f) == n;
    return fclose(f) == 0 && ok;
}

static void dbg_discard_owned(const char* dir, const char* zip) {
    static const char* names[]={"config.json","sync.log","title_cache.jsonl",
        "protected.lst","history.jsonl","branding.json","catalog.jsonl","info.json"};
    char p[400]; bool ok=true;
    if(zip&&unlink(zip)&&errno!=ENOENT)ok=false;
    for(size_t i=0;i<sizeof(names)/sizeof(names[0]);i++) {
        snprintf(p,sizeof(p),"%s/%s",dir,names[i]);
        if(unlink(p)&&errno!=ENOENT)ok=false;
    }
    if(rmdir(dir))ok=false;
    if(!ok)log_warn("support request scratch cleanup incomplete");
}

// POST only. A new private directory prevents stale files entering the bundle.
static void handle_debug_bundle(int fd) {
    config_t cfg;
    if (!config_snapshot(&cfg)) { reply_text(fd, 503, "no config"); return; }
    const char* sd = cfg.paths.state_dir[0] ? cfg.paths.state_dir : "/data/tostonsync";
    char dir[300], p[400], src[400];
    int n = snprintf(dir, sizeof(dir), "%s/debug_bundle.XXXXXX", sd);
    if (n < 0 || (size_t)n >= sizeof(dir) || !mkdtemp(dir)) {
        reply_text(fd, 503, "support staging unavailable"); return;
    }
    bool ok = true;
    char* cj = malloc(64 * 1024);
    if (!cj) ok = false;
    else {
        config_to_json(&cfg, cj, 64 * 1024);
        snprintf(p, sizeof(p), "%s/config.json", dir);
        ok = dbg_write(p, cj);
        free(cj);
    }
    static const char* copies[] = { "sync.log", "title_cache.jsonl",
        "protected.lst", "history.jsonl", "branding.json" };
    for (size_t i = 0; ok && i < sizeof(copies) / sizeof(copies[0]); i++) {
        snprintf(src, sizeof(src), "%s/%s", sd, copies[i]);
        snprintf(p, sizeof(p), "%s/%s", dir, copies[i]);
        struct stat st;
        if (lstat(src, &st) != 0) { if (errno != ENOENT) ok = false; continue; }
        ok = S_ISREG(st.st_mode) && dbg_copy(src, p);
    }
    backup_catalog_item_t* items = calloc(BACKUP_CATALOG_MAX, sizeof(*items));
    if (!items) ok = false;
    else if (ok) {
        size_t count = build_backup_catalog(items, BACKUP_CATALOG_MAX, "all");
        snprintf(p, sizeof(p), "%s/catalog.jsonl", dir);
        int out = open(p, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW, 0600);
        FILE* cf = out < 0 ? NULL : fdopen(out, "w");
        if (!cf) { if (out >= 0) close(out); ok = false; }
        else {
            for (size_t i = 0; ok && i < count; i++) {
                char row[4096], *w = row, *end = row + sizeof(row);
                jappendf(&w, end, "{\"source\":"); jappend_json_string(&w, end, items[i].source);
                jappendf(&w, end, ",\"user\":"); jappend_json_string(&w, end, items[i].user);
                jappendf(&w, end, ",\"title_id\":"); jappend_json_string(&w, end, items[i].title_id);
                jappendf(&w, end, ",\"size\":%llu,\"created\":%lld,\"protected\":%s}\n",
                    (unsigned long long)items[i].size_bytes, (long long)items[i].created_unix,
                    protect_is(items[i].name) ? "true" : "false");
                ok = w < end - 1 && fwrite(row, 1, (size_t)(w-row), cf) == (size_t)(w-row);
            }
            if (fclose(cf)) ok = false;
        }
    }
    free(items);
    char info[2048], *w = info, *end = info + sizeof(info);
    jappendf(&w, end, "{\"tostonsync_version\":\"%s\",\"oauth_state\":\"%s\",\"usb_enabled\":%s,\"saves_root\":",
        TOSTONSYNC_VERSION, state_to_str(gdrive_get_state()), cfg.usb.enabled ? "true" : "false");
    jappend_json_string(&w, end, cfg.paths.saves_root);
    jappendf(&w, end, ",\"server_unix\":%lld}\n", (long long)time(NULL));
    snprintf(p, sizeof(p), "%s/info.json", dir);
    ok = ok && w < end - 1 && dbg_write(p, info);
    if (!ok) { dbg_discard_owned(dir,NULL); reply_text(fd, 500, "could not collect debug bundle"); return; }
    char zip[400]; uint32_t crc = 0; uint64_t sz = 0;
    snprintf(zip, sizeof(zip), "%s.zip", dir);
    if (!zip_compress_directory(dir, zip, true, &crc, &sz)) {
        dbg_discard_owned(dir,zip); reply_text(fd, 500, "could not build debug bundle"); return;
    }
    if(s_prepare_download)reply_prepared(fd,zip,"application/zip","tostonsync-debug.zip",NULL,NULL,false,false,true);
    else reply_file(fd,zip,"application/zip");
    dbg_discard_owned(dir,zip);
}

static void handle_icon(int fd, const char* title_id) {
    if (!title_id || !title_id[0]) {
        reply_text(fd, 400, "missing title_id");
        return;
    }
    const char* assets[] = { "icon0.png", "icon0_savedata.png", "pic0.png" };
    char path[512];
    for (size_t i = 0; i < sizeof(assets)/sizeof(assets[0]); i++) {
        if (titlename_find_asset(title_id, assets[i], path, sizeof(path))) {
            // Cache it so the icon survives the title being uninstalled later.
            if (!s_http_observing) metacache_cache_icon(title_id, path);
            reply_file(fd, path, "image/png");
            return;
        }
    }
    // Fall back to a previously cached icon when the title isn't present now.
    char cpath[512];
    metacache_icon_path(title_id, cpath, sizeof(cpath));
    if (cpath[0] && metacache_has_icon(title_id)) {
        reply_file(fd, cpath, "image/png");
        return;
    }
    public_artwork_t cover;
    if (public_artwork_cached(title_id, &cover)) {
        reply_file(fd, cover.path, cover.mime);
        return;
    }
    reply_text(fd, 404, "icon not found");
}

static void handle_versions(int fd, const char* user, const char* title) {
    gdrive_version_t* versions =
        (gdrive_version_t*)malloc(sizeof(gdrive_version_t) * 64);
    if (!versions) { reply_json(fd, 200, "{\"versions\":[]}"); return; }
    size_t n = gdrive_list_versions(user, title, versions, 64);
    char buf[8192];
    char* p = buf;
    char* end = buf + sizeof(buf);
    jappendf(&p, end, "{\"versions\":[");
    for (size_t i = 0; i < n; i++) {
        jappendf(&p, end, "%s{\"file_id\":", i ? "," : "");
        jappend_json_string(&p, end, versions[i].file_id);
        jappendf(&p, end, ",\"name\":");
        jappend_json_string(&p, end, versions[i].name);
        jappendf(&p, end,
            ",\"size_bytes\":%llu,\"created_unix\":%lld}",
            (unsigned long long)versions[i].size_bytes,
            (long long)versions[i].created_unix);
    }
    jappendf(&p, end, "]}");
    free(versions);
    reply_json(fd, 200, buf);
}

static void handle_usb_versions(int fd, const char* user, const char* title) {
    // versions[128] is tens of KB; keep it off the connection thread's stack.
    usb_version_t* versions = (usb_version_t*)malloc(sizeof(usb_version_t) * 128);
    if (!versions) { reply_json(fd, 200, "{\"versions\":[]}"); return; }
    size_t n = usb_list_versions(user, title, versions, 128);
    char buf[16384];
    char* p = buf;
    char* end = buf + sizeof(buf);
    jappendf(&p, end, "{\"versions\":[");
    for (size_t i = 0; i < n; i++) {
        jappendf(&p, end, "%s{\"file_id\":", i ? "," : "");
        jappend_json_string(&p, end, versions[i].path);
        jappendf(&p, end, ",\"name\":");
        jappend_json_string(&p, end, versions[i].name);
        jappendf(&p, end,
            ",\"size_bytes\":%llu,\"created_unix\":%lld}",
            (unsigned long long)versions[i].size_bytes,
            (long long)versions[i].created_unix);
    }
    jappendf(&p, end, "]}");
    free(versions);
    reply_json(fd, 200, buf);
}



static void handle_history(int fd) {
    char buf[32768];
    history_to_json(buf, sizeof(buf));
    reply_json(fd, 200, buf);
}

// --------------------------------------------------------------------
// POST /api/activity — record a backup that happened OUTSIDE the daemon.
// The PS5 daemon can't reach Google Drive (no TLS), so the browser does
// the Drive upload and then tells us here. We append the event to the
// shared history (so "Recent activity" updates like a USB/FTP backup) and
// fire a PS5 on-screen toast — the same feedback a local backup gives.
// Body also accepts optional RAW completeness/status fields. Older clients can
// keep sending only {title_id,game,name,uid,size,dest}.
// --------------------------------------------------------------------
static bool activity_raw_state_ok(const char* s) {
    return !s || !s[0] || strcmp(s, "unknown") == 0 ||
           strcmp(s, "complete") == 0 ||
           strcmp(s, "active_only_warning") == 0 ||
           strcmp(s, "active_only_no_service_images") == 0;
}

static bool activity_status_ok(const char* s) {
    return !s || !s[0] || strcmp(s, "ok") == 0 ||
           strcmp(s, "warning") == 0 || strcmp(s, "partial") == 0 ||
           strcmp(s, "failed") == 0;
}

static bool activity_file_component_ok(const char* s) {
    if (!s || !s[0]) return true;
    for (size_t i = 0; s[i]; i++) {
        unsigned char c = (unsigned char)s[i];
        if (!((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
              (c >= '0' && c <= '9') || c == '_' || c == '-' || c == '.'))
            return false;
    }
    return true;
}

static bool activity_dest_list_ok(const char* s) {
    if (!s || !s[0]) return true;
    char copy[64];
    snprintf(copy, sizeof(copy), "%s", s);
    char* save = NULL;
    for (char* tok = strtok_r(copy, ",", &save); tok;
         tok = strtok_r(NULL, ",", &save)) {
        if (strcmp(tok, "usb") != 0 && strcmp(tok, "ftp") != 0 &&
            strcmp(tok, "drive") != 0 && strcmp(tok, "local") != 0)
            return false;
    }
    return true;
}

static void handle_activity_record(int fd, const char* body) {
    if (!body) { reply_text(fd, 400, "no body"); return; }
    char title_id[16] = {0}, game[96] = {0}, name[128] = {0};
    char uid[32] = {0}, dest[32] = {0};
    char backup_type[16] = {0}, trigger[16] = {0};
    history_meta_t meta;
    memset(&meta, 0, sizeof(meta));
    json_get_string(body, "title_id", title_id, sizeof(title_id));
    json_get_string(body, "game",     game,     sizeof(game));
    json_get_string(body, "name",     name,     sizeof(name));
    json_get_string(body, "uid",      uid,      sizeof(uid));
    json_get_string(body, "dest",     dest,     sizeof(dest));
    json_get_string(body, "backup_type", backup_type, sizeof(backup_type));
    json_get_string(body, "trigger", trigger, sizeof(trigger));
    json_get_string(body, "raw_completeness", meta.raw_completeness,
                    sizeof(meta.raw_completeness));
    json_get_string(body, "first_missing_service_image",
                    meta.first_missing_service_image,
                    sizeof(meta.first_missing_service_image));
    json_get_string(body, "status", meta.status, sizeof(meta.status));
    json_get_string(body, "failed_dests", meta.failed_dests,
                    sizeof(meta.failed_dests));
    if (!title_id[0] || !catalog_title_id_ok(title_id)) {
        reply_text(fd, 400, "valid title_id required"); return;
    }
    if (!activity_raw_state_ok(meta.raw_completeness) ||
        !activity_status_ok(meta.status) ||
        !activity_file_component_ok(meta.first_missing_service_image) ||
        !activity_dest_list_ok(dest) ||
        !activity_dest_list_ok(meta.failed_dests)) {
        reply_text(fd, 400, "invalid activity metadata"); return;
    }
    if (!dest[0]) snprintf(dest, sizeof(dest), "drive");
    double size_number = json_get_number(body, "size");
    if (size_number < 0 || size_number > (double)IMPORT_MAX_BYTES) {
        reply_text(fd, 400, "invalid activity size"); return;
    }
    uint64_t size = (uint64_t)size_number;
    double active = json_get_number(body, "active_images");
    double service = json_get_number(body, "service_images");
    double missing = json_get_number(body, "missing_service_images");
    if (active < 0 || service < 0 || missing < 0 ||
        active > 1024 || service > 1024 || missing > 1024) {
        reply_text(fd, 400, "invalid image counts"); return;
    }
    meta.active_images = (size_t)active;
    meta.service_images = (size_t)service;
    meta.missing_service_images = (size_t)missing;
    if (!meta.status[0])
        snprintf(meta.status, sizeof(meta.status), "%s",
                 strcmp(meta.raw_completeness, "active_only_warning") == 0
                    ? "warning" : "ok");

    const char* alias = config_alias_for_uid(uid[0] ? uid : "default");
    history_record(alias, title_id, game, name[0] ? name : "backup.zip",
                   backup_type[0] ? backup_type : "RAW",
                   trigger[0] ? trigger : "Manual", size, 0,
                   strcmp(meta.status, "failed") == 0 ? "" : dest, &meta);

    // Reflect this browser-side backup on the Home "Last backup" tile too.
    if (strcmp(meta.status, "failed") != 0)
        watcher_note_external_backup(game[0] ? game : title_id, dest);

    const char* pdest = (strcmp(dest, "usb") == 0) ? "USB"
                      : (strcmp(dest, "ftp") == 0) ? "FTP"
                      : (strcmp(dest, "local") == 0) ? "local storage"
                      : "Google Drive";
    const config_t* nc = config_get();
    bool es_lang = nc && strcmp(nc->general.language, "es") == 0;
    char ntf[200];
    if (strcmp(meta.status, "failed") == 0)
        snprintf(ntf, sizeof(ntf),
                 es_lang ? "Google Drive falló: %s" : "Google Drive failed: %s",
                 game[0] ? game : title_id);
    else if (strcmp(meta.status, "partial") == 0)
        snprintf(ntf, sizeof(ntf),
                 es_lang ? "Respaldo parcialmente completado: %s"
                         : "Backup partially completed: %s",
                 game[0] ? game : title_id);
    else if (strcmp(meta.raw_completeness, "active_only_warning") == 0)
        snprintf(ntf, sizeof(ntf),
                 es_lang ? "Respaldo completado con advertencia: %s"
                         : "Backup completed with warning: %s",
                 game[0] ? game : title_id);
    else
        snprintf(ntf, sizeof(ntf),
                 es_lang ? "Respaldo completado: %s (%s)"
                         : "Backup complete: %s (%s)",
                 game[0] ? game : title_id, pdest);
    log_notify_level(
        strcmp(meta.status, "failed") == 0 ||
        strcmp(meta.status, "partial") == 0 ||
        strcmp(meta.raw_completeness, "active_only_warning") == 0
            ? NOTIFY_IMPORTANT : NOTIFY_BALANCED,
        ntf);

    if (strcmp(meta.status, "failed") == 0)
        log_warn("Google Drive failed: %s", game[0] ? game : title_id);
    else if (strcmp(meta.raw_completeness, "active_only_warning") == 0)
        log_warn("Backup completed with warning: %s raw=%s active=%zu "
                 "service=%zu missing=%s", game[0] ? game : title_id,
                 meta.raw_completeness, meta.active_images,
                 meta.service_images,
                 meta.first_missing_service_image[0]
                    ? meta.first_missing_service_image : "unknown");
    else
        log_info("Backup complete: %s (%s) raw=%s active=%zu service=%zu",
                 game[0] ? game : title_id, pdest,
                 meta.raw_completeness[0] ? meta.raw_completeness : "unknown",
                 meta.active_images, meta.service_images);

    reply_json(fd, 200, "{\"ok\":true}");
}


static void handle_client_log(int fd,const char* body) {
    if(!body){reply_text(fd,400,"no body");return;}
    char message[128]="";json_get_string(body,"message",message,sizeof(message));
    const char* known[]={"ui_script_error","ui_unhandled_rejection","ui_page_loaded","Drive upload result unknown","Drive upload failed"};
    const char* safe=NULL;for(size_t i=0;i<sizeof(known)/sizeof(known[0]);i++)if(!strcmp(message,known[i]))safe=known[i];
    if(!safe){reply_text(fd,400,"unknown client event");return;}
    log_warn("browser: %s",safe);reply_json(fd,200,"{\"ok\":true}");
}

// --------------------------------------------------------------------
// /api/users — list PS5 console users (with aliases + a flag for which
// already have an alias stored). Pulls live UIDs from the saves root
// so freshly-created users show up without restart.
// --------------------------------------------------------------------
static const char* save_metadata_check_name(save_metadata_check_t check) {
    return check == SAVE_METADATA_PASS ? "PASS" : check == SAVE_METADATA_FAIL ? "FAIL" : "UNKNOWN";
}

static void save_metadata_check_json(char** p, char* end, save_metadata_check_t check,
                                     const char* detail) {
    jappendf(p, end, "{\"result\":\"%s\",\"detail\":", save_metadata_check_name(check));
    jappend_json_string(p, end, detail);
    jappendf(p, end, "}");
}

static void save_metadata_entries_json(char** p, char* end,
                                       const save_metadata_entry_t* entries, size_t count,
                                       const int8_t* session_changed) {
    jappendf(p, end, "[");
    for (size_t i = 0; i < count; i++) {
        const save_metadata_entry_t* e = &entries[i];
        jappendf(p, end, "%s{\"name\":", i ? "," : "");
        jappend_json_string(p, end, e->name);
        jappendf(p, end, ",\"image_name\":");
        jappend_json_string(p, end, e->image_name);
        jappendf(p, end, ",\"registered\":\"%s\",\"sdimg\":\"%s\",\"stat_errno\":%d,\"rowid\":",
                 save_metadata_check_name(e->registered), save_metadata_check_name(e->sdimg), e->stat_errno);
        if (e->rowid_available) jappendf(p, end, "%lld", (long long)e->rowid);
        else jappendf(p, end, "null");
        jappendf(p, end, ",\"session_changed\":%s", !session_changed || session_changed[i] < 0
            ? "null" : session_changed[i] ? "true" : "false");
        jappendf(p, end, ",\"metadata\":");
        if (!e->metadata_available) jappendf(p, end, "null");
        else {
            jappendf(p, end, "{\"type\":");
            jappend_json_string(p, end, e->type);
            jappendf(p, end, ",\"bytes\":%llu,\"device\":%llu,\"inode\":%llu,\"mode\":%u,"
                "\"mtime\":%lld,\"mtime_nsec\":%lld,\"ctime\":%lld,\"ctime_nsec\":%lld}",
                (unsigned long long)e->size, (unsigned long long)e->dev, (unsigned long long)e->inode,
                e->mode, (long long)e->mtime, (long long)e->mtime_nsec,
                (long long)e->ctime, (long long)e->ctime_nsec);
        }
        jappendf(p, end, "}");
    }
    jappendf(p, end, "]");
}

static void save_metadata_session_json(char** p, char* end,
                                       const session_saves_report_t* session) {
    jappendf(p, end, "{\"baseline\":\"%s\",\"closed_unix\":",
             session_saves_baseline_name(session->baseline));
    if (session->closed_available) jappendf(p, end, "%lld", (long long)session->closed_unix);
    else jappendf(p, end, "null");
    if (session->baseline == SESSION_SAVES_OK)
        jappendf(p, end, ",\"changed_active\":%u,\"changed_service\":%u}",
                 session->counts.changed_active, session->counts.changed_service);
    else jappendf(p, end, ",\"changed_active\":null,\"changed_service\":null}");
}

static void handle_save_metadata(int fd, const char* title, const char* requested_uid) {
    if (!title || strlen(title) != 9 || !title_id_candidate(title)) {
        reply_json(fd, 400, "{\"error\":\"invalid_title_id\"}");
        return;
    }
    watcher_save_metadata_t* r = calloc(1, sizeof(*r));
    if (!r) { reply_json(fd, 503, "{\"error\":\"metadata_memory_unavailable\"}"); return; }
    int64_t started = (int64_t)time(NULL);
    bool inspected = requested_uid ? watcher_inspect_save_metadata_for_uid(requested_uid, title, r)
                                   : watcher_inspect_save_metadata(title, r);
    if (!inspected) {
        if (requested_uid) {
            free(r); reply_json(fd, 400, "{\"error\":\"invalid_target_uid\"}"); return;
        }
        free(r); reply_json(fd, 400, "{\"error\":\"invalid_title_id\"}"); return;
    }
    if (requested_uid && r->uid_check != SAVE_METADATA_PASS) {
        free(r); reply_json(fd, 409, "{\"error\":\"metadata_owner_unavailable\"}"); return;
    }
    watcher_copy_save_session(r);
    // Bounds include worst-case JSON escaping of both exact names. No partial
    // JSON/inventory is ever silently advertised as a complete observation.
    // The fixed allowance also covers every bounded diagnostic field expanded
    // to six-byte JSON escapes, including SQLite messages/authorizer arguments.
    size_t capacity = 16384 + (r->inventory.active_count + r->inventory.service_count) * 4096;
    char* buf = calloc(1, capacity);
    if (!buf) { free(r); reply_json(fd, 503, "{\"error\":\"metadata_memory_unavailable\"}"); return; }
    char* p = buf; char* end = buf + capacity;
    jappendf(&p, end, "{\"operation\":\"inspect-save-metadata\",\"version\":\"%s\",\"title_id\":",
             TOSTONSYNC_VERSION);
    jappend_json_string(&p, end, r->title_id);
    jappendf(&p, end, ",\"uid\":"); jappend_json_string(&p, end, r->uid);
    jappendf(&p, end, ",\"started_unix\":%lld,\"finished_unix\":%lld,\"checks\":{\"uid\":",
             (long long)started, (long long)time(NULL));
    save_metadata_check_json(&p, end, r->uid_check, r->uid_detail);
    jappendf(&p, end, ",\"gate\":"); save_metadata_check_json(&p, end, r->gate, r->gate_detail);
    jappendf(&p, end, ",\"recovery_clear\":"); save_metadata_check_json(&p, end, r->recovery_clear, r->recovery_detail);
    jappendf(&p, end, ",\"game_closed\":"); save_metadata_check_json(&p, end, r->game_closed, r->game_detail);
    jappendf(&p, end, "},\"game_state\":\"%s\",\"recovery_errno\":%d,\"filesystem\":",
             r->game_closed == SAVE_METADATA_PASS ? "CLOSED_OBSERVED" :
             r->game_closed == SAVE_METADATA_FAIL ? "RUNNING_OBSERVED" : "UNKNOWN", r->recovery_errno);
    save_metadata_check_json(&p, end, r->inventory.filesystem, r->inventory.filesystem_detail);
    jappendf(&p, end, ",\"filesystem_errno\":%d,\"registry\":", r->inventory.filesystem_errno);
    save_metadata_check_json(&p, end, r->inventory.registry, r->inventory.registry_detail);
    jappendf(&p, end, ",\"registry_errno\":%d,\"registry_diagnostic\":{\"sqlite_failure\":", r->inventory.registry_errno);
    const save_metadata_registry_diagnostic_t* diagnostic = &r->inventory.registry_diagnostic;
    const save_metadata_sql_failure_t* failure = &diagnostic->sqlite_failure;
    if (!failure->present) jappendf(&p, end, "null");
    else {
        jappendf(&p, end, "{\"operation\":"); jappend_json_string(&p, end, failure->operation);
        jappendf(&p, end, ",\"sql\":");
        if (failure->sql[0]) jappend_json_string(&p, end, failure->sql);
        else jappendf(&p, end, "null");
        jappendf(&p, end, ",\"return_code\":%d,\"primary_code\":%d,\"extended_code\":",
                 failure->return_code, failure->primary_code);
        if (failure->database_error_available) jappendf(&p, end, "%d", failure->extended_code);
        else jappendf(&p, end, "null");
        jappendf(&p, end, ",\"message\":");
        if (failure->database_error_available) jappend_json_string(&p, end, failure->message);
        else jappendf(&p, end, "null");
        jappendf(&p, end, ",\"message_truncated\":%s}", failure->message_truncated ? "true" : "false");
    }
    jappendf(&p, end, ",\"authorizer_denial\":");
    const save_metadata_authorizer_denial_t* denial = &diagnostic->authorizer_denial;
    if (!denial->present) jappendf(&p, end, "null");
    else {
        // Stable SQLite authorizer codes already used by this reader. Any
        // unknown/new action stays numeric plus UNKNOWN, never guessed.
        const char* action_name = denial->action_code == 20 ? "SQLITE_READ" :
                                  denial->action_code == 21 ? "SQLITE_SELECT" :
                                  denial->action_code == 19 ? "SQLITE_PRAGMA" : "UNKNOWN";
        jappendf(&p, end, "{\"action_code\":%d,\"action_name\":\"%s\",\"argument1\":",
                 denial->action_code, action_name);
        if (denial->argument1_present) jappend_json_string(&p, end, denial->argument1);
        else jappendf(&p, end, "null");
        jappendf(&p, end, ",\"argument2\":");
        if (denial->argument2_present) jappend_json_string(&p, end, denial->argument2);
        else jappendf(&p, end, "null");
        jappendf(&p, end, ",\"database\":");
        if (denial->database_present) jappend_json_string(&p, end, denial->database);
        else jappendf(&p, end, "null");
        jappendf(&p, end, ",\"context\":");
        if (denial->context_present) jappend_json_string(&p, end, denial->context);
        else jappendf(&p, end, "null");
        jappendf(&p, end, ",\"truncated\":%s}", denial->truncated ? "true" : "false");
    }
    jappendf(&p, end, ",\"validation_rejection\":");
    if (diagnostic->validation_rejection[0]) jappend_json_string(&p, end, diagnostic->validation_rejection);
    else jappendf(&p, end, "null");
    jappendf(&p, end, ",\"post_query_stability\":{\"result\":\"%s\",\"operation\":",
             !diagnostic->post_query_stability_checked ? "NOT_CHECKED" :
             diagnostic->post_query_stable ? "PASS" : "UNKNOWN");
    if (diagnostic->stability_operation[0]) jappend_json_string(&p, end, diagnostic->stability_operation);
    else jappendf(&p, end, "null");
    jappendf(&p, end, ",\"errno\":");
    if (diagnostic->post_query_stability_checked) jappendf(&p, end, "%d", diagnostic->stability_errno);
    else jappendf(&p, end, "null");
    jappendf(&p, end, "}},\"active\":");
    save_metadata_entries_json(&p, end, r->inventory.active, r->inventory.active_count, r->session_active);
    jappendf(&p, end, ",\"service\":");
    save_metadata_entries_json(&p, end, r->inventory.service, r->inventory.service_count, r->session_service);
    jappendf(&p, end, ",\"session\":");
    save_metadata_session_json(&p, end, &r->session);
    jappendf(&p, end, ",\"limits\":\"Metadata observation, not an atomic snapshot or permission to restore. No image contents, imports or recovery journals read. Service registration denotes an exact service row, not the related active row.\"}");
    if (p >= end - 1) reply_json(fd, 503, "{\"error\":\"metadata_response_overflow\"}");
    else reply_json(fd, 200, buf);
    free(buf); free(r);
}

// Diagnostic-local: never let truncated/ambiguous URL input select another file.
static bool save_image_hash_query_exact(const char* query, const char* key,
                                        char* out, size_t capacity) {
    if (!query || !key || !out || !capacity || capacity > 512) return false;
    out[0] = 0;
    bool found = false;
    size_t kl = strlen(key);
    for (const char* p = query; *p;) {
        const char* end = strchr(p, '&');
        if (!end) end = p + strlen(p);
        const char* eq = memchr(p, '=', (size_t)(end - p));
        if (eq && (size_t)(eq - p) == kl && !memcmp(p, key, kl)) {
            if (found) return false;
            found = true;
            size_t n = 0;
            for (const char* r = eq + 1; r < end; r++) {
                unsigned char c = (unsigned char)*r;
                if (c == '%') {
                    if (end - r < 3 || !isxdigit((unsigned char)r[1]) ||
                        !isxdigit((unsigned char)r[2])) return false;
                    char hex[3] = {r[1], r[2], 0};
                    c = (unsigned char)strtol(hex, NULL, 16);
                    r += 2;
                } else if (c == '+') c = ' ';
                if (!c || n >= capacity - 1) return false;
                out[n++] = (char)c;
            }
            out[n] = 0;
            char validated[512];
            if (titlename_copy_utf8(validated, sizeof(validated), out) != n)
                return false;
        }
        p = *end ? end + 1 : end;
    }
    return found;
}

static bool save_metadata_query_uid(const char* query, char* uid, size_t size, bool* present) {
    *present = false;
    uid[0] = 0;
    // Reject encoded aliases too: an explicit owner must never become legacy.
    for (const char* p = query ? query : ""; *p;) {
        const char* end = strchr(p, '&');
        if (!end) end = p + strlen(p);
        const char* eq = memchr(p, '=', (size_t)(end - p));
        size_t n = (size_t)((eq ? eq : end) - p);
        char key[64];
        size_t prefix = n < sizeof(key) - 1 ? n : sizeof(key) - 1;
        memcpy(key, p, prefix); key[prefix] = 0;
        // Any encoded target_uid plus NUL fits here, even with a long suffix.
        url_decode_inplace(key);
        if (!strcmp(key, "target_uid")) {
            if (!eq || *present || n != 10 || memcmp(p, "target_uid", 10)) return false;
            *present = true;
        }
        p = *end ? end + 1 : end;
    }
    if (!*present) return true;
    if (!save_image_hash_query_exact(query, "target_uid", uid, size) || !uid[0]) return false;
    for (const unsigned char* p = (const unsigned char*)uid; *p; p++)
        if (!((*p >= 'A' && *p <= 'Z') || (*p >= 'a' && *p <= 'z') ||
              (*p >= '0' && *p <= '9') || *p == '_')) return false;
    return true;
}

static void save_image_hash_stat_json(char** p, char* end, const struct stat* s,
                                      bool available) {
    if (!available) { jappendf(p, end, "null"); return; }
#ifdef __APPLE__
    long an = s->st_atimespec.tv_nsec, mn = s->st_mtimespec.tv_nsec,
         cn = s->st_ctimespec.tv_nsec;
#else
    long an = s->st_atim.tv_nsec, mn = s->st_mtim.tv_nsec,
         cn = s->st_ctim.tv_nsec;
#endif
    jappendf(p, end, "{\"type\":\"%s\",\"device\":%llu,\"inode\":%llu,"
        "\"size\":%lld,\"mode\":%u,\"owner_uid\":%llu,\"owner_gid\":%llu,"
        "\"nlink\":%llu,\"blocks\":%lld,\"block_size\":%lld,"
        "\"atime\":%lld,\"atime_nsec\":%ld,\"mtime\":%lld,\"mtime_nsec\":%ld,"
        "\"ctime\":%lld,\"ctime_nsec\":%ld,\"birthtime\":",
        S_ISREG(s->st_mode) ? "regular" : S_ISLNK(s->st_mode) ? "symlink" :
        S_ISDIR(s->st_mode) ? "directory" : "other",
        (unsigned long long)s->st_dev, (unsigned long long)s->st_ino,
        (long long)s->st_size, (unsigned)s->st_mode,
        (unsigned long long)s->st_uid, (unsigned long long)s->st_gid,
        (unsigned long long)s->st_nlink, (long long)s->st_blocks,
        (long long)s->st_blksize, (long long)s->st_atime, an,
        (long long)s->st_mtime, mn, (long long)s->st_ctime, cn);
#if defined(__APPLE__) || defined(__FreeBSD__)
    jappendf(p, end, "%lld,\"birthtime_nsec\":%ld,\"flags\":%u}",
        (long long)s->st_birthtimespec.tv_sec, s->st_birthtimespec.tv_nsec,
        (unsigned)s->st_flags);
#else
    jappendf(p, end, "null,\"birthtime_nsec\":null,\"flags\":null}");
#endif
}

static void handle_save_image_hash(int fd, const char* uid, const char* title,
                                   const char* slot) {
    char path[512], detail[192] = {0};
    if (!save_image_hash_target(uid, title, slot, path, sizeof(path))) {
        reply_json(fd, 400, "{\"error\":\"invalid_image_scope\"}"); return;
    }
    save_image_hash_report_t r = {0};
    int gate = watcher_target_check_begin(detail, sizeof(detail));
    if (gate == 1) {
        save_image_hash_collect(path, &r);
        watcher_target_check_end();
    } else r.result = gate == 0 ? "BUSY" : "RECOVERY_REQUIRED";
    char buf[8192], *p = buf, *end = buf + sizeof(buf);
    jappendf(&p, end, "{\"operation\":\"inspect-save-image-hash\",\"version\":\"%s\",\"uid\":",
             TOSTONSYNC_VERSION);
    jappend_json_string(&p, end, uid);
    jappendf(&p, end, ",\"title_id\":"); jappend_json_string(&p, end, title);
    jappendf(&p, end, ",\"slot\":"); jappend_json_string(&p, end, slot);
    jappendf(&p, end, ",\"target\":"); jappend_json_string(&p, end, path);
    jappendf(&p, end, ",\"result\":\"%s\",\"detail\":", r.result);
    jappend_json_string(&p, end, detail);
    jappendf(&p, end, ",\"pre\":");
    save_image_hash_stat_json(&p, end, &r.pre, r.pre_available);
    jappendf(&p, end, ",\"post\":");
    save_image_hash_stat_json(&p, end, &r.post, r.post_available);
    jappendf(&p, end, ",\"sha256\":");
    if (r.sha256[0]) jappend_json_string(&p, end, r.sha256);
    else jappendf(&p, end, "null");
    jappendf(&p, end, ",\"stable_during_hash\":%s,\"pre_errno\":%d,"
        "\"post_errno\":%d,\"hash_errno\":%d,\"limits\":",
        !strcmp(r.result, "STABLE") ? "true" :
        !strcmp(r.result, "UNSTABLE") ? "false" : "null",
        r.pre_errno, r.post_errno, r.hash_errno);
    jappend_json_string(&p, end,
        "Only device/inode/size stability is required. Compare pre/post timestamps separately; changes alone are not corruption. Not an atomic byte snapshot: external same-inode writes or replacement-and-return may escape these observations. Reads may update atime. No mount, copy, download, database, save write or recovery action. ACL/xattrs were not queried.");
    jappendf(&p, end, "}");
    if (p >= end - 1) reply_json(fd, 503, "{\"error\":\"image_hash_response_overflow\"}");
    else reply_json(fd, gate == 1 ? 200 : 409, buf);
}

static void pfs_attributes_image_json(char** p, char* end, const pfs_attribute_image_t* image) {
    jappendf(p, end, "{\"result\":"); jappend_json_string(p, end, image->result ? image->result : "NOT_CHECKED");
    jappendf(p, end, ",\"source\":"); jappend_json_string(p, end, image->source);
    jappendf(p, end, ",\"sha256_acquired\":"); jappend_json_string(p, end, image->sha256);
    jappendf(p, end, ",\"outer_sdimg_before\":");
    save_image_hash_stat_json(p, end, &image->outer_before, image->outer_available);
    jappendf(p, end, ",\"outer_sdimg_after\":");
    save_image_hash_stat_json(p, end, &image->outer_after, image->source_stable);
    jappendf(p, end, ",\"source_stable_during_copy\":%s,\"inventory_complete\":%s,"
        "\"unmounted\":%s,\"private_copy_discarded\":%s,\"private_copy\":",
        image->source_stable ? "true" : "false", image->complete ? "true" : "false",
        image->unmounted ? "true" : "false", image->copy_discarded ? "true" : "false");
    jappend_json_string(p, end, image->copy);
    jappendf(p, end, ",\"mount\":"); jappend_json_string(p, end, image->mount);
    jappendf(p, end, ",\"errno\":%d,\"error_path\":", image->error);
    jappend_json_string(p, end, image->error_path);
    jappendf(p, end, ",\"attributes_observed_inside_pfs\":[");
    for (size_t i = 0; i < image->count; i++) {
        const pfs_attribute_entry_t* entry = &image->entries[i];
        jappendf(p, end, "%s{\"path\":", i ? "," : ""); jappend_json_string(p, end, entry->path);
        jappendf(p, end, ",\"mode_octal\":\"%07o\",\"stat\":", (unsigned)entry->stat.st_mode);
        save_image_hash_stat_json(p, end, &entry->stat, true);
        jappendf(p, end, ",\"rdev\":%llu,\"generation\":", (unsigned long long)entry->stat.st_rdev);
#if defined(__APPLE__) || defined(__FreeBSD__)
        jappendf(p, end, "%u", (unsigned)entry->stat.st_gen);
#else
        jappendf(p, end, "null");
#endif
        jappendf(p, end, ",\"acl\":[");
        const char* acl_names[] = {"access", "default", "nfs4"};
        for (size_t a = 0; a < 3; a++) {
            const pfs_acl_observation_t* acl = &entry->acl[a];
            jappendf(p, end, "%s{\"type\":\"%s\",\"status\":\"%s\",\"errno\":%d,\"entries\":[",
                a ? "," : "", acl_names[a], acl->status, acl->error);
            for (size_t k = 0; k < acl->count; k++) {
                const pfs_acl_entry_t* e = &acl->entries[k];
                jappendf(p, end, "%s{\"tag\":%u,\"id\":%u,\"permissions\":%u,\"entry_type\":%u,\"flags\":%u}",
                    k ? "," : "", e->tag, e->id, e->perm, e->type, e->flags);
            }
            jappendf(p, end, "]}");
        }
        jappendf(p, end, "],\"xattrs\":[");
        for (size_t a = 0; a < 2; a++) {
            const pfs_xattr_observation_t* x = &entry->xattrs[a];
            jappendf(p, end, "%s{\"namespace\":\"%s\",\"status\":\"%s\",\"errno\":%d,\"entries\":[",
                a ? "," : "", a ? "system" : "user", x->status, x->error);
            for (size_t k = 0; k < x->count; k++) {
                jappendf(p, end, "%s{\"name\":", k ? "," : "");
                jappend_json_string(p, end, x->entries[k].name);
                jappendf(p, end, ",\"size\":%lld,\"errno\":%d}", (long long)x->entries[k].size, x->entries[k].error);
            }
            jappendf(p, end, "]}");
        }
        jappendf(p, end, "]}");
    }
    jappendf(p, end, "]}");
}

static void handle_pfs_attributes(int fd, const char* uid, const char* title, const char* slot) {
    if (strcmp(uid, PFS_ATTRIBUTES_UID) || strcmp(title, PFS_ATTRIBUTES_TITLE) || strcmp(slot, PFS_ATTRIBUTES_SLOT)) {
        reply_json(fd, 400, "{\"error\":\"unsupported_forensic_scope\"}"); return;
    }
    const size_t capacity = 4 * 1024 * 1024;
    char* buf = malloc(capacity);
    if (!buf) { reply_json(fd, 503, "{\"error\":\"out_of_memory\"}"); return; }
    pfs_attributes_report_t report;
    watcher_inspect_pfs_attributes(&report);
    char *p = buf, *end = buf + capacity;
    jappendf(&p, end, "{\"operation\":\"inspect-save-pfs-attributes\",\"version\":\"%s\","
        "\"uid\":\"%s\",\"title_id\":\"%s\",\"slot\":\"%s\",\"result\":\"%s\","
        "\"writeback\":false,\"payload_read\":false,\"recovery_required\":%s,\"detail\":",
        TOSTONSYNC_VERSION, uid, title, slot, report.result, report.recovery_required ? "true" : "false");
    jappend_json_string(&p, end, report.detail);
    jappendf(&p, end, ",\"evidence_workspace\":"); jappend_json_string(&p, end, report.work);
    jappendf(&p, end, ",\"pre\":"); pfs_attributes_image_json(&p, end, &report.images[0]);
    jappendf(&p, end, ",\"rejected\":"); pfs_attributes_image_json(&p, end, &report.images[1]);
    jappendf(&p, end, ",\"limits\":");
    jappend_json_string(&p, end, "Internal metadata, not exported file attributes. Native mount/unmount may modify disposable copies; not native MOUNT_RO. ACL/xattr getter errors are UNKNOWN, not absence. Xattr values and save payloads are not read. Atime may change on source reads or directory enumeration. Gate excludes daemon work, not external writers; source stat/hash checks are observational, not an atomic filesystem snapshot. Walk ceiling: 1024 entries, 64 levels; errors/limits are incomplete, never OBSERVED complete. No automatic correction or proof of game acceptance.");
    jappendf(&p, end, "}");
    bool overflow = p >= end - 1;
    bool saved = false;
    if (report.work[0] && !overflow) {
        char path[320]; snprintf(path, sizeof(path), "%s/attributes.json", report.work);
        int out = open(path, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW, 0600);
        if (out >= 0) {
            size_t length = strlen(buf), offset = 0;
            while (offset < length) { ssize_t n = write(out, buf + offset, length - offset); if (n <= 0) break; offset += (size_t)n; }
            saved = offset == length && fsync(out) == 0;
            if (close(out) != 0) saved = false;
            int dir = open(report.work, O_RDONLY | O_DIRECTORY);
            if (dir < 0) saved = false;
            else { if (fsync(dir) != 0) saved = false; if (close(dir) != 0) saved = false; }
        }
    }
    if (overflow) reply_json(fd, 503, "{\"error\":\"pfs_attribute_response_overflow\",\"result\":\"INCOMPLETE\"}");
    else if (report.work[0] && !saved) reply_json(fd, 503, "{\"error\":\"pfs_attribute_evidence_write_failed\",\"result\":\"INCOMPLETE\"}");
    else reply_json(fd, !strcmp(report.result, "OBSERVED") ? 200 : 409, buf);
    pfs_attributes_free(&report); free(buf);
}

static void pfs_mode_observation_json(char** p, char* end, const pfs_mode_observation_t* observation) {
    jappendf(p, end, "{\"hashes_complete\":%s,\"regular_file_count\":%zu,\"metadata\":",
        observation->hashes_complete ? "true" : "false", observation->regular_file_count);
    pfs_attributes_image_json(p, end, &observation->attrs);
    jappendf(p, end, ",\"complete_file_sha256\":[");
    bool first = true;
    for (size_t i = 0; i < observation->attrs.count; i++) {
        if (!S_ISREG(observation->attrs.entries[i].stat.st_mode)) continue;
        jappendf(p, end, "%s{\"path\":", first ? "" : ","); first = false;
        jappend_json_string(p, end, observation->attrs.entries[i].path);
        jappendf(p, end, ",\"sha256\":");
        if (observation->file_sha256 && observation->file_sha256[i][0])
            jappend_json_string(p, end, observation->file_sha256[i]);
        else jappendf(p, end, "null");
        jappendf(p, end, "}");
    }
    jappendf(p, end, "]}");
}

static bool candidate_publication_request_exact(const char* query, const char* body,
                                                size_t body_len) {
    static const char scope[] = "target_uid=" PFS_ATTRIBUTES_UID "&title_id=" PFS_ATTRIBUTES_TITLE
                                "&slot=" PFS_ATTRIBUTES_SLOT;
    static const char expected[] = "{\"candidate_sha256\":\"" PFS_CANDIDATE_SHA
        "\",\"trial_receipt_sha256\":\"" PFS_CANDIDATE_RECEIPT_SHA "\"}";
    return query && !strcmp(query, scope) && body && body_len == sizeof(expected) - 1 &&
           !memcmp(body, expected, sizeof(expected) - 1);
}

static void handle_private_mode_trial(int fd, const char* query, const char* body, size_t body_len) {
    // Deliberately one literal request, no publish/commit switch or arbitrary paths.
    const char* scope = "target_uid=" PFS_ATTRIBUTES_UID "&title_id=" PFS_ATTRIBUTES_TITLE
                        "&slot=" PFS_ATTRIBUTES_SLOT;
    if (!query || strcmp(query, scope) ||
        (body_len && (body_len != 2 || !body || memcmp(body, "{}", 2)))) {
        reply_json(fd, 400, "{\"error\":\"unsupported_private_trial_scope\",\"publication_enabled\":false}");
        return;
    }
    const size_t capacity = 12 * 1024 * 1024;
    char* buf = malloc(capacity);
    if (!buf) { reply_json(fd, 503, "{\"error\":\"out_of_memory\"}"); return; }
    pfs_mode_trial_report_t r;
    watcher_private_mode_trial(&r);
    char* p = buf; char* end = buf + capacity;
    jappendf(&p, end, "{\"operation\":\"private-save-mode-trial\",\"version\":\"%s\","
        "\"uid\":\"%s\",\"title_id\":\"%s\",\"slot\":\"%s\",\"target\":\"%s\","
        "\"publication_enabled\":false,\"published\":false,\"live_writebacks\":0,"
        "\"private_payload_hashing_enabled\":true,\"plaintext_export\":false,\"result\":",
        TOSTONSYNC_VERSION, PFS_ATTRIBUTES_UID, PFS_ATTRIBUTES_TITLE, PFS_ATTRIBUTES_SLOT,
        PFS_ATTRIBUTES_REJECTED);
    jappend_json_string(&p, end, r.result);
    jappendf(&p, end, ",\"detail\":"); jappend_json_string(&p, end, r.detail);
    jappendf(&p, end, ",\"phase\":"); jappend_json_string(&p, end, r.phase);
    jappendf(&p, end, ",\"evidence_workspace\":"); jappend_json_string(&p, end, r.work);
    jappendf(&p, end, ",\"phase_evidence\":"); jappend_json_string(&p, end, r.evidence_path);
    jappendf(&p, end, ",\"recovery_required\":%s,\"evidence_durable\":%s,"
        "\"expected_source_image_sha256\":\"%s\",\"source_image_sha256\":",
        r.recovery_required ? "true" : "false", r.evidence_durable ? "true" : "false",
        PFS_MODE_TRIAL_EXPECTED_SHA);
    if (r.source_sha256[0]) jappend_json_string(&p, end, r.source_sha256);
    else jappendf(&p, end, "null");
    jappendf(&p, end, ",\"source_outer_before\":");
    save_image_hash_stat_json(&p, end, &r.source_before, r.source_available);
    jappendf(&p, end, ",\"source_outer_after\":");
    save_image_hash_stat_json(&p, end, &r.source_after, r.source_stable);
    jappendf(&p, end, ",\"source_stable\":%s,\"source_unchanged\":%s,\"arms\":[",
        r.source_stable ? "true" : "false", r.source_unchanged ? "true" : "false");
    for (size_t i = 0; i < 2; i++) {
        const pfs_mode_arm_t* arm = &r.arms[i];
        jappendf(&p, end, "%s{\"name\":\"%s\",\"closed_image\":", i ? "," : "", i ? "CANDIDATE" : "CONTROL");
        jappend_json_string(&p, end, arm->image);
        jappendf(&p, end, ",\"closed_image_sha256\":");
        if (arm->closed_sha256[0]) jappend_json_string(&p, end, arm->closed_sha256);
        else jappendf(&p, end, "null");
        jappendf(&p, end, ",\"ciphertext_changed_from_source\":");
        if (arm->closed_sha256[0] && r.source_sha256[0])
            jappendf(&p, end, "%s", strcmp(arm->closed_sha256, r.source_sha256) ? "true" : "false");
        else jappendf(&p, end, "null");
        jappendf(&p, end, ",\"verification_copy\":"); jappend_json_string(&p, end, arm->verification_copy);
        jappendf(&p, end, ",\"sealed_key_sha256\":");
        if (arm->sealed_key_sha256[0]) jappend_json_string(&p, end, arm->sealed_key_sha256);
        else jappendf(&p, end, "null");
        bool first_compared = arm->before.hashes_complete && arm->after.hashes_complete;
        bool closed_compared = arm->after.hashes_complete && arm->closed.hashes_complete && arm->verify_unmounted;
        jappendf(&p, end, ",\"first_unmounted\":%s,\"verify_unmounted\":%s,"
            "\"content_unchanged\":%s,\"attributes_preserved\":%s,\"closed_observation_matches\":%s,\"before\":",
            arm->first_unmounted ? "true" : "false", arm->verify_unmounted ? "true" : "false",
            first_compared ? (arm->content_unchanged ? "true" : "false") : "null",
            first_compared ? (arm->attributes_preserved ? "true" : "false") : "null",
            closed_compared ? (arm->closed_observation_matches ? "true" : "false") : "null");
        pfs_mode_observation_json(&p, end, &arm->before);
        jappendf(&p, end, ",\"after\":"); pfs_mode_observation_json(&p, end, &arm->after);
        jappendf(&p, end, ",\"closed_verification\":"); pfs_mode_observation_json(&p, end, &arm->closed);
        jappendf(&p, end, "}");
    }
    bool compared = r.arms[0].verify_unmounted && r.arms[1].verify_unmounted &&
                    r.arms[0].closed.hashes_complete && r.arms[1].closed.hashes_complete;
    jappendf(&p, end, "],\"closed_comparison_performed\":%s,\"closed_comparison\":{",
        compared ? "true" : "false");
    const char* names[] = {"inventory_equal", "content_hashes_equal", "identities_equal", "flags_equal",
        "links_equal", "other_modes_equal", "requested_modes_observed", "sealed_keys_equal", "plain_keys_equal",
        "content_equal", "metadata_equal", "modes_expected"};
    bool values[] = {r.inventory_equal, r.content_hashes_equal, r.identities_equal, r.flags_equal,
        r.links_equal, r.other_modes_equal, r.requested_modes_observed, r.sealed_keys_equal, r.plain_keys_equal,
        r.content_equal, r.metadata_equal, r.modes_expected};
    for (size_t i = 0; i < sizeof(values) / sizeof(values[0]); i++)
        jappendf(&p, end, "%s\"%s\":%s", i ? "," : "", names[i], compared ? (values[i] ? "true" : "false") : "null");
    jappendf(&p, end, "},\"timestamp_comparison\":{\"equal\":%s,\"excluded_from_equivalence\":true,"
        "\"observations\":\"All available timestamp values are retained separately in every metadata observation\"},\"limits\":",
        compared ? (r.timestamps_equal ? "true" : "false") : "null");
    jappend_json_string(&p, end, "PRIVATE ONLY: no live publication, Restore, SFO patch, import access, DB write or PRE snapshot rotation. Complete file hashes include the entire SFO/keystone; matching bytes do not prove cryptographic HMAC validity or game acceptance. Native mount/unmount may change encrypted representation and timestamps. Unsupported ACL/xattrs remain UNKNOWN; xattr values are not observed. Gate excludes daemon workers, not external writers; source stat/hash checks are observational. Any failed comparison stops with evidence retained and no replay.");
    jappendf(&p, end, "}");
    bool overflow = p >= end - 1, saved = false;
    if (r.work[0] && !overflow) {
        char path[320]; snprintf(path, sizeof(path), "%s/response.json", r.work);
        int out = open(path, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW, 0600);
        if (out >= 0) {
            size_t length = strlen(buf), offset = 0;
            while (offset < length) { ssize_t n = write(out, buf + offset, length - offset); if (n <= 0) break; offset += (size_t)n; }
            saved = offset == length && fsync(out) == 0;
            if (close(out) != 0) saved = false;
            int dir = open(r.work, O_RDONLY | O_DIRECTORY);
            if (dir < 0) saved = false;
            else { if (fsync(dir) != 0) saved = false; if (close(dir) != 0) saved = false; }
        }
    }
    if (overflow) reply_json(fd, 503, "{\"error\":\"private_trial_response_overflow\",\"result\":\"INCOMPLETE\",\"publication_enabled\":false}");
    else if (r.work[0] && !saved) reply_json(fd, 503, "{\"error\":\"private_trial_response_evidence_failed\",\"result\":\"INCOMPLETE\",\"publication_enabled\":false}");
    else reply_json(fd, !strcmp(r.result, "PRIVATE_PASS") && r.evidence_durable && !r.recovery_required ? 200 : 409, buf);
    pfs_mode_trial_free(&r); free(buf);
}

static void candidate_publication_json(char* buf, size_t capacity,
                                       const pfs_candidate_publication_t* report,
                                       const char* response_error, bool observations) {
    const pfs_mode_trial_report_t* r = &report->trial;
    bool uncertain = report->rename_attempted && !report->published;
    char *p = buf, *end = buf + capacity;
    jappendf(&p, end, "{\"operation\":\"publish-save-mode-candidate\",\"version\":\"%s\","
        "\"uid\":\"%s\",\"title_id\":\"%s\",\"slot\":\"%s\",\"target\":\"%s\","
        "\"publication_attempted\":%s,\"rename_attempted\":%s,\"publication_uncertain\":%s,"
        "\"published\":%s,\"live_writebacks\":", TOSTONSYNC_VERSION, PFS_ATTRIBUTES_UID, PFS_ATTRIBUTES_TITLE, PFS_ATTRIBUTES_SLOT,
        PFS_ATTRIBUTES_REJECTED, report->rename_attempted ? "true" : "false",
        report->rename_attempted ? "true" : "false", uncertain ? "true" : "false",
        uncertain ? "null" : report->published ? "true" : "false");
    if (uncertain) jappendf(&p, end, "null");
    else jappendf(&p, end, "%u", report->live_writebacks);
    jappendf(&p, end, ",\"result\":");
    jappend_json_string(&p, end, r->result);
    jappendf(&p, end, ",\"detail\":"); jappend_json_string(&p, end, r->detail);
    jappendf(&p, end, ",\"phase\":"); jappend_json_string(&p, end, r->phase);
    jappendf(&p, end, ",\"phase_evidence\":"); jappend_json_string(&p, end, r->evidence_path);
    jappendf(&p, end, ",\"evidence_workspace\":"); jappend_json_string(&p, end, r->work);
    jappendf(&p, end, ",\"recovery_required\":%s,\"evidence_durable\":%s,"
        "\"barrier_retained\":%s,\"barrier_cleared\":%s,\"barrier_path\":",
        r->recovery_required ? "true" : "false", r->evidence_durable ? "true" : "false",
        r->work[0] && r->recovery_required ? "true" : "false",
        !strcmp(r->result, "PUBLISHED_VERIFIED") && !r->recovery_required ? "true" : "false");
    char barrier[512] = {0};
    if (s_cfg) snprintf(barrier, sizeof(barrier), "%s/raw-recovery.pending", s_cfg->paths.state_dir);
    jappend_json_string(&p, end, barrier);
    jappendf(&p, end, ",\"candidate\":\"%s\",\"control\":\"%s\",\"trial_receipt\":\"%s\","
        "\"permanent_attempt_marker\":\"%s\",\"expected_source_sha256\":\"%s\","
        "\"expected_candidate_sha256\":\"%s\",\"expected_control_sha256\":\"%s\","
        "\"trial_receipt_sha256\":\"%s\",\"source_sha256\":",
        PFS_CANDIDATE_IMAGE, PFS_CANDIDATE_CONTROL, PFS_CANDIDATE_RECEIPT, PFS_CANDIDATE_ATTEMPT,
        PFS_MODE_TRIAL_EXPECTED_SHA, PFS_CANDIDATE_SHA, PFS_CANDIDATE_CONTROL_SHA, PFS_CANDIDATE_RECEIPT_SHA);
    if (r->source_sha256[0]) jappend_json_string(&p, end, r->source_sha256);
    else jappendf(&p, end, "null");
    jappendf(&p, end, ",\"final_sha256\":");
    if (report->final_sha256[0]) jappend_json_string(&p, end, report->final_sha256);
    else jappendf(&p, end, "null");
    jappendf(&p, end, ",\"retained_original\":"); jappend_json_string(&p, end, r->arms[0].image);
    jappendf(&p, end, ",\"candidate_verification_copy\":");
    jappend_json_string(&p, end, r->arms[1].verification_copy);
    jappendf(&p, end, ",\"identity_resolved\":%s,\"attempt_durable\":%s,\"pre_verified\":%s,"
        "\"post_verified\":%s,\"final_hash_verified\":%s,\"retained_unchanged\":%s,"
        "\"source_stable\":%s,\"source_unchanged\":%s,\"registry\":{\"dir_name\":",
        report->identity_resolved ? "true" : "false", report->attempt_durable ? "true" : "false",
        report->pre_verified ? "true" : "false", report->post_verified ? "true" : "false",
        report->final_hash_verified ? "true" : "false", report->retained_unchanged ? "true" : "false",
        r->source_stable ? "true" : "false", r->source_unchanged ? "true" : "false");
    jappend_json_string(&p, end, report->registry.dir_name);
    jappendf(&p, end, ",\"status\":"); jappend_json_string(&p, end, report->registry.status);
    jappendf(&p, end, ",\"detail\":"); jappend_json_string(&p, end, report->registry.detail);
    jappendf(&p, end, ",\"registry_status\":"); jappend_json_string(&p, end, report->registry.registry_status);
    jappendf(&p, end, ",\"registry_rowid\":");
    if (!strcmp(report->registry.registry_status, "ROW_FOUND"))
        jappendf(&p, end, "%lld", (long long)report->registry.registry_rowid);
    else jappendf(&p, end, "null");
    jappendf(&p, end, ",\"sqlite_code\":%d,\"sqlite_extended_code\":%d,\"sqlite_message\":",
        report->registry.sqlite_code, report->registry.sqlite_extended_code);
    jappend_json_string(&p, end, report->registry.sqlite_message);
    jappendf(&p, end, ",\"account_id\":");
    if (report->identity_resolved) jappendf(&p, end, "\"%016llx\"", (unsigned long long)report->account_id);
    else jappendf(&p, end, "null");
    jappendf(&p, end, ",\"user_id\":");
    if (report->identity_resolved) jappendf(&p, end, "%u", report->user_id);
    else jappendf(&p, end, "null");
    jappendf(&p, end, "},\"source_outer_before\":");
    save_image_hash_stat_json(&p, end, &r->source_before, r->source_available);
    jappendf(&p, end, ",\"source_outer_after\":");
    save_image_hash_stat_json(&p, end, &r->source_after, r->source_unchanged);
    jappendf(&p, end, ",\"timestamps_excluded_from_equivalence\":true,\"observations\":");
    if (observations) {
        jappendf(&p, end, "{\"source_pre\":");
        pfs_mode_observation_json(&p, end, &r->arms[0].before);
        jappendf(&p, end, ",\"candidate_pre\":");
        pfs_mode_observation_json(&p, end, &r->arms[1].after);
        jappendf(&p, end, ",\"published_post\":");
        pfs_mode_observation_json(&p, end, &r->arms[1].closed);
        jappendf(&p, end, "}");
    } else jappendf(&p, end, "null");
    jappendf(&p, end, ",\"response_error\":");
    if (response_error) jappend_json_string(&p, end, response_error);
    else jappendf(&p, end, "null");
    jappendf(&p, end, ",\"limits\":");
    jappend_json_string(&p, end, "One pinned closed image only; no retry, rollback, DB write, PRE rotation or cleanup. Core phase/observation evidence is authoritative; response.json is a convenience copy. An uncertain rename reports published/live_writebacks as null, not proof of no live change. Complete byte/metadata comparison does not demonstrate HMAC validity or PS5/game acceptance. Unavailable ACL/xattrs remain UNKNOWN; timestamps are observations only. Gate excludes daemon workers, not external writers.");
    jappendf(&p, end, "}");
}

static void handle_candidate_publication(int fd, const char* query, const char* body, size_t body_len) {
    if (!candidate_publication_request_exact(query, body, body_len)) {
        reply_json(fd, 400, "{\"error\":\"unsupported_candidate_publication_scope\",\"publication_attempted\":false}");
        return;
    }
    if (strcmp(TOSTONSYNC_VERSION, PFS_CANDIDATE_RELEASE)) {
        reply_json(fd, 409, "{\"error\":\"candidate_publication_version_mismatch\",\"publication_attempted\":false}");
        return;
    }
    const size_t capacity = 12 * 1024 * 1024;
    char* buf = malloc(capacity);
    if (!buf) { reply_json(fd, 503, "{\"error\":\"out_of_memory\",\"publication_attempted\":false}"); return; }
    pfs_candidate_publication_t report;
    watcher_publish_mode_candidate(&report);
    candidate_publication_json(buf, capacity, &report, NULL, true);
    bool overflow = strlen(buf) >= capacity - 1, saved = false;
    if (report.trial.work[0] && !overflow) {
        char path[320]; snprintf(path, sizeof(path), "%s/response.json", report.trial.work);
        int out = open(path, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW, 0600);
        if (out >= 0) {
            size_t length = strlen(buf), offset = 0;
            while (offset < length) {
                ssize_t n = write(out, buf + offset, length - offset);
                if (n < 0 && errno == EINTR) continue;
                if (n <= 0) break;
                offset += (size_t)n;
            }
            saved = offset == length && fsync(out) == 0;
            if (close(out) != 0) saved = false;
            int dir = open(report.trial.work, O_RDONLY | O_DIRECTORY | O_NOFOLLOW);
            if (dir < 0) saved = false;
            else { if (fsync(dir) != 0) saved = false; if (close(dir) != 0) saved = false; }
        }
    }
    if (overflow || (report.trial.work[0] && !saved)) {
        // Preserve actual rename/published facts even if the optional response
        // copy failed. Never reacquire/rearm the already finalized core gate.
        candidate_publication_json(buf, capacity, &report,
            overflow ? "publication_response_overflow" : "publication_response_evidence_failed", false);
        reply_json(fd, 503, buf);
    } else reply_json(fd, !strcmp(report.trial.result, "PUBLISHED_VERIFIED") &&
        report.trial.evidence_durable && !report.trial.recovery_required ? 200 : 409, buf);
    pfs_mode_trial_free(&report.trial); free(buf);
}

static void handle_users_list(int fd) {
    const config_t* cfg = config_get();
    if (!cfg) { reply_text(fd, 500, "no config"); return; }

    fs_dir_t users[16];
    size_t n = fs_list_users(cfg->paths.saves_root, users, 16);

    char buf[4096];
    char* p = buf;
    char* end = buf + sizeof(buf);
    jappendf(&p, end, "{\"users\":[");
    int first = 1;
    // Track which UIDs we've already emitted so a persisted alias whose user
    // is also live doesn't appear twice.
    char seen[16][16];
    size_t seen_n = 0;
    for (size_t i = 0; i < n; i++) {
        const char* alias = config_alias_for_uid(users[i].user_uid);
        bool has_alias = strcmp(alias, users[i].user_uid) != 0;
        jappendf(&p, end, "%s{\"uid\":", first ? "" : ",");
        jappend_json_string(&p, end, users[i].user_uid);
        jappendf(&p, end, ",\"alias\":");
        jappend_json_string(&p, end, alias);
        jappendf(&p, end, ",\"has_alias\":%s,\"present\":true}",
                 has_alias ? "true" : "false");
        first = 0;
        if (seen_n < 16) {
            snprintf(seen[seen_n], sizeof(seen[seen_n]), "%s",
                     users[i].user_uid);
            seen_n++;
        }
    }
    // Also surface UIDs that only exist as a remembered alias (e.g. a Google
    // Drive backup uploaded under a UID this console no longer has live). The
    // browser's catalog uses these to fold Drive-only backups into the named
    // user, and they let the owner re-bind a UID after a user change.
    for (size_t i = 0; i < cfg->users.count; i++) {
        const char* uid = cfg->users.entries[i].uid;
        const char* al  = cfg->users.entries[i].alias;
        if (!uid[0] || !al[0]) continue;
        bool dup = false;
        for (size_t s = 0; s < seen_n; s++)
            if (strcmp(seen[s], uid) == 0) { dup = true; break; }
        if (dup) continue;
        jappendf(&p, end, "%s{\"uid\":", first ? "" : ",");
        jappend_json_string(&p, end, uid);
        jappendf(&p, end, ",\"alias\":");
        jappend_json_string(&p, end, al);
        jappendf(&p, end, ",\"has_alias\":true,\"present\":false}");
        first = 0;
    }
    jappendf(&p, end, "]}");
    reply_json(fd, 200, buf);
}

// --------------------------------------------------------------------
// /api/cleanup — "factory reset" / cleanup actions.
//
// Body: {"actions":["legacy_savesync","orphan_mounts","staging",
//                   "tokens","history","reset_config","stale_pidfile"]}
//
// Each requested action is run independently and its result reported.
// Nothing happens that the user didn't ask for; the UI gates this
// behind a confirmation dialog. Useful when "something stops working
// in the future and we need to wipe and start fresh."
// --------------------------------------------------------------------
static void handle_cleanup(int fd, const char* body) {
    if (!body) { reply_text(fd, 400, "missing body"); return; }
    const config_t* cfg = config_get();
    if (!cfg) { reply_text(fd, 500, "no config"); return; }

    char done[512] = {0};
    char failed[512] = {0};
    char cleanup_detail[192] = {0};
    #define DONE(name) do { \
        if (done[0]) strncat(done, ",", sizeof(done) - strlen(done) - 1); \
        strncat(done, "\"" name "\"", sizeof(done) - strlen(done) - 1); \
    } while (0)
    #define FAIL(name) do { \
        if (failed[0]) strncat(failed, ",", sizeof(failed) - strlen(failed) - 1); \
        strncat(failed, "\"" name "\"", sizeof(failed) - strlen(failed) - 1); \
    } while (0)

    // Naive "is this token in the JSON array" check — exact-string
    // search inside the "actions" subobject. Good enough; the body
    // size cap upstream is already 16 KB.
    const char* actions = strstr(body, "\"actions\"");
    if (!actions) actions = body;

    char path[512];

    if (strstr(actions, "\"legacy_savesync\"")) {
        // Wipe /data/savesync/ if the rename migration left anything
        // behind, or if the user has been switching between the old
        // and new binaries.
        pfs_fs_rmrf("/data/savesync");
        DONE("legacy_savesync");
    }

    if (strstr(actions, "\"orphan_mounts\"")) {
        if (watcher_cleanup_scratch(true, cleanup_detail, sizeof(cleanup_detail)))
            DONE("orphan_mounts");
        else FAIL("orphan_mounts");
    }

    if (strstr(actions, "\"staging\"")) {
        if (watcher_cleanup_scratch(false, cleanup_detail, sizeof(cleanup_detail)))
            DONE("staging");
        else FAIL("staging");
    }

    if (strstr(actions, "\"tokens\"")) {
        snprintf(path, sizeof(path), "%s/tokens.json", cfg->paths.state_dir);
        if (unlink(path) == 0 || errno == ENOENT) DONE("tokens");
        else                                      FAIL("tokens");
    }

    if (strstr(actions, "\"history\"")) {
        snprintf(path, sizeof(path), "%s/history.jsonl", cfg->paths.state_dir);
        if (unlink(path) == 0 || errno == ENOENT) DONE("history");
        else                                      FAIL("history");
    }

    if (strstr(actions, "\"reset_config\"")) {
        // Move config.ini aside (with a timestamp) so a panicked user
        // hasn't actually lost their settings — they can find them in
        // <state_dir>/config.ini.bak.<ts> if they need to inspect.
        snprintf(path, sizeof(path), "%s/config.ini", cfg->paths.state_dir);
        char bak[600];
        time_t t = time(NULL);
        snprintf(bak, sizeof(bak), "%s.bak.%lld",
                 path, (long long)t);
        if (rename(path, bak) == 0 || errno == ENOENT) DONE("reset_config");
        else                                           FAIL("reset_config");
        // The active in-memory config keeps running until the next
        // boot; the renamed file means the next boot regenerates
        // defaults.
    }

    if (strstr(actions, "\"stale_pidfile\"")) {
        // We always rewrite our own pidfile at boot, so the only stale
        // one would be from a crashed previous run that the takeover
        // logic somehow didn't clear. Safe to delete.
        snprintf(path, sizeof(path), "%s/tostonsync.pid",
                 cfg->paths.state_dir);
        if (unlink(path) == 0 || errno == ENOENT) DONE("stale_pidfile");
        else                                      FAIL("stale_pidfile");
    }

    #undef DONE
    #undef FAIL

    char buf[2048], *p = buf, *end = buf + sizeof(buf);
    jappendf(&p, end, "{\"ok\":%s,\"done\":[%s],\"failed\":[%s],\"detail\":",
             failed[0] ? "false" : "true", done, failed);
    jappend_json_string(&p, end, cleanup_detail);
    jappendf(&p, end, "}");
    reply_json(fd, 200, buf);
}

// POST {"uid":"1230fa00","alias":"Alex"} → updates the alias and
// persists. Pass alias="" to clear (so the UID shows up under its
// raw name again). Refuses obviously bogus aliases.
static bool settings_action_parse(const char*,bool,char*,size_t,char*,size_t);
static void handle_display_alias(int fd,const char* body) {
    char uid[16]={0},alias[32]={0};
    if(!settings_action_parse(body,true,uid,sizeof(uid),alias,sizeof(alias))) {
        reply_json(fd,400,"{\"error\":\"invalid_display_alias\"}");return;
    }
    if(!config_set_display_alias(uid,alias)){reply_json(fd,409,"{\"error\":\"display_alias_not_saved\"}");return;}
    reply_json(fd,200,"{\"ok\":true}");
}

static void handle_users_alias(int fd, const char* body) {
    if (!body) { reply_text(fd, 400, "missing body"); return; }
    char uid[16] = {0};
    char alias[32] = {0};
    char validated[sizeof(alias)];
    if (!settings_action_parse(body, true, uid, sizeof(uid), alias, sizeof(alias)) ||
        !restore_uid_valid(uid) || !strcmp(alias, ".") || !strcmp(alias, "..") ||
        titlename_copy_utf8(validated, sizeof(validated), alias) != strlen(alias)) {
        reply_text(fd, 400, "invalid user alias request"); return;
    }
    // Same charset gate the watcher uses for restore: keeps a tampered
    // alias from sliding a "/" or ".." into the backup folder name.
    for (size_t i = 0; alias[i]; i++) {
        unsigned char c = (unsigned char)alias[i];
        if (c == '/' || c == '\\' || c < 0x20 || c == 0x7f ||
            (c == 0xc2 && (unsigned char)alias[i + 1] >= 0x80 && (unsigned char)alias[i + 1] <= 0x9f)) {
            reply_text(fd, 400, "alias contains forbidden characters");
            return;
        }
    }
    if (config_set_user_alias(uid, alias)) {
        reply_json(fd, 200, "{\"ok\":true}");
    } else {
        reply_text(fd, 500, "alias update failed");
    }
}

// POST /api/titles/alias {title_id, name} — manual game name for a TITLE_ID.
// Empty name clears it. Display only; never affects backup identity.
static void handle_title_alias(int fd, const char* body) {
    if (!body) { reply_text(fd, 400, "missing body"); return; }
    char title_id[16] = {0};
    char name[64] = {0};
    http_setting_text(body, "title_id", title_id, sizeof(title_id));
    http_setting_text(body, "name",     name,     sizeof(name));
    if (!title_id[0]) { reply_text(fd, 400, "missing title_id"); return; }
    if (config_set_title_alias(title_id, name))
        reply_json(fd, 200, "{\"ok\":true}");
    else
        reply_text(fd, 500, "title alias update failed");
}

static void reply_test(int fd, bool ok, const char* detail) {
    // Matrix diagnostics exceed 512 bytes. Truncating here produced malformed
    // JSON, so the browser showed "request failed" after a successful test.
    char buf[2048];
    char* p = buf;
    char* end = buf + sizeof(buf);
    jappendf(&p, end, "{\"ok\":%s,\"detail\":", ok ? "true" : "false");
    jappend_json_string(&p, end, detail ? detail : "");
    jappendf(&p, end, "}");
    reply_json(fd, 200, buf);
}

static void handle_test_usb(int fd) {
    char detail[512] = {0};
    jobs_ref_t admitted = 0;
    if (watcher_test_usb(&admitted, detail, sizeof(detail))) jobs_queued_reply(fd, admitted, false);
    else reply_test(fd, false, detail[0] ? detail : "USB write test could not be admitted");
}

static void handle_usb_mounts(int fd) {
    usb_mount_t active = {0}, mounts[8] = {{0}};
    size_t n = usb_observe_snapshot(&active, mounts, 8);
    char buf[32768] = {0};
    char* p = buf;
    char* end = buf + sizeof(buf);
    config_lock();
    jappendf(&p, end, "{\"selected\":");
    jappend_json_string(&p, end,
                        s_cfg->usb.mount_path[0] ? s_cfg->usb.mount_path : "auto");
    config_unlock();
    jappendf(&p, end, ",\"active\":");
    jappend_json_string(&p, end, active.selected ? active.path : "");
    append_usb_observation(&p, end, &active, "");
    jappendf(&p, end, ",\"mounts\":[");
    for (size_t i = 0; i < n && i < 8; i++) {
        if (i) jappendf(&p, end, ",");
        append_usb_mount(&p, end, &mounts[i]);
    }
    jappendf(&p, end, "]}");
    reply_json(fd, p < end - 1 ? 200 : 503,
        p < end - 1 ? buf : "{\"error\":\"usb_observation_too_large\"}");
}

static void handle_usb_confirm(int fd, const char* body) {
    char path[64]={0};
    if(!settings_action_parse(body,false,path,sizeof(path),NULL,0) || !path[0]) {
        reply_json(fd,400,"{\"error\":\"usb_confirmation_required\"}"); return;
    }
    usb_mount_t active={0};
    if(!usb_observe_selected(&active) || !active.selected || strcmp(path,active.path)) {
        reply_json(fd,409,"{\"error\":\"usb_selection_changed\"}"); return;
    }
    if(!usb_select_volume_identity(path)) {
        reply_json(fd,409,"{\"error\":\"usb_confirmation_failed\"}"); return;
    }
    handle_usb_mounts(fd);
}

static void handle_usb_name(int fd, const char* body) {
    char path[64] = {0}, name[64] = {0};
    json_get_string(body, "path", path, sizeof(path));
    json_get_string(body, "name", name, sizeof(name));
    if (!path[0]) { reply_text(fd, 400, "missing USB path"); return; }
    if (!usb_set_display_name(path, name)) {
        reply_text(fd, 400, "could not save USB display name");
        return;
    }
    reply_json(fd, 200, "{\"ok\":true}");
}



static void handle_test_drive(int fd) {
    gdrive_diagnostic_t d = {0};
    bool ok = gdrive_test_ready(&d);
    reply_test(fd, ok, d.detail);
}

// Two-leg internet probe: plain HTTP (no TLS) then HTTPS to Google infra.
// Reports the exact stage that failed so the UI never blames the wrong layer
// and never tells the user to "open a browser" for automatic backups.
static void handle_test_internet(int fd) {
    http_probe_t p = {0};
    bool ok = http_connectivity_probe(&p);
    char ca[512];
    http_ca_diag(ca, sizeof(ca));
    char detail[900];
    const char* local = http_transport_local_detail(p.plain_transport_error);
    if (!local) local = http_transport_local_detail(p.tls_transport_error);
    if (local) {
        snprintf(detail, sizeof(detail), "%s", local);
    } else if (ok) {
        snprintf(detail, sizeof(detail),
                 "DNS OK, TLS OK. The PS5 can reach Google directly; "
                 "automatic Drive can run daemon-side. [CA: %s]", ca);
    } else if (p.plain_ok && !p.tls_ok) {
        snprintf(detail, sizeof(detail),
                 "DNS OK, TLS failed (0x%x). The PS5 reached the internet but "
                 "could not complete TLS to Google. Check the CA bundle and the "
                 "PS5 date/time. [CA: %s]", (unsigned)p.tls_transport_error, ca);
    } else {
        snprintf(detail, sizeof(detail),
                 "DNS/network failed (0x%x). The PS5 could not reach the "
                 "internet. Check nanoDNS, the router, and internet access. "
                 "[CA: %s]", (unsigned)p.plain_transport_error, ca);
    }
    reply_test(fd, ok, detail);
}

// EXPERIMENTAL: isolated self-test of custom CA loading. Runs sceSslLoadRootCACert
// on a throwaway SSL context — this is the ONLY place it runs, and never during
// startup or sign-in. May destabilise the process on some SDKs (that is exactly
// what we are testing), so it is clearly labelled and opt-in.
static void handle_test_castore(int fd) {
    char detail[600];
    int r = http_ca_selftest(detail, sizeof(detail));
    char out[700];
    snprintf(out, sizeof(out), "%s%s",
             "EXPERIMENTAL custom CA test — ", detail);
    reply_test(fd, r == 1, out);
}

// EXPERIMENTAL: isolated libSceHttp (v1) trust test. Own contexts +
// sceHttpsLoadCert + one HTTPS GET. Never runs during startup or sign-in.
static void handle_test_httpsca(int fd) {
    char detail[640];
    int r = http_https_selftest(detail, sizeof(detail));
    char out[740];
    snprintf(out, sizeof(out), "%s%s",
             "EXPERIMENTAL libSceHttp trust test — ", detail);
    reply_test(fd, r == 1, out);
}

// EXPERIMENTAL: OAuth HTTPS matrix. Runs 6 GET/POST probes to gstatic and
// oauth2.googleapis.com over the live libSceHttp transport; full per-case
// results are in the daemon log (oauth-matrix: ...). Never runs at startup.
static void handle_test_oauthmatrix(int fd) {
    char detail[900];
    int result = http_oauth_matrix(detail, sizeof(detail));
    const char* local = http_transport_local_detail(result);
    char out[1000];
    snprintf(out, sizeof(out), "%s%s",
             local ? "" : "EXPERIMENTAL OAuth matrix (see log for detail)\n",
             local ? local : detail);
    reply_test(fd, result == 0, out);
}

// EXPERIMENTAL: Google host TLS matrix. GETs several Google/CDN hosts to isolate
// which the libSceHttp TLS handshake can reach. Full results in the daemon log
// (google-host-matrix: ...). Never runs at startup.
static void handle_test_googlehosts(int fd) {
    char detail[1100];
    int ok = http_google_host_matrix(detail, sizeof(detail));
    const char* local = http_transport_local_detail(ok);
    reply_test(fd, ok == 1,
        local ? local : ok == 1
            ? "Google TLS matrix passed. All required Google hosts are reachable."
            : "Google TLS matrix failed. See Technical logs for the unexpected host or status.");
}

static void handle_repair_google_certs(int fd) {
    if (watcher_active_jobs() > 0) {
        reply_test(fd, false,
                   "A backup is active. Retry certificate repair when it finishes.");
        return;
    }
    if (!http_google_cert_repair()) {
        reply_test(fd, false,
                   "Could not write /data/tostonsync/cacert.pem.");
        return;
    }
    http_client_rebuild_after_cert_repair();
    char detail[1100];
    int ok = http_google_host_matrix(detail, sizeof(detail));
    const char* local = http_transport_local_detail(ok);
    reply_test(fd, ok == 1,
        local ? local : ok == 1
            ? "Google certificates repaired. Google TLS matrix passed."
            : "The WE2 + WR2 bundle was installed, but the Google TLS matrix still failed. See Technical logs.");
}

// --------------------------------------------------------------------
// Optional UI access protection.
//
// A single access code (used as a PIN or a password — the user's choice)
// gates the whole UI on the LAN. We derive a non-reversible session token
// from the code with SHA-256 and hand it to the browser as a
// cookie; every request re-derives the expected token from the current
// code and compares. There is no server-side session table to keep, and
// changing the code instantly invalidates old cookies. This is plaintext
// HTTP on a home LAN, so it is a "keep casual snoopers out" control, not a
// cryptographic boundary — but it closes the wide-open-API gap.
// --------------------------------------------------------------------

static const char* ci_strstr(const char* hay, const char* needle);

static bool auth_random(uint8_t* out,size_t length) {
    int fd=open("/dev/urandom",O_RDONLY);if(fd<0)return false;
    size_t done=0;while(done<length){ssize_t n=read(fd,out+done,length-done);if(n<=0)break;done+=(size_t)n;}
    bool ok=done==length;if(close(fd))ok=false;if(!ok)memset(out,0,length);return ok;
}
static void auth_nonce_init(void) {
    if(s_auth_nonce_ready)return;
    s_auth_nonce_ready=auth_random(s_auth_nonce,sizeof(s_auth_nonce));
}
static bool auth_login_begin(void) {
    time_t now=time(NULL);if(!s_auth_nonce_ready||now<=0)return false;
    pthread_mutex_lock(&s_auth_lock);bool ok=true;
    if(s_login_expires<=now){ok=auth_random(s_login_nonce,sizeof(s_login_nonce));s_login_expires=ok?now+2592000:0;}
    pthread_mutex_unlock(&s_auth_lock);return ok;
}

static void auth_token(const char* code, char out[33]) {
    const char* salt = "tostonsync-auth:";
    static const char hex[] = "0123456789abcdef";
    sha256_ctx_t ctx;
    uint8_t digest[32];
    sha256_init(&ctx);
    sha256_update(&ctx, salt, strlen(salt));
    pthread_mutex_lock(&s_auth_lock);
    sha256_update(&ctx, s_login_nonce, sizeof(s_login_nonce));
    pthread_mutex_unlock(&s_auth_lock);
    sha256_update(&ctx, code, strlen(code));
    sha256_final(&ctx, digest);
    for (size_t i = 0; i < 16; i++) {
        out[i * 2] = hex[digest[i] >> 4];
        out[i * 2 + 1] = hex[digest[i] & 15];
    }
    out[32] = '\0';
    memset(digest, 0, sizeof(digest));
}

// Constant-ish time compare (length-independent enough for this purpose).
static bool str_eq(const char* a, const char* b) {
    size_t la = strlen(a), lb = strlen(b);
    if (la != lb) return false;
    unsigned diff = 0;
    for (size_t i = 0; i < la; i++) diff |= (unsigned)(a[i] ^ b[i]);
    return diff == 0;
}

static bool cookie_has_auth(const char* headers, const char* code) {
    if(!headers||!code||!code[0])return false;
    char got[33]="";bool found=false,header_seen=false;
    const char* p=headers;
    while(*p){const char* e=strstr(p,"\r\n");if(!e)e=p+strlen(p);if(e==p)break;
        if(e-p>=7&&!strncasecmp(p,"Cookie:",7)){
            if(header_seen)return false;header_seen=true;const char* c=p+7;
            while(c<e){while(c<e&&(*c==' '||*c=='\t'||*c==';'))c++;
                const char* end=memchr(c,';',(size_t)(e-c));if(!end)end=e;
                if(end-c>=16&&!memcmp(c,"tostonsync_auth=",16)){
                    const char* value=c+16;while(end>value&&(end[-1]==' '||end[-1]=='\t'))end--;
                    if(found||end-value!=32)return false;memcpy(got,value,32);got[32]=0;found=true;
                }
                const char* semi=memchr(c,';',(size_t)(e-c));if(!semi)break;c=semi+1;
            }
        }
        if(!*e)break;p=e+2;
    }
    if(!found)return false;
    pthread_mutex_lock(&s_auth_lock);time_t expires=s_login_expires;pthread_mutex_unlock(&s_auth_lock);
    time_t now=time(NULL);if(now<=0||now>=expires)return false;
    char expected[33];auth_token(code,expected);
    pthread_mutex_lock(&s_auth_lock);bool same=expires==s_login_expires;pthread_mutex_unlock(&s_auth_lock);
    return same&&str_eq(got,expected);
}

static void snapshot_ui_auth(bool* enabled, char code[64]) {
    bool en = false;
    char pw[64] = {0};
    config_lock();
    const config_t* cfg = config_get();
    if (cfg) {
        en = cfg->general.ui_auth_enabled;
        snprintf(pw, sizeof(pw), "%s", cfg->general.ui_password);
    }
    config_unlock();
    if (enabled) *enabled = en;
    if (code) snprintf(code, 64, "%s", pw);
}

typedef struct {
    uint32_t addr;
    time_t   window_start;
    time_t   blocked_until;
    unsigned failures;
} login_rate_t;

static login_rate_t s_login_rates[8];
static login_rate_t s_login_global;
static pthread_mutex_t s_login_rate_lock = PTHREAD_MUTEX_INITIALIZER;

static login_rate_t* login_rate_slot(uint32_t addr, time_t now) {
    login_rate_t* oldest = &s_login_rates[0];
    for (size_t i = 0; i < sizeof(s_login_rates) / sizeof(s_login_rates[0]); i++) {
        login_rate_t* r = &s_login_rates[i];
        if (r->addr == addr) return r;
        if (r->addr == 0 || r->window_start < oldest->window_start) oldest = r;
    }
    memset(oldest, 0, sizeof(*oldest));
    oldest->addr = addr;
    oldest->window_start = now;
    return oldest;
}

static bool login_rate_limited(uint32_t addr) {
    time_t now = time(NULL);
    pthread_mutex_lock(&s_login_rate_lock);
    login_rate_t* r = login_rate_slot(addr, now);
    bool blocked = r->blocked_until > now || s_login_global.blocked_until > now;
    pthread_mutex_unlock(&s_login_rate_lock);
    return blocked;
}

static void login_rate_record(uint32_t addr, bool success) {
    time_t now = time(NULL);
    pthread_mutex_lock(&s_login_rate_lock);
    login_rate_t* r = login_rate_slot(addr, now);
    if (success || now - r->window_start > 60) {
        r->window_start = now;
        r->failures = 0;
        r->blocked_until = 0;
    }
    if (!success && ++r->failures >= 5) r->blocked_until = now + 30;
    if(now-s_login_global.window_start>60){memset(&s_login_global,0,sizeof(s_login_global));s_login_global.window_start=now;}
    if(!success&&++s_login_global.failures>=20)s_login_global.blocked_until=now+30;
    pthread_mutex_unlock(&s_login_rate_lock);
}

static void handle_auth_state(int fd, bool auth_required, bool authed) {
    char buf[80];
    snprintf(buf, sizeof(buf), "{\"auth_required\":%s,\"authed\":%s}",
             auth_required ? "true" : "false", authed ? "true" : "false");
    reply_json(fd, 200, buf);
}

static void handle_login(int fd, const char* body, uint32_t peer_addr) {
    if (login_rate_limited(peer_addr)) {
        static const char limited[] = "{\"ok\":false,\"error\":\"rate_limited\"}";
        reply(fd, 429, "application/json; charset=utf-8", limited,
              sizeof(limited) - 1, "Retry-After: 30\r\n");
        return;
    }
    char code[64] = {0};
    http_setting_text(body, "code", code, sizeof(code));
    char pw[64] = {0};
    bool enabled = false;
    snapshot_ui_auth(&enabled, pw);
    if (!enabled || !pw[0]) { reply_json(fd, 200, "{\"ok\":true,\"note\":\"auth disabled\"}"); return; }
    if (code[0] && str_eq(code, pw)) {
        if(!auth_login_begin()){reply_json(fd,503,"{\"error\":\"session_entropy_unavailable\"}");return;}
        login_rate_record(peer_addr, true);
        char tok[33]; auth_token(pw, tok);
        char ck[160];
        snprintf(ck, sizeof(ck),
            "Set-Cookie: tostonsync_auth=%s; Path=/; HttpOnly; SameSite=Strict; Max-Age=2592000\r\n",
            tok);
        static const char ok[] = "{\"ok\":true}";
        reply(fd, 200, "application/json; charset=utf-8", ok, sizeof(ok) - 1, ck);
    } else {
        login_rate_record(peer_addr, false);
        reply_json(fd, 401, "{\"ok\":false}");
    }
}

static void handle_logout(int fd) {
    pthread_mutex_lock(&s_auth_lock);s_login_expires=0;memset(s_login_nonce,0,sizeof(s_login_nonce));pthread_mutex_unlock(&s_auth_lock);
    static const char ok[] = "{\"ok\":true}";
    reply(fd, 200, "application/json; charset=utf-8", ok, sizeof(ok) - 1,
          "Set-Cookie: tostonsync_auth=; Path=/; Max-Age=0\r\n");
}

static void handle_auth_set(int fd, const char* body) {
    char code[64] = {0};
    http_setting_text(body, "code", code, sizeof(code));
    bool enabled = http_setting_bool(body,"enabled");
    bool reset_ob = http_setting_bool(body,"reset_on_boot");
    char current[64] = {0};
    snapshot_ui_auth(NULL, current);
    if (enabled && !code[0] && !current[0]) {
        reply_json(fd, 400, "{\"ok\":false,\"error\":\"code_required\"}");
        return;
    }
    if (config_set_ui_auth(enabled, code, reset_ob)) {
        pthread_mutex_lock(&s_auth_lock);s_login_expires=0;memset(s_login_nonce,0,sizeof(s_login_nonce));pthread_mutex_unlock(&s_auth_lock);
        // If a code was just set, the caller's old cookie (if any) no longer
        // matches; the UI handles the re-login.
        reply_json(fd, 200, enabled ? "{\"ok\":true,\"enabled\":true}"
                                    : "{\"ok\":true,\"enabled\":false}");
    } else {
        reply_text(fd, 500, "could not save access code");
    }
}

static bool request_is_public(const char* method, const char* path);

static void handle_cooperative_stop(int fd, const char* body, size_t body_len) {
    static const char confirm[] = "{\"confirm\":true}";
    if (body_len != sizeof(confirm) - 1 || memcmp(body, confirm, sizeof(confirm) - 1)) {
        reply_json(fd, 400, "{\"ok\":false,\"error\":\"explicit_stop_confirmation_required\"}");
        return;
    }
    life_snapshot_t snapshot;
    if (!lifecycle_request_cooperative_stop(watcher_lifecycle_snapshot, &snapshot)) {
        char response[512];
        snprintf(response, sizeof(response),
                 "{\"ok\":false,\"error\":\"stop_blocked\",\"reason\":\"%s\"}", snapshot.reason);
        reply_json(fd, 409, response);
        return;
    }
    static const char accepted[] = "{\"ok\":true,\"state\":\"STOP_ACCEPTED\",\"shutdown_complete\":false}";
    char header[4096];
    int length = snprintf(header, sizeof(header),
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n"
        "Content-Length: %zu\r\nCache-Control: no-store\r\n"
        "X-Content-Type-Options: nosniff\r\n" HTTP_SECURITY_HEADERS "Connection: close\r\n\r\n", sizeof(accepted) - 1);
    // Freeze even if the response is lost. Main must not close the listener
    // until the accepted response has been completely sent by this handler.
    if (length > 0 && (size_t)length < sizeof(header) &&
        send_all(fd, header, (size_t)length) && send_all(fd, accepted, sizeof(accepted) - 1)) {
        lifecycle_cooperative_response_sent();
    } else {
        log_warn("stop[web] response lost; shutdown UNKNOWN, admission frozen and lock retained");
    }
}

#if TOSTONSYNC_STARTUP_VALIDATION_ONLY
static bool startup_validation_request_allowed(const char* method,
                                               const char* path) {
    return strcmp(method, "GET") == 0 &&
        (strcmp(path, "/api/config") == 0 ||
         strcmp(path, "/api/inspect-save-metadata") == 0);
}
#endif

typedef struct {
    char name[UPDATE_NAME_MAX], sha256[65], id[65];
    uint64_t size;
    bool confirm, allow_downgrade;
} update_http_request_t;

static void update_http_space(const char** p) {
    while (**p == ' ' || **p == '\t' || **p == '\r' || **p == '\n') ++*p;
}

static bool update_http_string(const char** p, char* out, size_t cap) {
    if (*(*p)++ != '"') return false;
    size_t n = 0;
    while (**p && **p != '"') {
        unsigned char c = (unsigned char)*(*p)++;
        if (c == '\\') {
            c = (unsigned char)*(*p)++;
            if (c != '"' && c != '\\' && c != '/') return false;
        }
        if (c < 32 || c == 127 || n + 1 >= cap) return false;
        out[n++] = (char)c;
    }
    if (**p != '"') return false;
    ++*p;
    out[n] = 0;
    return true;
}

static bool update_http_boolean(const char** p, bool* value) {
    if (!strncmp(*p, "true", 4)) { *p += 4; *value = true; return true; }
    if (!strncmp(*p, "false", 5)) { *p += 5; *value = false; return true; }
    return false;
}

// This flat protocol rejects duplicate/unknown keys rather than using the
// permissive Google-response helpers for executable publication authority.
static bool update_http_parse(const char* body, size_t length, bool start,
                              update_http_request_t* out) {
    if (!body || !out || !length || length > 1024 || strlen(body) != length) return false;
    memset(out, 0, sizeof(*out));
    const char* p = body;
    unsigned seen = 0;
    update_http_space(&p);
    if (*p++ != '{') return false;
    for (;;) {
        char key[24]; unsigned bit = 0;
        update_http_space(&p);
        if (!update_http_string(&p, key, sizeof(key))) return false;
        if (!strcmp(key, "confirm")) bit = 1;
        else if (start && !strcmp(key, "name")) bit = 2;
        else if (start && !strcmp(key, "size")) bit = 4;
        else if (start && !strcmp(key, "sha256")) bit = 8;
        else if (start && !strcmp(key, "allow_downgrade")) bit = 16;
        else if (!start && !strcmp(key, "id")) bit = 32;
        if (!bit || (seen & bit)) return false;
        seen |= bit;
        update_http_space(&p);
        if (*p++ != ':') return false;
        update_http_space(&p);
        if (bit == 1 || bit == 16) {
            if (!update_http_boolean(&p, bit == 1 ? &out->confirm : &out->allow_downgrade)) return false;
        } else if (bit == 4) {
            if (*p < '1' || *p > '9') return false;
            while (*p >= '0' && *p <= '9') {
                if (out->size > UPDATE_MAX_BYTES / 10) return false;
                out->size = out->size * 10 + (unsigned)(*p++ - '0');
                if (out->size > UPDATE_MAX_BYTES) return false;
            }
        } else if (!update_http_string(&p, bit == 2 ? out->name : bit == 8 ? out->sha256 : out->id,
                                       bit == 2 ? sizeof(out->name) : sizeof(out->id))) return false;
        update_http_space(&p);
        if (*p == '}') { ++p; break; }
        if (*p++ != ',') return false;
    }
    update_http_space(&p);
    return !*p && (start ? ((seen & 15) == 15) : seen == 33);
}

static void update_http_owner(uint32_t peer, char out[65]) {
    bool enabled = false;
    char code[64] = {0}; uint8_t digest[32];
    static const char hex[] = "0123456789abcdef";
    snapshot_ui_auth(&enabled, code);
    sha256_ctx_t hash;
    sha256_init(&hash);
    sha256_update(&hash, s_auth_nonce, sizeof(s_auth_nonce));
    sha256_update(&hash, &peer, sizeof(peer));
    sha256_update(&hash, &enabled, sizeof(enabled));
    sha256_update(&hash, code, strlen(code));
    sha256_final(&hash, digest);
    memset(code, 0, sizeof(code));
    for (size_t i = 0; i < sizeof(digest); ++i) {
        out[2*i] = hex[digest[i] >> 4]; out[2*i+1] = hex[digest[i] & 15];
    }
    out[64] = 0;
    memset(digest, 0, sizeof(digest));
}

static void update_http_file(char** p, char* end, const update_file_info_t* file) {
    jappendf(p, end, "{\"state\":"); jappend_json_string(p, end, file->state);
    jappendf(p, end, ",\"version\":");
    if (file->version[0]) jappend_json_string(p, end, file->version); else jappendf(p, end, "null");
    jappendf(p, end, ",\"build\":"); jappend_json_string(p, end, file->build);
    jappendf(p, end, ",\"bytes\":%llu,\"modified_unix\":%lld,\"sha256\":",
             (unsigned long long)file->bytes, (long long)file->mtime_unix);
    if (file->sha256[0]) jappend_json_string(p, end, file->sha256); else jappendf(p, end, "null");
    jappendf(p, end, ",\"valid\":%s}", file->valid ? "true" : "false");
}

static void handle_github_update_status(int fd) {
    github_update_status_t status;github_update_status(&status);
    char body[32768],*p=body,*end=body+sizeof(body);
    jappendf(&p,end,"{\"ok\":true,\"state\":");jappend_json_string(&p,end,status.state);
    jappendf(&p,end,",\"auto_check\":%s,\"last_attempt_unix\":%lld,\"last_success_unix\":%lld",
        status.auto_check?"true":"false",(long long)status.last_attempt_unix,(long long)status.last_success_unix);
    jappendf(&p,end,",\"next_check_unix\":%lld,\"automatic_paused\":%s,\"notes_verified\":%s",
        (long long)status.next_check_unix,status.automatic_paused?"true":"false",status.notes_verified?"true":"false");
#define GH_FIELD(name) do {jappendf(&p,end,",\"" #name "\":");jappend_json_string(&p,end,status.name);}while(0)
    GH_FIELD(version);GH_FIELD(build);GH_FIELD(notes);GH_FIELD(candidate_id);GH_FIELD(error);GH_FIELD(detail);
    GH_FIELD(saved_version);GH_FIELD(saved_sha256);
#undef GH_FIELD
    jappendf(&p,end,"}");reply_json(fd,200,body);
}
// Two explicit presentation actions; reject unknown/duplicate keys and truncation.
static bool settings_action_parse(const char* body,bool alias,char* first,size_t cap,char* second,size_t second_cap) {
    settings_json_t* d=settings_parse(body,body?strlen(body):0);if(!d)return false;
    http_setting_field_t fields[]={{alias?"uid":"path",SET_STRING,cap,true},{alias?"alias":"confirm",alias?SET_STRING:SET_BOOL,second_cap,true}};
    bool ok=http_settings_flat(d,fields,2);
    const settings_value_t* a=settings_member(d,&d->values[0],fields[0].name);
    const settings_value_t* b=settings_member(d,&d->values[0],fields[1].name);
    if(ok){strcpy(first,a->text);if(alias)strcpy(second,b->text);else ok=b->boolean;}
    free(d);return ok;
}

static bool github_update_http_parse(const char* body,size_t length,bool install,char candidate_id[65]) {
    if(!body||!length||length>256||strlen(body)!=length)return false;
    const char* p=body;unsigned seen=0;bool confirm=false;candidate_id[0]=0;
    update_http_space(&p);if(*p++!='{')return false;
    for(;;) {
        char key[24];update_http_space(&p);
        if(!update_http_string(&p,key,sizeof(key)))return false;
        unsigned bit=!strcmp(key,"confirm")?1:install&&!strcmp(key,"candidate_id")?2:0;
        if(!bit||(seen&bit))return false;seen|=bit;
        update_http_space(&p);if(*p++!=':')return false;update_http_space(&p);
        if(bit==1) {if(!update_http_boolean(&p,&confirm))return false;}
        else if(!update_http_string(&p,candidate_id,65)||strlen(candidate_id)!=64||strspn(candidate_id,"0123456789abcdef")!=64)return false;
        update_http_space(&p);if(*p=='}'){p++;break;}if(*p++!=',')return false;
    }
    update_http_space(&p);return !*p&&confirm&&seen==(install?3u:1u);
}
static void handle_github_update_action(int fd,bool install,const char* body,size_t length) {
    char id[65];
    if(!github_update_http_parse(body,length,install,id)) {
        reply_json(fd,400,"{\"ok\":false,\"error\":\"invalid_update_request\",\"detail\":\"Explicit confirmation and the exact candidate are required.\"}");return;
    }
    bool accepted=install?github_update_install(id):github_update_check();
    if(!accepted) {reply_json(fd,409,"{\"ok\":false,\"error\":\"update_request_busy_or_stale\",\"detail\":\"An update operation is active or the selected release changed. Check the current state.\"}");return;}
    handle_github_update_status(fd);
}

static void handle_update_status(int fd) {
    update_status_t status;
    if (!update_get_status(&status)) {
        reply_json(fd, 503, "{\"ok\":false,\"error\":\"update_status_unknown\"}"); return;
    }
    char buf[2048], *p = buf, *end = buf + sizeof(buf);
    jappendf(&p, end, "{\"ok\":true,\"running\":{\"version\":");
    jappend_json_string(&p, end, status.running_version);
    jappendf(&p, end, ",\"build\":"); jappend_json_string(&p, end, status.running_build);
    jappendf(&p, end, "},\"boot_id\":"); jappend_json_string(&p, end, status.boot_id);
    jappendf(&p, end, ",\"saved\":"); update_http_file(&p, end, &status.saved);
    jappendf(&p, end, ",\"previous\":"); update_http_file(&p, end, &status.previous);
    jappendf(&p, end, ",\"launcher\":"); jappend_json_string(&p, end, status.launcher);
    jappendf(&p, end, ",\"receiving\":%s,\"pending_saved\":%s,\"publication_unknown\":%s}",
             status.receiving ? "true" : "false", status.pending_saved ? "true" : "false",
             status.publication_unknown ? "true" : "false");
    reply_json(fd, 200, buf);
}

static void update_http_reply(int fd, bool ok, const update_result_t* result, bool finish,
                              jobs_ref_t observed) {
    int code = ok ? 200 : result->code == UPDATE_INVALID ? 400 :
        result->code == UPDATE_NOT_FOUND ? 404 : result->code == UPDATE_BUSY ||
        result->code == UPDATE_CONFLICT ? 409 : 500;
    char buf[1536], *p = buf, *end = buf + sizeof(buf);
    jappendf(&p, end, "{\"ok\":%s,\"result\":\"%s\",\"error\":", ok ? "true" : "false",
             result->code == UPDATE_UNKNOWN ? "UNKNOWN" : ok ? (finish ? "SAVED" : "ACCEPTED") : "REJECTED");
    jappend_json_string(&p, end, result->error);
    jappendf(&p, end, ",\"detail\":"); jappend_json_string(&p, end, result->detail);
    jappendf(&p, end, ",\"id\":"); jappend_json_string(&p, end, result->session_id);
    jappendf(&p, end, ",\"offset\":%llu,\"expires_unix\":%lld,\"bytes\":%llu,\"version\":",
             (unsigned long long)result->next_offset, (long long)result->expires_unix,
             (unsigned long long)result->bytes);
    jappend_json_string(&p, end, result->version);
    jappendf(&p, end, ",\"sha256\":"); jappend_json_string(&p, end, result->sha256);
    jappendf(&p, end, ",\"previous_version\":");
    if (result->previous_version[0]) jappend_json_string(&p, end, result->previous_version);
    else jappendf(&p, end, "null");
    jappendf(&p, end, ",\"published\":%s", result->code == UPDATE_UNKNOWN ? "null" :
             result->published ? "true" : "false");
    jobs_json_fields(&p, end, observed, false); jappendf(&p, end, "}");
    reply_json(fd, code, buf);
}

static void update_http_reject(int fd) {
    log_warn("update: rejected reason=invalid_update_request");
    reply_json(fd, 400, "{\"ok\":false,\"error\":\"invalid_update_request\"}");
}

static void handle_update_write(int fd, const char* path, const char* query,
                                const char* body, size_t body_len, uint32_t peer) {
    char owner[65]; update_http_owner(peer, owner);
    update_result_t result = {0}; bool ok = false;
    jobs_ref_t observed = 0;
    bool finish = !strcmp(path, "/api/update/finish");
    if (!strcmp(path, "/api/update/chunk")) {
        char id[65] = {0}, number[21] = {0}; int consumed = 0;
        if (!query || sscanf(query, "id=%64[0-9a-f]&offset=%20[0-9]&confirm=true%n", id, number, &consumed) != 2 ||
            !consumed || query[consumed] || strlen(id) != 64 ||
            (number[0] == '0' && number[1])) {
            update_http_reject(fd); return;
        }
        errno = 0; char* end; unsigned long long offset = strtoull(number, &end, 10);
        if (errno || *end || offset > UPDATE_MAX_BYTES || !body || !body_len || body_len > UPDATE_CHUNK_BYTES) {
            update_http_reject(fd); return;
        }
        jobs_ref_t binding = jobs_native_current(JOB_UPDATE);
        update_jobs_snapshot_t before;
        if (update_jobs_snapshot(&before) == UPDATE_JOBS_OBSERVED && before.current_present &&
            !strcmp(before.native_id, id)) observed = jobs_native_observe(JOB_UPDATE, id, binding);
        ok = update_chunk(owner, id, offset, body, body_len, true, &result);
    } else {
        update_http_request_t request;
        if (!update_http_parse(body, body_len, !finish, &request)) {
            update_http_reject(fd); return;
        }
        if (finish) {
            jobs_ref_t binding = jobs_native_current(JOB_UPDATE);
            update_jobs_snapshot_t before;
            if (update_jobs_snapshot(&before) == UPDATE_JOBS_OBSERVED && before.current_present &&
                !strcmp(before.native_id, request.id)) {
                observed = jobs_native_observe(JOB_UPDATE, request.id, binding);
                jobs_phase(observed, "ps5", "verifying", 0, false);
            }
        }
        ok = finish ? update_finish(owner, request.id, request.confirm, &result) :
            update_start(owner, request.name, request.size, request.sha256,
                         request.confirm, request.allow_downgrade, &result);
    }
    if (ok && result.session_id[0]) {
        jobs_ref_t binding = jobs_native_current(JOB_UPDATE);
        update_jobs_snapshot_t current;
        if (update_jobs_snapshot(&current) == UPDATE_JOBS_OBSERVED && current.current_present &&
            !strcmp(current.native_id, result.session_id)) {
            jobs_ref_t current_ref = jobs_native_observe(JOB_UPDATE, current.native_id, binding);
            if (current_ref) observed = current_ref;
            jobs_queued(current_ref, JOB_UPDATE, "", "", "", "ps5");
            jobs_phase(current_ref, "ps5", current.receiving ? "receiving" : "verifying",
                       current.expected, current.receiving && current.expected > 0);
            if (current.receiving) {
                jobs_ref_t previous = jobs_bind(current_ref);
                jobs_progress(current.received, current.expected, current.expected > 0); jobs_bind(previous);
            }
        }
    }
    if (observed) {
        if (ok && finish) jobs_finish(observed, JOB_DONE, "");
        else if (result.code == UPDATE_UNKNOWN) jobs_finish(observed, JOB_UNKNOWN, "update_state_unknown");
        else if (result.code == UPDATE_IO_ERROR || result.code == UPDATE_CONFLICT)
            jobs_finish(observed, JOB_FAILED, "update_failed");
    }
    update_http_reply(fd, ok, &result, finish, observed);
}

static void handle_individual_compatibility_route(int fd, const char* body) {
    if (individual_import_route_admit(fd, body, false)) handle_import_compatibility(fd, body);
}

static void handle_individual_commit_route(int fd, const char* body) {
    if (individual_import_route_admit(fd, body, true)) handle_import_commit(fd, body);
}

static void handle_update_restart(int fd, const char* body, size_t body_len) {
    static const char confirm[] = "{\"confirm\":true}";
    if (!body || body_len != sizeof(confirm) - 1 || memcmp(body, confirm, sizeof(confirm) - 1)) {
        reply_json(fd, 400, "{\"ok\":false,\"error\":\"explicit_restart_confirmation_required\"}");
        return;
    }
    life_snapshot_t snapshot; update_result_t result;
    if (!update_restart_request(watcher_lifecycle_snapshot, &snapshot, &result)) {
        char response[512], *p = response, *end = response + sizeof(response);
        jappendf(&p, end, "{\"ok\":false,\"error\":\"restart_blocked\",\"reason\":");
        jappend_json_string(&p, end, result.detail); jappendf(&p, end, "}");
        reply_json(fd, 409, response); return;
    }
    char accepted[512], *p = accepted, *end = accepted + sizeof(accepted);
    jappendf(&p, end, "{\"ok\":true,\"state\":\"RESTART_ACCEPTED\",\"boot_id\":");
    jappend_json_string(&p, end, update_boot_id());
    jappendf(&p, end, ",\"version\":"); jappend_json_string(&p, end, result.version);
    jappendf(&p, end, ",\"sha256\":"); jappend_json_string(&p, end, result.sha256);
    jappendf(&p, end, "}");
    char header[4096];
    int length = snprintf(header, sizeof(header),
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n"
        "Content-Length: %zu\r\nCache-Control: no-store\r\n"
        "X-Content-Type-Options: nosniff\r\n" HTTP_SECURITY_HEADERS "Connection: close\r\n\r\n", strlen(accepted));
    if (length > 0 && (size_t)length < sizeof(header) &&
        send_all(fd, header, (size_t)length) && send_all(fd, accepted, strlen(accepted))) {
        update_restart_response_sent();
    } else {
        log_warn("restart[web] response lost; no relaunch armed; admission frozen and lock retained");
    }
}

static bool http_action_path(const char* path) {
    static const char* exact[] = {
        "/api/update/status", "/api/jobs", "/api/debug/bundle", "/api/backups/individual",
        "/api/import/status", "/api/import/preserved", "/api/saves", "/api/backup-names",
        "/api/title-metadata", "/api/backups/catalog", "/api/backup/export",
        "/api/inspect-save-pfs-attributes"
    };
    static const char* prefixes[] = {"/api/slots/", "/api/download/", "/api/icon/", "/api/versions/"};
    for (size_t i = 0; i < sizeof(exact)/sizeof(exact[0]); i++) if (!strcmp(path, exact[i])) return true;
    for (size_t i = 0; i < sizeof(prefixes)/sizeof(prefixes[0]); i++)
        if (!strncmp(path, prefixes[i], strlen(prefixes[i]))) return true;
    return false;
}
static void update_http_observation_diagnostic(char** p, char* end,
                                                const update_observation_diagnostic_t* diagnostic) {
    jappendf(p, end, "{\"phase\":"); jappend_json_string(p, end, diagnostic->phase);
    jappendf(p, end, ",\"failed\":%s,\"rc\":%lld,\"errno\":", diagnostic->failed ? "true" : "false", (long long)diagnostic->rc);
    if (diagnostic->errno_valid) jappendf(p, end, "%d", diagnostic->error);
    else jappendf(p, end, "null");
    jappendf(p, end, ",\"canary\":"); jappend_json_string(p, end, diagnostic->canary);
    jappendf(p, end, ",\"identity\":"); jappend_json_string(p, end, diagnostic->identity);
    jappendf(p, end, ",\"field\":");
    if (diagnostic->field) jappend_json_string(p, end, diagnostic->field);
    else jappendf(p, end, "null");
    jappendf(p, end, "}");
}
static void handle_update_observation(int fd) {
    update_status_t status;
    bool observed = update_observe_status(&status);
    char buf[4096], *p = buf, *end = buf + sizeof(buf);
    jappendf(&p, end, "{\"ok\":%s,\"observation_only\":true", observed ? "true" : "false");
    if (!observed) jappendf(&p, end, ",\"error\":\"update_status_unknown\"");
    else {
        jappendf(&p, end, ",\"running\":{\"version\":");
        jappend_json_string(&p, end, status.running_version);
        jappendf(&p, end, ",\"build\":"); jappend_json_string(&p, end, status.running_build);
        jappendf(&p, end, "},\"boot_id\":"); jappend_json_string(&p, end, status.boot_id);
        jappendf(&p, end, ",\"saved\":"); update_http_file(&p, end, &status.saved);
        jappendf(&p, end, ",\"previous\":"); update_http_file(&p, end, &status.previous);
        jappendf(&p, end, ",\"launcher\":"); jappend_json_string(&p, end, status.launcher);
    }
    jappendf(&p, end, ",\"diagnostics\":{\"directory\":");
    update_http_observation_diagnostic(&p, end, &status.diagnostics.directory);
    jappendf(&p, end, ",\"saved\":");
    update_http_observation_diagnostic(&p, end, &status.diagnostics.saved);
    jappendf(&p, end, ",\"previous\":");
    update_http_observation_diagnostic(&p, end, &status.diagnostics.previous);
    jappendf(&p, end, "}}");
    reply_json(fd, observed ? 200 : 503, buf);
}

static void observation_reply(int fd, const char* path, const char* query) {
    char key[1024], type[64] = "application/json; charset=utf-8";
    observation_key(key, path, query);
    char* body = NULL; size_t size = 0; int status = 503; bool cached = false;
    pthread_mutex_lock(&s_observation_lock);
    for (size_t i = 0; key[0] && i < HTTP_OBSERVATION_SLOTS; i++) {
        const http_observation_t* item = &s_observations[i];
        if (strcmp(item->key, key)) continue;
        cached = true;
        if (!item->body) break;
        body = malloc(item->size + 1);
        if (body) {
            memcpy(body, item->body, item->size + 1); size = item->size; status = item->status;
            snprintf(type, sizeof(type), "%s", item->type);
        }
        break;
    }
    pthread_mutex_unlock(&s_observation_lock);
    if (body) { reply(fd, status, type, body, size, NULL); free(body); }
    else if (!cached && !strcmp(path, "/api/update/status")) handle_update_observation(fd);
    else reply_json(fd, 503, "{\"ok\":false,\"error\":\"observation_unavailable\"}");
}
static void handle_observation(int fd, const char* suffix, const char* query) {
    char path[512];
    int n = snprintf(path, sizeof(path), "/api/%s", suffix);
    if (n < 0 || (size_t)n >= sizeof(path) || !http_action_path(path)) {
        reply_text(fd, 404, "not found"); return;
    }
    s_http_observing = true;
    if (!strcmp(path, "/api/jobs")) handle_jobs(fd);
    else if (!strcmp(path, "/api/saves")) handle_saves(fd);
    else if (!strcmp(path, "/api/import/status")) handle_import_status(fd, query);
    else if (!strcmp(path, "/api/import/preserved")) handle_import_preserved(fd, query);
    else if (!strncmp(path, "/api/icon/", 10)) handle_icon(fd, path + 10);
    else observation_reply(fd, path, query);
    s_http_observing = false;
}
void httpd_maintenance(void) {
    if (lifecycle_stopping()) return;
    bool complete = jobs_observe_sessions();
    atomic_store(&s_sessions_observed_complete, complete);
    release_prepared();
}

static void route(int fd, const char* method, const char* path,
                  const char* query, const char* body, size_t body_len,
                  bool auth_required, bool authed, uint32_t peer_addr) {
    observe_restore_request(method, path);
    s_observation_key[0] = '\0'; s_http_observing = false;
    s_prepare_download = false;
#if TOSTONSYNC_STARTUP_VALIDATION_ONLY
    if (!startup_validation_request_allowed(method, path)) {
        reply_json(fd, 503, "{\"ok\":false,\"error\":\"startup_validation_only\"}");
        return;
    }
#endif
    // Gate everything except the assets needed to render the login screen
    // and the auth endpoints themselves.
    bool open_ep = request_is_public(method, path);
    if (auth_required && !authed && !open_ep) {
        reply_json(fd, 401, "{\"error\":\"auth_required\"}");
        return;
    }

    if (!strcmp(method,"POST") && !http_settings_request(path,body,body_len)) {
        reply_json(fd,400,"{\"error\":\"invalid_settings\"}"); return;
    }
    if (!strcmp(method, "GET") && http_action_path(path)) {
        reply(fd, 405, "application/json; charset=utf-8", "{\"error\":\"explicit_action_required\"}",
              strlen("{\"error\":\"explicit_action_required\"}"), "Allow: POST\r\n"); return;
    }
    if (!strcmp(method, "GET") && body_len) {
        reply_json(fd, 400, "{\"error\":\"get_body_not_allowed\"}"); return;
    }
    if (!strcmp(path,"/api/observe/rollbacks")) {
        if(strcmp(method,"GET"))reply_text(fd,405,"GET required");
        else if (lifecycle_stopping()) reply_json(fd,503,"{\"error\":\"daemon_stopping\"}");
        else handle_rollbacks(fd,query);
        return;
    }
    if (!strcmp(method, "GET") && !strncmp(path, "/api/observe/", 13)) {
        if (lifecycle_stopping()) reply_json(fd, 503, "{\"error\":\"daemon_stopping\"}");
        else handle_observation(fd, path + 13, query);
        return;
    }
    if (!strcmp(method, "GET") && !strncmp(path, "/api/download-prepared/", 23)) {
        if (lifecycle_stopping()) reply_json(fd, 503, "{\"error\":\"daemon_stopping\"}");
        else read_prepared(fd, path + 23);
        return;
    }
    if (!strcmp(method, "POST") && http_action_path(path)) {
        observation_key(s_observation_key, path, query);
        observation_store(503, "application/json; charset=utf-8", "{\"error\":\"observation_unavailable\"}",
            strlen("{\"error\":\"observation_unavailable\"}"));
        s_prepare_download = !strcmp(path, "/api/debug/bundle") || !strcmp(path, "/api/backup/export") ||
            !strncmp(path, "/api/download/", 14);
    }

    if (strcmp(method, "POST") == 0 && strcmp(path, "/api/restart") == 0) {
        handle_update_restart(fd, body, body_len); return;
    }

    if (lifecycle_stopping()) {
        reply_json(fd, 503, "{\"ok\":false,\"error\":\"daemon_stopping\"}");
        return;
    }
    if (strcmp(method, "GET") == 0 && strcmp(path, "/api/auth/state") == 0) {
        handle_auth_state(fd, auth_required, authed); return;
    }
    if (strcmp(method, "POST") == 0 && strcmp(path, "/api/login") == 0) {
        handle_login(fd, body, peer_addr); return;
    }
    if (strcmp(method, "POST") == 0 && strcmp(path, "/api/logout") == 0) {
        handle_logout(fd); return;
    }
    if (strcmp(method, "POST") == 0 && strcmp(path, "/api/auth/set") == 0) {
        // Reachable only when unprotected (first-time setup) or already
        // authed — the gate above enforces that.
        handle_auth_set(fd, body); return;
    }
    if (strcmp(method, "POST") == 0 && strcmp(path, "/api/stop") == 0) {
        handle_cooperative_stop(fd, body, body_len); return;
    }
    if (strcmp(method, "POST") == 0 && strcmp(path, "/api/update/status") == 0) {
        handle_update_status(fd); return;
    }
    if (strcmp(method, "POST") == 0 &&
        (!strcmp(path, "/api/update/start") || !strcmp(path, "/api/update/chunk") ||
         !strcmp(path, "/api/update/finish"))) {
        handle_update_write(fd, path, query, body, body_len, peer_addr); return;
    }
    if (!strcmp(path, "/api/github-update/status")) {
        if (strcmp(method, "GET")) reply_json(fd,405,"{\"ok\":false,\"error\":\"method_not_allowed\"}");
        else if (body_len) reply_json(fd,400,"{\"ok\":false,\"error\":\"get_body_not_allowed\"}");
        else handle_github_update_status(fd);
        return;
    }
    if (!strcmp(path,"/api/github-update/check") || !strcmp(path,"/api/github-update/install")) {
        if (strcmp(method,"POST")) reply_json(fd,405,"{\"ok\":false,\"error\":\"explicit_action_required\"}");
        else if (lifecycle_stopping()) reply_json(fd,503,"{\"ok\":false,\"error\":\"daemon_stopping\"}");
        else handle_github_update_action(fd,!strcmp(path,"/api/github-update/install"),body,body_len);
        return;
    }

    if (strcmp(method, "GET") == 0 && strcmp(path, "/") == 0) {
        reply(fd, 200, "text/html; charset=utf-8",
              UI_HTML_INDEX, strlen(UI_HTML_INDEX), NULL);
        return;
    }
    if (strcmp(method, "GET") == 0 && strcmp(path, "/assets/app.css") == 0) {
        reply(fd, 200, "text/css; charset=utf-8",
              UI_CSS_APP, strlen(UI_CSS_APP), NULL);
        return;
    }
    if (strcmp(method, "GET") == 0 && strcmp(path, "/assets/app.js") == 0) {
        reply(fd, 200, "application/javascript; charset=utf-8",
              UI_JS_APP, strlen(UI_JS_APP), NULL);
        return;
    }
    if (strcmp(method, "GET") == 0 && strcmp(path, "/assets/logo.svg") == 0) {
        reply(fd, 200, "image/svg+xml; charset=utf-8",
              UI_SVG_LOGO, strlen(UI_SVG_LOGO), NULL);
        return;
    }
    if (strcmp(method, "GET") == 0 && strcmp(path, "/assets/favicon.png") == 0) {
        reply(fd, 200, "image/png",
              (const char*)FAVICON_PNG_64, FAVICON_PNG_64_LEN, NULL);
        return;
    }
    if (strcmp(method, "GET") == 0 && strcmp(path, "/assets/favicon-180.png") == 0) {
        reply(fd, 200, "image/png",
              (const char*)FAVICON_PNG_180, FAVICON_PNG_180_LEN, NULL);
        return;
    }
    if (strcmp(method, "GET") == 0 &&
        strcmp(path, "/assets/support/tostonsync-kofi-qr.png") == 0) {
        reply(fd, 200, "image/png", (const char*)SUPPORT_QR_PNG,
              SUPPORT_QR_PNG_LEN, NULL);
        return;
    }
    if (strcmp(method, "GET") == 0 && strcmp(path, "/api/status") == 0) {
        handle_status(fd); return;
    }
    if (strcmp(method, "POST") == 0 && strcmp(path, "/api/jobs") == 0) {
        handle_jobs(fd); return;
    }
    if (strcmp(method, "GET") == 0 && strcmp(path, "/api/log") == 0) {
        handle_log(fd, query); return;
    }
    if (strcmp(method, "POST") == 0 && strcmp(path, "/api/debug/bundle") == 0) {
        handle_debug_bundle(fd); return;
    }
    if (strcmp(method, "GET") == 0 && strcmp(path, "/api/branding") == 0) {
        handle_branding(fd); return;
    }
    if (strcmp(method, "GET") == 0 && strcmp(path, "/api/qr") == 0) {
        handle_qr(fd, query); return;
    }
    if (strcmp(method, "GET") == 0 && strcmp(path, "/api/config") == 0) {
        handle_config_get(fd); return;
    }
    if (strcmp(method, "POST") == 0 && strcmp(path, "/api/backup-timezone") == 0) {
        handle_backup_timezone(fd, body); return;
    }
    if (strcmp(method, "POST") == 0 && strcmp(path, "/api/config") == 0) {
        pthread_mutex_lock(&s_catalog_lock);
        catalog_cleanup_revoke();
        handle_config_post(fd, body);
        pthread_mutex_unlock(&s_catalog_lock);
        return;
    }
    if (strcmp(method, "POST") == 0 && strcmp(path, "/api/oauth/start") == 0) {
        handle_oauth_start(fd); return;
    }
    if (strcmp(method, "POST") == 0 && strcmp(path, "/api/oauth/poll") == 0) {
        handle_oauth_poll(fd); return;
    }
    if (strcmp(method, "POST") == 0 && strcmp(path, "/api/oauth/cancel") == 0) {
        handle_oauth_cancel(fd); return;
    }
    if (strcmp(method, "POST") == 0 && strcmp(path, "/api/oauth/signout") == 0) {
        pthread_mutex_lock(&s_catalog_lock);
        catalog_cleanup_revoke();
        handle_signout(fd);
        pthread_mutex_unlock(&s_catalog_lock);
        return;
    }
    if (strcmp(method, "POST") == 0 && strcmp(path, "/api/sync") == 0) {
        handle_sync(fd); return;
    }
    if (strcmp(method, "POST") == 0 && strcmp(path, "/api/restore") == 0) {
        handle_restore(fd, body); return;
    }
    if (strcmp(method, "POST") == 0 && strcmp(path, "/api/import") == 0) {
        // Kept for older clients. The current UI always uses the resumable
        // session endpoints below, including for small ZIPs.
        handle_import_upload(fd, query, body, body_len); return;
    }
    if (strcmp(method, "POST") == 0 && strcmp(path, "/api/import/start") == 0) {
        char individual_source[24] = {0};
        json_get_string(body, "source", individual_source, sizeof(individual_source));
        if (!strcmp(individual_source, "individual")) {
            handle_individual_import_start(fd, body); return;
        }
        handle_import_start(fd, body); return;
    }
    if (strcmp(method, "POST") == 0 && strcmp(path, "/api/backups/individual") == 0) {
        handle_individual_list(fd, query); return;
    }
    if (strcmp(method, "POST") == 0 && strcmp(path, "/api/import/individual") == 0) {
        handle_individual_import(fd, body); return;
    }
    if (strcmp(method, "POST") == 0 && strcmp(path, "/api/import/chunk") == 0) {
        handle_import_chunk(fd, query, body, body_len); return;
    }
    if (strcmp(method, "POST") == 0 && strcmp(path, "/api/import/status") == 0) {
        handle_import_status(fd, query); return;
    }
    if (strcmp(method, "POST") == 0 && strcmp(path, "/api/import/preserve") == 0) {
        handle_import_preserve(fd, body, body_len); return;
    }
    if (strcmp(method, "POST") == 0 && strcmp(path, "/api/import/preserved") == 0) {
        handle_import_preserved(fd, query); return;
    }
    if (strcmp(method, "POST") == 0 && strcmp(path, "/api/import/finish") == 0) {
        handle_import_finish(fd, body); return;
    }
    if (strcmp(method, "POST") == 0 &&
        strcmp(path, "/api/import/compatibility") == 0) {
        handle_individual_compatibility_route(fd, body); return;
    }
    if (strcmp(method, "POST") == 0 && strcmp(path, "/api/import/commit") == 0) {
        handle_individual_commit_route(fd, body); return;
    }
    if (strcmp(method, "POST") == 0 && strcmp(path, "/api/import/raw-selected/commit") == 0) {
        handle_raw_selected_commit(fd, body); return;
    }
    if (strcmp(method, "GET") == 0 && strcmp(path, "/api/import/raw-selected/status") == 0) {
        handle_raw_selected_status(fd, query); return;
    }
    if (strcmp(method, "POST") == 0 && strcmp(path, "/api/import/raw-selected/preflight") == 0) {
        handle_raw_selected_preflight(fd, body); return;
    }
    if (strcmp(method, "POST") == 0 && strcmp(path, "/api/import/recover") == 0) {
        handle_import_recover(fd, body); return;
    }
    if (strcmp(method, "POST") == 0 && strcmp(path, "/api/import/cancel") == 0) {
        handle_import_cancel(fd, body); return;
    }
    if (!strcmp(path,"/api/users/display-alias")) {
        if(strcmp(method,"POST")) reply_json(fd,405,"{\"error\":\"method_not_allowed\"}");
        else handle_display_alias(fd,body);
        return;
    }
    if (!strcmp(path,"/api/usb/confirm")) {
        if(strcmp(method,"POST")) reply_json(fd,405,"{\"error\":\"method_not_allowed\"}");
        else handle_usb_confirm(fd,body);
        return;
    }
    if (strcmp(method, "GET") == 0 && strcmp(path, "/api/usb/mounts") == 0) {
        handle_usb_mounts(fd); return;
    }
    if (strcmp(method, "POST") == 0 && strcmp(path, "/api/usb/name") == 0) {
        handle_usb_name(fd, body); return;
    }
    if (strcmp(method, "POST") == 0 && strcmp(path, "/api/saves") == 0) {
        handle_saves(fd); return;
    }
    if (strcmp(method, "POST") == 0 && strcmp(path, "/api/backup-names") == 0) {
        handle_backup_names(fd, query); return;
    }
    if (strcmp(method, "POST") == 0 && strcmp(path, "/api/title-metadata") == 0) {
        handle_title_metadata(fd, query); return;
    }
    if (strcmp(method, "POST") == 0 &&
        strncmp(path, "/api/slots/", 11) == 0) {
        const char* rest = path + 11;
        const char* slash = strchr(rest, '/');
        if (slash) {
            char user[32] = {0};
            char title[64] = {0};
            size_t ul = (size_t)(slash - rest);
            if (ul >= sizeof(user)) ul = sizeof(user) - 1;
            memcpy(user, rest, ul);
            user[ul] = '\0';
            strncpy(title, slash + 1, sizeof(title) - 1);
            url_decode_inplace(user);
            url_decode_inplace(title);
            handle_slots(fd, user[0] ? user : NULL, title);
        } else {
            char title[64] = {0};
            strncpy(title, rest, sizeof(title) - 1);
            url_decode_inplace(title);
            handle_slots(fd, NULL, title);
        }
        return;
    }
    if (strcmp(method, "POST") == 0 && strcmp(path, "/api/saves/toggle") == 0) {
        handle_saves_toggle(fd, body); return;
    }
    if (strcmp(method, "POST") == 0 && strcmp(path, "/api/saves/hide") == 0) {
        handle_saves_hide(fd, body); return;
    }
    if (strcmp(path,"/api/backup/cancel")==0) {
        if (strcmp(method,"POST")) {reply_text(fd,405,"POST required");return;}
        handle_backup_cancel(fd,body);return;
    }
    if (strcmp(method, "POST") == 0 &&
        strcmp(path, "/api/rollback/delete") == 0) {
        handle_rollback_delete(fd, body); return;
    }
    if (strcmp(method, "POST") == 0 && strcmp(path, "/api/backup") == 0) {
        handle_backup(fd, body); return;
    }
    if (strcmp(method, "POST") == 0 && strcmp(path, "/api/download/raw-selected") == 0) {
        handle_raw_selected_download(fd, body); return;
    }
    if (strcmp(method, "POST") == 0 && strcmp(path, "/api/download/container-selected") == 0) {
        handle_container_selected_download(fd, body); return;
    }
    if (strcmp(method, "POST") == 0 && strcmp(path, "/api/backup/container-selected") == 0) {
        handle_container_selected_backup(fd, body); return;
    }
    if (strcmp(method, "POST") == 0 &&
        strncmp(path, "/api/download/", 14) == 0) {
        const char* rest = path + 14;
        const char* slash1 = strchr(rest, '/');
        if (!slash1) { reply_text(fd, 400, "missing mode/title"); return; }
        char mode[24] = {0};
        size_t ml = (size_t)(slash1 - rest);
        if (ml >= sizeof(mode)) ml = sizeof(mode) - 1;
        memcpy(mode, rest, ml);
        mode[ml] = '\0';
        const char* after_mode = slash1 + 1;
        const char* slash2 = strchr(after_mode, '/');
        if (slash2) {
            char user[32] = {0};
            char title[64] = {0};
            size_t ul = (size_t)(slash2 - after_mode);
            if (ul >= sizeof(user)) ul = sizeof(user) - 1;
            memcpy(user, after_mode, ul);
            user[ul] = '\0';
            strncpy(title, slash2 + 1, sizeof(title) - 1);
            url_decode_inplace(mode);
            url_decode_inplace(user);
            url_decode_inplace(title);
            handle_download(fd, mode, user[0] ? user : NULL, title);
        } else {
            char title[64] = {0};
            strncpy(title, after_mode, sizeof(title) - 1);
            url_decode_inplace(mode);
            url_decode_inplace(title);
            handle_download(fd, mode, NULL, title);
        }
        return;
    }
    if (strcmp(method, "POST") == 0 && strcmp(path, "/api/backups/catalog") == 0) {
        handle_backup_catalog(fd); return;
    }
    if (strcmp(method, "POST") == 0 && strcmp(path, "/api/restore-selected") == 0) {
        handle_restore_selected(fd, body); return;
    }
    if (strcmp(method, "POST") == 0 && strcmp(path, "/api/backup/delete") == 0) {
        handle_backup_delete(fd, body); return;
    }
    if (strcmp(method, "POST") == 0 && strcmp(path, "/api/backup/verify") == 0) {
        handle_backup_verify(fd, body); return;
    }
    if (strcmp(method, "POST") == 0 && strcmp(path, "/api/backup/export") == 0) {
        handle_backup_export(fd, query); return;
    }
    if (strcmp(method, "POST") == 0 && strcmp(path, "/api/backup/prune") == 0) {
        handle_backup_prune(fd, body); return;
    }
    if (strcmp(method, "POST") == 0 && strcmp(path, "/api/backup/protect") == 0) {
        handle_backup_protect(fd, body); return;
    }
    if (strcmp(method, "GET") == 0 && strcmp(path, "/api/backup/protected") == 0) {
        handle_backup_protected(fd); return;
    }
    if (strcmp(method, "POST") == 0 && strcmp(path, "/api/restore-all") == 0) {
        handle_restore_all(fd, body); return;
    }
    if (strcmp(method, "POST") == 0 &&
        strncmp(path, "/api/icon/", 10) == 0) {
        char title[64] = {0};
        strncpy(title, path + 10, sizeof(title) - 1);
        url_decode_inplace(title);
        handle_icon(fd, title);
        return;
    }
    if (strcmp(method, "POST") == 0 &&
        strncmp(path, "/api/versions/", 14) == 0) {
        // Accept both /api/versions/<title> (legacy, "default" user) and
        // /api/versions/<user>/<title> (multi-user).
        const char* rest = path + 14;
        const char* slash = strchr(rest, '/');
        if (slash) {
            char user[32] = {0};
            char title[64] = {0};
            size_t ul = (size_t)(slash - rest);
            if (ul >= sizeof(user)) ul = sizeof(user) - 1;
            memcpy(user, rest, ul); user[ul] = '\0';
            strncpy(title, slash + 1, sizeof(title) - 1);
            url_decode_inplace(user);
            url_decode_inplace(title);
            handle_versions(fd, user, title);
        } else {
            char title[64] = {0};
            strncpy(title, rest, sizeof(title) - 1);
            url_decode_inplace(title);
            handle_versions(fd, "default", title);
        }
        return;
    }
    if (strcmp(method, "GET") == 0 &&
        strncmp(path, "/api/usb/versions/", 18) == 0) {
        const char* rest = path + 18;
        const char* slash = strchr(rest, '/');
        if (slash) {
            char user[32] = {0};
            char title[64] = {0};
            size_t ul = (size_t)(slash - rest);
            if (ul >= sizeof(user)) ul = sizeof(user) - 1;
            memcpy(user, rest, ul); user[ul] = '\0';
            strncpy(title, slash + 1, sizeof(title) - 1);
            url_decode_inplace(user);
            url_decode_inplace(title);
            handle_usb_versions(fd, user, title);
        } else {
            char title[64] = {0};
            strncpy(title, rest, sizeof(title) - 1);
            url_decode_inplace(title);
            handle_usb_versions(fd, "default", title);
        }
        return;
    }

    if (strcmp(method, "GET") == 0 && strcmp(path, "/api/inspect-save-metadata") == 0) {
        char title[64] = {0};
        query_get_decoded(query, "title_id", title, sizeof(title));
        char uid[16] = {0}; bool uid_present = false;
        if (!save_metadata_query_uid(query, uid, sizeof(uid), &uid_present)) {
            reply_json(fd, 400, "{\"error\":\"invalid_target_uid\"}"); return;
        }
        handle_save_metadata(fd, title, uid_present ? uid : NULL); return;
    }
    if (strcmp(method, "GET") == 0 && strcmp(path, "/api/inspect-save-image-hash") == 0) {
        char uid[64] = {0}, title[64] = {0}, slot[512] = {0};
        if (!save_image_hash_query_exact(query, "target_uid", uid, sizeof(uid)) ||
            !save_image_hash_query_exact(query, "title_id", title, sizeof(title)) ||
            !save_image_hash_query_exact(query, "slot", slot, sizeof(slot))) {
            reply_json(fd, 400, "{\"error\":\"invalid_image_scope\"}"); return;
        }
        handle_save_image_hash(fd, uid, title, slot); return;
    }
    if (strcmp(method, "POST") == 0 && strcmp(path, "/api/inspect-save-pfs-attributes") == 0) {
        char uid[64] = {0}, title[64] = {0}, slot[512] = {0};
        if (!save_image_hash_query_exact(query, "target_uid", uid, sizeof(uid)) ||
            !save_image_hash_query_exact(query, "title_id", title, sizeof(title)) ||
            !save_image_hash_query_exact(query, "slot", slot, sizeof(slot))) {
            reply_json(fd, 400, "{\"error\":\"invalid_forensic_scope\"}"); return;
        }
        handle_pfs_attributes(fd, uid, title, slot); return;
    }
    if (strcmp(method, "POST") == 0 && strcmp(path, "/api/private-save-mode-trial") == 0) {
        handle_private_mode_trial(fd, query, body, body_len); return;
    }
    if (strcmp(method, "POST") == 0 && strcmp(path, "/api/publish-save-mode-candidate") == 0) {
        handle_candidate_publication(fd, query, body, body_len); return;
    }
    if (strcmp(method, "GET") == 0 && strcmp(path, "/api/users") == 0) {
        handle_users_list(fd); return;
    }
    if (strcmp(method, "POST") == 0 && strcmp(path, "/api/users/alias") == 0) {
        handle_users_alias(fd, body); return;
    }
    if (strcmp(method, "POST") == 0 && strcmp(path, "/api/titles/alias") == 0) {
        handle_title_alias(fd, body); return;
    }
    if (strcmp(method, "POST") == 0 && strcmp(path, "/api/cleanup") == 0) {
        handle_cleanup(fd, body); return;
    }
    if (strcmp(method, "GET") == 0 && strcmp(path, "/api/history") == 0) {
        handle_history(fd); return;
    }
    if (strcmp(method, "POST") == 0 && strcmp(path, "/api/activity") == 0) {
        handle_activity_record(fd, body); return;
    }
    if (strcmp(method, "POST") == 0 && strcmp(path, "/api/client-log") == 0) {
        handle_client_log(fd, body); return;
    }
    if (strcmp(method, "POST") == 0 && strcmp(path, "/api/test/usb") == 0) {
        handle_test_usb(fd); return;
    }

    if (strcmp(method, "POST") == 0 && strcmp(path, "/api/test/internet") == 0) {
        handle_test_internet(fd); return;
    }
    if (strcmp(method, "POST") == 0 && strcmp(path, "/api/test/castore") == 0) {
        handle_test_castore(fd); return;
    }
    if (strcmp(method, "POST") == 0 && strcmp(path, "/api/test/httpsca") == 0) {
        handle_test_httpsca(fd); return;
    }
    if (strcmp(method, "POST") == 0 && strcmp(path, "/api/test/oauthmatrix") == 0) {
        handle_test_oauthmatrix(fd); return;
    }
    if (strcmp(method, "POST") == 0 && strcmp(path, "/api/test/googlehosts") == 0) {
        handle_test_googlehosts(fd); return;
    }
    if (strcmp(method, "POST") == 0 && strcmp(path, "/api/repair/google-certs") == 0) {
        handle_repair_google_certs(fd); return;
    }
    if (strcmp(method, "POST") == 0 && strcmp(path, "/api/test/drive") == 0) {
        handle_test_drive(fd); return;
    }
    if (strcmp(method, "GET") == 0 && strcmp(path, "/api/titles") == 0) {
        handle_titles(fd);
        return;
    }
    reply_text(fd, 404, "not found");
}

// --------------------------------------------------------------------
// Connection handler.
// --------------------------------------------------------------------

// Case-insensitive substring search (header names are case-insensitive
// per RFC 7230; avoids depending on the non-standard strcasestr).
static const char* ci_strstr(const char* hay, const char* needle) {
    size_t nl = strlen(needle);
    if (!nl) return hay;
    for (; *hay; hay++) {
        size_t i = 0;
        while (i < nl && hay[i] &&
               tolower((unsigned char)hay[i]) == tolower((unsigned char)needle[i]))
            i++;
        if (i == nl) return hay;
    }
    return NULL;
}

static bool parse_content_length(const char* headers, size_t header_len,
                                 size_t* out_len) {
    if (!headers || !out_len) return false;
    *out_len = 0;
    const char* limit = headers + header_len;
    const char* p = strstr(headers, "\r\n");
    if (!p || p >= limit) return false;
    p += 2;
    bool seen = false;
    while (p + 2 <= limit && !(p[0] == '\r' && p[1] == '\n')) {
        const char* eol = strstr(p, "\r\n");
        if (!eol || eol > limit) return false;
        const char* colon = memchr(p, ':', (size_t)(eol - p));
        if (!colon) return false;
        size_t name_len = (size_t)(colon - p);
        if (name_len == 14 && strncasecmp(p, "Content-Length", 14) == 0) {
            if (seen) return false;
            const char* v = colon + 1;
            while (v < eol && (*v == ' ' || *v == '\t')) v++;
            if (v == eol || *v == '-') return false;
            errno = 0;
            char* end = NULL;
            unsigned long long n = strtoull(v, &end, 10);
            while (end && end < eol && (*end == ' ' || *end == '\t')) end++;
            if (errno == ERANGE || !end || end != eol ||
                n > (unsigned long long)SIZE_MAX)
                return false;
            *out_len = (size_t)n;
            seen = true;
        } else if (name_len == 17 &&
                   strncasecmp(p, "Transfer-Encoding", 17) == 0) {
            // Chunked requests are unsupported; rejecting them prevents CL/TE
            // ambiguity and request smuggling through this tiny HTTP parser.
            return false;
        }
        p = eol + 2;
    }
    return true;
}

// Mutating browser calls must use a non-simple content type. Besides making
// the API contract explicit, this prevents a malicious web page from issuing
// a fire-and-forget form/text POST to an unprotected TostónSync on the LAN.
// Cross-origin application/json and application/zip requests require a CORS
// preflight, and this server deliberately grants no cross-origin access.
static bool post_content_type_allowed(const char* method, const char* path,
                                      const char* headers) {
    if (!method || strcmp(method, "POST") != 0) return true;
    if (!headers || !path) return false;
    const char* p = ci_strstr(headers, "\r\nContent-Type:");
    if (!p) return false;
    p += strlen("\r\nContent-Type:");
    while (*p == ' ' || *p == '\t') p++;
    const char* expected = strcmp(path, "/api/import") == 0
                           ? "application/zip"
                           : (strcmp(path, "/api/import/chunk") == 0 || strcmp(path, "/api/update/chunk") == 0)
                             ? "application/octet-stream"
                             : "application/json";
    size_t n = strlen(expected);
    if (strncasecmp(p, expected, n) != 0) return false;
    char end = p[n];
    return end == '\r' || end == ';' || end == ' ' || end == '\t';
}

#ifndef HTTP_REQUEST_TIMEOUT_MS
#define HTTP_REQUEST_TIMEOUT_MS 120000
#endif

static bool peer_is_loopback(const struct sockaddr_in* p);

static int64_t request_monotonic_ms(void) {
    struct timespec ts;
    return clock_gettime(CLOCK_MONOTONIC, &ts) == 0
        ? (int64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000 : -1;
}

static ssize_t recv_before_deadline(int fd, void* buf, size_t len,
                                    int64_t deadline) {
    for (;;) {
        int64_t now = request_monotonic_ms();
        if (now < 0 || now >= deadline) { errno = ETIMEDOUT; return -1; }
        int64_t remaining = deadline - now;
        if (remaining > 30000) remaining = 30000; // preserve the idle bound
        struct timeval timeout = {
            .tv_sec = (time_t)(remaining / 1000),
            .tv_usec = (suseconds_t)((remaining % 1000) * 1000)
        };
        if (setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) != 0)
            return -1;
        errno = 0;
        ssize_t n = recv(fd, buf, len, 0);
        if (n < 0 && errno == EINTR) continue;
        if ((n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) ||
            request_monotonic_ms() >= deadline) {
            errno = ETIMEDOUT;
            return -1;
        }
        return n;
    }
}

static bool request_is_public(const char* method, const char* path) {
    return (strcmp(method, "GET") == 0 &&
            (strcmp(path, "/") == 0 ||
             strcmp(path, "/assets/app.css") == 0 ||
             strcmp(path, "/assets/app.js") == 0 ||
             strcmp(path, "/assets/logo.svg") == 0 ||
             strcmp(path, "/assets/favicon.png") == 0 ||
             strcmp(path, "/assets/favicon-180.png") == 0)) ||
        strcmp(path, "/api/auth/state") == 0 ||
        (strcmp(method, "POST") == 0 && strcmp(path, "/api/login") == 0);
}

static int authorize_request_headers(char* buf, size_t header_len,
                                      size_t content_len,
                                      const struct sockaddr_in* peer) {
    if (!s_cfg || !http_request_boundary(buf,header_len,s_cfg->general.http_port,s_cfg->general.http_hostname)) return -8;
    const char* line_end = strstr(buf, "\r\n");
    const char* sp1 = strchr(buf, ' ');
    const char* sp2 = sp1 ? strchr(sp1 + 1, ' ') : NULL;
    if (!line_end || !sp1 || !sp2 || sp2 >= line_end) return -1;
    const char* q = memchr(sp1 + 1, '?', (size_t)(sp2 - sp1 - 1));
    size_t method_len = (size_t)(sp1 - buf);
    size_t path_len = (size_t)((q ? q : sp2) - sp1 - 1);
    char method[8] = {0}, path[512] = {0};
    if (!method_len || method_len >= sizeof(method) ||
        !path_len || path_len >= sizeof(path)) return -1;
    memcpy(method, buf, method_len);
    memcpy(path, sp1 + 1, path_len);
    observe_restore_request(method, path);
    if (!strcmp(method, "GET") && content_len) return -7;
#if TOSTONSYNC_STARTUP_VALIDATION_ONLY
    if (!startup_validation_request_allowed(method, path)) return -6;
#endif
    if (request_is_public(method, path))
        return content_len > HTTP_INITIAL_CAP ? -2 : 0;

    char pw[64] = {0};
    bool enabled = false;
    snapshot_ui_auth(&enabled, pw);
    if (!enabled || !pw[0] || peer_is_loopback(peer)) return 0;
    // recv may already contain a few body bytes. Only headers may authorize.
    char saved = buf[header_len - 2];
    buf[header_len - 2] = '\0';
    bool authed = cookie_has_auth(sp2 + 1, pw);
    buf[header_len - 2] = saved;
    return authed ? 0 : -4;
}

// Read a full HTTP request: headers, then any body indicated by
// Content-Length. Small API calls stay small; ZIP imports grow the request
// buffer only after the header has been parsed. Returns bytes read, -1 on
// malformed/truncated input, -2 when the body exceeds the upload cap, or -3
// when another large browser upload already owns the bounded body slot,
// -4 when authentication fails, -5 when the request deadline expires, or
// -6 when this startup-validation build forbids the route, or -7 for a GET body.
static ssize_t recv_request(int fd, char** out_buf,
                            size_t* out_body_len, size_t* out_body_off,
                            bool* out_large_body_slot,
                            const struct sockaddr_in* peer) {
    int64_t started = request_monotonic_ms();
    if (started < 0) return -1;
    int64_t deadline = started + HTTP_REQUEST_TIMEOUT_MS;
    struct timeval receive_started;
    gettimeofday(&receive_started, NULL);
    if (out_large_body_slot) *out_large_body_slot = false;
    size_t cap = HTTP_INITIAL_CAP;
    char* buf = (char*)malloc(cap);
    if (!buf) return -1;
    size_t total = 0;
    char*  hdr_end = NULL;
    // 1. Read until we have the full header block (\r\n\r\n).
    while (total + 1 < cap) {
        ssize_t n = recv_before_deadline(fd, buf + total, cap - 1 - total,
                                        deadline);
        if (n <= 0) break;
        total += (size_t)n;
        buf[total] = '\0';
        hdr_end = strstr(buf, "\r\n\r\n");
        if (hdr_end) break;
    }
    if (!hdr_end) {
        int error = errno == ETIMEDOUT ? -5 : -1;
        free(buf);
        return error;
    }

    // 2. Honor Content-Length for the body.
    size_t header_len = (size_t)(hdr_end - buf) + 4;
    size_t content_len = 0;
    if (!parse_content_length(buf, header_len, &content_len)) {
        free(buf);
        return -1;
    }
#if TOSTONSYNC_STARTUP_VALIDATION_ONLY
    int auth_error = authorize_request_headers(buf, header_len, content_len, peer);
    if (auth_error) { free(buf); return auth_error; }
#endif
    if (content_len > HTTP_MAX_UPLOAD_BYTES) {
        free(buf);
        return -2;
    }

#if !TOSTONSYNC_STARTUP_VALIDATION_ONLY
    int auth_error = authorize_request_headers(buf, header_len, content_len, peer);
    if (auth_error) { free(buf); return auth_error; }
#endif
    if (request_monotonic_ms() >= deadline) { free(buf); return -5; }

    bool large_body_slot = false;
    if (content_len > HTTP_INITIAL_CAP) {
        if (pthread_mutex_trylock(&s_large_body_lock) != 0) {
            free(buf);
            return -3;
        }
        large_body_slot = true;
    }

    size_t want = header_len + content_len;
    if (want + 1 > cap) {
        char* nb = (char*)realloc(buf, want + 1);
        if (!nb) {
            if (large_body_slot) pthread_mutex_unlock(&s_large_body_lock);
            free(buf);
            return -1;
        }
        buf = nb;
    }
    while (total < want) {
        ssize_t n = recv_before_deadline(fd, buf + total, want - total, deadline);
        if (n <= 0) break;
        total += (size_t)n;
    }
    if (total < want) {
        int error = errno == ETIMEDOUT ? -5 : -1;
        if (large_body_slot) pthread_mutex_unlock(&s_large_body_lock);
        free(buf);
        return error;
    }
    if (content_len > HTTP_INITIAL_CAP) {
        struct timeval now;
        gettimeofday(&now, NULL);
        int64_t duration_ms = (int64_t)(now.tv_sec - receive_started.tv_sec) * 1000 +
                              (now.tv_usec - receive_started.tv_usec) / 1000;
        log_info("HTTP upload body received: bytes=%zu duration_ms=%lld",
                 content_len, (long long)duration_ms);
    }
    buf[total] = '\0';
    if (out_buf) *out_buf = buf;
    else free(buf);
    if (out_body_len) *out_body_len = content_len;
    if (out_body_off) *out_body_off = header_len;
    if (out_large_body_slot) *out_large_body_slot = large_body_slot;
    else if (large_body_slot) pthread_mutex_unlock(&s_large_body_lock);
    return (ssize_t)total;
}

// Heap-allocated args carry the connection fd plus the captured peer
// address so conn_thread can decide whether to bypass auth without
// re-issuing getpeername() on every request.
typedef struct {
    int                fd;
    struct sockaddr_in peer;
} conn_args_t;

// True for any client connecting through the loopback interface. We
// gate the local-PS5 bypass on this — when TostónSync opens the PS5's
// own browser via sceSystemServiceLaunchWebBrowser to http://127.0.0.1
// the kernel routes the TCP connection through lo0 and the peer addr
// here is INADDR_LOOPBACK. A device on the LAN can never spoof that;
// the loopback range is unrouted off-box.
static bool peer_is_loopback(const struct sockaddr_in* p) {
    if (!p) return false;
    // sin_family is sometimes left zero by accept() in unusual SDKs;
    // the IPv4 byte ordering check works regardless of the family
    // field as long as sin_addr was actually populated.
    uint32_t a = ntohl(p->sin_addr.s_addr);
    return (a >> 24) == 127;   // 127.0.0.0/8
}

static void* conn_thread(void* arg) {
    s_restore_request = NULL;
    conn_args_t* args = (conn_args_t*)arg;
    int fd = args->fd;
    struct sockaddr_in peer = args->peer;
    free(args);

    // The accept thread transferred an activity lease before pthread_create.
    // It covers slow bodies/auth and every GET/POST, not merely queue jobs.
    bool lifecycle_admitted = lifecycle_http_operation_begin();
    if (!lifecycle_admitted) {
        reply_json(fd, 503, "{\"ok\":false,\"error\":\"daemon_stopping\"}");
        close(fd);
        atomic_fetch_sub(&s_active_connections, 1);
        lifecycle_activity_end();
        return NULL;
    }

    // Defensive: some PS5 SDK builds leave peer unpopulated after
    // accept(); ask the kernel explicitly so the loopback bypass
    // works regardless of which path the connection arrived on.
    if (peer.sin_addr.s_addr == 0) {
        socklen_t pl = sizeof(peer);
        getpeername(fd, (struct sockaddr*)&peer, &pl);
    }

    char* buf = NULL;
    size_t body_len = 0, body_off = 0;
    bool large_body_slot = false;
    ssize_t n = recv_request(fd, &buf, &body_len, &body_off,
                             &large_body_slot, &peer);
    if (n == -2) {
        reply_json(fd, 413, "{\"ok\":false,\"error\":\"request_too_large\"}");
        goto done;
    }
    if (n == -3) {
        reply_json(fd, 503, "{\"ok\":false,\"error\":\"upload_busy\"}");
        goto done;
    }
    if (n == -4) {
        reply_json(fd, 401, "{\"ok\":false,\"error\":\"auth_required\"}");
        goto done;
    }
    if (n == -5) {
        reply_json(fd, 408, "{\"ok\":false,\"error\":\"request_timeout\"}");
        goto done;
    }
    if (n == -6) {
        reply_json(fd, 503, "{\"ok\":false,\"error\":\"startup_validation_only\"}");
        goto done;
    }
    if (n == -7) {
        reply_json(fd, 400, "{\"error\":\"get_body_not_allowed\"}"); goto done;
    }
    if (n == -8) { reply_json(fd,400,"{\"error\":\"invalid_request_origin\"}"); goto done; }
    if (n <= 0 || !buf) goto done;
    buf[n] = '\0';

    char method[8]  = {0};
    char path[512]  = {0};
    char query[512] = {0};
    char* sp1 = strchr(buf, ' ');
    char* sp2 = sp1 ? strchr(sp1 + 1, ' ') : NULL;
    if (!sp1 || !sp2) goto done;
    *sp1 = 0; *sp2 = 0;
    strncpy(method, buf, sizeof(method) - 1);
    char* q = strchr(sp1 + 1, '?');
    if (q) {
        *q = 0;
        strncpy(path, sp1 + 1, sizeof(path) - 1);
        strncpy(query, q + 1, sizeof(query) - 1);
    } else {
        strncpy(path, sp1 + 1, sizeof(path) - 1);
    }

    // Body starts after \r\n\r\n.
    char* body = body_off ? (buf + body_off) : strstr(sp2 + 1, "\r\n\r\n");
    if (body && !body_off) body += 4;
    if (!body) { body = (char*)""; body_len = 0; }
    if (body_off >= 4)
        buf[body_off - 2] = '\0';   // retain the final header CRLF, exclude ZIP bytes

    // Determine auth before any handler runs.
    //
    // Three gates, in order:
    //   1. Access protection switch off, or no code stored -> let everyone in.
    //      This makes auth explicitly optional and prevents stale ui_password
    //      lines from locking the owner out after an update.
    //   2. Request comes from the PS5 itself -> let it in. The menu app opens
    //      http://127.0.0.1:1993, so the TCP peer must be in 127.0.0.0/8.
    //      External LAN devices connect through the PS5 LAN IP and cannot
    //      produce a loopback peer address.
    //   3. External LAN device -> require the session cookie derived from
    //      the configured access code.
    const char* headers = sp2 + 1;
    char pw[64] = {0};
    bool enabled = false;
    snapshot_ui_auth(&enabled, pw);
    bool local_ps5 = peer_is_loopback(&peer);
    bool auth_required = enabled && pw[0] && !local_ps5;
    bool authed = !auth_required || cookie_has_auth(headers, pw);

    if (!post_content_type_allowed(method, path, headers)) {
        reply_json(fd, 415,
                   "{\"ok\":false,\"error\":\"unsupported_content_type\"}");
        goto done;
    }

    route(fd, method, path, query, body, body_len, auth_required, authed,
          peer.sin_addr.s_addr);

done:
    if (large_body_slot) pthread_mutex_unlock(&s_large_body_lock);
    free(buf);
    close(fd);
    atomic_fetch_sub(&s_active_connections, 1);
    lifecycle_http_operation_end();
    return NULL;
}

static void* accept_loop(void* arg) {
    (void)arg;
    // HTTP handlers (especially the per-title version listers) put multi-KB
    // arrays on the stack, and the SDK default thread stack is too small for
    // that — a request like /api/usb/versions would overflow conn_thread and
    // kill the whole daemon. Give every connection thread a 1 MB stack.
    pthread_attr_t cattr;
    pthread_attr_t* cattrp = NULL;
    bool attr_initialized = pthread_attr_init(&cattr) == 0;
    if (attr_initialized &&
        pthread_attr_setstacksize(&cattr, 1024 * 1024) == 0)
        cattrp = &cattr;
    while (s_running) {
        struct sockaddr_in peer;
        socklen_t pl = sizeof(peer);
        memset(&peer, 0, sizeof(peer));
        int c = accept(s_listen_fd, (struct sockaddr*)&peer, &pl);
        if (c < 0) continue;
        if (!lifecycle_activity_begin()) {
            reply_json(c, 503, "{\"ok\":false,\"error\":\"daemon_stopping\"}");
            close(c); continue;
        }
        struct timeval io_timeout = { .tv_sec = 30, .tv_usec = 0 };
        setsockopt(c, SOL_SOCKET, SO_RCVTIMEO, &io_timeout,
                   sizeof(io_timeout));
        setsockopt(c, SOL_SOCKET, SO_SNDTIMEO, &io_timeout,
                   sizeof(io_timeout));
        if (atomic_fetch_add(&s_active_connections, 1) >=
            HTTP_MAX_CONNECTIONS) {
            atomic_fetch_sub(&s_active_connections, 1);
            close(c);
            lifecycle_activity_end();
            continue;
        }
        conn_args_t* args = (conn_args_t*)malloc(sizeof(*args));
        if (!args) {
            atomic_fetch_sub(&s_active_connections, 1);
            close(c);
            lifecycle_activity_end();
            continue;
        }
        args->fd   = c;
        args->peer = peer;
        pthread_t t;
        if (pthread_create(&t, cattrp, conn_thread, args) != 0) {
            atomic_fetch_sub(&s_active_connections, 1);
            free(args);
            close(c);
            lifecycle_activity_end();
            continue;
        }
        pthread_detach(t);
    }
    if (attr_initialized) pthread_attr_destroy(&cattr);
    return NULL;
}

// --------------------------------------------------------------------
// Lifecycle.
// --------------------------------------------------------------------

bool httpd_start(const config_t* cfg) {
    if (lifecycle_stopping()) return false;
    s_cfg = cfg;
    (void)update_boot_id();
    if (!TOSTONSYNC_STARTUP_VALIDATION_ONLY) {
        auth_nonce_init();
        if(!s_auth_nonce_ready){log_error("http: secure boot entropy unavailable");return false;}
        import_session_init(cfg);
    }
    discover_lan_ip();

    s_listen_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (s_listen_fd < 0) return false;
    int yes = 1;
    setsockopt(s_listen_fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));
    // Do NOT enable SO_REUSEPORT here. On PS5/FreeBSD it can let an old
    // TostónSync and a new TostónSync both bind :1993, so the user sees a
    // new "ready" notification while the browser/API still hits the old UI.
    // A failed bind is the correct signal that the previous daemon is alive.

    struct sockaddr_in addr = {0};
    addr.sin_family      = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    addr.sin_port        = htons((uint16_t)cfg->general.http_port);

    // Retry the bind for a few seconds. When a new build is sent while an
    // old TostónSync is still shutting down, the port can be briefly held;
    // main() also kills the previous instance, but this rides out the
    // short window where its socket is still releasing.
    bool bound = false;
    for (int attempt = 0; attempt < 20; attempt++) {
        if (bind(s_listen_fd, (struct sockaddr*)&addr, sizeof(addr)) == 0) {
            bound = true; break;
        }
        usleep(300 * 1000);   // 300 ms
    }
    if (!bound) {
        log_warn("httpd: could not bind :%d after retries — is another "
                 "TostónSync still running on that port?", cfg->general.http_port);
        close(s_listen_fd); s_listen_fd = -1;
        return false;
    }
    if (listen(s_listen_fd, 8) < 0) {
        close(s_listen_fd); s_listen_fd = -1;
        return false;
    }

    s_running = 1;
    s_accept_started = false;
    int thread_error = pthread_create(&s_accept_thread, NULL,
                                      accept_loop, NULL);
    if (thread_error != 0) {
        log_error("httpd: failed to create accept thread (%d)", thread_error);
        s_running = 0;
        close(s_listen_fd);
        s_listen_fd = -1;
        return false;
    }
    s_accept_started = true;
    log_debug("httpd listening on http://%s:%d/",
              s_lan_ip[0] ? s_lan_ip : "127.0.0.1",
              cfg->general.http_port);
    return true;
}

void httpd_stop(void) {
    if (!s_running) return;
    s_running = 0;
    if (s_listen_fd >= 0) {
        shutdown(s_listen_fd, SHUT_RDWR);
        close(s_listen_fd);
        s_listen_fd = -1;
    }
    if (s_accept_started) pthread_join(s_accept_thread, NULL);
    s_accept_started = false;
    // Let already-accepted handlers release shared Google/network state before
    // resume recovery replaces it. Never hold shutdown forever on a bad peer.
    for (int i = 0; i < 20 && atomic_load(&s_active_connections) > 0; i++)
        usleep(100 * 1000);
    if (atomic_load(&s_active_connections) > 0)
        log_warn("httpd: %d connection(s) still draining after stop",
                 atomic_load(&s_active_connections));
}

unsigned httpd_active_connections(void) {
    int count = atomic_load(&s_active_connections);
    return count < 0 ? UINT_MAX : (unsigned)count;
}

bool httpd_stop_cooperatively(void) {
    s_running = 0;
    if (s_listen_fd >= 0) {
        int fd = s_listen_fd;
        s_listen_fd = -1;
        if (shutdown(fd, SHUT_RDWR) != 0 && errno != ENOTCONN) {
            log_warn("stop[web] HTTP shutdown failed; close remains necessary");
        }
        if (close(fd) != 0) return false;
    }
    if (s_accept_started) {
        int result = pthread_join(s_accept_thread, NULL);
        if (result != 0) return false;
        s_accept_started = false;
    }
    return httpd_active_connections() == 0;
}
