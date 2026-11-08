// TostónSync — log + on-screen notification.

#include "log.h"
#include "diagnostic_text.h"

#include <errno.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

// On-screen toast. This is the mechanism EVERY working ps5-payload uses
// (ftpsrv, nanodns, pldmgr, etc.): a libkernel syscall, not a libSce*
// notification lib. The request struct is the de-facto standard from
// ps5-payload-dev — 45 reserved bytes, then up to 3075 bytes of message.
// (The old code called a made-up sceNotificationSend(), which produced
//  no toast on hardware.)
typedef struct notify_request {
    char useless1[45];
    char message[3075];
} notify_request_t;

int sceKernelSendNotificationRequest(int device, notify_request_t* req,
                                     size_t size, int blocking);

static void send_toast(const char* text) {
    notify_request_t req;
    memset(&req, 0, sizeof(req));
    snprintf(req.message, sizeof(req.message), "%s", text);
    sceKernelSendNotificationRequest(0, &req, sizeof(req), 0);
}

typedef enum { LV_ERR=0, LV_WARN=1, LV_INFO=2, LV_DEBUG=3 } level_t;

static const config_t* s_cfg     = NULL;
static FILE*           s_fp      = NULL;
static level_t         s_min     = LV_INFO;
static pthread_mutex_t s_lock    = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t s_notify_lock = PTHREAD_MUTEX_INITIALIZER;
static char            s_path[300];

typedef struct {
    char text[1024];
    time_t last;
    unsigned suppressed;
} notify_slot_t;

static notify_slot_t s_notify_slots[8];

static level_t parse_level(const char* s) {
    if (!s || !*s) return LV_INFO;
    if (!strcmp(s, "debug")) return LV_DEBUG;
    if (!strcmp(s, "info"))  return LV_INFO;
    if (!strcmp(s, "warn"))  return LV_WARN;
    if (!strcmp(s, "error")) return LV_ERR;
    return LV_INFO;
}

static const char* level_tag(level_t l) {
    switch (l) {
        case LV_ERR:   return "ERROR";
        case LV_WARN:  return "WARN ";
        case LV_INFO:  return "INFO ";
        case LV_DEBUG: return "DEBUG";
    }
    return "?    ";
}

static void rotate_if_needed(void) {
    if (!s_fp || !s_cfg) return;
    struct stat st;
    if (fstat(fileno(s_fp), &st) != 0) return;
    if (st.st_size < s_cfg->general.log_max_bytes) return;
    fclose(s_fp); s_fp = NULL;
    char old_path[320];
    snprintf(old_path, sizeof(old_path), "%s.1", s_path);
    rename(s_path, old_path);
    chmod(old_path, 0600);
    s_fp = fopen(s_path, "a");
    if (s_fp) chmod(s_path, 0600);
}

void log_init(const config_t* cfg) {
    s_cfg = cfg;
    s_min = parse_level(cfg->general.log_level);
    snprintf(s_path, sizeof(s_path), "%s/sync.log", cfg->paths.state_dir);
    mkdir(cfg->paths.state_dir, 0700);
    chmod(cfg->paths.state_dir, 0700);
    s_fp = fopen(s_path, "a");
    if (s_fp) chmod(s_path, 0600);
}

static bool emit(level_t lv, bool durable, const char* fmt, va_list ap) {
    int saved_errno = errno;
    if (!durable && lv > s_min) return true;
    char msg[1024];
    vsnprintf(msg, sizeof(msg), fmt, ap);
    diagnostic_redact(msg,strlen(msg),NULL,NULL);

    time_t t = time(NULL);
    struct tm tm; gmtime_r(&t, &tm);
    char ts[32];
    strftime(ts, sizeof(ts), "%Y-%m-%dT%H:%M:%SZ", &tm);

    pthread_mutex_lock(&s_lock);
    rotate_if_needed();
    const char* failed = NULL;
    int error = 0;
    if (!s_fp) {
        if (durable || s_cfg) {
            failed = "stream";
            error = EBADF;
        }
    } else {
        if (fprintf(s_fp, "%s %s %s\n", ts, level_tag(lv), msg) < 0)
            failed = "fprintf";
        else if (fflush(s_fp) != 0)
            failed = "fflush";
        else if (fsync(fileno(s_fp)) != 0)
            failed = "fsync";
        if (failed) error = errno;
    }
    // A broken logger must report its first failure without calling itself.
    if (failed)
        fprintf(stderr, "%s ERROR logger: persistence failed step=%s errno=%d\n",
                ts, failed, error);
    fprintf(stderr, "%s %s %s\n", ts, level_tag(lv), msg);
    pthread_mutex_unlock(&s_lock);
    errno = saved_errno;
    return failed == NULL;
}

void log_info (const char* fmt, ...) { va_list ap; va_start(ap, fmt); emit(LV_INFO,  false, fmt, ap); va_end(ap); }
void log_warn (const char* fmt, ...) { va_list ap; va_start(ap, fmt); emit(LV_WARN,  false, fmt, ap); va_end(ap); }
void log_error(const char* fmt, ...) { va_list ap; va_start(ap, fmt); emit(LV_ERR,   false, fmt, ap); va_end(ap); }
void log_debug(const char* fmt, ...) { va_list ap; va_start(ap, fmt); emit(LV_DEBUG, false, fmt, ap); va_end(ap); }
bool log_durable(const char* fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    bool persisted = emit(LV_INFO, true, fmt, ap);
    va_end(ap);
    return persisted;
}

static void coalesced_text(const notify_slot_t* slot, const char* text,
                           char* out, size_t out_sz) {
    static const char* en = "Auto backup complete: ";
    static const char* es = "Respaldo automático completado: ";
    const char* start = strncmp(text, en, strlen(en)) == 0 ? text + strlen(en) :
                        strncmp(text, es, strlen(es)) == 0 ? text + strlen(es) : NULL;
    if (!start || slot->suppressed == 0) {
        snprintf(out, out_sz, "%s", text);
        return;
    }
    const char* end = strstr(start, " (");
    size_t len = end ? (size_t)(end - start) : strlen(start);
    snprintf(out, out_sz,
             start == text + strlen(es) ? "%u backups completados para %.*s"
                                        : "%u backups completed for %.*s",
             slot->suppressed + 1, (int)len, start);
}

static void notify_level(int required_level, const char* text) {
    if (!text) return;
    if (s_cfg && (!s_cfg->general.notifications ||
                  s_cfg->general.notification_level < required_level)) return;

    time_t now = time(NULL);
    pthread_mutex_lock(&s_notify_lock);
    notify_slot_t* slot = NULL;
    notify_slot_t* oldest = &s_notify_slots[0];
    for (size_t i = 0; i < sizeof(s_notify_slots) / sizeof(s_notify_slots[0]); i++) {
        if (strcmp(s_notify_slots[i].text, text) == 0) { slot = &s_notify_slots[i]; break; }
        if (s_notify_slots[i].last < oldest->last) oldest = &s_notify_slots[i];
    }
    if (!slot) {
        slot = oldest;
        snprintf(slot->text, sizeof(slot->text), "%s", text);
        slot->last = 0;
        slot->suppressed = 0;
    }
    if (slot->last && now - slot->last < 90) {
        slot->suppressed++;
        pthread_mutex_unlock(&s_notify_lock);
        return;
    }
    char shown[1024];
    coalesced_text(slot, text, shown, sizeof(shown));
    slot->last = now;
    slot->suppressed = 0;
    pthread_mutex_unlock(&s_notify_lock);
    send_toast(shown);
}

void log_notify_level(int required_level, const char* text) {
    if (text) log_info("%s", text);
    notify_level(required_level, text);
}

void log_notify_level_quiet(int required_level, const char* text) {
    notify_level(required_level, text);
}

void log_notify(const char* text) {
    log_notify_level(NOTIFY_IMPORTANT, text);
}
