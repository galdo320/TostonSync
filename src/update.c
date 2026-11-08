#include "update.h"
#include "lifecycle.h"
#include "log.h"
#include "sha256.h"
#include "version.h"
#include "at_io.h"
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <poll.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#ifndef UPDATE_DIRECTORY
#define UPDATE_DIRECTORY "/data/tostonsync"
#endif
#ifndef UPDATE_LAUNCHER
#define UPDATE_LAUNCHER "/system_ex/app/TOST10001/eboot.bin"
#endif
#ifndef UPDATE_TTL_SECONDS
#define UPDATE_TTL_SECONDS UPDATE_SESSION_SECONDS
#endif

static const char update_marker[] __attribute__((used)) =
    "TOSTONSYNC_UPDATE_V1|version=" TOSTONSYNC_VERSION "|build=" __DATE__ " " __TIME__ "|END";
static const char current_name[] = "tostonsync.elf";
static const char previous_name[] = "tostonsync.previous.elf";
static pthread_mutex_t update_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t update_condition = PTHREAD_COND_INITIALIZER;
static pthread_once_t boot_once = PTHREAD_ONCE_INIT;
static char boot_id[65], pending_hash[65];
static bool timer_started, blocked_unknown;
static _Thread_local bool update_quiet;

typedef struct {
    bool active, lease, allow_downgrade;
    int dir, fd;
    char owner[65], id[65], temp[96], hash[65];
    uint64_t size, offset;
    int64_t deadline, expires;
    struct stat temp_stat;
} update_session_t;
static update_session_t session = {.dir = -1, .fd = -1};
static bool restart_prepared, restart_armed, restart_consumed;
static update_file_info_t restart_expected;
static struct stat restart_stat;

static void update_trace(const char* phase, const char* event, long long rc, int error) {
    int saved_errno = errno;
    (void)log_durable("update: phase=%s event=%s rc=%lld errno=%d errno_valid=%d",
                      phase, event, rc, error, error > 0 ? 1 : 0);
    errno = saved_errno;
}

// Only this finish interval emits fine traces; other threads/getters stay quiet.
static _Thread_local bool update_window_active;
#define UPDATE_WINDOW_CALL(phase, expression, native_error) ({ \
    if (update_window_active) update_trace((phase), "begin", 0, -1); \
    __auto_type window_value = (expression); \
    int window_errno = errno; \
    if (update_window_active) update_trace((phase), "end", (long long)(intptr_t)window_value, \
        (native_error) && (intptr_t)window_value < 0 ? window_errno : -1); \
    errno = window_errno; \
    window_value; \
})
#define UPDATE_WINDOW_STAT(phase, expression, destination) ({ \
    toston_stat_guard_t window_stat = TOSTON_STAT_GUARD_INIT; \
    if (update_window_active) update_trace((phase), "begin", 0, -1); \
    int window_rc = (expression), window_errno = errno; \
    if (!toston_stat_guard_valid(&window_stat)) { \
        window_rc = -1; window_errno = EOVERFLOW; \
        update_trace((phase), "canary_failure", window_rc, window_errno); \
    } else if (window_rc == 0) *(destination) = window_stat.value; \
    if (update_window_active) update_trace((phase), "end", window_rc, window_rc ? window_errno : -1); \
    errno = window_errno; \
    window_rc; \
})

update_jobs_observation_t update_jobs_snapshot(update_jobs_snapshot_t* out) {
    if (!out) return UPDATE_JOBS_UNKNOWN;
    int saved_errno = errno;
    memset(out, 0, sizeof(*out));
    out->uncertain = true;
    int locked = pthread_mutex_trylock(&update_lock);
    if (locked) {
        errno = saved_errno;
        return locked == EBUSY ? UPDATE_JOBS_BUSY : UPDATE_JOBS_UNKNOWN;
    }
    out->current_present = session.active || session.id[0];
    out->receiving = session.active;
    out->uncertain = blocked_unknown ||
        strnlen(session.id, sizeof(session.id)) == sizeof(session.id) ||
        (session.active &&
        (!session.id[0] || !session.size || session.offset > session.size));
    out->pending_observed = !blocked_unknown && pending_hash[0];
    memcpy(out->native_id, session.id, sizeof(out->native_id));
    out->native_id[sizeof(out->native_id) - 1] = 0;
    out->received = session.offset;
    out->expected = session.size;
    out->expires_unix = session.expires;
    if (pthread_mutex_unlock(&update_lock)) out->uncertain = true;
    errno = saved_errno;
    return out->uncertain ? UPDATE_JOBS_UNKNOWN : UPDATE_JOBS_OBSERVED;
}

static bool update_result(update_result_t* out, update_code_t code,
                          const char* error, const char* detail) {
    if (out) {
        memset(out, 0, sizeof(*out));
        out->code = code;
        snprintf(out->error, sizeof(out->error), "%s", error ? error : "");
        snprintf(out->detail, sizeof(out->detail), "%s", detail ? detail : "");
    }
    if (code != UPDATE_OK) log_warn("update: rejected reason=%s", error ? error : "unknown");
    return code == UPDATE_OK;
}

static int64_t update_monotonic(void) {
    struct timespec ts;
    return clock_gettime(CLOCK_MONOTONIC, &ts) == 0 ? (int64_t)ts.tv_sec : -1;
}

static bool update_hex(const char* value) {
    if (!value || strlen(value) != 64) return false;
    for (size_t i = 0; i < 64; i++)
        if (!((value[i] >= '0' && value[i] <= '9') || (value[i] >= 'a' && value[i] <= 'f'))) return false;
    return true;
}

static bool update_random(char out[65]) {
    unsigned char bytes[32];
    out[0] = 0;
#if defined(__PROSPERO__)
    extern int sceRandomGetRandomNumber(unsigned char* buf, size_t size);
    int native_rc = sceRandomGetRandomNumber(bytes, sizeof(bytes));
    if (native_rc != 0) {
        log_warn("update: entropy provider=sceRandomGetRandomNumber phase=generate rc=%d requested=32", native_rc);
        return false;
    }
#else
    size_t received = 0;
    unsigned attempts = 0;
    const char* phase = NULL;
    ssize_t rc = 0;
    int failure_errno = 0, close_rc = 0, close_errno = 0;
    errno = 0;
    int fd = open("/dev/urandom", O_RDONLY | O_NOFOLLOW);
    if (fd < 0) {
        phase = "open"; rc = fd; failure_errno = errno;
    } else {
        // shortcut: the call budget bounds interruptions, not a blocking native read.
        while (received < sizeof(bytes) && attempts < 64) {
            errno = 0;
            rc = read(fd, bytes + received, sizeof(bytes) - received);
            failure_errno = errno;
            attempts++;
            if (rc == -1 && failure_errno == EINTR) continue;
            if (rc < 0) { phase = "read"; break; }
            if (!rc) { phase = "eof"; break; }
            if ((size_t)rc > sizeof(bytes) - received) { phase = "invalid_count"; break; }
            received += (size_t)rc;
        }
        if (!phase && received != sizeof(bytes)) phase = "budget";
        errno = 0;
        close_rc = close(fd);
        close_errno = errno;
        if (close_rc != 0 && !phase) {
            phase = "close"; rc = close_rc; failure_errno = close_errno;
        }
    }
    if (phase) {
        log_warn("update: entropy phase=%s rc=%lld errno=%d received=%zu attempts=%u close_attempted=%s close_rc=%d close_errno=%d",
            phase, (long long)rc, failure_errno, received, attempts, fd >= 0 ? "true" : "false", close_rc, close_errno);
        return false;
    }
#endif
    for (size_t i = 0; i < sizeof(bytes); i++) snprintf(out + i * 2, 3, "%02x", bytes[i]);
    return true;
}

static void update_init_boot(void) {
    bool ready = update_random(boot_id);
    log_info("update: boot_identity state=%s", ready ? "ready" : "unavailable");
}
const char* update_boot_id(void) { pthread_once(&boot_once, update_init_boot); return boot_id; }

static bool update_same_file(const struct stat* a, const struct stat* b) {
    return a->st_dev == b->st_dev && a->st_ino == b->st_ino &&
        a->st_mode == b->st_mode && a->st_size == b->st_size &&
#ifdef __APPLE__
        a->st_mtimespec.tv_sec == b->st_mtimespec.tv_sec && a->st_mtimespec.tv_nsec == b->st_mtimespec.tv_nsec &&
        a->st_ctimespec.tv_sec == b->st_ctimespec.tv_sec && a->st_ctimespec.tv_nsec == b->st_ctimespec.tv_nsec;
#else
        a->st_mtim.tv_sec == b->st_mtim.tv_sec && a->st_mtim.tv_nsec == b->st_mtim.tv_nsec &&
        a->st_ctim.tv_sec == b->st_ctim.tv_sec && a->st_ctim.tv_nsec == b->st_ctim.tv_nsec;
#endif
}

static const char* update_file_difference(const struct stat* a, const struct stat* b) {
    if (a->st_dev != b->st_dev) return "dev";
    if (a->st_ino != b->st_ino) return "ino";
    if (a->st_mode != b->st_mode) return "mode";
    if (a->st_size != b->st_size) return "size";
#ifdef __APPLE__
    if (a->st_mtimespec.tv_sec != b->st_mtimespec.tv_sec || a->st_mtimespec.tv_nsec != b->st_mtimespec.tv_nsec) return "mtime";
    if (a->st_ctimespec.tv_sec != b->st_ctimespec.tv_sec || a->st_ctimespec.tv_nsec != b->st_ctimespec.tv_nsec) return "ctime";
#else
    if (a->st_mtim.tv_sec != b->st_mtim.tv_sec || a->st_mtim.tv_nsec != b->st_mtim.tv_nsec) return "mtime";
    if (a->st_ctim.tv_sec != b->st_ctim.tv_sec || a->st_ctim.tv_nsec != b->st_ctim.tv_nsec) return "ctime";
#endif
    return "none";
}

// Walk every component: O_NOFOLLOW on the final filename alone is insufficient.
static int update_open_directory(void) {
    const char* name = UPDATE_DIRECTORY;
    if (!name || name[0] != '/' || UPDATE_WINDOW_CALL("window_directory_length", strlen(name), false) >= PATH_MAX) return -1;
    char path[PATH_MAX]; UPDATE_WINDOW_CALL("window_directory_path", snprintf(path, sizeof(path), "%s", name), false);
    int fd = UPDATE_WINDOW_CALL("window_directory_root", open("/", O_RDONLY | O_DIRECTORY | O_NOFOLLOW), true);
    if (fd < 0) return -1;
    char* cursor = path + 1;
    while (*cursor) {
        char* slash = UPDATE_WINDOW_CALL("window_directory_separator", strchr(cursor, '/'), false);
        if (slash) *slash = 0;
        if (!*cursor || !UPDATE_WINDOW_CALL("window_directory_dot", strcmp(cursor, "."), false) ||
            !UPDATE_WINDOW_CALL("window_directory_parent", strcmp(cursor, ".."), false)) {
            UPDATE_WINDOW_CALL("window_directory_invalid_close", close(fd), true); return -1;
        }
        int child = UPDATE_WINDOW_CALL("window_directory_openat", toston_openat(fd, cursor, O_RDONLY | O_DIRECTORY | O_NOFOLLOW, 0), true);
        int closed = UPDATE_WINDOW_CALL("window_directory_parent_close", close(fd), true); fd = child;
        if (fd < 0 || closed != 0) {
            if (fd >= 0) UPDATE_WINDOW_CALL("window_directory_error_close", close(fd), true);
            return -1;
        }
        if (!slash) break;
        cursor = slash + 1;
    }
    return fd;
}

static bool update_directory_current(int fd) {
    struct stat a, b;
    int now = UPDATE_WINDOW_CALL("window_directory_walk", update_open_directory(), false);
    bool ok = now >= 0 &&
        UPDATE_WINDOW_STAT("window_directory_held_stat", toston_fstat(fd, &window_stat.value), &a) == 0 &&
        UPDATE_WINDOW_STAT("window_directory_named_stat", toston_fstat(now, &window_stat.value), &b) == 0 &&
        a.st_dev == b.st_dev && a.st_ino == b.st_ino;
    if (now >= 0 && UPDATE_WINDOW_CALL("window_directory_close", close(now), true) != 0) ok = false;
    return ok;
}

static uint64_t update_le(const unsigned char* p, size_t n) {
    uint64_t value = 0;
    while (n) value = (value << 8) | p[--n];
    return value;
}

// Same ELF/segment contract as app/eboot.c:validate_elf, without changing the launcher.
static bool update_elf(const unsigned char* bytes, size_t size) {
    if (size < 64 || size > UPDATE_MAX_BYTES || memcmp(bytes, "\177ELF", 4) ||
        bytes[4] != 2 || bytes[5] != 1 || bytes[6] != 1 ||
        (update_le(bytes + 16, 2) != 2 && update_le(bytes + 16, 2) != 3) ||
        update_le(bytes + 18, 2) != 62 || update_le(bytes + 20, 4) != 1 ||
        update_le(bytes + 52, 2) != 64 || update_le(bytes + 54, 2) != 56) return false;
    uint64_t entry = update_le(bytes + 24, 8), offset = update_le(bytes + 32, 8), count = update_le(bytes + 56, 2);
    if (!entry || !count || count > 128 || offset < 64 || offset > size || count * 56 > size - offset) return false;
    bool executable = false;
    for (uint64_t i = 0; i < count; i++) {
        const unsigned char* p = bytes + offset + i * 56;
        uint64_t off = update_le(p + 8, 8), addr = update_le(p + 16, 8), file = update_le(p + 32, 8), mem = update_le(p + 40, 8);
        if (off > size || file > size - off) return false;
        if (update_le(p, 4) == 1) {
            if (file > mem || addr + mem < addr) return false;
            if ((update_le(p + 4, 4) & 1) && entry >= addr && entry - addr < mem) executable = true;
        }
    }
    return executable;
}

static bool update_version(const char* text, uint32_t value[3]) {
    if (!text || !*text || strlen(text) >= UPDATE_VERSION_MAX) return false;
    const char* p = text;
    for (size_t i = 0; i < 3; i++) {
        if (*p < '0' || *p > '9') return false;
        if (*p == '0' && p[1] >= '0' && p[1] <= '9') return false;
        uint64_t n = 0;
        while (*p >= '0' && *p <= '9') {
            n = n * 10 + (unsigned)(*p++ - '0');
            if (n > UINT32_MAX) return false;
        }
        value[i] = (uint32_t)n;
        if (i < 2) { if (*p++ != '.') return false; }
        else if (*p) return false;
    }
    return true;
}

static bool update_build(const char* text) {
    static const char months[] = "JanFebMarAprMayJunJulAugSepOctNovDec";
    if (strlen(text) != 20 || text[3] != ' ' || text[6] != ' ' || text[11] != ' ' ||
        text[14] != ':' || text[17] != ':') return false;
    bool month = false;
    for (size_t i = 0; i < 12; i++) if (!memcmp(text, months + i * 3, 3)) month = true;
    if (!month || !((text[4] >= '0' && text[4] <= '3') || text[4] == ' ')) return false;
    const unsigned positions[] = {5, 7, 8, 9, 10, 12, 13, 15, 16, 18, 19};
    for (size_t i = 0; i < sizeof(positions) / sizeof(*positions); i++)
        if (text[positions[i]] < '0' || text[positions[i]] > '9') return false;
    int day = (text[4] == ' ' ? 0 : text[4] - '0') * 10 + text[5] - '0';
    int year = (text[7] - '0') * 1000 + (text[8] - '0') * 100 + (text[9] - '0') * 10 + text[10] - '0';
    return day >= 1 && day <= 31 && year >= 1970 &&
        (text[12] - '0') * 10 + text[13] - '0' <= 23 &&
        (text[15] - '0') * 10 + text[16] - '0' <= 59 &&
        (text[18] - '0') * 10 + text[19] - '0' <= 59;
}

static bool update_parse_marker(const unsigned char* bytes, size_t size, update_file_info_t* info) {
    const char* prefix = update_marker;
    size_t start = 0, found = 0, length = sizeof("TOSTONSYNC_UPDATE_V1|version=") - 1;
    for (size_t i = 0; i + length <= size; i++)
        if (!memcmp(bytes + i, prefix, length)) { start = i + length; if (++found > 1) return false; }
    if (found != 1) return false;
    size_t v = 0, b = 0;
    while (start < size && bytes[start] != '|') {
        if ((bytes[start] < '0' || bytes[start] > '9') && bytes[start] != '.') return false;
        if (v + 1 >= sizeof(info->version)) return false;
        info->version[v++] = (char)bytes[start++];
    }
    info->version[v] = 0;
    uint32_t version[3];
    if (!update_version(info->version, version) || start + 7 > size || memcmp(bytes + start, "|build=", 7)) return false;
    start += 7;
    while (start < size && bytes[start] != '|') {
        if (bytes[start] < 32 || bytes[start] > 126 || b + 1 >= sizeof(info->build)) return false;
        info->build[b++] = (char)bytes[start++];
    }
    info->build[b] = 0;
    return b && update_build(info->build) && start + 4 <= size && !memcmp(bytes + start, "|END", 4) &&
        (start + 4 == size || bytes[start + 4] == 0);
}

static void update_hash_bytes(const unsigned char* bytes, size_t length, char out[65]) {
    unsigned char digest[32]; sha256_ctx_t hash;
    sha256_init(&hash); sha256_update(&hash, bytes, length); sha256_final(&hash, digest);
    for (size_t i = 0; i < sizeof(digest); i++) snprintf(out + i * 2, 3, "%02x", digest[i]);
}

typedef struct {
    const char* check;
    const char* field;
    long long rc;
    int error;
    bool pair_valid;
    struct stat expected, observed;
} update_read_diagnostic_t;

static bool update_read_fd_diagnostic(int fd, update_file_info_t* info, struct stat* observed,
                                      update_read_diagnostic_t* diagnostic) {
#define UPDATE_READ_FAILURE(name, result, error_value, difference) do { \
    if (diagnostic) { diagnostic->check = (name); diagnostic->rc = (result); \
        diagnostic->error = (error_value); diagnostic->field = (difference); \
        update_trace((name), "first_failure", diagnostic->rc, diagnostic->error); } \
} while (0)
    if (diagnostic) *diagnostic = (update_read_diagnostic_t){.check="none", .field="none", .rc=0, .error=-1};
    struct stat before, after;
    if (diagnostic) errno = 0;
    int stat_rc = toston_fstat(fd, &before);
    if (stat_rc != 0) { UPDATE_READ_FAILURE("fstat", stat_rc, errno, "none"); return false; }
    if (!S_ISREG(before.st_mode)) { UPDATE_READ_FAILURE("type", 0, -1, "none"); return false; }
    if (before.st_size < 0 || (uint64_t)before.st_size > UPDATE_MAX_BYTES) {
        UPDATE_READ_FAILURE("size", 0, -1, "none"); return false;
    }
    if (diagnostic) errno = 0;
    off_t seek_rc = lseek(fd, 0, SEEK_SET);
    if (seek_rc != 0) { UPDATE_READ_FAILURE("lseek", seek_rc, seek_rc < 0 ? errno : -1, "none"); return false; }
    size_t size = (size_t)before.st_size;
    if (diagnostic) errno = 0;
    unsigned char* bytes = malloc(size ? size : 1);
    if (!bytes) { UPDATE_READ_FAILURE("memory", 0, errno, "none"); return false; }
    size_t used = 0;
    while (used < size) {
        if (diagnostic) errno = 0;
        ssize_t n = read(fd, bytes + used, size - used);
        if (n <= 0) {
            UPDATE_READ_FAILURE(n < 0 ? "read" : "short_read", n, n < 0 ? errno : -1, "none");
            free(bytes); return false;
        }
        used += (size_t)n;
    }
    unsigned char extra;
    if (diagnostic) errno = 0;
    ssize_t extra_rc = read(fd, &extra, 1);
    bool stable = extra_rc == 0;
    if (!stable) UPDATE_READ_FAILURE(extra_rc < 0 ? "extra_read" : "extra_byte", extra_rc, extra_rc < 0 ? errno : -1, "none");
    if (stable) {
        if (diagnostic) errno = 0;
        stat_rc = toston_fstat(fd, &after);
        stable = stat_rc == 0;
        if (!stable) UPDATE_READ_FAILURE("final_fstat", stat_rc, errno, "none");
        else {
            stable = update_same_file(&before, &after);
            if (!stable) {
                if (diagnostic) {
                    diagnostic->expected = before; diagnostic->observed = after;
                    diagnostic->pair_valid = true;
                }
                UPDATE_READ_FAILURE("final_metadata", 0, -1, update_file_difference(&before, &after));
            }
        }
    }
    if (stable) {
        info->bytes = size; info->mtime_unix = before.st_mtime;
        update_hash_bytes(bytes, size, info->sha256);
        info->valid = update_elf(bytes, size) && update_parse_marker(bytes, size, info);
        if (!info->valid) { info->version[0] = 0; info->build[0] = 0; }
        if (observed) *observed = after;
    }
    free(bytes); return stable;
#undef UPDATE_READ_FAILURE
}

static bool update_read_fd(int fd, update_file_info_t* info, struct stat* observed) {
    return update_read_fd_diagnostic(fd, info, observed, NULL);
}

static bool update_inspect_at_diagnostic(int dir, const char* name, update_file_info_t* info,
                                         struct stat* observed, bool diagnostic) {
#define UPDATE_INSPECT_FAILURE(phase, result, error) do { \
    if (diagnostic) update_trace((phase), "first_failure", (result), (error)); \
} while (0)
    memset(info, 0, sizeof(*info)); snprintf(info->state, sizeof(info->state), "unreadable");
    struct stat before, opened, after;
    if (diagnostic) errno = 0;
    int rc = toston_fstatat(dir, name, &before, AT_SYMLINK_NOFOLLOW);
    if (rc != 0) {
        if (errno == ENOENT) { snprintf(info->state, sizeof(info->state), "missing"); return true; }
        UPDATE_INSPECT_FAILURE("inspect_named", rc, errno); return false;
    }
    if (!S_ISREG(before.st_mode)) { UPDATE_INSPECT_FAILURE("inspect_type", 0, -1); return false; }
    if (diagnostic) errno = 0;
    int fd = toston_openat(dir, name, O_RDONLY | O_NOFOLLOW | O_NONBLOCK, 0);
    if (fd < 0) { UPDATE_INSPECT_FAILURE("inspect_open", fd, errno); return false; }
    if (diagnostic) errno = 0;
    rc = toston_fstat(fd, &opened);
    bool ok = rc == 0;
    if (!ok) UPDATE_INSPECT_FAILURE("inspect_fd", rc, errno);
    if (ok) {
        ok = update_same_file(&before, &opened);
        if (!ok) UPDATE_INSPECT_FAILURE("inspect_identity", 0, -1);
    }
    if (ok) {
        update_read_diagnostic_t read_error;
        ok = diagnostic ? update_read_fd_diagnostic(fd, info, &after, &read_error) : update_read_fd(fd, info, &after);
    }
    if (ok) {
        ok = update_same_file(&before, &after);
        if (!ok) UPDATE_INSPECT_FAILURE("inspect_read_identity", 0, -1);
    }
    if (ok) {
        if (diagnostic) errno = 0;
        rc = toston_fstatat(dir, name, &opened, AT_SYMLINK_NOFOLLOW);
        ok = rc == 0;
        if (!ok) UPDATE_INSPECT_FAILURE("inspect_final_named", rc, errno);
    }
    if (ok) {
        ok = update_same_file(&after, &opened);
        if (!ok) UPDATE_INSPECT_FAILURE("inspect_final_identity", 0, -1);
    }
    if (diagnostic) errno = 0;
    rc = close(fd);
    if (rc != 0) {
        if (ok) UPDATE_INSPECT_FAILURE("inspect_close", rc, errno);
        ok = false;
    }
    if (ok) { snprintf(info->state, sizeof(info->state), "present"); if (observed) *observed = opened; }
    else { memset(info, 0, sizeof(*info)); snprintf(info->state, sizeof(info->state), "unreadable"); }
    return ok;
#undef UPDATE_INSPECT_FAILURE
}

static bool update_inspect_at(int dir, const char* name, update_file_info_t* info, struct stat* observed) {
    return update_inspect_at_diagnostic(dir, name, info, observed, false);
}

bool update_inspect_bytes(const void* bytes, size_t size, update_file_info_t* out) {
    if (!out) return false;
    memset(out, 0, sizeof(*out));
    if (!bytes || size < 64 || size > UPDATE_MAX_BYTES) return false;
    out->bytes = size;
    update_hash_bytes(bytes, size, out->sha256);
    out->valid = update_elf(bytes, size) && update_parse_marker(bytes, size, out);
    snprintf(out->state, sizeof(out->state), "%s", out->valid ? "present" : "unreadable");
    return out->valid;
}

bool update_get_status(update_status_t* out) {
    if (!out) return false;
    memset(out, 0, sizeof(*out));
    snprintf(out->running_version, sizeof(out->running_version), "%s", TOSTONSYNC_VERSION);
    snprintf(out->running_build, sizeof(out->running_build), "%s", TOSTONSYNC_BUILD);
    snprintf(out->boot_id, sizeof(out->boot_id), "%s", update_boot_id());
    pthread_mutex_lock(&update_lock);
    int dir = update_open_directory();
    if (dir < 0) {
        snprintf(out->saved.state, sizeof(out->saved.state), "unreadable");
        snprintf(out->previous.state, sizeof(out->previous.state), "unreadable");
    } else {
        (void)update_inspect_at(dir, current_name, &out->saved, NULL);
        (void)update_inspect_at(dir, previous_name, &out->previous, NULL);
        bool stable = update_directory_current(dir);
        if (close(dir) != 0) stable = false;
        if (!stable) {
            memset(&out->saved, 0, sizeof(out->saved)); memset(&out->previous, 0, sizeof(out->previous));
            snprintf(out->saved.state, sizeof(out->saved.state), "unreadable");
            snprintf(out->previous.state, sizeof(out->previous.state), "unreadable");
        }
    }
    out->receiving = session.active;
    out->publication_unknown = blocked_unknown;
    out->pending_saved = !blocked_unknown && pending_hash[0] && out->saved.valid && !strcmp(pending_hash, out->saved.sha256);
    pthread_mutex_unlock(&update_lock);
    struct stat launcher;
    snprintf(out->launcher, sizeof(out->launcher), "%s",
        lstat(UPDATE_LAUNCHER, &launcher) == 0 ? (S_ISREG(launcher.st_mode) ? "present" : "unknown") :
        (errno == ENOENT ? "missing" : "unknown"));
    return out->boot_id[0] != 0;
}

// Presentation reads return their first failure; cleanup cannot overwrite it.
static void update_observe_failure(update_observation_diagnostic_t* diagnostic,
                                   const char* phase, int64_t rc, int error) {
    if (diagnostic->failed) return;
    diagnostic->failed = true; diagnostic->phase = phase; diagnostic->rc = rc;
    diagnostic->errno_valid = rc < 0 && error > 0;
    diagnostic->error = diagnostic->errno_valid ? error : 0;
}

static bool update_observe_stat(update_observation_diagnostic_t* diagnostic,
                                const char* phase, int fd, const char* name,
                                struct stat* out) {
    toston_stat_guard_t guard = TOSTON_STAT_GUARD_INIT;
    errno = 0;
    int rc = name ? toston_fstatat(fd, name, &guard.value, AT_SYMLINK_NOFOLLOW) :
        toston_fstat(fd, &guard.value);
    int error = errno;
    bool intact = toston_stat_guard_valid(&guard);
    if (!diagnostic->failed) diagnostic->canary = intact ? "intact" : "altered";
    if (rc != 0) update_observe_failure(diagnostic, phase, rc, error);
    if (!intact) update_observe_failure(diagnostic, phase, 0, 0);
    if (rc != 0 || !intact) return false;
    *out = guard.value;
    return true;
}

static bool update_observe_identity(update_observation_diagnostic_t* diagnostic,
                                    const char* phase, const struct stat* before,
                                    const struct stat* after, bool directory) {
    bool same = directory ? before->st_dev == after->st_dev && before->st_ino == after->st_ino :
        update_same_file(before, after);
    if (!diagnostic->failed) {
        diagnostic->identity = same ? "match" : "mismatch";
        diagnostic->field = same ? NULL : directory ? (before->st_dev != after->st_dev ? "dev" : "ino") :
            update_file_difference(before, after);
    }
    if (!same) update_observe_failure(diagnostic, phase, 0, 0);
    return same;
}

static bool update_observe_close(int fd, update_observation_diagnostic_t* diagnostic,
                                 const char* phase) {
    errno = 0;
    int rc = close(fd), error = errno;
    if (rc != 0) update_observe_failure(diagnostic, phase, rc, error);
    return rc == 0;
}

// Keep the action engine's reader and trace policy unchanged.
static bool update_observe_read_fd(int fd, update_file_info_t* info, struct stat* observed,
                                   update_observation_diagnostic_t* diagnostic) {
    struct stat before, after;
    if (!update_observe_stat(diagnostic, "read_stat", fd, NULL, &before)) return false;
    if (!S_ISREG(before.st_mode)) {
        update_observe_failure(diagnostic, "read_type", 0, 0); return false;
    }
    if (before.st_size < 0 || (uint64_t)before.st_size > UPDATE_MAX_BYTES) {
        update_observe_failure(diagnostic, "size", 0, 0); return false;
    }
    errno = 0;
    off_t offset = lseek(fd, 0, SEEK_SET);
    if (offset != 0) {
        update_observe_failure(diagnostic, "seek", offset, offset < 0 ? errno : 0); return false;
    }
    size_t size = (size_t)before.st_size, used = 0;
    unsigned char* bytes = malloc(size ? size : 1);
    if (!bytes) { update_observe_failure(diagnostic, "memory", 0, 0); return false; }
    bool ok = true;
    while (used < size) {
        errno = 0;
        ssize_t count = read(fd, bytes + used, size - used);
        if (count <= 0 || (size_t)count > size - used) {
            update_observe_failure(diagnostic, count < 0 ? "read" : "read_count", count, count < 0 ? errno : 0);
            ok = false; break;
        }
        used += (size_t)count;
    }
    if (ok) {
        unsigned char extra;
        errno = 0;
        ssize_t count = read(fd, &extra, 1);
        if (count != 0) {
            update_observe_failure(diagnostic, "extra_read", count, count < 0 ? errno : 0); ok = false;
        }
    }
    if (ok) ok = update_observe_stat(diagnostic, "final_read_stat", fd, NULL, &after);
    if (ok) ok = update_observe_identity(diagnostic, "read_identity", &before, &after, false);
    if (ok) {
        info->bytes = size; info->mtime_unix = before.st_mtime;
        update_hash_bytes(bytes, size, info->sha256);
        info->valid = update_elf(bytes, size) && update_parse_marker(bytes, size, info);
        if (!info->valid) {
            info->version[0] = 0; info->build[0] = 0;
            update_observe_failure(diagnostic, "content", 0, 0);
        }
        *observed = after;
    }
    free(bytes);
    return ok;
}

static void update_observe_file(int dir, const char* name, update_file_info_t* info,
                                update_observation_diagnostic_t* diagnostic) {
    memset(info, 0, sizeof(*info)); snprintf(info->state, sizeof(info->state), "unreadable");
    struct stat named, opened, read_stat, final;
    if (!update_observe_stat(diagnostic, "named_stat", dir, name, &named)) {
        if (diagnostic->errno_valid && diagnostic->error == ENOENT && strcmp(diagnostic->canary, "altered"))
            snprintf(info->state, sizeof(info->state), "missing");
        return;
    }
    if (!S_ISREG(named.st_mode)) { update_observe_failure(diagnostic, "type", 0, 0); return; }
    errno = 0;
    int fd = toston_openat(dir, name, O_RDONLY | O_NOFOLLOW | O_NONBLOCK, 0);
    if (fd < 0) { update_observe_failure(diagnostic, "open", fd, errno); return; }
    bool ok = update_observe_stat(diagnostic, "opened_stat", fd, NULL, &opened);
    if (ok) ok = update_observe_identity(diagnostic, "opened_identity", &named, &opened, false);
    if (ok) ok = update_observe_read_fd(fd, info, &read_stat, diagnostic);
    if (ok) ok = update_observe_identity(diagnostic, "named_read_identity", &named, &read_stat, false);
    if (ok) ok = update_observe_stat(diagnostic, "final_named_stat", dir, name, &final);
    if (ok) ok = update_observe_identity(diagnostic, "final_named_identity", &read_stat, &final, false);
    if (!update_observe_close(fd, diagnostic, "close")) ok = false;
    if (ok) {
        snprintf(info->state, sizeof(info->state), "present");
        if (!diagnostic->failed) diagnostic->phase = "complete";
    } else {
        memset(info, 0, sizeof(*info)); snprintf(info->state, sizeof(info->state), "unreadable");
    }
}

// Presentation reads must stay quiet even while a caller is tracing an update.
static int update_observe_open_directory(update_observation_diagnostic_t* diagnostic, bool reopen) {
    const char* name = UPDATE_DIRECTORY;
    if (!name || name[0] != '/' || strlen(name) >= PATH_MAX) {
        update_observe_failure(diagnostic, "directory_path", 0, 0); return -1;
    }
    char path[PATH_MAX]; snprintf(path, sizeof(path), "%s", name);
    errno = 0;
    int fd = open("/", O_RDONLY | O_DIRECTORY | O_NOFOLLOW);
    if (fd < 0) {
        update_observe_failure(diagnostic, reopen ? "reopen_root" : "open_root", fd, errno); return -1;
    }
    char* cursor = path + 1;
    while (*cursor) {
        char* slash = strchr(cursor, '/');
        if (slash) *slash = 0;
        if (!*cursor || !strcmp(cursor, ".") || !strcmp(cursor, "..")) {
            update_observe_failure(diagnostic, "directory_component", 0, 0);
            update_observe_close(fd, diagnostic, "component_cleanup"); return -1;
        }
        errno = 0;
        int child = toston_openat(fd, cursor, O_RDONLY | O_DIRECTORY | O_NOFOLLOW, 0);
        if (child < 0) update_observe_failure(diagnostic, reopen ? "reopen_component" : "open_component", child, errno);
        bool closed = update_observe_close(fd, diagnostic, reopen ? "reopen_parent_close" : "parent_close");
        fd = child;
        if (fd < 0 || !closed) {
            if (fd >= 0) update_observe_close(fd, diagnostic, "child_cleanup");
            return -1;
        }
        if (!slash) break;
        cursor = slash + 1;
    }
    return fd;
}

bool update_observe_status(update_status_t* out) {
    if (!out) return false;
    int saved_errno = errno;
    memset(out, 0, sizeof(*out));
    update_observation_diagnostic_t initial = {.phase="not_checked", .canary="not_checked", .identity="not_checked"};
    out->diagnostics.directory = out->diagnostics.saved = out->diagnostics.previous = initial;
    update_observation_diagnostic_t* directory = &out->diagnostics.directory;
    snprintf(out->running_version, sizeof(out->running_version), "%s", TOSTONSYNC_VERSION);
    snprintf(out->running_build, sizeof(out->running_build), "%s", TOSTONSYNC_BUILD);
    // HTTP startup initializes this immutable identity before creating workers.
    snprintf(out->boot_id, sizeof(out->boot_id), "%s", boot_id);
    snprintf(out->saved.state, sizeof(out->saved.state), "%s", "unknown");
    snprintf(out->previous.state, sizeof(out->previous.state), "%s", "unknown");
    snprintf(out->launcher, sizeof(out->launcher), "%s", "unknown");
    if (!out->boot_id[0]) {
        update_observe_failure(directory, "boot", 0, 0); errno = saved_errno; return false;
    }
    int locked = pthread_mutex_trylock(&update_lock);
    if (locked == 0) {
        int dir = update_observe_open_directory(directory, false);
        bool stable = false;
        if (dir >= 0) {
            update_observe_file(dir, current_name, &out->saved, &out->diagnostics.saved);
            update_observe_file(dir, previous_name, &out->previous, &out->diagnostics.previous);
            int now = update_observe_open_directory(directory, true);
            struct stat held, named;
            stable = now >= 0 && update_observe_stat(directory, "held_stat", dir, NULL, &held) &&
                update_observe_stat(directory, "reopened_stat", now, NULL, &named) &&
                update_observe_identity(directory, "directory_identity", &held, &named, true);
            if (now >= 0 && !update_observe_close(now, directory, "reopened_close")) stable = false;
            if (!update_observe_close(dir, directory, "directory_close")) stable = false;
        }
        if (!stable) {
            memset(&out->saved, 0, sizeof(out->saved)); memset(&out->previous, 0, sizeof(out->previous));
            snprintf(out->saved.state, sizeof(out->saved.state), "unreadable");
            snprintf(out->previous.state, sizeof(out->previous.state), "unreadable");
        } else directory->phase = "complete";
        int unlocked = pthread_mutex_unlock(&update_lock);
        if (unlocked) update_observe_failure(directory, "unlock", unlocked, 0);
    } else update_observe_failure(directory, "lock", locked, 0);
    struct stat launcher;
    snprintf(out->launcher, sizeof(out->launcher), "%s",
        lstat(UPDATE_LAUNCHER, &launcher) == 0 ? (S_ISREG(launcher.st_mode) ? "present" : "unknown") :
        (errno == ENOENT ? "missing" : "unknown"));
    errno = saved_errno;
    return true;
}

static void update_unlink_owned(int dir, const char* name, const struct stat* own) {
    struct stat now;
    if (name[0] && toston_fstatat(dir, name, &now, AT_SYMLINK_NOFOLLOW) == 0 &&
        S_ISREG(now.st_mode) && now.st_dev == own->st_dev && now.st_ino == own->st_ino)
        (void)unlinkat(dir, name, 0);
}

static void update_end(bool preserve) {
    if (session.fd >= 0) close(session.fd);
    if (!preserve && session.dir >= 0) update_unlink_owned(session.dir, session.temp, &session.temp_stat);
    if (session.dir >= 0) close(session.dir);
    if (session.lease) lifecycle_activity_end();
    memset(&session, 0, sizeof(session)); session.dir = session.fd = -1;
}

bool update_abort(const char* owner, const char* id) {
    pthread_mutex_lock(&update_lock);
    bool own = owner && id && session.active && !strcmp(owner, session.owner) && !strcmp(id, session.id);
    if (own) update_end(false);
    pthread_mutex_unlock(&update_lock);
    return own;
}

static void* update_expiration(void* unused) {
    (void)unused;
    pthread_mutex_lock(&update_lock);
    for (;;) {
        while (!session.active) pthread_cond_wait(&update_condition, &update_lock);
        int64_t now = update_monotonic();
        if (now < 0 || now >= session.deadline) {
            log_warn("update: rejected reason=update_expired"); update_end(false); continue;
        }
        pthread_mutex_unlock(&update_lock);
        struct timespec pause = {1, 0}; (void)nanosleep(&pause, NULL);
        pthread_mutex_lock(&update_lock);
    }
    return NULL;
}

static bool update_timer(void) {
    if (timer_started) return true;
    pthread_attr_t attr;
    if (pthread_attr_init(&attr) != 0) return false;
    bool ok = pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED) == 0;
    pthread_t thread;
    if (ok) ok = pthread_create(&thread, &attr, update_expiration, NULL) == 0;
    pthread_attr_destroy(&attr);
    timer_started = ok; return ok;
}

static bool update_filename(const char* name) {
    if (!name) return false;
    size_t n = strlen(name);
    if (n < 5 || n >= UPDATE_NAME_MAX || strcasecmp(name + n - 4, ".elf")) return false;
    for (size_t i = 0; i < n; i++)
        if ((unsigned char)name[i] < 32 || (unsigned char)name[i] == 127 || name[i] == '/' || name[i] == '\\') return false;
    return true;
}

static void update_session_result(update_result_t* out) {
    update_result(out, UPDATE_OK, "", "");
    if (!out) return;
    snprintf(out->session_id, sizeof(out->session_id), "%s", session.id);
    out->next_offset = session.offset; out->bytes = session.size; out->expires_unix = session.expires;
}

bool update_start(const char* owner, const char* name, uint64_t size,
                  const char* sha256, bool confirm, bool allow_downgrade, update_result_t* out) {
    if (!confirm || !update_hex(owner) || !update_filename(name) || size < 64 || size > UPDATE_MAX_BYTES || !update_hex(sha256))
        return update_result(out, UPDATE_INVALID, "update_invalid_request", "Expected confirmed ELF, exact size and SHA-256.");
    pthread_mutex_lock(&update_lock);
    if (blocked_unknown || session.active) {
        pthread_mutex_unlock(&update_lock);
        return update_result(out, blocked_unknown ? UPDATE_UNKNOWN : UPDATE_BUSY,
            blocked_unknown ? "update_publication_unknown" : "update_busy", "No new upload was started.");
    }
    int64_t now = update_monotonic();
    char id[65];
    if (now < 0 || !update_boot_id()[0] || !update_random(id) || !update_timer() || !lifecycle_activity_begin()) {
        pthread_mutex_unlock(&update_lock);
        return update_result(out, UPDATE_BUSY, "update_admission_failed", "Update admission could not be confirmed.");
    }
    session.lease = true; session.dir = update_open_directory();
    if (session.dir < 0) goto failed;
    snprintf(session.temp, sizeof(session.temp), ".update-%s.tmp", id);
    session.fd = toston_openat(session.dir, session.temp, O_RDWR | O_CREAT | O_EXCL | O_NOFOLLOW, 0600);
    if (session.fd < 0 || toston_fstat(session.fd, &session.temp_stat) != 0 || !S_ISREG(session.temp_stat.st_mode)) goto failed;
    snprintf(session.id, sizeof(session.id), "%s", id); snprintf(session.owner, sizeof(session.owner), "%s", owner);
    snprintf(session.hash, sizeof(session.hash), "%s", sha256);
    session.size = size; session.deadline = now + UPDATE_TTL_SECONDS;
    session.expires = (int64_t)time(NULL) + UPDATE_TTL_SECONDS;
    session.allow_downgrade = allow_downgrade; session.active = true;
    update_session_result(out); pthread_cond_signal(&update_condition);
    pthread_mutex_unlock(&update_lock);
    log_info("update: received bytes=%llu", (unsigned long long)size);
    return true;
failed:
    update_end(false); pthread_mutex_unlock(&update_lock);
    return update_result(out, UPDATE_IO_ERROR, "update_stage_failed", "Could not create an exclusive update file.");
}

static bool update_admit(const char* owner, const char* id, bool confirm, update_result_t* out) {
    if (!confirm || !update_hex(owner) || !update_hex(id))
        return update_result(out, UPDATE_INVALID, "update_invalid_request", "Explicit confirmation and session identity are required.");
    if (!session.active || strcmp(session.id, id) || strcmp(session.owner, owner))
        return update_result(out, UPDATE_NOT_FOUND, "update_session_unavailable", "Upload session is absent, expired or belongs to another access context.");
    int64_t now = update_monotonic();
    if (now < 0 || now >= session.deadline) {
        update_end(false);
        return update_result(out, UPDATE_NOT_FOUND, "update_expired", "Upload expired; no retry was sent.");
    }
    return true;
}

static bool update_temp_current(void) {
    struct stat named, fd;
    return UPDATE_WINDOW_CALL("window_directory_current", update_directory_current(session.dir), false) &&
        UPDATE_WINDOW_STAT("window_staging_fd", toston_fstat(session.fd, &window_stat.value), &fd) == 0 &&
        UPDATE_WINDOW_STAT("window_staging_named", toston_fstatat(session.dir, session.temp, &window_stat.value, AT_SYMLINK_NOFOLLOW), &named) == 0 &&
        S_ISREG(named.st_mode) && named.st_nlink == 1 && UPDATE_WINDOW_CALL("window_staging_identity", update_same_file(&fd, &named), false) &&
        fd.st_dev == session.temp_stat.st_dev && fd.st_ino == session.temp_stat.st_ino &&
        fd.st_size == (off_t)session.offset;
}

static bool update_temp_verified(const struct stat* verified) {
    struct stat now;
    return UPDATE_WINDOW_CALL("window_temp_current", update_temp_current(), false) &&
        UPDATE_WINDOW_STAT("window_verified_fd", toston_fstat(session.fd, &window_stat.value), &now) == 0 &&
        UPDATE_WINDOW_CALL("window_verified_identity", update_same_file(verified, &now), false);
}

bool update_chunk(const char* owner, const char* id, uint64_t offset,
                  const void* bytes, size_t length, bool confirm, update_result_t* out) {
    pthread_mutex_lock(&update_lock);
    if (!update_admit(owner, id, confirm, out)) { pthread_mutex_unlock(&update_lock); return false; }
    uint64_t remaining = session.size - session.offset;
    size_t expected = remaining > UPDATE_CHUNK_BYTES ? UPDATE_CHUNK_BYTES : (size_t)remaining;
    bool final = remaining <= UPDATE_CHUNK_BYTES;
    if (final) update_trace("chunk_final", "begin", 0, -1);
    if (!bytes || !length || offset != session.offset || length != expected || !update_temp_current()) {
        update_trace("chunk_check", "first_failure", 0, -1);
        if (final) update_trace("chunk_final", "end", -1, -1);
        update_end(false); pthread_mutex_unlock(&update_lock);
        return update_result(out, UPDATE_CONFLICT, "update_chunk_mismatch", "Unexpected offset, size or replaced staging file; upload stopped.");
    }
    size_t used = 0;
    while (used < length) {
        ssize_t n = write(session.fd, (const unsigned char*)bytes + used, length - used);
        if (n <= 0) { update_trace("chunk_write", "first_failure", n, n < 0 ? errno : -1); break; }
        used += (size_t)n;
    }
    if (final) update_trace("chunk_final", "end", used == length ? 0 : -1, -1);
    if (used != length) {
        update_end(false); pthread_mutex_unlock(&update_lock);
        return update_result(out, UPDATE_IO_ERROR, "update_write_failed", "Update write failed; current executable was not replaced.");
    }
    session.offset += length;
    update_session_result(out); pthread_mutex_unlock(&update_lock); return true;
}

static bool update_path_same(int dir, const char* name, bool existed, const struct stat* before) {
    struct stat after;
    if (UPDATE_WINDOW_STAT("window_path_named", toston_fstatat(dir, name, &window_stat.value, AT_SYMLINK_NOFOLLOW), &after) != 0)
        return !existed && errno == ENOENT;
    return existed && UPDATE_WINDOW_CALL("window_path_identity", update_same_file(before, &after), false);
}

typedef struct {
    bool valid;
    struct stat expected, observed, source_again, path_again;
    int source_rc, source_errno, path_rc, path_errno;
} update_identity_diagnostic_t;

static void update_identity_observe(update_identity_diagnostic_t* diagnostic, int source, int dir,
                                    const struct stat* expected, const struct stat* observed) {
    if (diagnostic->valid) return;
    int saved_errno = errno;
    *diagnostic = (update_identity_diagnostic_t){.valid=true, .expected=*expected, .observed=*observed};
    update_trace("identity_observe", "begin", 0, -1);
    errno = 0;
    diagnostic->source_rc = toston_fstat(source, &diagnostic->source_again);
    diagnostic->source_errno = diagnostic->source_rc == 0 ? -1 : errno;
    errno = 0;
    diagnostic->path_rc = toston_fstatat(dir, current_name, &diagnostic->path_again, AT_SYMLINK_NOFOLLOW);
    diagnostic->path_errno = diagnostic->path_rc == 0 ? -1 : errno;
    update_trace("identity_observe", "end", diagnostic->source_rc || diagnostic->path_rc ? -1 : 0,
                 diagnostic->source_rc ? diagnostic->source_errno : diagnostic->path_errno);
    errno = saved_errno;
}

static void update_identity_log(const char* stage, const char* view, const struct stat* observed,
                                int rc, int error) {
    bool valid = rc == 0;
    long long mtime_sec=0, mtime_nsec=0, ctime_sec=0, ctime_nsec=0;
    if (valid) {
#ifdef __APPLE__
        mtime_sec = (long long)observed->st_mtimespec.tv_sec; mtime_nsec = (long long)observed->st_mtimespec.tv_nsec;
        ctime_sec = (long long)observed->st_ctimespec.tv_sec; ctime_nsec = (long long)observed->st_ctimespec.tv_nsec;
#else
        mtime_sec = (long long)observed->st_mtim.tv_sec; mtime_nsec = (long long)observed->st_mtim.tv_nsec;
        ctime_sec = (long long)observed->st_ctim.tv_sec; ctime_nsec = (long long)observed->st_ctim.tv_nsec;
#endif
    }
    log_warn("update: previous_identity stage=%s view=%s valid=%d rc=%d errno=%d errno_valid=%d dev=%llu ino=%llu mode=%llu size=%lld mtime_sec=%lld mtime_nsec=%lld ctime_sec=%lld ctime_nsec=%lld",
             stage, view, valid ? 1 : 0, rc, error, rc != 0 && error > 0 ? 1 : 0,
             valid ? (unsigned long long)observed->st_dev : 0, valid ? (unsigned long long)observed->st_ino : 0,
             valid ? (unsigned long long)observed->st_mode : 0, valid ? (long long)observed->st_size : 0,
             mtime_sec, mtime_nsec, ctime_sec, ctime_nsec);
}

static bool update_copy_previous(int dir, const char* name, const struct stat* before,
                                 const char* expected_hash, struct stat* copied) {
    update_trace("previous", "begin", 0, -1);
    const struct stat reference = *before;
    unsigned long long observed_dev = 0, observed_ino = 0;
    bool observed_valid = false;
    update_identity_diagnostic_t identity = {0};
    const char* failure = NULL;
    const char* failure_check = "none";
    const char* failure_field = "none";
    long long failure_rc = 0;
    int failure_errno = -1;
#define UPDATE_COPY_FAILURE(stage, result, error) do { \
    if (!failure) { failure = (stage); failure_rc = (result); failure_errno = (error); \
        update_trace(failure, "first_failure", failure_rc, failure_errno); } \
} while (0)
    errno = 0;
    int source = toston_openat(dir, current_name, O_RDONLY | O_NOFOLLOW | O_NONBLOCK, 0);
    if (source < 0) UPDATE_COPY_FAILURE("open_source", source, errno);
    errno = 0;
    int target = toston_openat(dir, name, O_RDWR | O_CREAT | O_EXCL | O_NOFOLLOW, 0600);
    if (target < 0) UPDATE_COPY_FAILURE("open_target", target, errno);
    struct stat opened;
    bool own = false;
    if (target >= 0) {
        errno = 0;
        int rc = toston_fstat(target, copied);
        own = rc == 0;
        if (!own) UPDATE_COPY_FAILURE("stat_target", rc, errno);
    }
    bool reference_unchanged = update_same_file(&reference, before);
    bool ok = source >= 0 && own;
    if (ok) {
        errno = 0;
        int rc = toston_fstat(source, &opened);
        ok = rc == 0;
        if (!ok) UPDATE_COPY_FAILURE("stat_source", rc, errno);
        else {
            observed_dev = (unsigned long long)opened.st_dev;
            observed_ino = (unsigned long long)opened.st_ino;
            observed_valid = true;
            ok = update_same_file(before, &opened);
            if (!ok) {
                UPDATE_COPY_FAILURE("source_identity", 0, -1);
                failure_check = "same_file";
                failure_field = update_file_difference(before, &opened);
                update_identity_observe(&identity, source, dir, before, &opened);
            }
        }
    }
    unsigned char buf[32768]; uint64_t count = 0;
    while (ok && count < (uint64_t)before->st_size) {
        size_t need = (uint64_t)before->st_size - count > sizeof(buf) ? sizeof(buf) : (size_t)((uint64_t)before->st_size - count);
        errno = 0;
        ssize_t n = read(source, buf, need);
        if (n <= 0) {
            UPDATE_COPY_FAILURE("read_source", n, n < 0 ? errno : -1);
            ok = false; break;
        }
        size_t used = 0;
        while (used < (size_t)n) {
            errno = 0;
            ssize_t written = write(target, buf + used, (size_t)n - used);
            if (written <= 0) {
                UPDATE_COPY_FAILURE("write_target", written, written < 0 ? errno : -1);
                ok = false; break;
            }
            used += (size_t)written;
        }
        count += (uint64_t)n;
    }
    update_file_info_t info = {0}; struct stat after;
    if (ok) {
        errno = 0;
        int rc = toston_fstat(source, &after);
        ok = rc == 0;
        if (!ok) UPDATE_COPY_FAILURE("restat_source", rc, errno);
        else {
            ok = update_same_file(before, &after);
            if (!ok) {
                UPDATE_COPY_FAILURE("source_stable", 0, -1);
                failure_check = "same_file";
                failure_field = update_file_difference(before, &after);
                update_identity_observe(&identity, source, dir, before, &after);
            }
        }
    }
    if (ok) {
        errno = 0;
        int rc = fsync(target);
        ok = rc == 0;
        if (!ok) UPDATE_COPY_FAILURE("sync_target", rc, errno);
    }
    if (ok) {
        update_read_diagnostic_t diagnostic;
        ok = update_read_fd_diagnostic(target, &info, copied, &diagnostic);
        if (!ok) {
            UPDATE_COPY_FAILURE("verify_target", diagnostic.rc, diagnostic.error);
            failure_check = diagnostic.check;
            failure_field = diagnostic.field;
            if (diagnostic.pair_valid)
                update_identity_observe(&identity, source, dir, &diagnostic.expected, &diagnostic.observed);
        }
    }
    if (ok) {
        int rc = strcmp(info.sha256, expected_hash);
        ok = rc == 0;
        if (!ok) UPDATE_COPY_FAILURE("target_hash", rc, -1);
    }
    if (source >= 0) {
        errno = 0;
        int rc = close(source);
        if (rc != 0) { UPDATE_COPY_FAILURE("close_source", rc, errno); ok = false; }
    }
    if (target >= 0) {
        errno = 0;
        int rc = close(target);
        if (rc != 0) { UPDATE_COPY_FAILURE("close_target", rc, errno); ok = false; }
    }
    if (!ok && own) update_unlink_owned(dir, name, copied);
    if (!ok) {
        int saved_errno = errno;
        log_warn("update: previous_copy failed stage=%s check=%s field=%s rc=%lld errno=%d errno_valid=%d expected_dev=%llu expected_ino=%llu observed_dev=%llu observed_ino=%llu observed_valid=%d reference_unchanged=%d",
                 failure, failure_check, failure_field, failure_rc, failure_errno, failure_errno > 0 ? 1 : 0,
                 (unsigned long long)reference.st_dev, (unsigned long long)reference.st_ino,
                 observed_dev, observed_ino, observed_valid ? 1 : 0, reference_unchanged ? 1 : 0);
        if (identity.valid) {
            update_identity_log(failure, "expected", &identity.expected, 0, -1);
            update_identity_log(failure, "observed", &identity.observed, 0, -1);
            update_identity_log(failure, "source_again", &identity.source_again, identity.source_rc, identity.source_errno);
            update_identity_log(failure, "path_again", &identity.path_again, identity.path_rc, identity.path_errno);
        }
        errno = saved_errno;
    }
#undef UPDATE_COPY_FAILURE
    update_trace("previous", "end", ok ? 0 : -1, failure_errno);
    return ok;
}

bool update_finish(const char* owner, const char* id, bool confirm, update_result_t* out) {
    update_trace("finish_entry", "begin", 0, -1);
    pthread_mutex_lock(&update_lock);
    if (!update_admit(owner, id, confirm, out)) {
        update_trace("finish_entry", "end", -1, -1);
        pthread_mutex_unlock(&update_lock); return false;
    }
    update_trace("finish_entry", "end", 0, -1);
    const char* error = "update_incomplete";
    update_file_info_t incoming = {0}, old = {0}, previous = {0};
    struct stat incoming_stat = {0}, old_stat = {0}, previous_stat = {0}, copy_stat = {0};
    char copy_name[112] = {0}; bool copy_exists = false;
    if (session.offset != session.size || !update_temp_current()) {
        update_trace(error, "first_failure", 0, -1); goto rejected;
    }
    error = "update_verification_failed";
    update_trace("fsync", "begin", 0, -1);
    errno = 0;
    int sync_rc = fsync(session.fd), sync_error = sync_rc ? errno : -1;
    if (sync_rc) update_trace("fsync", "first_failure", sync_rc, sync_error);
    update_trace("fsync", "end", sync_rc, sync_error);
    if (sync_rc) goto rejected;
    update_trace("hash", "begin", 0, -1);
    update_read_diagnostic_t diagnostic;
    bool readable = update_read_fd_diagnostic(session.fd, &incoming, &incoming_stat, &diagnostic);
    if (!readable || incoming.bytes != session.size || strcmp(incoming.sha256, session.hash) || !incoming.valid) {
        if (readable) update_trace("hash_check", "first_failure", 0, -1);
        update_trace("hash", "end", -1, readable ? -1 : diagnostic.error); goto rejected;
    }
    update_trace("hash", "end", 0, -1);
    uint32_t incoming_version[3], running_version[3];
    if (!update_version(incoming.version, incoming_version) || !update_version(TOSTONSYNC_VERSION, running_version)) {
        update_trace("version", "first_failure", 0, -1); goto rejected;
    }
    bool older = false;
    for (size_t i = 0; i < 3; i++) {
        if (incoming_version[i] == running_version[i]) continue;
        older = incoming_version[i] < running_version[i]; break;
    }
    if (older && !session.allow_downgrade) {
        error = "update_downgrade_confirmation_required";
        update_trace(error, "first_failure", 0, -1); goto rejected;
    }
    error = "update_current_unreadable";
    if (!update_inspect_at_diagnostic(session.dir, current_name, &old, &old_stat, true) ||
        !update_inspect_at_diagnostic(session.dir, previous_name, &previous, &previous_stat, true)) {
        update_trace(error, "first_failure", 0, -1); goto rejected;
    }
    bool old_exists = !strcmp(old.state, "present"), previous_exists = !strcmp(previous.state, "present");
    if (old_exists) {
        snprintf(copy_name, sizeof(copy_name), ".update-previous-%s.tmp", session.id);
        error = "update_previous_failed";
        update_trace("previous_return", "begin", 0, -1);
        bool copied = update_copy_previous(session.dir, copy_name, &old_stat, old.sha256, &copy_stat);
        update_trace("previous_return", "end", copied ? 0 : -1, -1);
        if (!copied) goto rejected;
        copy_exists = true;
    }
    update_window_active = true;
    error = "update_source_changed";
    if (!UPDATE_WINDOW_CALL("window_temp_verified", update_temp_verified(&incoming_stat), false) ||
        !UPDATE_WINDOW_CALL("window_current_path", update_path_same(session.dir, current_name, old_exists, &old_stat), false) ||
        !UPDATE_WINDOW_CALL("window_previous_path", update_path_same(session.dir, previous_name, previous_exists, &previous_stat), false)) {
        update_trace(error, "first_failure", 0, -1); goto rejected;
    }
    if (copy_exists) {
        error = "update_previous_publish_failed";
        if (!UPDATE_WINDOW_CALL("window_copy_path", update_path_same(session.dir, copy_name, true, &copy_stat), false)) {
            update_trace(error, "first_failure", 0, -1); goto rejected;
        }
        update_window_active = false;
        update_trace("previous_publish", "begin", 0, -1);
        errno = 0;
        int rc = renameat(session.dir, copy_name, session.dir, previous_name);
        int rename_error = rc ? errno : -1;
        if (rc) update_trace("previous_rename", "first_failure", rc, rename_error);
        update_trace("previous_publish", "end", rc, rename_error);
        if (rc != 0) {
            if (!update_path_same(session.dir, copy_name, true, &copy_stat) ||
                !update_path_same(session.dir, previous_name, previous_exists, &previous_stat)) goto unknown;
            goto rejected;
        }
        copy_exists = false;
        update_trace("previous_dir_fsync", "begin", 0, -1);
        errno = 0;
        rc = fsync(session.dir);
        int sync_error = rc ? errno : -1;
        if (rc) update_trace("previous_dir_fsync", "first_failure", rc, sync_error);
        update_trace("previous_dir_fsync", "end", rc, sync_error);
        if (rc != 0) goto unknown;
    }
    update_window_active = false;
    error = "update_source_changed";
    if (!update_temp_verified(&incoming_stat) || !update_path_same(session.dir, current_name, old_exists, &old_stat)) {
        update_trace(error, "first_failure", 0, -1); goto rejected;
    }
    error = "update_publish_failed";
    update_trace("publish", "begin", 0, -1);
    errno = 0;
    int publish_rc = renameat(session.dir, session.temp, session.dir, current_name);
    int publish_error = publish_rc ? errno : -1;
    if (publish_rc) update_trace("publish_rename", "first_failure", publish_rc, publish_error);
    update_trace("publish", "end", publish_rc, publish_error);
    if (publish_rc != 0) {
        // A failed rename whose named files no longer match is not safely retryable.
        if (!update_temp_current() || !update_path_same(session.dir, current_name, old_exists, &old_stat)) goto unknown;
        goto rejected;
    }
    update_trace("publish_dir_fsync", "begin", 0, -1);
    errno = 0;
    sync_rc = fsync(session.dir); sync_error = sync_rc ? errno : -1;
    if (sync_rc) update_trace("publish_dir_fsync", "first_failure", sync_rc, sync_error);
    update_trace("publish_dir_fsync", "end", sync_rc, sync_error);
    if (sync_rc != 0) goto unknown;
    if (!update_directory_current(session.dir)) { update_trace("publish_directory", "first_failure", 0, -1); goto unknown; }
    update_trace("publish_verify", "begin", 0, -1);
    update_file_info_t verify = {0};
    if (!update_inspect_at_diagnostic(session.dir, current_name, &verify, NULL, true) || !verify.valid ||
        verify.bytes != incoming.bytes || strcmp(verify.sha256, incoming.sha256)) {
        update_trace("publish_verify", "first_failure", 0, -1);
        update_trace("publish_verify", "end", -1, -1); goto unknown;
    }
    update_trace("publish_verify", "end", 0, -1);
    snprintf(pending_hash, sizeof(pending_hash), "%s", incoming.sha256);
    update_result(out, UPDATE_OK, "", "Update saved. The running process has not restarted.");
    if (out) {
        out->published = true; out->bytes = incoming.bytes; out->next_offset = incoming.bytes;
        snprintf(out->version, sizeof(out->version), "%s", incoming.version);
        snprintf(out->sha256, sizeof(out->sha256), "%s", incoming.sha256);
        snprintf(out->previous_version, sizeof(out->previous_version), "%s", old.version);
    }
    update_end(true); pthread_mutex_unlock(&update_lock);
    log_info("update: saved version=%s sha256=%s bytes=%llu previous_version=%s", incoming.version,
             incoming.sha256, (unsigned long long)incoming.bytes, old.version[0] ? old.version : "older_or_missing");
    char notice[160]; snprintf(notice, sizeof(notice), "TostónSync update saved (v%s). Restart TostónSync to use it.", incoming.version);
    if (!update_quiet) log_notify(notice); return true;
unknown:
    blocked_unknown = true; pending_hash[0] = 0;
    update_result(out, UPDATE_UNKNOWN, "update_publication_unknown", "Publication may have occurred. Files preserved; do not retry.");
    if (out) { out->bytes = incoming.bytes; snprintf(out->sha256, sizeof(out->sha256), "%s", incoming.sha256); }
    update_end(true); pthread_mutex_unlock(&update_lock); return false;
rejected:
    update_window_active = false;
    update_trace("cleanup", "begin", 0, -1);
    if (copy_exists) update_unlink_owned(session.dir, copy_name, &copy_stat);
    update_end(false);
    update_trace("cleanup", "returned", -1, -1);
    pthread_mutex_unlock(&update_lock);
    return update_result(out, UPDATE_IO_ERROR, error, "Update not saved. The current executable was not replaced by this request.");
}

bool update_finish_quiet(const char* owner, const char* id, bool confirm, update_result_t* out) {
    bool previous = update_quiet; update_quiet = true;
    bool ok = update_finish(owner, id, confirm, out);
    update_quiet = previous;
    return ok;
}

bool update_restart_request(life_snapshot_fn snapshot, life_snapshot_t* state,
                            update_result_t* out) {
    if (!state || !out) return false;
    memset(state, 0, sizeof(*state)); memset(out, 0, sizeof(*out));
    pthread_mutex_lock(&update_lock);
    const char* reason = restart_prepared || restart_armed || restart_consumed ? "restart_already_pending" :
        lifecycle_stopping() ? "already_stopping" : session.active ? "update_busy" :
        blocked_unknown ? "update_publication_unknown" : !update_boot_id()[0] ? "restart_boot_unknown" : NULL;
    update_file_info_t saved = {0}; struct stat saved_stat = {0};
    if (!reason) {
        int dir = update_open_directory();
        bool valid = dir >= 0 && update_inspect_at(dir, current_name, &saved, &saved_stat) &&
            update_directory_current(dir);
        if (dir >= 0 && close(dir) != 0) valid = false;
        if (!valid) reason = "restart_saved_unreadable";
        else if (strcmp(saved.state, "present") || !saved.valid) reason = "restart_saved_invalid";
    }
    if (!reason && !lifecycle_request_cooperative_stop(snapshot, state)) reason = state->reason;
    if (reason) {
        out->code = UPDATE_BUSY;
        snprintf(out->error, sizeof(out->error), "restart_blocked");
        snprintf(out->detail, sizeof(out->detail), "%s", reason);
        pthread_mutex_unlock(&update_lock);
        log_warn("restart[web] blocked reason=%s", out->detail);
        return false;
    }
    restart_expected = saved; restart_stat = saved_stat; restart_prepared = true;
    out->code = UPDATE_OK; out->bytes = saved.bytes;
    snprintf(out->version, sizeof(out->version), "%s", saved.version);
    snprintf(out->sha256, sizeof(out->sha256), "%s", saved.sha256);
    pthread_mutex_unlock(&update_lock);
    return true;
}

void update_restart_response_sent(void) {
    pthread_mutex_lock(&update_lock);
    if (restart_prepared && !restart_armed && !restart_consumed) {
        restart_armed = true;
        log_info("restart[web] begin");
        lifecycle_cooperative_response_sent();
    }
    pthread_mutex_unlock(&update_lock);
}

static int64_t update_restart_now(void) {
    struct timespec now;
    if (clock_gettime(CLOCK_MONOTONIC, &now) || now.tv_sec < 0 ||
        now.tv_sec > (INT64_MAX - 5000) / 1000 || now.tv_nsec < 0 || now.tv_nsec >= 1000000000) return -1;
    return (int64_t)now.tv_sec * 1000 + now.tv_nsec / 1000000;
}

static int update_restart_remaining(int64_t deadline) {
    int64_t now = update_restart_now();
    return now < 0 || now >= deadline ? 0 : (int)(deadline - now);
}

static void update_restart_stat_log(const char* view, const struct stat* value) {
    if (!value) {
        (void)log_durable("restart: snapshot_stat view=%s available=0", view);
        return;
    }
#ifdef __APPLE__
    struct timespec mtime = value->st_mtimespec, ctime = value->st_ctimespec;
#else
    struct timespec mtime = value->st_mtim, ctime = value->st_ctim;
#endif
    (void)log_durable("restart: snapshot_stat view=%s available=1 dev=%llu ino=%llu mode=%llu size=%lld mtime_sec=%lld mtime_nsec=%lld ctime_sec=%lld ctime_nsec=%lld",
        view, (unsigned long long)value->st_dev, (unsigned long long)value->st_ino,
        (unsigned long long)value->st_mode, (long long)value->st_size,
        (long long)mtime.tv_sec, (long long)mtime.tv_nsec,
        (long long)ctime.tv_sec, (long long)ctime.tv_nsec);
}

static void update_restart_snapshot_failure(const char* phase, const char* reason,
        const char* field, long long rc, int error, uint64_t bytes, int remaining,
        const update_file_info_t* expected, const char* observed_hash,
        const struct stat* accepted, const struct stat* observed) {
    int saved_errno = errno;
    // Persist the primary failure before diagnostic observations or cleanup.
    update_trace(phase, "first_failure", rc, error);
    (void)log_durable("restart: snapshot_failure phase=%s reason=%s field=%s rc=%lld errno=%d errno_valid=%d bytes=%llu remaining_ms_last=%d expected_sha256=%s observed_sha256=%s",
        phase, reason, field, rc, error, error > 0 ? 1 : 0,
        (unsigned long long)bytes, remaining, expected->sha256,
        observed_hash[0] ? observed_hash : "unavailable");
    update_restart_stat_log("accepted", accepted);
    update_restart_stat_log("observed", observed);
    errno = saved_errno;
}

static unsigned char* update_restart_snapshot(const update_file_info_t* expected,
                                              const struct stat* accepted, int64_t deadline) {
    int entry_errno = errno, first_errno = 0, dir = -1, fd = -1, check_dir = -1, remaining = -1;
    unsigned char* bytes = NULL;
    bool ok = false, failed = false, checking_directory = false;
    size_t offset = 0;
    char hash[65] = {0};
    update_file_info_t observed = {0};
    toston_stat_guard_t before = TOSTON_STAT_GUARD_INIT;
    toston_stat_guard_t after = TOSTON_STAT_GUARD_INIT;
    toston_stat_guard_t named = TOSTON_STAT_GUARD_INIT;
    toston_stat_guard_t directory_held = TOSTON_STAT_GUARD_INIT;
    toston_stat_guard_t directory_named = TOSTON_STAT_GUARD_INIT;
    const struct stat* comparison = accepted;
    const struct stat* last_stat = NULL;
#define RESTART_FAIL(phase, reason, field, result, error_value, stat_value) do { \
    if (!failed) { \
        int snapshot_failure_errno = (error_value); failed = true; first_errno = snapshot_failure_errno; \
        update_restart_snapshot_failure((phase), (reason), (field), (result), snapshot_failure_errno, \
            offset, remaining, expected, hash, comparison, (stat_value)); \
    } \
} while (0)
#define RESTART_TIME(phase, phase_open) do { \
    int64_t restart_now = update_restart_now(); \
    remaining = restart_now < 0 || restart_now >= deadline ? 0 : (int)(deadline - restart_now); \
    if (!remaining) { \
        RESTART_FAIL((phase), restart_now < 0 ? "clock" : "deadline", "remaining", 0, -1, last_stat); \
        if (phase_open) update_trace((phase), "end", -1, -1); \
        goto done; \
    } \
} while (0)
#define RESTART_STAT(phase, expression, guard) do { \
    (guard) = (toston_stat_guard_t)TOSTON_STAT_GUARD_INIT; \
    update_trace((phase), "begin", 0, -1); errno = 0; \
    int restart_rc = (expression), restart_error = restart_rc ? errno : -1; \
    bool restart_before = (guard).before == UINT64_C(0x8d23f19ac46be075); \
    bool restart_after = (guard).after == UINT64_C(0x75e06bc49af1238d); \
    if (restart_rc) RESTART_FAIL((phase), "io", "stat", restart_rc, restart_error, NULL); \
    else if (!toston_stat_guard_valid(&(guard))) { \
        restart_rc = -1; restart_error = EOVERFLOW; \
        RESTART_FAIL((phase), "canary", restart_before ? "after" : "before", restart_rc, restart_error, NULL); \
    } \
    (void)log_durable("restart: snapshot_canary phase=%s before=%s after=%s", (phase), \
        restart_before ? "intact" : "altered", restart_after ? "intact" : "altered"); \
    update_trace((phase), "end", restart_rc, restart_error); \
    if (restart_rc) goto done; \
    last_stat = &(guard).value; \
    update_restart_stat_log((phase), last_stat); \
} while (0)
    update_trace("restart_snapshot", "begin", 0, -1);
    update_restart_stat_log("accepted", accepted);
    update_trace("restart_directory", "begin", 0, -1); errno = 0;
    dir = update_open_directory();
    int error = dir < 0 ? errno : -1;
    if (dir < 0) RESTART_FAIL("restart_directory", "io", "directory", dir, error, NULL);
    update_trace("restart_directory", "end", dir, error);
    if (dir < 0) goto done;
    RESTART_TIME("restart_named", false);
    RESTART_STAT("restart_named", toston_fstatat(dir, current_name, &named.value, AT_SYMLINK_NOFOLLOW), named);
    if (!update_same_file(accepted, &named.value)) {
        RESTART_FAIL("restart_named", "metadata", update_file_difference(accepted, &named.value), 0, -1, &named.value); goto done;
    }
    update_trace("restart_open", "begin", 0, -1); errno = 0;
    fd = toston_openat(dir, current_name, O_RDONLY | O_NOFOLLOW | O_NONBLOCK, 0);
    error = fd < 0 ? errno : -1;
    if (fd < 0) RESTART_FAIL("restart_open", "io", "file", fd, error, last_stat);
    update_trace("restart_open", "end", fd, error);
    if (fd < 0) goto done;
    RESTART_STAT("restart_fd", toston_fstat(fd, &before.value), before);
    if (!S_ISREG(before.value.st_mode) || !update_same_file(accepted, &before.value)) {
        RESTART_FAIL("restart_fd", "metadata", !S_ISREG(before.value.st_mode) ? "type" : update_file_difference(accepted, &before.value), 0, -1, &before.value); goto done;
    }
    if (before.value.st_size < 64 || (uint64_t)before.value.st_size > UPDATE_MAX_BYTES ||
        (uint64_t)before.value.st_size != expected->bytes) {
        RESTART_FAIL("restart_fd", "content", "size", 0, -1, &before.value); goto done;
    }
    update_trace("restart_memory", "begin", 0, -1); errno = 0;
    bytes = malloc((size_t)expected->bytes); error = bytes ? -1 : errno;
    if (!bytes) RESTART_FAIL("restart_memory", "memory", "allocation", 0, error, last_stat);
    update_trace("restart_memory", "end", bytes ? 1 : 0, error);
    if (!bytes) goto done;
    update_trace("restart_read", "begin", 0, -1);
    while (offset < expected->bytes) {
        RESTART_TIME("restart_read", true);
        size_t need = (size_t)expected->bytes - offset;
        if (need > 32768) need = 32768;
        errno = 0; ssize_t n = read(fd, bytes + offset, need); error = n < 0 ? errno : -1;
        if (n <= 0 || (size_t)n > need) {
            RESTART_FAIL("restart_read", n < 0 ? "io" : "content", n < 0 ? "read" : n == 0 ? "short_read" : "read_count", n, error, last_stat);
            update_trace("restart_read", "end", n, error); goto done;
        }
        offset += (size_t)n;
    }
    update_trace("restart_read", "end", (long long)offset, -1);
    RESTART_TIME("restart_eof", false);
    unsigned char extra;
    update_trace("restart_eof", "begin", 0, -1); errno = 0;
    ssize_t extra_rc = read(fd, &extra, 1); error = extra_rc < 0 ? errno : -1;
    if (extra_rc != 0) RESTART_FAIL("restart_eof", extra_rc < 0 ? "io" : "content", "eof", extra_rc, error, last_stat);
    update_trace("restart_eof", "end", extra_rc, error);
    if (extra_rc != 0) goto done;
    RESTART_STAT("restart_final_fd", toston_fstat(fd, &after.value), after);
    if (!update_same_file(&before.value, &after.value)) {
        RESTART_FAIL("restart_final_fd", "metadata", update_file_difference(&before.value, &after.value), 0, -1, &after.value); goto done;
    }
    update_trace("restart_elf", "begin", 0, -1);
    bool valid = update_elf(bytes, offset);
    if (!valid) RESTART_FAIL("restart_elf", "content", "elf", 0, -1, last_stat);
    update_trace("restart_elf", "end", valid, -1);
    if (!valid) goto done;
    update_trace("restart_marker", "begin", 0, -1);
    valid = update_parse_marker(bytes, offset, &observed);
    if (!valid) RESTART_FAIL("restart_marker", "content", "marker", 0, -1, last_stat);
    update_trace("restart_marker", "end", valid, -1);
    if (!valid) goto done;
    update_trace("restart_hash", "begin", 0, -1);
    update_hash_bytes(bytes, offset, hash);
    const char* mismatch = strcmp(hash, expected->sha256) ? "sha256" :
        strcmp(observed.version, expected->version) ? "version" : strcmp(observed.build, expected->build) ? "build" : NULL;
    if (mismatch) RESTART_FAIL("restart_hash", "content", mismatch, 0, -1, last_stat);
    (void)log_durable("restart: snapshot_hash expected_sha256=%s observed_sha256=%s", expected->sha256, hash);
    update_trace("restart_hash", "end", mismatch ? 0 : 1, -1);
    if (mismatch) goto done;
    // Same directory checks as update_directory_current, with the failing call retained.
    checking_directory = true;
    update_trace("restart_directory_current", "begin", 0, -1);
    update_trace("restart_directory_reopen", "begin", 0, -1); errno = 0;
    check_dir = update_open_directory(); error = check_dir < 0 ? errno : -1;
    if (check_dir < 0) RESTART_FAIL("restart_directory_reopen", "io", "directory", check_dir, error, NULL);
    update_trace("restart_directory_reopen", "end", check_dir, error);
    if (check_dir < 0) goto done;
    RESTART_STAT("restart_directory_fd", toston_fstat(dir, &directory_held.value), directory_held);
    comparison = &directory_held.value;
    RESTART_STAT("restart_directory_named_fd", toston_fstat(check_dir, &directory_named.value), directory_named);
    if (directory_held.value.st_dev != directory_named.value.st_dev ||
        directory_held.value.st_ino != directory_named.value.st_ino) {
        RESTART_FAIL("restart_directory_current", "metadata",
            directory_held.value.st_dev != directory_named.value.st_dev ? "dev" : "ino", 0, -1, &directory_named.value); goto done;
    }
    update_trace("restart_directory_close", "begin", 0, -1); errno = 0;
    int directory_close_rc = close(check_dir); error = directory_close_rc ? errno : -1; check_dir = -1;
    if (directory_close_rc) RESTART_FAIL("restart_directory_close", "io", "close", directory_close_rc, error, NULL);
    update_trace("restart_directory_close", "end", directory_close_rc, error);
    if (directory_close_rc) goto done;
    update_trace("restart_directory_current", "end", 1, -1); checking_directory = false;
    comparison = accepted; last_stat = &after.value;
    RESTART_STAT("restart_final_named", toston_fstatat(dir, current_name, &named.value, AT_SYMLINK_NOFOLLOW), named);
    if (!update_same_file(&after.value, &named.value)) {
        RESTART_FAIL("restart_final_named", "metadata", update_file_difference(&after.value, &named.value), 0, -1, &named.value); goto done;
    }
    RESTART_TIME("restart_final_named", false);
    ok = true;
done:
    if (checking_directory) update_trace("restart_directory_current", "end", -1, first_errno > 0 ? first_errno : -1);
    if (check_dir >= 0) {
        update_trace("restart_directory_close", "begin", 0, -1); errno = 0;
        int rc = close(check_dir); error = rc ? errno : -1;
        if (rc) RESTART_FAIL("restart_directory_close", "io", "close", rc, error, NULL);
        update_trace("restart_directory_close", "end", rc, error);
    }
    if (fd >= 0) {
        update_trace("restart_close_file", "begin", 0, -1); errno = 0;
        int rc = close(fd); error = rc ? errno : -1;
        if (rc) { RESTART_FAIL("restart_close_file", "io", "close", rc, error, last_stat); ok = false; }
        update_trace("restart_close_file", "end", rc, error);
    }
    if (dir >= 0) {
        update_trace("restart_close_directory", "begin", 0, -1); errno = 0;
        int rc = close(dir); error = rc ? errno : -1;
        if (rc) { RESTART_FAIL("restart_close_directory", "io", "close", rc, error, last_stat); ok = false; }
        update_trace("restart_close_directory", "end", rc, error);
    }
    if (!ok) { free(bytes); bytes = NULL; }
    update_trace("restart_snapshot", "end", ok ? 0 : -1, first_errno > 0 ? first_errno : -1);
    errno = first_errno > 0 ? first_errno : entry_errno;
    return bytes;
#undef RESTART_STAT
#undef RESTART_TIME
#undef RESTART_FAIL
}

static bool update_restart_wait(int fd, int64_t deadline) {
    for (;;) {
        int left = update_restart_remaining(deadline);
        if (!left) return false;
        struct pollfd pollfd = {.fd = fd, .events = POLLOUT};
        int n = poll(&pollfd, 1, left);
        if (n < 0 && errno == EINTR) continue;
        return n > 0 && !(pollfd.revents & POLLNVAL) && update_restart_remaining(deadline);
    }
}

static bool update_restart_send(const unsigned char* bytes, size_t size,
                                int64_t deadline, const char** stage) {
    *stage = "socket";
    if (!update_restart_remaining(deadline)) { *stage = "deadline"; return false; }
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return false;
    bool ok = false;
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0 || fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0) goto done;
#ifdef SO_NOSIGPIPE
    int yes = 1;
    if (setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &yes, sizeof(yes))) goto done;
#endif
    struct sockaddr_in address = {0};
    address.sin_family = AF_INET; address.sin_port = htons(9021);
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    *stage = "connect";
    if (!update_restart_remaining(deadline)) goto done;
    int connected = connect(fd, (const struct sockaddr*)&address, sizeof(address));
    if (connected != 0) {
        if (errno != EINPROGRESS && errno != EINTR) goto done;
        int error = 0; socklen_t length = sizeof(error);
        if (!update_restart_wait(fd, deadline) || getsockopt(fd, SOL_SOCKET, SO_ERROR, &error, &length) ||
            length != sizeof(error) || error) goto done;
    }
    *stage = "send";
    size_t sent = 0;
    while (sent < size) {
        if (!update_restart_wait(fd, deadline)) goto done;
#ifdef MSG_NOSIGNAL
        ssize_t n = send(fd, bytes + sent, size - sent, MSG_NOSIGNAL);
#else
        ssize_t n = send(fd, bytes + sent, size - sent, 0);
#endif
        if (n < 0 && (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK)) continue;
        if (n <= 0 || (size_t)n > size - sent) goto done;
        sent += (size_t)n;
    }
    *stage = "eof";
    ok = update_restart_remaining(deadline) && shutdown(fd, SHUT_WR) == 0 && update_restart_remaining(deadline);
done:
    if (close(fd) != 0) { ok = false; *stage = "close"; }
    return ok;
}

update_restart_outcome_t update_restart_after_stop(void) {
    pthread_mutex_lock(&update_lock);
    if (!restart_armed || restart_consumed) { pthread_mutex_unlock(&update_lock); return UPDATE_RESTART_NONE; }
    restart_consumed = true; restart_armed = false;
    update_file_info_t expected = restart_expected; struct stat accepted = restart_stat;
    pthread_mutex_unlock(&update_lock);
    const char* stage = "clock";
    int64_t now = update_restart_now();
    unsigned char* bytes = NULL; bool sent = false;
    if (now >= 0) {
        int64_t deadline = now + 5000;
        stage = "saved_file_changed_or_unreadable";
        bytes = update_restart_snapshot(&expected, &accepted, deadline);
        if (bytes) sent = update_restart_send(bytes, (size_t)expected.bytes, deadline, &stage);
    }
    free(bytes);
    if (sent) {
        log_info("restart[web] relaunch sent bytes=%llu sha256=%s", (unsigned long long)expected.bytes, expected.sha256);
        return UPDATE_RESTART_SENT;
    }
    log_warn("restart[web] relaunch failed stage=%s; TostónSync is stopped", stage);
    log_notify("TostónSync stopped but could not start again. Open the TostónSync icon.");
    return UPDATE_RESTART_FAILED;
}
