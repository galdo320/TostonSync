#include "paired_capture.h"
#include "at_io.h"
#include "sha256.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#ifdef PAIRED_CAPTURE_READONLY_PROBE
#include <time.h>
#endif

#define PAIR_PATH_MAX 1280
#define PAIR_TREE_DEPTH 8
#define PAIR_BYTES_MAX (8ULL * 1024ULL * 1024ULL * 1024ULL)

typedef struct {
    size_t image;
    char path[260], sha256[65];
    uint64_t size;
    bool directory;
} tree_entry_t;

typedef struct {
    tree_entry_t* entries;
    size_t count;
    uint64_t bytes;
} tree_t;

typedef struct { const char* p; } reader_t;

typedef struct {
    paired_capture_diagnostic_t* diagnostic;
    paired_capture_stage_t stage;
    char path[260];
#ifdef PAIRED_CAPTURE_READONLY_PROBE
    struct timespec deadline;
#endif
} diagnostic_context_t;
/* Each additive entrypoint saves/restores this per-thread context, including
 * nested calls. No diagnostic is shared between daemon worker threads. */
#ifdef PAIRED_CAPTURE_READONLY_PROBE
/* The separate one-shot probe has one thread and deliberately no TLS runtime. */
static diagnostic_context_t* diagnostic_context;
#else
static _Thread_local diagnostic_context_t* diagnostic_context;
#endif

static const char* const stage_names[] = {
    "open_title", "open_capture", "allocation", "title_shape", "capture_shape",
    "raw_closed", "collect_tree", "create_excl", "fdopen", "write", "fflush",
    "descriptor_stat_limits", "fsync_file", "fclose", "fsync_directory",
    "close_capture", "close_title", "descriptor_read", "descriptor_parse",
    "portable_provenance", "tree_compare", "raw_shape", "raw_manifest"
};
const char* paired_capture_stage_name(paired_capture_stage_t stage) {
    return (unsigned)stage < PAIR_DIAG_STAGE_COUNT ? stage_names[stage] : "UNKNOWN";
}
const char* paired_capture_stage_state_name(paired_capture_stage_state_t state) {
    static const char* const names[] = {"UNKNOWN", "PASS", "FAIL", "SKIPPED"};
    return (unsigned)state < 4 ? names[state] : "UNKNOWN";
}
void paired_capture_diagnostic_init(paired_capture_diagnostic_t* d) {
    if (d) memset(d, 0, sizeof(*d));
}
static const char* diagnostic_errno_name(int e) {
    switch (e) {
        case EACCES: return "EACCES"; case EPERM: return "EPERM";
        case ENOENT: return "ENOENT"; case ENOTDIR: return "ENOTDIR";
        case ELOOP: return "ELOOP"; case EEXIST: return "EEXIST";
        case ENOMEM: return "ENOMEM"; case EIO: return "EIO";
        case EBADF: return "EBADF"; case EINVAL: return "EINVAL";
        case EINTR: return "EINTR"; case ENOSPC: return "ENOSPC";
        case EROFS: return "EROFS"; case EMFILE: return "EMFILE";
        case ENFILE: return "ENFILE"; case EFBIG: return "EFBIG";
        case ENAMETOOLONG: return "ENAMETOOLONG"; case ETIMEDOUT: return "ETIMEDOUT";
        case ENOSYS: return "ENOSYS"; case ENOTEMPTY: return "ENOTEMPTY";
        default: return "UNKNOWN";
    }
}
static paired_capture_stage_diagnostic_t* diagnostic_failure(const char* op,
        bool rc_valid, int64_t rc, int e, const char* expected, const char* observed) {
    if (!diagnostic_context || !diagnostic_context->diagnostic) return NULL;
    paired_capture_diagnostic_t* d = diagnostic_context->diagnostic;
    paired_capture_stage_t stage = diagnostic_context->stage;
    paired_capture_stage_diagnostic_t* s = &d->stages[stage];
    if (s->state == PAIR_DIAG_FAIL) return NULL;
    /* Acquisition can fail in several independent read stages. Durable write
     * and close observations retain only their first failure across stages. */
    if (stage >= PAIR_DIAG_CREATE_EXCL && stage <= PAIR_DIAG_CLOSE_TITLE)
        for (unsigned i = PAIR_DIAG_CREATE_EXCL; i <= PAIR_DIAG_CLOSE_TITLE; i++)
            if (d->stages[i].state == PAIR_DIAG_FAIL) return NULL;
    s->state = PAIR_DIAG_FAIL; s->return_valid = rc_valid; s->return_value = rc;
    s->errno_valid = e > 0; s->errno_code = e > 0 ? e : 0;
    snprintf(s->operation, sizeof(s->operation), "%s", op);
    snprintf(s->errno_name, sizeof(s->errno_name), "%s", e > 0 ? diagnostic_errno_name(e) : "UNKNOWN");
    snprintf(s->expected, sizeof(s->expected), "%s", expected ? expected : "UNKNOWN");
    snprintf(s->observed, sizeof(s->observed), "%s", observed ? observed : "UNKNOWN");
    snprintf(s->private_relative_path, sizeof(s->private_relative_path), "%s", diagnostic_context->path);
    return s;
}
static void diagnostic_begin(paired_capture_stage_t stage, const char* path) {
    if (!diagnostic_context) return;
    diagnostic_context->stage = stage;
    snprintf(diagnostic_context->path, sizeof(diagnostic_context->path), "%s", path ? path : "");
}
static bool diagnostic_end(bool ok) {
    if (diagnostic_context && diagnostic_context->diagnostic) {
        paired_capture_stage_diagnostic_t* s = &diagnostic_context->diagnostic->stages[diagnostic_context->stage];
        if (!ok && s->state != PAIR_DIAG_FAIL)
            diagnostic_failure("validation", true, 0, 0, "valid", "UNKNOWN");
        else if (ok && s->state != PAIR_DIAG_FAIL) s->state = PAIR_DIAG_PASS;
        if (!ok && s->state != PAIR_DIAG_FAIL && diagnostic_context->stage >= PAIR_DIAG_CREATE_EXCL &&
            diagnostic_context->stage <= PAIR_DIAG_CLOSE_TITLE) s->state = PAIR_DIAG_SKIPPED;
    }
    return ok;
}
static void diagnostic_skip(paired_capture_stage_t stage) {
    if (diagnostic_context && diagnostic_context->diagnostic &&
        diagnostic_context->diagnostic->stages[stage].state == PAIR_DIAG_UNKNOWN)
        diagnostic_context->diagnostic->stages[stage].state = PAIR_DIAG_SKIPPED;
}
static void diagnostic_path(const char* name) {
    if (!diagnostic_context) return;
    if (diagnostic_context->stage == PAIR_DIAG_RAW_CLOSED)
        snprintf(diagnostic_context->path, sizeof(diagnostic_context->path), ".capture/%s", name);
    else if (diagnostic_context->stage == PAIR_DIAG_CAPTURE_SHAPE ||
             diagnostic_context->stage == PAIR_DIAG_DESCRIPTOR_READ)
        snprintf(diagnostic_context->path, sizeof(diagnostic_context->path), ".capture/%s", name);
    else if (diagnostic_context->stage != PAIR_DIAG_COLLECT_TREE)
        snprintf(diagnostic_context->path, sizeof(diagnostic_context->path), "%s", name);
}
static bool diagnostic_budget(void) {
#ifdef PAIRED_CAPTURE_READONLY_PROBE
    struct timespec now;
    if (diagnostic_context && (clock_gettime(CLOCK_MONOTONIC, &now) ||
        now.tv_sec > diagnostic_context->deadline.tv_sec ||
        (now.tv_sec == diagnostic_context->deadline.tv_sec && now.tv_nsec >= diagnostic_context->deadline.tv_nsec))) {
        diagnostic_failure("deadline", true, -1, ETIMEDOUT, "within 20 seconds", "deadline exceeded");
        return false;
    }
#endif
    return true;
}
static int diagnostic_fstatat(int parent, const char* path, struct stat* st, int flags) {
    diagnostic_path(path);
    int rc = toston_fstatat(parent, path, st, flags); int saved = errno;
    if (rc) diagnostic_failure("toston_fstatat", true, rc, rc < 0 ? saved : 0, "return 0", "call failed");
    errno = saved; return rc;
}
#ifndef PAIRED_CAPTURE_READONLY_PROBE
static int diagnostic_optional_stat(int parent, const char* path, struct stat* st, int* saved) {
    diagnostic_path(path);
    int rc = toston_fstatat(parent, path, st, AT_SYMLINK_NOFOLLOW); *saved = errno;
    if (rc > 0 || (rc < 0 && *saved != ENOENT))
        diagnostic_failure("toston_fstatat", true, rc, rc < 0 ? *saved : 0, "capture directory or absent", "call failed");
    errno = *saved; return rc;
}
#endif
static int diagnostic_fstat(int fd, struct stat* st) {
    int rc = fstat(fd, st); int saved = errno;
    if (rc) diagnostic_failure("fstat", true, rc, rc < 0 ? saved : 0, "return 0", "call failed");
    errno = saved; return rc;
}
static int diagnostic_openat(int parent, const char* path, int flags, mode_t mode) {
    diagnostic_path(path);
    int rc = toston_openat(parent, path, flags, mode); int saved = errno;
    if (rc < 0) diagnostic_failure("toston_openat", true, rc, saved, "descriptor", "call failed");
    errno = saved; return rc;
}
static int diagnostic_dup(int fd) {
    int rc = dup(fd); int saved = errno;
    if (rc < 0) diagnostic_failure("dup", true, rc, saved, "descriptor", "call failed");
    errno = saved; return rc;
}
static DIR* diagnostic_fdopendir(int fd) {
    DIR* d = fdopendir(fd); int saved = errno;
    if (!d) diagnostic_failure("fdopendir", true, 0, saved, "directory stream", "NULL");
    errno = saved; return d;
}
static struct dirent* diagnostic_readdir(DIR* d) {
    if (!diagnostic_budget()) { errno = ETIMEDOUT; return NULL; }
    struct dirent* e = readdir(d); int saved = errno;
    if (!e && saved) diagnostic_failure("readdir", true, 0, saved, "entry or EOF", "call failed");
    errno = saved; return e;
}
static int diagnostic_close(int fd) {
    int rc = close(fd); int saved = errno;
    if (rc) diagnostic_failure("close", true, rc, rc < 0 ? saved : 0, "return 0", "call failed");
    errno = saved; return rc;
}
static int diagnostic_closedir(DIR* d) {
    int rc = closedir(d); int saved = errno;
    if (rc) diagnostic_failure("closedir", true, rc, rc < 0 ? saved : 0, "return 0", "call failed");
    errno = saved; return rc;
}
static const char* diagnostic_mode_name(mode_t mode) {
    if (S_ISDIR(mode)) return "directory";
    if (S_ISREG(mode)) return "regular file";
    if (S_ISLNK(mode)) return "symlink";
    if (S_ISCHR(mode)) return "character device";
    if (S_ISBLK(mode)) return "block device";
    if (S_ISFIFO(mode)) return "FIFO";
    if (S_ISSOCK(mode)) return "socket";
    return "UNKNOWN";
}
static bool diagnostic_type(const struct stat* st, bool directory) {
    bool ok = directory ? S_ISDIR(st->st_mode) : S_ISREG(st->st_mode);
    if (!ok) {
        paired_capture_stage_diagnostic_t* s = diagnostic_failure("type", true, 0, 0,
            directory ? "directory" : "regular file", diagnostic_mode_name(st->st_mode));
        if (s) { s->observed_mode = st->st_mode; s->mode_valid = true; }
    }
    return ok;
}
#undef toston_fstatat
#undef toston_openat
#undef fstat
#undef dup
#undef fdopendir
#undef readdir
#undef close
#undef closedir
#define toston_fstatat diagnostic_fstatat
#define toston_openat diagnostic_openat
#define fstat diagnostic_fstat
#define dup diagnostic_dup
#define fdopendir diagnostic_fdopendir
#define readdir diagnostic_readdir
#define close diagnostic_close
#define closedir diagnostic_closedir

typedef struct { char* out; size_t cap, used; } diagnostic_json_t;
static void diagnostic_json_append(diagnostic_json_t* w, const char* format, ...) {
    va_list args; va_start(args, format);
    size_t available = w->used < w->cap ? w->cap - w->used : 0;
    int n = vsnprintf(available ? w->out + w->used : NULL, available, format, args);
    va_end(args); if (n > 0) w->used += (size_t)n;
}
static void diagnostic_json_string(diagnostic_json_t* w, const char* text) {
    diagnostic_json_append(w, "\"");
    for (const unsigned char* p = (const unsigned char*)text; *p; p++) {
        if (*p == '"' || *p == '\\') diagnostic_json_append(w, "\\%c", *p);
        else if (*p < 0x20) diagnostic_json_append(w, "\\u%04x", *p);
        else diagnostic_json_append(w, "%c", *p);
    }
    diagnostic_json_append(w, "\"");
}
size_t paired_capture_diagnostic_json(const paired_capture_diagnostic_t* d,
                                      char* out, size_t cap, bool private_detail) {
    diagnostic_json_t w = {out, out ? cap : 0, 0};
    if (!d) { diagnostic_json_append(&w, "null"); return w.used; }
    diagnostic_json_append(&w, "{\"stages\":{");
    for (unsigned i = 0; i < PAIR_DIAG_STAGE_COUNT; i++) {
        const paired_capture_stage_diagnostic_t* s = &d->stages[i];
        diagnostic_json_append(&w, "%s\"%s\":{\"state\":\"%s\"", i ? "," : "", stage_names[i],
            paired_capture_stage_state_name(s->state));
        if (s->state == PAIR_DIAG_FAIL) {
            diagnostic_json_append(&w, ",\"operation\":"); diagnostic_json_string(&w, s->operation);
            diagnostic_json_append(&w, ",\"return\":");
            if (s->return_valid) diagnostic_json_append(&w, "%lld", (long long)s->return_value);
            else diagnostic_json_append(&w, "null");
            diagnostic_json_append(&w, ",\"errno\":");
            if (s->errno_valid) diagnostic_json_append(&w, "%d", s->errno_code);
            else diagnostic_json_append(&w, "null");
            diagnostic_json_append(&w, ",\"errno_name\":"); diagnostic_json_string(&w, s->errno_name);
            diagnostic_json_append(&w, ",\"expected\":"); diagnostic_json_string(&w, s->expected);
            diagnostic_json_append(&w, ",\"observed\":"); diagnostic_json_string(&w, s->observed);
            diagnostic_json_append(&w, ",\"stat_pair\":");
            if (s->stat_pair[0]) diagnostic_json_string(&w, s->stat_pair); else diagnostic_json_append(&w, "null");
            diagnostic_json_append(&w, ",\"stat_field\":");
            if (s->stat_field[0]) diagnostic_json_string(&w, s->stat_field); else diagnostic_json_append(&w, "null");
            diagnostic_json_append(&w, ",\"expected_value\":");
            if (s->values_valid) diagnostic_json_append(&w, "%lld", (long long)s->expected_value); else diagnostic_json_append(&w, "null");
            diagnostic_json_append(&w, ",\"observed_value\":");
            if (s->values_valid) diagnostic_json_append(&w, "%lld", (long long)s->observed_value); else diagnostic_json_append(&w, "null");
            diagnostic_json_append(&w, ",\"observed_mode\":");
            if (s->mode_valid) diagnostic_json_append(&w, "%llu", (unsigned long long)s->observed_mode); else diagnostic_json_append(&w, "null");
            diagnostic_json_append(&w, ",\"relative_path\":");
            if (private_detail && s->private_relative_path[0]) diagnostic_json_string(&w, s->private_relative_path); else diagnostic_json_append(&w, "null");
            diagnostic_json_append(&w, ",\"raw_size_expected\":");
            if (s->expected_raw_size) diagnostic_json_append(&w, "%llu", (unsigned long long)s->expected_raw_size); else diagnostic_json_append(&w, "null");
            diagnostic_json_append(&w, ",\"raw_size_observed\":");
            if (s->raw_size_valid) diagnostic_json_append(&w, "%llu", (unsigned long long)s->observed_raw_size); else diagnostic_json_append(&w, "null");
            diagnostic_json_append(&w, ",\"raw_sha256_expected\":");
            if (private_detail && s->expected_raw_sha256[0]) diagnostic_json_string(&w, s->expected_raw_sha256); else diagnostic_json_append(&w, "null");
            diagnostic_json_append(&w, ",\"raw_sha256_observed\":");
            if (private_detail && s->observed_raw_sha256[0]) diagnostic_json_string(&w, s->observed_raw_sha256); else diagnostic_json_append(&w, "null");
        }
        diagnostic_json_append(&w, "}");
    }
    diagnostic_json_append(&w, "},\"tree_entries\":%llu,\"tree_files\":%llu,\"tree_directories\":%llu,\"maximum_depth\":%u}",
        (unsigned long long)d->tree_entries, (unsigned long long)d->tree_files,
        (unsigned long long)d->tree_directories, d->maximum_depth);
    return w.used;
}

#ifndef PAIRED_CAPTURE_READONLY_PROBE
static bool fail(char* error, size_t cap, const char* message) {
    if (error && cap) snprintf(error, cap, "%s", message);
    return false;
}
#endif

/* Literal UTF-8 only: no normalization, escaped Unicode aliases or NUL. */
static bool utf8_ok(const char* text) {
    const unsigned char* p = (const unsigned char*)text;
    while (*p) {
        unsigned char c = *p++;
        if (c < 0x20 || c == 0x7f) return false;
        if (c < 0x80) continue;
        unsigned n; uint32_t value, minimum;
        if (c >= 0xc2 && c <= 0xdf) { n = 1; value = c & 31; minimum = 0x80; }
        else if (c >= 0xe0 && c <= 0xef) { n = 2; value = c & 15; minimum = 0x800; }
        else if (c >= 0xf0 && c <= 0xf4) { n = 3; value = c & 7; minimum = 0x10000; }
        else return false;
        while (n--) {
            if ((*p & 0xc0) != 0x80) return false;
            value = (value << 6) | (*p++ & 63);
        }
        if (value < minimum || value > 0x10ffff ||
            (value >= 0xd800 && value <= 0xdfff)) return false;
    }
    return true;
}

static bool component_ok(const char* s) {
    return s && s[0] && strcmp(s, ".") && strcmp(s, "..") &&
           !strchr(s, '/') && !strchr(s, '\\') && utf8_ok(s);
}

static bool hash_ok(const char* hash) {
    if (strnlen(hash, 65) != 64) return false;
    for (size_t i = 0; i < 64; i++)
        if (!((hash[i] >= '0' && hash[i] <= '9') ||
              (hash[i] >= 'a' && hash[i] <= 'f'))) return false;
    return true;
}

static bool image_role(const char* name, bool* service, const char** slot) {
    if (!component_ok(name) || strnlen(name, 128) >= 128 ||
        strncmp(name, "sdimg_", 6)) return false;
    *service = !strncmp(name, "sdimg_sce_bu_", 13);
    *slot = name + (*service ? 13 : 6);
    return component_ok(*slot) && strlen(*slot) < 64;
}

static bool record_ok(const paired_capture_t* c) {
    if (!c || !memchr(c->capture_id, 0, sizeof(c->capture_id)) ||
        !component_ok(c->capture_id) ||
        !memchr(c->producer_version, 0, sizeof(c->producer_version)) ||
        !component_ok(c->producer_version) ||
        !memchr(c->title_id, 0, sizeof(c->title_id)) ||
        strlen(c->title_id) != 9 || strncmp(c->title_id, "PPSA", 4) ||
        !memchr(c->source_uid, 0, sizeof(c->source_uid)) ||
        strlen(c->source_uid) != 8 || c->started_at < 0 ||
        c->finished_at < c->started_at || !c->image_count ||
        c->image_count > PAIRED_CAPTURE_MAX_IMAGES ||
        c->raw_zip_size < 22 || c->raw_zip_size > PAIR_BYTES_MAX ||
        !hash_ok(c->raw_zip_sha256)) return false;
    for (size_t i = 4; i < 9; i++)
        if (c->title_id[i] < '0' || c->title_id[i] > '9') return false;
    for (size_t i = 0; i < 8; i++)
        if (!((c->source_uid[i] >= '0' && c->source_uid[i] <= '9') ||
              (c->source_uid[i] >= 'a' && c->source_uid[i] <= 'f'))) return false;
    size_t active = 0;
    for (size_t i = 0; i < c->image_count; i++)
        if (!memchr(c->images[i].name, 0, sizeof(c->images[i].name))) return false;
    for (size_t i = 0; i < c->image_count; i++) {
        const paired_capture_image_t* image = &c->images[i];
        bool service; const char* slot;
        if (!memchr(image->name, 0, sizeof(image->name)) ||
            !image_role(image->name, &service, &slot) || !hash_ok(image->sha256) ||
            image->size > PAIR_BYTES_MAX) return false;
        for (size_t j = 0; j < i; j++)
            if (!strcmp(c->images[j].name, image->name)) return false;
        if (!service) { if (++active > PAIRED_CAPTURE_MAX_ACTIVE) return false; }
        else {
            bool companion = false;
            for (size_t j = 0; j < c->image_count; j++)
                if (!strncmp(c->images[j].name, "sdimg_", 6) &&
                    strncmp(c->images[j].name, "sdimg_sce_bu_", 13) &&
                    strcmp(c->images[j].name + 6, slot) == 0) companion = true;
            if (!companion) return false;
        }
    }
    return active != 0;
}

static bool stat_same(const struct stat* a, const struct stat* b, const char* pair) {
#define SAME_FIELD(member, label) do { if (a->member != b->member) { \
    paired_capture_stage_diagnostic_t* s = diagnostic_failure("stat_compare", true, 0, 0, "equal stat fields", "different stat field"); \
    if (s) { snprintf(s->stat_pair, sizeof(s->stat_pair), "%s", pair); \
        snprintf(s->stat_field, sizeof(s->stat_field), "%s", label); \
        s->values_valid = true; s->expected_value = (int64_t)a->member; s->observed_value = (int64_t)b->member; } \
    return false; } } while (0)
    SAME_FIELD(st_dev, "dev"); SAME_FIELD(st_ino, "ino");
    SAME_FIELD(st_mode, "mode"); SAME_FIELD(st_size, "size");
    SAME_FIELD(st_mtime, "mtime"); SAME_FIELD(st_ctime, "ctime");
#ifdef __APPLE__
    SAME_FIELD(st_mtimespec.tv_nsec, "mtime_nsec");
    SAME_FIELD(st_ctimespec.tv_nsec, "ctime_nsec");
#else
    SAME_FIELD(st_mtim.tv_nsec, "mtime_nsec");
    SAME_FIELD(st_ctim.tv_nsec, "ctime_nsec");
#endif
#undef SAME_FIELD
    return true;
}

static bool hash_at(int parent, const char* name, uint64_t* size, char hash[65]) {
    struct stat before, opened, after, closed;
    if (toston_fstatat(parent, name, &before, AT_SYMLINK_NOFOLLOW) ||
        !diagnostic_type(&before, false) || before.st_size < 0) return false;
    int fd = toston_openat(parent, name, O_RDONLY | O_NOFOLLOW | O_NONBLOCK, 0);
    if (fd < 0) return false;
    bool ok = !fstat(fd, &opened) && stat_same(&before, &opened, "path_before/open_fd");
    sha256_ctx_t ctx; sha256_init(&ctx);
    unsigned char buffer[32768], digest[32]; uint64_t bytes = 0;
    while (ok) {
        if (!diagnostic_budget()) { ok = false; break; }
        ssize_t n = read(fd, buffer, sizeof(buffer));
        if (n < 0) { int saved = errno; if (saved == EINTR) continue;
            diagnostic_failure("read", true, n, saved, "bytes or EOF", "call failed"); ok = false; break; }
        if (!n) break;
        if ((uint64_t)n > PAIR_BYTES_MAX - bytes) { ok = false; break; }
        bytes += (uint64_t)n; sha256_update(&ctx, buffer, (size_t)n);
    }
    ok = ok && !fstat(fd, &closed) && stat_same(&opened, &closed, "open_fd/closed_fd") &&
         !toston_fstatat(parent, name, &after, AT_SYMLINK_NOFOLLOW) &&
         stat_same(&before, &after, "path_before/path_after") && bytes == (uint64_t)before.st_size;
    if (close(fd)) ok = false;
    if (!ok) return false;
    sha256_final(&ctx, digest);
    for (size_t i = 0; i < 32; i++) snprintf(hash + i * 2, 3, "%02x", digest[i]);
    *size = bytes;
    return true;
}

#ifndef PAIRED_CAPTURE_READONLY_PROBE

static int diagnostic_fputs(const char* text, FILE* f) {
    int rc = fputs(text, f); int saved = errno;
    if (rc == EOF) diagnostic_failure("fputs", true, rc, saved, "write bytes", "call failed");
    errno = saved; return rc;
}
static int diagnostic_fputc(int c, FILE* f) {
    int rc = fputc(c, f); int saved = errno;
    if (rc == EOF) diagnostic_failure("fputc", true, rc, saved, "write byte", "call failed");
    errno = saved; return rc;
}
static int diagnostic_fprintf(FILE* f, const char* format, ...) {
    va_list args; va_start(args, format); int rc = vfprintf(f, format, args); int saved = errno; va_end(args);
    if (rc < 0) diagnostic_failure("fprintf", true, rc, saved, "write bytes", "call failed");
    errno = saved; return rc;
}
#undef fputs
#undef fputc
#undef fprintf
#define fputs diagnostic_fputs
#define fputc diagnostic_fputc
#define fprintf diagnostic_fprintf
static char* read_at(int parent, const char* name, size_t limit) {
    struct stat before, after, path_after;
    if (toston_fstatat(parent, name, &before, AT_SYMLINK_NOFOLLOW) ||
        !diagnostic_type(&before, false) || before.st_size < 2 ||
        (uint64_t)before.st_size > limit) return NULL;
    int fd = toston_openat(parent, name, O_RDONLY | O_NOFOLLOW | O_NONBLOCK, 0);
    if (fd < 0) return NULL;
    char* data = malloc((size_t)before.st_size + 1);
    int saved = errno; if (!data) diagnostic_failure("malloc", true, 0, saved, "descriptor allocation", "NULL");
    bool ok = data && !fstat(fd, &after) && stat_same(&before, &after, "path_before/open_fd");
    size_t used = 0;
    while (ok && used < (size_t)before.st_size) {
        ssize_t n = read(fd, data + used, (size_t)before.st_size - used);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) { int saved = errno;
            diagnostic_failure("read", true, n, n < 0 ? saved : 0, "descriptor bytes", n < 0 ? "call failed" : "unexpected EOF"); ok = false; break; }
        used += (size_t)n;
    }
    char extra;
    if (ok) {
        ssize_t rc = read(fd, &extra, 1); int saved_extra = errno;
        if (rc != 0) diagnostic_failure("read", true, rc, rc < 0 ? saved_extra : 0, "EOF", rc < 0 ? "call failed" : "unexpected bytes");
        ok = rc == 0;
    }
    ok = ok && !fstat(fd, &after) &&
         stat_same(&before, &after, "open_fd/closed_fd") &&
         !toston_fstatat(parent, name, &path_after, AT_SYMLINK_NOFOLLOW) &&
         stat_same(&before, &path_after, "path_before/path_after");
    if (close(fd)) ok = false;
    if (!ok || memchr(data, 0, used)) { free(data); return NULL; }
    data[used] = 0;
    return data;
}

static void ws(reader_t* r) {
    while (*r->p == ' ' || *r->p == '\t' || *r->p == '\r' || *r->p == '\n') r->p++;
}

static bool token(reader_t* r, char c) {
    ws(r); if (*r->p != c) return false; r->p++; return true;
}

static bool string(reader_t* r, char* out, size_t cap) {
    if (!token(r, '"')) return false;
    size_t n = 0;
    while (*r->p && *r->p != '"') {
        unsigned char c = (unsigned char)*r->p++;
        if (c == '\\') {
            c = (unsigned char)*r->p++;
            if (c != '"' && c != '\\' && c != '/') return false;
        }
        if (c < 0x20 || c == 0x7f || n + 1 >= cap) return false;
        out[n++] = (char)c;
    }
    if (*r->p++ != '"') return false;
    out[n] = 0;
    return utf8_ok(out);
}

static bool number(reader_t* r, uint64_t* out) {
    ws(r); const char* p = r->p;
    if (*p < '0' || *p > '9' || (*p == '0' && p[1] >= '0' && p[1] <= '9')) return false;
    uint64_t value = 0;
    do {
        unsigned digit = (unsigned)(*p++ - '0');
        if (value > (UINT64_MAX - digit) / 10) return false;
        value = value * 10 + digit;
    } while (*p >= '0' && *p <= '9');
    r->p = p; *out = value; return true;
}

static bool literal(reader_t* r, const char* value) {
    ws(r); size_t n = strlen(value);
    if (strncmp(r->p, value, n)) return false;
    r->p += n; return true;
}

static bool field(reader_t* r, const char* const* names, size_t count,
                   uint64_t* seen, size_t* index) {
    char key[64];
    if (!string(r, key, sizeof(key)) || !token(r, ':')) return false;
    for (size_t i = 0; i < count; i++) if (!strcmp(key, names[i])) {
        uint64_t bit = UINT64_C(1) << i;
        if (*seen & bit) return false;
        *seen |= bit; *index = i; return true;
    }
    return false;
}

static bool next(reader_t* r, char end, bool* more) {
    ws(r);
    if (*r->p == end) { r->p++; *more = false; return true; }
    if (*r->p++ != ',') return false;
    *more = true; return true;
}

/* Only skips known non-authoritative Portable metadata fields. Direct
 * identity/version fields are parsed below, never found by substring. */
static bool skip_metadata(reader_t* r, unsigned depth) {
    if (depth > 16) return false;
    ws(r);
    if (*r->p == '"') { char value[1024]; return string(r, value, sizeof(value)); }
    if (*r->p == '[' || *r->p == '{') {
        bool object = *r->p == '{'; char end = object ? '}' : ']'; r->p++; ws(r);
        if (*r->p == end) { r->p++; return true; }
        bool more = true; char keys[64][64]; size_t count = 0;
        while (more) {
            if (object) {
                if (count == 64 || !string(r, keys[count], sizeof(keys[count])) || !token(r, ':')) return false;
                for (size_t i = 0; i < count; i++) if (!strcmp(keys[i], keys[count])) return false;
                count++;
            }
            if (!skip_metadata(r, depth + 1) || !next(r, end, &more)) return false;
        }
        return true;
    }
    if (*r->p >= '0' && *r->p <= '9') { uint64_t value; return number(r, &value); }
    if (*r->p == 't') return literal(r, "true");
    if (*r->p == 'f') return literal(r, "false");
    if (*r->p == 'n') return literal(r, "null");
    return false;
}

static bool portable_provenance(int title, const paired_capture_t* c) {
    struct stat st;
    int saved;
    if (diagnostic_optional_stat(title, "manifest.json", &st, &saved)) return saved == ENOENT;
    const char* const keys[] = {"format", "format_version", "title_id", "source_user_uid", "user_uid",
        "app", "app_version", "platform", "title_name", "backup_type", "trigger", "created_at_utc",
        "created_at_epoch", "source_console_name", "source_console_type", "recovered_from_raw",
        "source_created_at_utc", "recovered_active_images", "service_images_retained_in_original", "save_dirs"};
    char* text = read_at(title, "manifest.json", 16384);
    if (!text) return false;
    reader_t r = {text}; uint64_t seen = 0; bool more = true, ok = token(&r, '{');
    while (ok && more) {
        size_t i; char value[128]; uint64_t n;
        if (!field(&r, keys, 20, &seen, &i)) { ok = false; break; }
        switch (i) {
            case 0: ok = string(&r, value, sizeof(value)) && !strcmp(value, "tostonsync.migration_decrypted"); break;
            case 1: ok = number(&r, &n) && n == 1; break;
            case 2: ok = string(&r, value, sizeof(value)) && !strcmp(value, c->title_id); break;
            case 3: case 4: ok = string(&r, value, sizeof(value)) && !strcmp(value, c->source_uid); break;
            case 6: ok = string(&r, value, sizeof(value)) && !strcmp(value, c->producer_version); break;
            case 7: ok = string(&r, value, sizeof(value)) && !strcmp(value, "ps5"); break;
            case 12: ok = number(&r, &n) && n == (uint64_t)c->started_at; break;
            default: ok = skip_metadata(&r, 0); break;
        }
        if (ok) ok = next(&r, '}', &more);
    }
    ws(&r);
    ok = ok && !*r.p && (seen & 7) == 7 && (seen & ((UINT64_C(1) << 3) | (UINT64_C(1) << 4)));
    free(text);
    return ok;
}
#endif

static int entry_compare(const void* a, const void* b) {
    const tree_entry_t* x = a; const tree_entry_t* y = b;
    if (x->image != y->image) return x->image < y->image ? -1 : 1;
    return strcmp(x->path, y->path);
}

static bool add_entry(tree_t* tree, const paired_capture_t* c, size_t image,
                       const char* relative, bool directory, uint64_t size,
                       const char* hash) {
    if (tree->count == PAIRED_CAPTURE_MAX_ENTRIES || image >= c->image_count ||
        strlen(relative) >= sizeof(tree->entries[0].path) ||
        strlen(c->title_id) + strlen(c->images[image].name) +
            (strcmp(relative, ".") ? strlen(relative) + 2 : 1) >= 260 ||
        size > PAIR_BYTES_MAX - tree->bytes) return false;
    tree_entry_t* e = &tree->entries[tree->count++];
    e->image = image; e->directory = directory; e->size = size;
    snprintf(e->path, sizeof(e->path), "%s", relative);
    if (hash) snprintf(e->sha256, sizeof(e->sha256), "%s", hash);
    tree->bytes += size;
    if (diagnostic_context && diagnostic_context->diagnostic) {
        paired_capture_diagnostic_t* d = diagnostic_context->diagnostic;
        d->tree_entries++; if (directory) d->tree_directories++; else d->tree_files++;
    }
    return true;
}

static void tree_diagnostic_path(const paired_capture_t* c, size_t image, const char* relative) {
    if (diagnostic_context) snprintf(diagnostic_context->path, sizeof(diagnostic_context->path),
        "%s%s%s", c->images[image].name, strcmp(relative, ".") ? "/" : "",
        strcmp(relative, ".") ? relative : "");
}

static bool walk_tree(int fd, const char* relative, unsigned depth,
                       const paired_capture_t* c, size_t image, tree_t* tree) {
    struct stat before, after;
    tree_diagnostic_path(c, image, relative);
    if (diagnostic_context && diagnostic_context->diagnostic &&
        depth > diagnostic_context->diagnostic->maximum_depth)
        diagnostic_context->diagnostic->maximum_depth = depth;
    if (!diagnostic_budget() || fstat(fd, &before) || !diagnostic_type(&before, true) ||
        !add_entry(tree, c, image, relative, true, 0, NULL)) return false;
    int listing = dup(fd);
    DIR* d = listing >= 0 ? fdopendir(listing) : NULL;
    if (!d) { if (listing >= 0) close(listing); return false; }
    bool ok = true;
    for (;;) {
        errno = 0; struct dirent* e = readdir(d);
        if (!e) { if (errno) ok = false; break; }
        if (!strcmp(e->d_name, ".") || !strcmp(e->d_name, "..")) continue;
        if (!component_ok(e->d_name)) { ok = false; break; }
        char rel[260];
        int n = snprintf(rel, sizeof(rel), "%s%s%s", strcmp(relative, ".") ? relative : "",
                         strcmp(relative, ".") ? "/" : "", e->d_name);
        struct stat st;
        tree_diagnostic_path(c, image, rel);
        if (n < 0 || (size_t)n >= sizeof(rel) ||
            toston_fstatat(fd, e->d_name, &st, AT_SYMLINK_NOFOLLOW)) { ok = false; break; }
        if (S_ISDIR(st.st_mode)) {
            int child = depth < PAIR_TREE_DEPTH
                ? toston_openat(fd, e->d_name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW, 0) : -1;
            struct stat opened, closed;
            ok = child >= 0 && !fstat(child, &opened) && stat_same(&st, &opened, "path_before/open_fd") &&
                 walk_tree(child, rel, depth + 1, c, image, tree);
            tree_diagnostic_path(c, image, rel);
            ok = ok && !toston_fstatat(fd, e->d_name, &closed, AT_SYMLINK_NOFOLLOW) &&
                 stat_same(&st, &closed, "path_before/path_after");
            if (child >= 0 && close(child)) ok = false;
        } else if (S_ISREG(st.st_mode)) {
            uint64_t size; char hash[65];
            ok = hash_at(fd, e->d_name, &size, hash) &&
                 add_entry(tree, c, image, rel, false, size, hash);
        } else { diagnostic_type(&st, false); ok = false; }
        if (!ok) break;
    }
    if (closedir(d)) ok = false;
    tree_diagnostic_path(c, image, relative);
    return ok && !fstat(fd, &after) && stat_same(&before, &after, "open_fd/closed_fd");
}

static bool collect_tree(int title_fd, const paired_capture_t* c, tree_t* tree) {
    for (size_t i = 0; i < c->image_count; i++) {
        bool service; const char* slot;
        if (!image_role(c->images[i].name, &service, &slot)) return false;
        if (service) continue;
        struct stat before, opened, after;
        tree_diagnostic_path(c, i, ".");
        if (toston_fstatat(title_fd, c->images[i].name, &before, AT_SYMLINK_NOFOLLOW) ||
            !diagnostic_type(&before, true)) return false;
        int child = toston_openat(title_fd, c->images[i].name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW, 0);
        bool ok = child >= 0 && !fstat(child, &opened) && stat_same(&before, &opened, "path_before/open_fd") &&
                  walk_tree(child, ".", 0, c, i, tree);
        tree_diagnostic_path(c, i, ".");
        ok = ok && !toston_fstatat(title_fd, c->images[i].name, &after, AT_SYMLINK_NOFOLLOW) &&
                  stat_same(&before, &after, "path_before/path_after");
        if (child >= 0 && close(child)) ok = false;
        if (!ok) return false;
    }
    qsort(tree->entries, tree->count, sizeof(*tree->entries), entry_compare);
    return tree->count != 0;
}

/* Pair roots have only active Portable trees and their fixed metadata. */
static bool title_shape(int title_fd, const paired_capture_t* c) {
    int listing = dup(title_fd); DIR* d = listing >= 0 ? fdopendir(listing) : NULL;
    if (!d) { if (listing >= 0) close(listing); return false; }
    bool ok = true;
    for (;;) {
        errno = 0; struct dirent* e = readdir(d);
        if (!e) { if (errno) ok = false; break; }
        if (!strcmp(e->d_name, ".") || !strcmp(e->d_name, "..")) continue;
        struct stat st;
        if (toston_fstatat(title_fd, e->d_name, &st, AT_SYMLINK_NOFOLLOW)) { ok = false; break; }
        if (!strcmp(e->d_name, "manifest.json") || !strcmp(e->d_name, "checksums.json"))
            ok = diagnostic_type(&st, false);
        else if (!strcmp(e->d_name, ".capture")) ok = diagnostic_type(&st, true);
        else {
            bool found = false;
            for (size_t i = 0; i < c->image_count; i++) {
                bool service; const char* slot;
                if (image_role(c->images[i].name, &service, &slot) && !service &&
                    !strcmp(e->d_name, c->images[i].name)) found = true;
            }
            ok = found && diagnostic_type(&st, true);
            if (!found) {
                paired_capture_stage_diagnostic_t* s = diagnostic_failure("unexpected_entry", true, 0, 0,
                    "active tree or fixed metadata", diagnostic_mode_name(st.st_mode));
                if (s) { s->mode_valid = true; s->observed_mode = st.st_mode; }
            }
        }
        if (!ok) break;
    }
    if (closedir(d)) ok = false;
    return ok;
}

static bool capture_shape(int capture_fd, bool descriptor) {
    int listing = dup(capture_fd); DIR* d = listing >= 0 ? fdopendir(listing) : NULL;
    if (!d) { if (listing >= 0) close(listing); return false; }
    bool ok = true; unsigned seen = 0;
    for (;;) {
        errno = 0; struct dirent* e = readdir(d);
        if (!e) { if (errno) ok = false; break; }
        if (!strcmp(e->d_name, ".") || !strcmp(e->d_name, "..")) continue;
        unsigned bit = !strcmp(e->d_name, "raw.zip") ? 1 :
                       descriptor && !strcmp(e->d_name, "capture.json") ? 2 : 0;
        struct stat st;
        if (toston_fstatat(capture_fd, e->d_name, &st, AT_SYMLINK_NOFOLLOW)) { ok = false; break; }
        if (!bit || (seen & bit)) {
            paired_capture_stage_diagnostic_t* s = diagnostic_failure("unexpected_entry", true, 0, 0,
                descriptor ? "raw.zip and capture.json" : "raw.zip only", diagnostic_mode_name(st.st_mode));
            if (s) { s->mode_valid = true; s->observed_mode = st.st_mode; }
            ok = false; break;
        }
        if (!diagnostic_type(&st, false)) { ok = false; break; }
        seen |= bit;
    }
    if (closedir(d)) ok = false;
    if (ok && seen != (descriptor ? 3U : 1U)) {
        paired_capture_stage_diagnostic_t* s = diagnostic_failure("inventory", true, 0, 0,
            descriptor ? "raw.zip and capture.json" : "raw.zip only", "required entry missing");
        if (s) { s->values_valid = true; s->expected_value = descriptor ? 3 : 1; s->observed_value = seen; }
    }
    return ok && seen == (descriptor ? 3U : 1U);
}

static bool raw_closed(int capture_fd, const paired_capture_t* c) {
    bool prior_failure = diagnostic_context && diagnostic_context->diagnostic &&
        diagnostic_context->diagnostic->stages[diagnostic_context->stage].state == PAIR_DIAG_FAIL;
    uint64_t size; char hash[65];
    bool read_ok = hash_at(capture_fd, "raw.zip", &size, hash);
    bool ok = read_ok && size == c->raw_zip_size && !strcmp(hash, c->raw_zip_sha256);
    if (!ok) {
        diagnostic_failure("raw_binding", true, 0, 0, "declared closed RAW", "size or SHA differ");
        if (!prior_failure && diagnostic_context && diagnostic_context->diagnostic) {
            paired_capture_stage_diagnostic_t* s = &diagnostic_context->diagnostic->stages[diagnostic_context->stage];
            s->expected_raw_size = c->raw_zip_size;
            snprintf(s->expected_raw_sha256, sizeof(s->expected_raw_sha256), "%s", c->raw_zip_sha256);
            if (read_ok) { s->raw_size_valid = true; s->observed_raw_size = size;
                snprintf(s->observed_raw_sha256, sizeof(s->observed_raw_sha256), "%s", hash); }
        }
    }
    return ok;
}

static bool acquisition(const char* title_root, const paired_capture_t* c,
                        int* title, int* capture, tree_t* tree) {
    diagnostic_begin(PAIR_DIAG_OPEN_TITLE, "");
    *title = open(title_root, O_RDONLY | O_DIRECTORY | O_NOFOLLOW); int saved = errno;
    if (*title < 0) diagnostic_failure("open", true, *title, saved, "title directory", "call failed");
    diagnostic_end(*title >= 0);
    if (*title >= 0) {
        diagnostic_begin(PAIR_DIAG_OPEN_CAPTURE, ".capture");
        *capture = toston_openat(*title, ".capture", O_RDONLY | O_DIRECTORY | O_NOFOLLOW, 0);
        diagnostic_end(*capture >= 0);
    } else diagnostic_skip(PAIR_DIAG_OPEN_CAPTURE);
    diagnostic_begin(PAIR_DIAG_ALLOCATION, "");
    tree->entries = calloc(PAIRED_CAPTURE_MAX_ENTRIES, sizeof(*tree->entries)); saved = errno;
    if (!tree->entries) diagnostic_failure("calloc", true, 0, saved, "tree allocation", "NULL");
    diagnostic_end(tree->entries != NULL);
    bool title_ok = false, capture_ok = false, raw_ok = false, tree_ok = false;
    if (*title >= 0) { diagnostic_begin(PAIR_DIAG_TITLE_SHAPE, ""); title_ok = diagnostic_end(title_shape(*title, c)); }
    else diagnostic_skip(PAIR_DIAG_TITLE_SHAPE);
    if (*capture >= 0) {
        diagnostic_begin(PAIR_DIAG_CAPTURE_SHAPE, ".capture"); capture_ok = diagnostic_end(capture_shape(*capture, false));
        diagnostic_begin(PAIR_DIAG_RAW_CLOSED, ".capture/raw.zip"); raw_ok = diagnostic_end(raw_closed(*capture, c));
    } else { diagnostic_skip(PAIR_DIAG_CAPTURE_SHAPE); diagnostic_skip(PAIR_DIAG_RAW_CLOSED); }
    if (*title >= 0 && tree->entries) {
        diagnostic_begin(PAIR_DIAG_COLLECT_TREE, "");
        if (diagnostic_context && diagnostic_context->diagnostic) {
            diagnostic_context->diagnostic->tree_entries = diagnostic_context->diagnostic->tree_files =
                diagnostic_context->diagnostic->tree_directories = 0;
            diagnostic_context->diagnostic->maximum_depth = 0;
        }
        tree_ok = diagnostic_end(collect_tree(*title, c, tree));
    } else diagnostic_skip(PAIR_DIAG_COLLECT_TREE);
    return *title >= 0 && *capture >= 0 && tree->entries && title_ok && capture_ok && raw_ok && tree_ok;
}

bool paired_capture_probe_readonly(const char* title_root, const paired_capture_t* c,
                                  paired_capture_diagnostic_t* d) {
    diagnostic_context_t context = {.diagnostic = d, .stage = PAIR_DIAG_OPEN_TITLE};
    diagnostic_context_t* previous = diagnostic_context; diagnostic_context = &context;
#ifdef PAIRED_CAPTURE_READONLY_PROBE
    if (clock_gettime(CLOCK_MONOTONIC, &context.deadline)) memset(&context.deadline, 0, sizeof(context.deadline));
    else context.deadline.tv_sec += 20;
#endif
    int title = -1, capture = -1; tree_t tree = {0};
    const char* leaf = title_root ? strrchr(title_root, '/') : NULL; leaf = leaf ? leaf + 1 : title_root;
    bool ok = title_root && record_ok(c) && !strcmp(leaf, c->title_id);
    if (ok) ok = acquisition(title_root, c, &title, &capture, &tree);
    else { diagnostic_begin(PAIR_DIAG_DESCRIPTOR_PARSE, ""); diagnostic_end(false); }
    free(tree.entries);
    if (capture >= 0) { diagnostic_begin(PAIR_DIAG_CLOSE_CAPTURE, ".capture"); if (!diagnostic_end(!close(capture))) ok = false; }
    if (title >= 0) { diagnostic_begin(PAIR_DIAG_CLOSE_TITLE, ""); if (!diagnostic_end(!close(title))) ok = false; }
    diagnostic_context = previous; return ok;
}

#ifndef PAIRED_CAPTURE_READONLY_PROBE

static bool quoted(FILE* f, const char* s) {
    if (fputc('"', f) == EOF) return false;
    for (const unsigned char* p = (const unsigned char*)s; *p; p++) {
        if ((*p == '"' || *p == '\\') && fputc('\\', f) == EOF) return false;
        if (fputc(*p, f) == EOF) return false;
    }
    return fputc('"', f) != EOF;
}

static bool write_descriptor(FILE* f, const paired_capture_t* c, const tree_t* tree) {
    fputs("{\"format\":\"tostonsync.capture_pair\",\"format_version\":1,\"capture_id\":", f);
    quoted(f, c->capture_id); fputs(",\"producer_version\":", f); quoted(f, c->producer_version);
    fputs(",\"title_id\":", f); quoted(f, c->title_id);
    fputs(",\"source_uid\":", f); quoted(f, c->source_uid);
    fprintf(f, ",\"started_at\":%lld,\"finished_at\":%lld,"
            "\"acquisition_stable_observed\":true,\"atomic_snapshot\":false,"
            "\"raw_zip\":{\"path\":\"raw.zip\",\"size\":%llu,\"sha256\":",
            (long long)c->started_at, (long long)c->finished_at,
            (unsigned long long)c->raw_zip_size);
    quoted(f, c->raw_zip_sha256); fputs("},\"images\":[", f);
    for (size_t i = 0; i < c->image_count; i++) {
        bool service; const char* slot; image_role(c->images[i].name, &service, &slot);
        if (i) fputc(',', f);
        fputs("{\"name\":", f); quoted(f, c->images[i].name);
        fprintf(f, ",\"role\":\"%s\",\"size\":%llu,\"sha256\":",
                service ? "service" : "active", (unsigned long long)c->images[i].size);
        quoted(f, c->images[i].sha256); fputc('}', f);
    }
    fputs("],\"portable\":[", f); bool first_slot = true;
    for (size_t i = 0; i < c->image_count; i++) {
        bool service; const char* slot; image_role(c->images[i].name, &service, &slot);
        if (service) continue;
        if (!first_slot) fputc(',', f);
        first_slot = false;
        fputs("{\"source_image\":", f); quoted(f, c->images[i].name); fputs(",\"entries\":[", f);
        bool first = true;
        for (size_t j = 0; j < tree->count; j++) {
            const tree_entry_t* e = &tree->entries[j]; if (e->image != i) continue;
            if (!first) fputc(',', f);
            first = false;
            fputs("{\"path\":", f); quoted(f, e->path);
            if (e->directory) fputs(",\"type\":\"directory\"}", f);
            else {
                fprintf(f, ",\"type\":\"file\",\"size\":%llu,\"sha256\":", (unsigned long long)e->size);
                quoted(f, e->sha256); fputc('}', f);
            }
        }
        fputs("]}", f);
    }
    fputs("]}\n", f);
    return !ferror(f);
}

bool paired_capture_write_diagnostic(const char* title_root, const paired_capture_t* c,
                          char* error, size_t error_sz, paired_capture_diagnostic_t* d) {
    diagnostic_context_t context = {.diagnostic = d, .stage = PAIR_DIAG_DESCRIPTOR_PARSE};
    diagnostic_context_t* previous = diagnostic_context; diagnostic_context = &context;
    if (error && error_sz) error[0] = 0;
    const char* leaf = title_root ? strrchr(title_root, '/') : NULL;
    leaf = leaf ? leaf + 1 : title_root;
    if (!title_root || !record_ok(c) || strcmp(leaf, c->title_id)) {
        diagnostic_end(false); diagnostic_context = previous;
        return fail(error, error_sz, "Invalid capture provenance or image declaration");
    }
    int title = -1, capture = -1; tree_t tree = {0};
    bool ok = acquisition(title_root, c, &title, &capture, &tree);
    int fd = -1; FILE* f = NULL;
    if (ok) {
        diagnostic_begin(PAIR_DIAG_CREATE_EXCL, ".capture/capture.json");
        fd = toston_openat(capture, "capture.json", O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW, 0600);
        ok = diagnostic_end(fd >= 0);
    } else diagnostic_skip(PAIR_DIAG_CREATE_EXCL);
    if (fd >= 0) {
        diagnostic_begin(PAIR_DIAG_FDOPEN, ".capture/capture.json");
        f = fdopen(fd, "wb"); int saved = errno;
        if (!f) diagnostic_failure("fdopen", true, 0, saved, "stream", "NULL");
        ok = diagnostic_end(f != NULL);
        if (!f) close(fd);
    } else diagnostic_skip(PAIR_DIAG_FDOPEN);
    if (f) {
        diagnostic_begin(PAIR_DIAG_WRITE, ".capture/capture.json"); ok = diagnostic_end(write_descriptor(f, c, &tree));
        if (ok) {
            diagnostic_begin(PAIR_DIAG_FFLUSH, ".capture/capture.json"); int rc = fflush(f); int saved = errno;
            if (rc) diagnostic_failure("fflush", true, rc, rc < 0 ? saved : 0, "return 0", "call failed");
            ok = diagnostic_end(!rc);
        } else diagnostic_skip(PAIR_DIAG_FFLUSH);
        struct stat st;
        if (ok) {
            diagnostic_begin(PAIR_DIAG_DESCRIPTOR_STAT, ".capture/capture.json");
            ok = !fstat(fileno(f), &st);
            if (ok) {
                ok = st.st_size >= 2 && (uint64_t)st.st_size <= PAIRED_CAPTURE_JSON_MAX &&
                    c->raw_zip_size <= PAIR_BYTES_MAX - tree.bytes &&
                    (uint64_t)st.st_size <= PAIR_BYTES_MAX - tree.bytes - c->raw_zip_size;
                if (!ok) {
                    paired_capture_stage_diagnostic_t* s = diagnostic_failure("limits", true, 0, 0,
                        "descriptor and pair byte bounds", "outside bounds");
                    if (s) { s->values_valid = true; s->expected_value = PAIRED_CAPTURE_JSON_MAX; s->observed_value = st.st_size; }
                }
            }
            diagnostic_end(ok);
        } else diagnostic_skip(PAIR_DIAG_DESCRIPTOR_STAT);
        if (ok) {
            diagnostic_begin(PAIR_DIAG_FSYNC_FILE, ".capture/capture.json"); int rc = fsync(fileno(f)); int saved = errno;
            if (rc) diagnostic_failure("fsync", true, rc, rc < 0 ? saved : 0, "return 0", "call failed");
            ok = diagnostic_end(!rc);
        } else diagnostic_skip(PAIR_DIAG_FSYNC_FILE);
        diagnostic_begin(PAIR_DIAG_FCLOSE, ".capture/capture.json"); int rc = fclose(f); int saved = errno;
        if (rc) diagnostic_failure("fclose", true, rc, rc < 0 ? saved : 0, "return 0", "call failed");
        if (!diagnostic_end(!rc)) ok = false;
        if (ok) {
            diagnostic_begin(PAIR_DIAG_FSYNC_DIRECTORY, ".capture"); rc = fsync(capture); saved = errno;
            if (rc) diagnostic_failure("fsync", true, rc, rc < 0 ? saved : 0, "return 0", "call failed");
            ok = diagnostic_end(!rc);
        } else diagnostic_skip(PAIR_DIAG_FSYNC_DIRECTORY);
    } else for (unsigned i = PAIR_DIAG_WRITE; i <= PAIR_DIAG_FSYNC_DIRECTORY; i++) diagnostic_skip((paired_capture_stage_t)i);
    free(tree.entries);
    if (capture >= 0) { diagnostic_begin(PAIR_DIAG_CLOSE_CAPTURE, ".capture"); if (!diagnostic_end(!close(capture))) ok = false; }
    else diagnostic_skip(PAIR_DIAG_CLOSE_CAPTURE);
    if (title >= 0) { diagnostic_begin(PAIR_DIAG_CLOSE_TITLE, ""); if (!diagnostic_end(!close(title))) ok = false; }
    else diagnostic_skip(PAIR_DIAG_CLOSE_TITLE);
    diagnostic_context = previous;
    return ok || fail(error, error_sz, "Capture descriptor acquisition, inventory or durable write failed; partial evidence retained");
}

bool paired_capture_write(const char* root, const paired_capture_t* c, char* error, size_t size) {
    return paired_capture_write_diagnostic(root, c, error, size, NULL);
}

static bool parse_raw_zip(reader_t* r, paired_capture_t* c) {
    const char* const keys[] = {"path", "size", "sha256"}; uint64_t seen = 0; bool more = true;
    if (!token(r, '{')) return false;
    while (more) {
        size_t i; char path[32];
        if (!field(r, keys, 3, &seen, &i)) return false;
        if (i == 0 && (!string(r, path, sizeof(path)) || strcmp(path, "raw.zip"))) return false;
        if (i == 1 && !number(r, &c->raw_zip_size)) return false;
        if (i == 2 && !string(r, c->raw_zip_sha256, sizeof(c->raw_zip_sha256))) return false;
        if (!next(r, '}', &more)) return false;
    }
    return seen == 7;
}

static bool parse_image(reader_t* r, paired_capture_image_t* image) {
    const char* const keys[] = {"name", "role", "size", "sha256"}; uint64_t seen = 0; bool more = true;
    char role[16] = {0};
    if (!token(r, '{')) return false;
    while (more) {
        size_t i; if (!field(r, keys, 4, &seen, &i)) return false;
        if (i == 0 && !string(r, image->name, sizeof(image->name))) return false;
        if (i == 1 && !string(r, role, sizeof(role))) return false;
        if (i == 2 && !number(r, &image->size)) return false;
        if (i == 3 && !string(r, image->sha256, sizeof(image->sha256))) return false;
        if (!next(r, '}', &more)) return false;
    }
    bool service; const char* slot;
    return seen == 15 && image_role(image->name, &service, &slot) &&
           !strcmp(role, service ? "service" : "active");
}

static bool parse_images(reader_t* r, paired_capture_t* c) {
    bool more = true; if (!token(r, '[')) return false;
    while (more) {
        if (c->image_count == PAIRED_CAPTURE_MAX_IMAGES ||
            !parse_image(r, &c->images[c->image_count++]) || !next(r, ']', &more)) return false;
    }
    return c->image_count != 0;
}

static bool relative_ok(const char* path, bool directory) {
    if (!strcmp(path, ".")) return directory;
    if (!path[0] || !utf8_ok(path) || strchr(path, '\\') || path[0] == '/') return false;
    const char* p = path;
    while (*p) {
        const char* slash = strchr(p, '/'); size_t n = slash ? (size_t)(slash - p) : strlen(p);
        if (!n || (n == 1 && *p == '.') || (n == 2 && !memcmp(p, "..", 2))) return false;
        if (!slash) break;
        p = slash + 1; if (!*p) return false;
    }
    return true;
}

static bool parse_entry(reader_t* r, tree_entry_t* e) {
    const char* const keys[] = {"path", "type", "size", "sha256"}; uint64_t seen = 0; bool more = true;
    char type[16] = {0};
    if (!token(r, '{')) return false;
    while (more) {
        size_t i; if (!field(r, keys, 4, &seen, &i)) return false;
        if (i == 0 && !string(r, e->path, sizeof(e->path))) return false;
        if (i == 1 && !string(r, type, sizeof(type))) return false;
        if (i == 2 && !number(r, &e->size)) return false;
        if (i == 3 && !string(r, e->sha256, sizeof(e->sha256))) return false;
        if (!next(r, '}', &more)) return false;
    }
    e->directory = !strcmp(type, "directory");
    return relative_ok(e->path, e->directory) &&
           (e->directory ? seen == 3 : seen == 15 && !strcmp(type, "file") && hash_ok(e->sha256));
}

/* Portable groups may precede images in JSON; resolve their literal name later. */
typedef struct { char name[128]; size_t begin, count; } group_t;
static bool parse_portable(reader_t* r, tree_t* tree, group_t groups[32], size_t* count) {
    const char* const keys[] = {"source_image", "entries"}; bool more = true;
    if (!token(r, '[')) return false;
    while (more) {
        if (*count == PAIRED_CAPTURE_MAX_ACTIVE || !token(r, '{')) return false;
        group_t* group = &groups[(*count)++]; uint64_t seen = 0; bool fields = true;
        while (fields) {
            size_t i; if (!field(r, keys, 2, &seen, &i)) return false;
            if (i == 0 && !string(r, group->name, sizeof(group->name))) return false;
            if (i == 1) {
                if (!token(r, '[')) return false;
                group->begin = tree->count; bool entries = true;
                while (entries) {
                    if (tree->count == PAIRED_CAPTURE_MAX_ENTRIES ||
                        !parse_entry(r, &tree->entries[tree->count++]) || !next(r, ']', &entries)) return false;
                }
                group->count = tree->count - group->begin;
            }
            if (!next(r, '}', &fields)) return false;
        }
        if (seen != 3 || !group->count || !next(r, ']', &more)) return false;
    }
    return *count != 0;
}

static bool parse_descriptor(const char* text, paired_capture_t* c, tree_t* tree) {
    const char* const keys[] = {"format", "format_version", "capture_id", "producer_version",
        "title_id", "source_uid", "started_at", "finished_at", "acquisition_stable_observed",
        "atomic_snapshot", "raw_zip", "images", "portable"};
    reader_t r = {text}; uint64_t seen = 0; bool more = true;
    group_t groups[32] = {{0}}; size_t count = 0;
    if (!token(&r, '{')) return false;
    while (more) {
        size_t i; uint64_t value; char format[48];
        if (!field(&r, keys, 13, &seen, &i)) return false;
        switch (i) {
            case 0: if (!string(&r, format, sizeof(format)) || strcmp(format, "tostonsync.capture_pair")) return false; break;
            case 1: if (!number(&r, &value) || value != 1) return false; break;
            case 2: if (!string(&r, c->capture_id, sizeof(c->capture_id))) return false; break;
            case 3: if (!string(&r, c->producer_version, sizeof(c->producer_version))) return false; break;
            case 4: if (!string(&r, c->title_id, sizeof(c->title_id))) return false; break;
            case 5: if (!string(&r, c->source_uid, sizeof(c->source_uid))) return false; break;
            case 6: if (!number(&r, &value) || value > INT64_MAX) return false; c->started_at = (int64_t)value; break;
            case 7: if (!number(&r, &value) || value > INT64_MAX) return false; c->finished_at = (int64_t)value; break;
            case 8: if (!literal(&r, "true")) return false; break;
            case 9: if (!literal(&r, "false")) return false; break;
            case 10: if (!parse_raw_zip(&r, c)) return false; break;
            case 11: if (!parse_images(&r, c)) return false; break;
            case 12: if (!parse_portable(&r, tree, groups, &count)) return false; break;
        }
        if (!next(&r, '}', &more)) return false;
    }
    ws(&r); if (*r.p || seen != 8191 || !record_ok(c)) return false;
    size_t active = 0; bool represented[64] = {false};
    for (size_t i = 0; i < c->image_count; i++) {
        bool service; const char* slot; image_role(c->images[i].name, &service, &slot);
        if (!service) active++;
    }
    if (active != count) return false;
    for (size_t g = 0; g < count; g++) {
        size_t image = c->image_count;
        for (size_t i = 0; i < c->image_count; i++)
            if (!strcmp(groups[g].name, c->images[i].name)) image = i;
        bool service; const char* slot;
        if (image == c->image_count || represented[image] ||
            !image_role(c->images[image].name, &service, &slot) || service) return false;
        represented[image] = true;
        for (size_t j = groups[g].begin; j < groups[g].begin + groups[g].count; j++) {
            tree_entry_t* e = &tree->entries[j]; e->image = image;
            if (strlen(c->title_id) + strlen(c->images[image].name) +
                    (strcmp(e->path, ".") ? strlen(e->path) + 2 : 1) >= 260 ||
                e->size > PAIR_BYTES_MAX - tree->bytes) return false;
            tree->bytes += e->size;
        }
    }
    qsort(tree->entries, tree->count, sizeof(*tree->entries), entry_compare);
    for (size_t i = 1; i < tree->count; i++)
        if (!entry_compare(&tree->entries[i - 1], &tree->entries[i])) return false;
    return c->raw_zip_size <= PAIR_BYTES_MAX - tree->bytes;
}

bool paired_capture_validate_title_diagnostic(const char* title_root, paired_capture_t* out,
                                   bool* present, char* error, size_t error_sz, paired_capture_diagnostic_t* d) {
    diagnostic_context_t context = {.diagnostic = d, .stage = PAIR_DIAG_OPEN_TITLE};
    diagnostic_context_t* previous = diagnostic_context; diagnostic_context = &context;
    if (present) *present = false;
    if (error && error_sz) error[0] = 0;
    if (out) memset(out, 0, sizeof(*out));
    if (!title_root) { diagnostic_end(false); diagnostic_context = previous; return fail(error, error_sz, "Capture title root is missing"); }
    int title = open(title_root, O_RDONLY | O_DIRECTORY | O_NOFOLLOW);
    int saved = errno;
    if (title < 0) { diagnostic_failure("open", true, title, saved, "title directory", "call failed");
        diagnostic_context = previous; return fail(error, error_sz, "Capture title root is unsafe or unreadable"); }
    diagnostic_end(true); diagnostic_begin(PAIR_DIAG_OPEN_CAPTURE, ".capture");
    struct stat st; int rc = diagnostic_optional_stat(title, ".capture", &st, &saved);
    if (rc && saved == ENOENT) {
        diagnostic_skip(PAIR_DIAG_OPEN_CAPTURE); diagnostic_begin(PAIR_DIAG_CLOSE_TITLE, ""); diagnostic_end(!close(title));
        diagnostic_context = previous; return true;
    }
    if (present) *present = true;
    int capture = !rc && diagnostic_type(&st, true)
        ? toston_openat(title, ".capture", O_RDONLY | O_DIRECTORY | O_NOFOLLOW, 0) : -1;
    diagnostic_end(capture >= 0);
    bool shape_ok = false;
    if (capture >= 0) { diagnostic_begin(PAIR_DIAG_CAPTURE_SHAPE, ".capture"); shape_ok = diagnostic_end(capture_shape(capture, true)); }
    else diagnostic_skip(PAIR_DIAG_CAPTURE_SHAPE);
    char* text = NULL;
    if (capture >= 0) { diagnostic_begin(PAIR_DIAG_DESCRIPTOR_READ, ".capture/capture.json");
        text = read_at(capture, "capture.json", PAIRED_CAPTURE_JSON_MAX); diagnostic_end(text != NULL); }
    else diagnostic_skip(PAIR_DIAG_DESCRIPTOR_READ);
    paired_capture_t c = {0}; tree_t expected = {0}, actual = {0};
    diagnostic_begin(PAIR_DIAG_ALLOCATION, "");
    expected.entries = calloc(PAIRED_CAPTURE_MAX_ENTRIES, sizeof(*expected.entries));
    saved = errno; if (!expected.entries) diagnostic_failure("calloc", true, 0, saved, "expected tree allocation", "NULL");
    actual.entries = calloc(PAIRED_CAPTURE_MAX_ENTRIES, sizeof(*actual.entries));
    saved = errno; if (!actual.entries) diagnostic_failure("calloc", true, 0, saved, "actual tree allocation", "NULL");
    diagnostic_end(expected.entries && actual.entries);
    const char* leaf = strrchr(title_root, '/'); leaf = leaf ? leaf + 1 : title_root;
    bool parsed = false;
    if (text && expected.entries) { diagnostic_begin(PAIR_DIAG_DESCRIPTOR_PARSE, ".capture/capture.json");
        parsed = diagnostic_end(parse_descriptor(text, &c, &expected)); }
    else diagnostic_skip(PAIR_DIAG_DESCRIPTOR_PARSE);
    bool provenance_ok = false, title_ok = false, raw_ok = false, tree_ok = false;
    if (parsed) {
        diagnostic_begin(PAIR_DIAG_PORTABLE_PROVENANCE, "manifest.json");
        provenance_ok = diagnostic_end(!strcmp(leaf, c.title_id) && portable_provenance(title, &c));
        diagnostic_begin(PAIR_DIAG_TITLE_SHAPE, ""); title_ok = diagnostic_end(title_shape(title, &c));
        if (capture >= 0) { diagnostic_begin(PAIR_DIAG_RAW_CLOSED, ".capture/raw.zip"); raw_ok = diagnostic_end(raw_closed(capture, &c)); }
        else diagnostic_skip(PAIR_DIAG_RAW_CLOSED);
        if (actual.entries) {
            diagnostic_begin(PAIR_DIAG_COLLECT_TREE, "");
            if (d) { d->tree_entries = d->tree_files = d->tree_directories = 0; d->maximum_depth = 0; }
            tree_ok = diagnostic_end(collect_tree(title, &c, &actual));
        } else diagnostic_skip(PAIR_DIAG_COLLECT_TREE);
    } else {
        diagnostic_skip(PAIR_DIAG_PORTABLE_PROVENANCE); diagnostic_skip(PAIR_DIAG_TITLE_SHAPE);
        diagnostic_skip(PAIR_DIAG_RAW_CLOSED); diagnostic_skip(PAIR_DIAG_COLLECT_TREE);
    }
    diagnostic_begin(PAIR_DIAG_TREE_COMPARE, "");
    bool ok = shape_ok && parsed && actual.entries && provenance_ok && title_ok && raw_ok && tree_ok &&
              expected.count == actual.count && expected.bytes == actual.bytes;
    for (size_t i = 0; ok && i < expected.count; i++) {
        const tree_entry_t* a = &actual.entries[i]; const tree_entry_t* e = &expected.entries[i];
        ok = !entry_compare(a, e) && a->directory == e->directory && a->size == e->size &&
             !strcmp(a->sha256, e->sha256);
    }
    if (ok && (uint64_t)strlen(text) > PAIR_BYTES_MAX - expected.bytes - c.raw_zip_size) ok = false;
    if (shape_ok && parsed && actual.entries && provenance_ok && title_ok && raw_ok && tree_ok) diagnostic_end(ok);
    else diagnostic_skip(PAIR_DIAG_TREE_COMPARE);
    if (ok) {
        diagnostic_begin(PAIR_DIAG_DESCRIPTOR_READ, ".capture/capture.json");
        sha256_ctx_t ctx; unsigned char digest[32]; char parsed_hash[65]; uint64_t size;
        sha256_init(&ctx); sha256_update(&ctx, text, strlen(text)); sha256_final(&ctx, digest);
        for (size_t i = 0; i < 32; i++) snprintf(parsed_hash + i * 2, 3, "%02x", digest[i]);
        ok = hash_at(capture, "capture.json", &size, c.descriptor_sha256) &&
             size == strlen(text) && !strcmp(parsed_hash, c.descriptor_sha256);
        diagnostic_end(ok);
    }
    free(text); free(expected.entries); free(actual.entries);
    if (capture >= 0) { diagnostic_begin(PAIR_DIAG_CLOSE_CAPTURE, ".capture"); if (!diagnostic_end(!close(capture))) ok = false; }
    else diagnostic_skip(PAIR_DIAG_CLOSE_CAPTURE);
    diagnostic_begin(PAIR_DIAG_CLOSE_TITLE, ""); if (!diagnostic_end(!close(title))) ok = false;
    if (ok && out) *out = c;
    diagnostic_context = previous;
    return ok || fail(error, error_sz, "Reserved capture descriptor, literal tree or closed RAW binding is invalid");
}

bool paired_capture_validate_title(const char* root, paired_capture_t* out, bool* present, char* error, size_t size) {
    return paired_capture_validate_title_diagnostic(root, out, present, error, size, NULL);
}

static bool image_index(const paired_capture_t* c, const char* name, size_t* index) {
    for (size_t i = 0; i < c->image_count; i++) if (!strcmp(c->images[i].name, name)) { *index = i; return true; }
    return false;
}

static bool raw_array(reader_t* r, const paired_capture_t* c, bool images, size_t* count) {
    bool more = true, seen[64] = {false}; *count = 0;
    if (!token(r, '[')) return false;
    while (more) {
        char value[128]; size_t index = c->image_count;
        if (!string(r, value, sizeof(value))) return false;
        if (images) { if (!image_index(c, value, &index)) return false; }
        else for (size_t i = 0; i < c->image_count; i++) {
            bool service; const char* slot; image_role(c->images[i].name, &service, &slot);
            if (!service && !strcmp(slot, value)) index = i;
        }
        if (index == c->image_count || seen[index]) return false;
        seen[index] = true; (*count)++;
        if (!next(r, ']', &more)) return false;
    }
    size_t expected = 0;
    for (size_t i = 0; i < c->image_count; i++) {
        bool service; const char* slot; image_role(c->images[i].name, &service, &slot);
        if (images || !service) expected++;
    }
    return *count == expected;
}

/* Strict direct fields, never the tiny JSON module's substring key lookup. */
static bool raw_manifest(const char* text, const paired_capture_t* c) {
    const char* const keys[] = {"format", "format_version", "tostonsync_version", "title_id",
        "user_uid", "platform", "backup_type", "trigger", "created_at_utc", "created_at_epoch",
        "backup_scope", "partial", "complete_recovery", "raw_completeness", "available_slots",
        "selected_slots_count", "active_images", "service_images", "total_size", "selected_slots",
        "included_images", "capture_id", "source_user_uid", "portable_status", "portable_error"};
    reader_t r = {text}; uint64_t seen = 0; bool more = true;
    size_t active = 0, services = 0; uint64_t total = 0;
    for (size_t i = 0; i < c->image_count; i++) {
        bool service; const char* slot; image_role(c->images[i].name, &service, &slot);
        if (service) services++; else active++;
        if (c->images[i].size > UINT64_MAX - total) return false;
        total += c->images[i].size;
    }
    if (!token(&r, '{')) return false;
    while (more) {
        size_t i, count; uint64_t n; char value[256];
        if (!field(&r, keys, 25, &seen, &i)) return false;
        switch (i) {
            case 0: if (!string(&r, value, sizeof(value)) || strcmp(value, "tostonsync.encrypted_image")) return false; break;
            case 1: if (!number(&r, &n) || n != 1) return false; break;
            case 2: if (!string(&r, value, sizeof(value)) || strcmp(value, c->producer_version)) return false; break;
            case 3: if (!string(&r, value, sizeof(value)) || strcmp(value, c->title_id)) return false; break;
            case 4: case 22: if (!string(&r, value, sizeof(value)) || strcmp(value, c->source_uid)) return false; break;
            case 5: if (!string(&r, value, sizeof(value)) || strcmp(value, "ps5")) return false; break;
            case 6: if (!string(&r, value, sizeof(value)) || strcmp(value, "RAW")) return false; break;
            case 9: if (!number(&r, &n) || n != (uint64_t)c->started_at) return false; break;
            case 10: if (!string(&r, value, sizeof(value)) || strcmp(value, "selected_containers")) return false; break;
            case 11: if (!literal(&r, "true")) return false; break;
            case 12: if (!literal(&r, "false")) return false; break;
            case 13: if (!string(&r, value, sizeof(value)) || strcmp(value, "selected_partial")) return false; break;
            case 14: if (!number(&r, &n) || n < active || n > 32) return false; break;
            case 15: case 16: if (!number(&r, &n) || n != active) return false; break;
            case 17: if (!number(&r, &n) || n != services) return false; break;
            case 18: if (!number(&r, &n) || n != total) return false; break;
            case 19: if (!raw_array(&r, c, false, &count)) return false; break;
            case 20: if (!raw_array(&r, c, true, &count)) return false; break;
            case 21: if (!string(&r, value, sizeof(value)) || strcmp(value, c->capture_id)) return false; break;
            default: if (!string(&r, value, sizeof(value))) return false; break;
        }
        if (!next(&r, '}', &more)) return false;
    }
    ws(&r);
    uint64_t required = (UINT64_C(1) << 0) | (UINT64_C(1) << 1) | (UINT64_C(1) << 2) | (UINT64_C(1) << 3) |
        (UINT64_C(1) << 4) | (UINT64_C(1) << 5) | (UINT64_C(1) << 6) |
        (UINT64_C(1) << 9) | (UINT64_C(1) << 21) |
        (((UINT64_C(1) << 21) - 1) & ~((UINT64_C(1) << 10) - 1));
    return !*r.p && (seen & required) == required;
}

bool paired_capture_validate_raw_diagnostic(const char* root, const paired_capture_t* c,
                                 char* error, size_t error_sz, paired_capture_diagnostic_t* diagnostic) {
    diagnostic_context_t context = {.diagnostic = diagnostic, .stage = PAIR_DIAG_RAW_MANIFEST};
    diagnostic_context_t* previous = diagnostic_context; diagnostic_context = &context;
    if (error && error_sz) error[0] = 0;
    if (!root || !record_ok(c)) { diagnostic_end(false); diagnostic_context = previous;
        return fail(error, error_sz, "Invalid RAW capture declaration"); }
    diagnostic_begin(PAIR_DIAG_OPEN_TITLE, "");
    int fd = open(root, O_RDONLY | O_DIRECTORY | O_NOFOLLOW);
    int saved = errno; if (fd < 0) diagnostic_failure("open", true, fd, saved, "extracted root", "call failed");
    diagnostic_end(fd >= 0);
    diagnostic_begin(PAIR_DIAG_OPEN_CAPTURE, c->title_id);
    int title = fd >= 0 ? toston_openat(fd, c->title_id, O_RDONLY | O_DIRECTORY | O_NOFOLLOW, 0) : -1;
    if (fd >= 0) diagnostic_end(title >= 0); else diagnostic_skip(PAIR_DIAG_OPEN_CAPTURE);
    bool ok = fd >= 0 && title >= 0;
    diagnostic_begin(PAIR_DIAG_RAW_SHAPE, "");
    int listing = ok ? dup(fd) : -1; DIR* d = listing >= 0 ? fdopendir(listing) : NULL;
    if (!d) { if (listing >= 0) close(listing); ok = false; }
    while (ok) {
        errno = 0; struct dirent* e = readdir(d);
        if (!e) { if (errno) ok = false; break; }
        if (!strcmp(e->d_name, ".") || !strcmp(e->d_name, "..")) continue;
        if (strcmp(e->d_name, c->title_id)) { diagnostic_path(e->d_name);
            diagnostic_failure("unexpected_entry", true, 0, 0, "declared RAW title only", "unexpected entry"); ok = false; }
    }
    if (d && closedir(d)) ok = false;
    listing = ok ? dup(title) : -1; d = listing >= 0 ? fdopendir(listing) : NULL;
    if (!d) { if (listing >= 0) close(listing); ok = false; }
    size_t count = 0; unsigned metadata = 0;
    while (ok) {
        errno = 0; struct dirent* e = readdir(d);
        if (!e) { if (errno) ok = false; break; }
        if (!strcmp(e->d_name, ".") || !strcmp(e->d_name, "..")) continue;
        struct stat st; size_t index;
        if (toston_fstatat(title, e->d_name, &st, AT_SYMLINK_NOFOLLOW) || !diagnostic_type(&st, false)) { ok = false; break; }
        if (!strcmp(e->d_name, "manifest.json")) metadata |= 1;
        else if (!strcmp(e->d_name, "checksums.json")) metadata |= 2;
        else if (image_index(c, e->d_name, &index)) {
            uint64_t size; char hash[65];
            ok = hash_at(title, e->d_name, &size, hash) && size == c->images[index].size &&
                 !strcmp(hash, c->images[index].sha256); count++;
            if (!ok) diagnostic_failure("image_binding", true, 0, 0, "declared image size and SHA", "image differs");
        } else { diagnostic_failure("unexpected_entry", true, 0, 0, "declared image or fixed metadata", "unexpected entry"); ok = false; }
    }
    if (d && closedir(d)) ok = false;
    ok = ok && metadata == 3 && count == c->image_count;
    if (fd >= 0 && title >= 0) diagnostic_end(ok); else diagnostic_skip(PAIR_DIAG_RAW_SHAPE);
    char* json = NULL;
    if (ok) {
        diagnostic_begin(PAIR_DIAG_RAW_MANIFEST, "manifest.json"); json = read_at(title, "manifest.json", 16384);
        ok = diagnostic_end(json && raw_manifest(json, c));
    } else diagnostic_skip(PAIR_DIAG_RAW_MANIFEST);
    free(json);
    if (title >= 0) { diagnostic_begin(PAIR_DIAG_CLOSE_CAPTURE, c->title_id); if (!diagnostic_end(!close(title))) ok = false; }
    else diagnostic_skip(PAIR_DIAG_CLOSE_CAPTURE);
    if (fd >= 0) { diagnostic_begin(PAIR_DIAG_CLOSE_TITLE, ""); if (!diagnostic_end(!close(fd))) ok = false; }
    else diagnostic_skip(PAIR_DIAG_CLOSE_TITLE);
    diagnostic_context = previous;
    return ok || fail(error, error_sz, "Fixed RAW child provenance, roles, literal images or hashes differ from capture");
}
bool paired_capture_validate_raw(const char* root, const paired_capture_t* c, char* error, size_t size) {
    return paired_capture_validate_raw_diagnostic(root, c, error, size, NULL);
}
#endif
