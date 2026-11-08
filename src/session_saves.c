#include "session_saves.h"

#include <dirent.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#define SESSION_PATH_BYTES 1024
#define SESSION_PATH_PARTS 64

typedef struct {
    uint64_t size, device, inode;
    int64_t mtime, mtime_nsec, ctime, ctime_nsec;
    uint32_t mode;
} stat_guard_t;

static bool stat_guard(const struct stat *s, stat_guard_t *out) {
    memset(out, 0, sizeof(*out));
    if (s->st_size < 0 || s->st_mtime < 0 || s->st_ctime < 0) return false;
    out->size = (uint64_t)s->st_size;
    out->device = (uint64_t)s->st_dev;
    out->inode = (uint64_t)s->st_ino;
    out->mtime = (int64_t)s->st_mtime;
    out->ctime = (int64_t)s->st_ctime;
    out->mode = (uint32_t)s->st_mode;
    if ((off_t)out->size != s->st_size || (dev_t)out->device != s->st_dev ||
        (ino_t)out->inode != s->st_ino || (time_t)out->mtime != s->st_mtime ||
        (time_t)out->ctime != s->st_ctime || (mode_t)out->mode != s->st_mode)
        return false;
#ifdef __APPLE__
    out->mtime_nsec = s->st_mtimespec.tv_nsec;
    out->ctime_nsec = s->st_ctimespec.tv_nsec;
#else
    out->mtime_nsec = s->st_mtim.tv_nsec;
    out->ctime_nsec = s->st_ctim.tv_nsec;
#endif
    return out->mtime_nsec >= 0 && out->mtime_nsec < 1000000000 &&
           out->ctime_nsec >= 0 && out->ctime_nsec < 1000000000;
}

static bool path_guards(const char *path, stat_guard_t *out, size_t *count) {
    *count = 0;
    if (!path || path[0] != '/' || strlen(path) >= SESSION_PATH_BYTES) return false;
    char part[SESSION_PATH_BYTES];
    size_t length = strlen(path), component = 1;
    if (length < 2 || path[length - 1] == '/') return false;
    memcpy(part, path, length + 1);
    for (size_t i = 1; i <= length; i++) {
        if (part[i] && part[i] != '/') continue;
        size_t n = i - component;
        if (!n || (n == 1 && part[component] == '.') ||
            (n == 2 && part[component] == '.' && part[component + 1] == '.') ||
            *count == SESSION_PATH_PARTS) return false;
        char saved = part[i];
        part[i] = 0;
        struct stat s;
        bool ok = lstat(part, &s) == 0 && S_ISDIR(s.st_mode) &&
                  stat_guard(&s, &out[*count]);
        part[i] = saved;
        if (!ok) return false;
        (*count)++;
        component = i + 1;
    }
    return true;
}

static int entry_order(const void *left, const void *right) {
    const session_saves_entry_t *a = left, *b = right;
    if (a->service != b->service) return a->service ? 1 : -1;
    return strcmp(a->image_name, b->image_name);
}

static session_saves_baseline_t scan(const char *path,
                                      session_saves_snapshot_t *out) {
    DIR *dir = opendir(path);
    if (!dir) return SESSION_SAVES_ERROR;
    session_saves_baseline_t result = SESSION_SAVES_OK;
    for (;;) {
        errno = 0;
        struct dirent *de = readdir(dir);
        if (!de) {
            if (errno) result = SESSION_SAVES_ERROR;
            break;
        }
        if (strncmp(de->d_name, "sdimg_", 6)) continue;
        size_t length = strlen(de->d_name);
        bool service = !strncmp(de->d_name, "sdimg_sce_bu_", 13);
        if (length >= sizeof(out->entries[0].image_name) ||
            length <= (service ? 13u : 6u) || strchr(de->d_name, '/')) {
            result = SESSION_SAVES_ERROR; break;
        }
        char image[SESSION_PATH_BYTES];
        int n = snprintf(image, sizeof(image), "%s/%s", path, de->d_name);
        struct stat s;
        stat_guard_t g;
        if (n < 0 || (size_t)n >= sizeof(image) || lstat(image, &s) != 0 ||
            !S_ISREG(s.st_mode) || !stat_guard(&s, &g)) {
            result = SESSION_SAVES_ERROR; break;
        }
        if (out->count == SESSION_SAVES_MAX_IMAGES) {
            result = SESSION_SAVES_OVERFLOW; break;
        }
        session_saves_entry_t *e = &out->entries[out->count++];
        memcpy(e->image_name, de->d_name, length + 1);
        e->service = service;
        e->size = g.size; e->device = g.device; e->inode = g.inode;
        e->mtime = g.mtime; e->mtime_nsec = g.mtime_nsec;
        e->ctime = g.ctime; e->ctime_nsec = g.ctime_nsec; e->mode = g.mode;
    }
    if (closedir(dir) != 0) result = SESSION_SAVES_ERROR;
    if (result != SESSION_SAVES_OK) return result;
    qsort(out->entries, out->count, sizeof(out->entries[0]), entry_order);
    for (size_t i = 1; i < out->count; i++)
        if (!entry_order(&out->entries[i - 1], &out->entries[i])) return SESSION_SAVES_ERROR;
    return result;
}

session_saves_baseline_t session_saves_snapshot(
    const char *path, session_saves_snapshot_t **out) {
    if (!out) return SESSION_SAVES_ERROR;
    *out = NULL;
    session_saves_snapshot_t *first = calloc(1, sizeof(*first));
    session_saves_snapshot_t *second = calloc(1, sizeof(*second));
    stat_guard_t *guards = calloc(2 * SESSION_PATH_PARTS, sizeof(*guards));
    session_saves_baseline_t result = SESSION_SAVES_ERROR;
    size_t before = 0, after = 0;
    if (!first || !second || !guards || !path_guards(path, guards, &before)) goto done;
    result = scan(path, first);
    if (result != SESSION_SAVES_OK) goto done;
    result = scan(path, second);
    if (result != SESSION_SAVES_OK) goto done;
    if (!path_guards(path, guards + SESSION_PATH_PARTS, &after) || before != after ||
        memcmp(guards, guards + SESSION_PATH_PARTS, before * sizeof(*guards)) ||
        first->count != second->count ||
        memcmp(first->entries, second->entries, first->count * sizeof(first->entries[0]))) {
        result = SESSION_SAVES_ERROR; goto done;
    }
    *out = first;
    first = NULL;
done:
    free(guards); free(second); free(first);
    return result;
}

static bool entry_changed(const session_saves_entry_t *a,
                           const session_saves_entry_t *b) {
    return a->size != b->size || a->mtime != b->mtime || a->mtime_nsec != b->mtime_nsec;
}

// A merge iterator also covers the disjoint union of two full 128-entry sets.
static const session_saves_entry_t *next_delta(
    const session_saves_snapshot_t *before, const session_saves_snapshot_t *after,
    size_t *a, size_t *b, unsigned *kind) {
    while (*a < before->count || *b < after->count) {
        int order = *a == before->count ? 1 : *b == after->count ? -1 :
                    entry_order(&before->entries[*a], &after->entries[*b]);
        if (order < 0) { *kind = 2; return &before->entries[(*a)++]; }
        if (order > 0) { *kind = 1; return &after->entries[(*b)++]; }
        bool changed = entry_changed(&before->entries[*a], &after->entries[*b]);
        (*a)++; (*b)++;
        if (changed) { *kind = 0; return &after->entries[*b - 1]; }
    }
    return NULL;
}

void session_saves_diff(const session_saves_snapshot_t *before,
                        const session_saves_snapshot_t *after,
                        session_saves_counts_t *out) {
    if (!out) return;
    memset(out, 0, sizeof(*out));
    if (!before || !after || before->count > SESSION_SAVES_MAX_IMAGES ||
        after->count > SESSION_SAVES_MAX_IMAGES) return;
    size_t a = 0, b = 0; unsigned kind;
    const session_saves_entry_t *entry;
    while ((entry = next_delta(before, after, &a, &b, &kind))) {
        if (kind == 0) out->changed++;
        else if (kind == 1) out->added++;
        else out->removed++;
        if (entry->service) out->changed_service++;
        else out->changed_active++;
    }
}

void session_saves_reset(session_saves_state_t *state) {
    if (!state) return;
    free(state->before); free(state->after);
    memset(state, 0, sizeof(*state));
}

bool session_saves_observe(session_saves_state_t *state, const char *path,
                          session_saves_observation_t observation, int64_t now,
                          session_saves_snapshotter_t snapshotter, void *context) {
    if (!state) return false;
    if (observation == SESSION_SAVES_UNKNOWN) {
        if (state->cycle || state->baseline != SESSION_SAVES_MISSING)
            state->baseline = SESSION_SAVES_ERROR;
        state->observation = SESSION_SAVES_UNKNOWN;
        state->closed_available = false;
        memset(&state->counts, 0, sizeof(state->counts));
        return false;
    }
    if (observation == SESSION_SAVES_OPEN) {
        if (!state->cycle) {
            bool start_known = state->observation == SESSION_SAVES_CLOSED;
            session_saves_reset(state);
            state->cycle = true;
            if (start_known) state->baseline = snapshotter
                ? snapshotter(path, &state->before, context) : SESSION_SAVES_ERROR;
            if (state->baseline == SESSION_SAVES_OK && !state->before)
                state->baseline = SESSION_SAVES_ERROR;
        }
        state->observation = SESSION_SAVES_OPEN;
        return false;
    }
    if (observation != SESSION_SAVES_CLOSED) return false;
    state->observation = SESSION_SAVES_CLOSED;
    if (!state->cycle) return false;
    state->cycle = false;
    state->closed_available = now >= 0;
    state->closed_unix = now >= 0 ? now : 0;
    if (now < 0) state->baseline = SESSION_SAVES_ERROR;
    if (state->baseline == SESSION_SAVES_OK) {
        state->baseline = snapshotter
            ? snapshotter(path, &state->after, context) : SESSION_SAVES_ERROR;
        if (state->baseline == SESSION_SAVES_OK && !state->after)
            state->baseline = SESSION_SAVES_ERROR;
        if (state->baseline == SESSION_SAVES_OK)
            session_saves_diff(state->before, state->after, &state->counts);
    }
    if (state->baseline != SESSION_SAVES_OK) {
        free(state->before); free(state->after);
        state->before = state->after = NULL;
        memset(&state->counts, 0, sizeof(state->counts));
    }
    return true;
}

void session_saves_report(const session_saves_state_t *state,
                          session_saves_report_t *out) {
    if (!out) return;
    memset(out, 0, sizeof(*out));
    if (!state || state->cycle || state->observation != SESSION_SAVES_CLOSED) return;
    out->baseline = state->baseline;
    out->closed_available = state->closed_available;
    out->closed_unix = state->closed_unix;
    if (state->baseline != SESSION_SAVES_OK || !state->before || !state->after) return;
    out->counts = state->counts;
    out->count = state->after->count;
    memcpy(out->entries, state->after->entries, out->count * sizeof(out->entries[0]));
    size_t a = 0;
    for (size_t b = 0; b < out->count; b++) {
        while (a < state->before->count && entry_order(&state->before->entries[a], &out->entries[b]) < 0) a++;
        out->changed[b] = a == state->before->count ||
            entry_order(&state->before->entries[a], &out->entries[b]) != 0 ||
            entry_changed(&state->before->entries[a], &out->entries[b]);
    }
}

const char *session_saves_baseline_name(session_saves_baseline_t baseline) {
    switch (baseline) {
        case SESSION_SAVES_OK: return "ok";
        case SESSION_SAVES_OVERFLOW: return "overflow";
        case SESSION_SAVES_ERROR: return "error";
        default: return "missing";
    }
}

static bool append(char *out, size_t capacity, size_t *used, const char *text) {
    size_t n = strlen(text);
    if (*used >= capacity || n >= capacity - *used) return false;
    memcpy(out + *used, text, n + 1); *used += n;
    return true;
}

static bool escape(char *out, size_t capacity, const char *text) {
    size_t used = 0;
    out[0] = 0;
    if (!text) return false;
    for (const unsigned char *p = (const unsigned char *)text; *p; p++) {
        char next[5] = {(char)*p, 0, 0, 0, 0};
        if (*p < 32 || *p >= 127 || *p == ',' || *p == '[' || *p == ']' || *p == '\\' || *p == '+')
            snprintf(next, sizeof(next), "\\x%02X", *p);
        if (!append(out, capacity, &used, next)) return false;
    }
    return true;
}

bool session_saves_format_log(const session_saves_state_t *state,
                             const char *run, long pid, const char *display,
                             const char *title, const char *uid,
                             char *out, size_t capacity) {
    if (!out || !capacity) return false;
    out[0] = 0;
    if (!state) return false;
    if (capacity > SESSION_SAVES_LOG_BYTES) capacity = SESSION_SAVES_LOG_BYTES;
    char escaped[SESSION_SAVES_LOG_BYTES], number[128];
    size_t used = 0;
    const session_saves_counts_t zero = {0};
    bool valid = !state->cycle && state->observation == SESSION_SAVES_CLOSED &&
        state->baseline == SESSION_SAVES_OK && state->before && state->after;
    const session_saves_counts_t *counts = valid ? &state->counts : &zero;
#define PUT(text) do { if (!append(out, capacity, &used, (text))) goto failed; } while (0)
#define ESC(text) do { if (!escape(escaped, sizeof(escaped), (text))) goto failed; PUT(escaped); } while (0)
    PUT("watcher[run="); ESC(run);
    snprintf(number, sizeof(number), " pid=%ld watcher=1]: Session saves: ", pid); PUT(number);
    ESC(display && *display ? display : title); PUT(" uid="); ESC(uid); PUT(" baseline=");
    PUT(session_saves_baseline_name(state->cycle ? SESSION_SAVES_MISSING : state->baseline));
    snprintf(number, sizeof(number), " changed=%u added=%u removed=%u active=[",
             counts->changed, counts->added, counts->removed); PUT(number);
    unsigned displayed = 0;
    for (unsigned service = 0; service < 2; service++) {
        size_t a = 0, b = 0; unsigned kind, shown = 0;
        unsigned total = service ? counts->changed_service : counts->changed_active;
        const session_saves_entry_t *entry;
        if (service) PUT("] service=[");
        while (valid && (entry = next_delta(state->before, state->after, &a, &b, &kind))) {
            if (entry->service != (service != 0)) continue;
            if (displayed >= 16) break;
            if (!escape(escaped, sizeof(escaped), entry->image_name + (service ? 13 : 6))) break;
            size_t need = strlen(escaped) + (shown ? 1 : 0);
            // Reserve both +256 markers, delimiters and NUL before any label.
            if (used >= capacity || need + 32 >= capacity - used) break;
            if (shown) PUT(",");
            PUT(escaped); shown++; displayed++;
        }
        if (shown < total) {
            snprintf(number, sizeof(number), "%s+%u", shown ? "," : "", total - shown);
            PUT(number);
        }
    }
    PUT("]");
#undef ESC
#undef PUT
    return true;
failed:
    out[0] = 0;
    // One bounded retry of formatting only: a full literal title ID replaces a
    // display name that cannot fit. Never shorten an untrusted name silently.
    if (display && *display && title && strcmp(display, title))
        return session_saves_format_log(state, run, pid, NULL, title, uid, out, capacity);
    return false;
}
