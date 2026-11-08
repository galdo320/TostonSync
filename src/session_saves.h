// A1 metadata observations only; callers own locking and UID/title association.
#ifndef TOSTONSYNC_SESSION_SAVES_H
#define TOSTONSYNC_SESSION_SAVES_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define SESSION_SAVES_MAX_IMAGES 128
#define SESSION_SAVES_LOG_BYTES 1024

typedef enum {
    SESSION_SAVES_MISSING = 0,
    SESSION_SAVES_OK,
    SESSION_SAVES_OVERFLOW,
    SESSION_SAVES_ERROR
} session_saves_baseline_t;

typedef enum {
    SESSION_SAVES_UNKNOWN = 0,
    SESSION_SAVES_CLOSED,
    SESSION_SAVES_OPEN
} session_saves_observation_t;

typedef struct {
    char image_name[256];
    uint64_t size, device, inode;
    int64_t mtime, mtime_nsec, ctime, ctime_nsec;
    uint32_t mode;
    bool service;
} session_saves_entry_t;

typedef struct {
    size_t count;
    session_saves_entry_t entries[SESSION_SAVES_MAX_IMAGES];
} session_saves_snapshot_t;

typedef struct {
    unsigned changed, added, removed, changed_active, changed_service;
} session_saves_counts_t;

typedef struct {
    session_saves_baseline_t baseline;
    bool closed_available;
    int64_t closed_unix;
    session_saves_counts_t counts;
    size_t count;
    session_saves_entry_t entries[SESSION_SAVES_MAX_IMAGES];
    bool changed[SESSION_SAVES_MAX_IMAGES];
} session_saves_report_t;

// Zero initialization is sufficient. At most two bounded heap snapshots/title.
typedef struct {
    session_saves_observation_t observation;
    bool cycle;
    session_saves_baseline_t baseline;
    bool closed_available;
    int64_t closed_unix;
    session_saves_snapshot_t *before, *after;
    session_saves_counts_t counts;
} session_saves_state_t;

typedef session_saves_baseline_t (*session_saves_snapshotter_t)(
    const char *path, session_saves_snapshot_t **out, void *context);

// Two finite metadata passes; no image opens, payload reads, DB, hash or writes.
session_saves_baseline_t session_saves_snapshot(
    const char *path, session_saves_snapshot_t **out);
void session_saves_diff(const session_saves_snapshot_t *before,
                        const session_saves_snapshot_t *after,
                        session_saves_counts_t *out);
// Returns true exactly once per observed closed cycle. Snapshotter may reject
// busy/uncertain I/O before and after snapshot; it is never called mid-session.
bool session_saves_observe(session_saves_state_t *state, const char *path,
                          session_saves_observation_t observation, int64_t now,
                          session_saves_snapshotter_t snapshotter, void *context);
void session_saves_report(const session_saves_state_t *state,
                          session_saves_report_t *out);
void session_saves_reset(session_saves_state_t *state);
const char *session_saves_baseline_name(session_saves_baseline_t baseline);
// Entire log_info("%s", out) message, including watcher prefix, <=1023 bytes.
// False means the fixed prefix cannot fit; never returns a partial log message.
bool session_saves_format_log(const session_saves_state_t *state,
                             const char *run, long pid, const char *display,
                             const char *title, const char *uid,
                             char *out, size_t capacity);

#endif
