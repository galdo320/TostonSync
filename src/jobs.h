// Observations only: these IDs never authorize, schedule, cancel or retry work.
#ifndef TOSTONSYNC_JOBS_H
#define TOSTONSYNC_JOBS_H
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define JOBS_LIVE_MAX 256
#define JOBS_RECENT_MAX 20
#define JOBS_SNAPSHOT_MAX (JOBS_LIVE_MAX + JOBS_RECENT_MAX)
typedef uint64_t jobs_ref_t;
typedef enum { JOB_FULL_BACKUP, JOB_INDIVIDUAL_BACKUP, JOB_RESTORE, JOB_IMPORT, JOB_UPDATE, JOB_USB_TEST } jobs_kind_t;
typedef enum { JOB_QUEUED, JOB_RUNNING, JOB_DONE, JOB_FAILED, JOB_UNKNOWN } jobs_state_t;

typedef struct {
    jobs_ref_t id;
    jobs_kind_t kind;
    jobs_state_t state;
    char user_uid[16], title_id[16], container[64], destination[16];
    char phase[48], error[64];
    char backup_detail[768]; // Fixed backup-summary grammar only; never free diagnostics.
    uint64_t bytes_done, bytes_total, phase_epoch;
    bool bytes_known, total_known, terminal;
    unsigned saved_destinations; // Completed copies retained when later destinations are canceled.
    int64_t started_unix, updated_unix, finished_unix;
} jobs_record_t;

typedef struct {
    bool complete;
    uint64_t dropped_observations;
    size_t count;
    jobs_record_t items[JOBS_SNAPSHOT_MAX];
} jobs_snapshot_t;

// Even refs preserve native watcher job_id; odd refs identify controller work.
jobs_ref_t jobs_watch_id(unsigned long native_id);
jobs_ref_t jobs_watch_queued(unsigned long native_id, jobs_kind_t kind, const char* uid,
    const char* title, const char* container, const char* destination);
// Metadata only: a retired/missing ID can never create or resurrect a record.
void jobs_queued(jobs_ref_t ref, jobs_kind_t kind, const char* uid,
                 const char* title, const char* container, const char* destination);
jobs_ref_t jobs_begin(jobs_kind_t kind, const char* uid, const char* title,
                      const char* container, const char* destination);
// Native session IDs are private correlation keys, never copied to snapshots.
// Current import/update bindings survive eviction from the recent-20 ring.
jobs_ref_t jobs_native(jobs_kind_t kind, const char* native_id);
// Only a newly admitted controller may start another operation of a terminal session.
jobs_ref_t jobs_native_begin(jobs_kind_t kind, const char* native_id);
// Passive getters never create observations or increment dropped counters.
// Missing, invalid or contended lookups return zero and preserve errno.
jobs_ref_t jobs_native_lookup(jobs_kind_t kind, const char* native_id);
jobs_ref_t jobs_native_current(jobs_kind_t kind);
jobs_ref_t jobs_native_observe(jobs_kind_t kind, const char* native_id, jobs_ref_t expected_ref);
void jobs_native_absent(jobs_kind_t kind, jobs_ref_t expected_ref);
bool jobs_tracked(jobs_ref_t ref);
void jobs_incomplete(void);

// TLS is observation context, propagated explicitly to any child thread.
jobs_ref_t jobs_bind(jobs_ref_t ref); // returns previous binding for restoration
jobs_ref_t jobs_bound(void);
void jobs_phase(jobs_ref_t ref, const char* destination, const char* phase,
                 uint64_t total, bool total_known);
void jobs_progress(uint64_t done, uint64_t total, bool total_known);
void jobs_progress_add(uint64_t bytes);
void jobs_backup_detail(jobs_ref_t ref, const char* detail);
void jobs_note_saved(unsigned destination_mask);
void jobs_finish(jobs_ref_t ref, jobs_state_t state, const char* error);
// Contention returns an incomplete snapshot without changing the registry.
bool jobs_snapshot(jobs_snapshot_t* out);
const char* jobs_kind_name(jobs_kind_t kind);
const char* jobs_state_name(jobs_state_t state);

#ifdef JOBS_TEST
void jobs_test_reset(void);
void jobs_test_lock(bool lock);
#endif
#endif
