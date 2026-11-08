// Local executable staging and cooperative restart; never a save import.
#ifndef TOSTONSYNC_UPDATE_H
#define TOSTONSYNC_UPDATE_H
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include "lifecycle.h"

#define UPDATE_MAX_BYTES (16u * 1024u * 1024u)
#define UPDATE_CHUNK_BYTES (1024u * 1024u)
#define UPDATE_NAME_MAX 128
#define UPDATE_VERSION_MAX 32
#define UPDATE_BUILD_MAX 64
#define UPDATE_SESSION_SECONDS 300

typedef enum {
    UPDATE_OK, UPDATE_INVALID, UPDATE_BUSY, UPDATE_NOT_FOUND,
    UPDATE_CONFLICT, UPDATE_IO_ERROR, UPDATE_UNKNOWN
} update_code_t;

typedef struct {
    char state[16];                 // present, missing, unreadable
    char version[UPDATE_VERSION_MAX], build[UPDATE_BUILD_MAX], sha256[65];
    uint64_t bytes;
    int64_t mtime_unix;
    bool valid;                     // structure and exactly one valid marker
} update_file_info_t;

// Returned by pure observation only; errno is meaningful solely for a failed I/O call.
typedef struct {
    const char* phase;
    const char* canary;
    const char* identity;
    const char* field;
    int64_t rc;
    int error;
    bool failed, errno_valid;
} update_observation_diagnostic_t;

typedef struct {
    update_observation_diagnostic_t directory, saved, previous;
} update_observation_diagnostics_t;

typedef struct {
    char running_version[UPDATE_VERSION_MAX], running_build[UPDATE_BUILD_MAX];
    char boot_id[65], launcher[16]; // present, missing, unknown; not registration
    update_file_info_t saved, previous;
    bool receiving, pending_saved, publication_unknown;
    update_observation_diagnostics_t diagnostics;
} update_status_t;

typedef struct {
    update_code_t code;
    char error[64], detail[192], session_id[65];
    uint64_t next_offset, bytes;
    int64_t expires_unix;
    char version[UPDATE_VERSION_MAX], sha256[65], previous_version[UPDATE_VERSION_MAX];
    bool published;                // true only after verified publication; UNKNOWN is not proof
} update_result_t;

const char* update_boot_id(void);
bool update_get_status(update_status_t* out);
bool update_inspect_bytes(const void* bytes, size_t size, update_file_info_t* out);
bool update_abort(const char* owner, const char* id);
bool update_finish_quiet(const char* owner, const char* id, bool confirm, update_result_t* out);
// Pure presentation after boot initialization; action flags remain false, never authority.
bool update_observe_status(update_status_t* out);
bool update_start(const char* owner, const char* name, uint64_t size,
                  const char* sha256, bool confirm, bool allow_downgrade,
                  update_result_t* out);
bool update_chunk(const char* owner, const char* id, uint64_t offset,
                  const void* bytes, size_t length, bool confirm,
                  update_result_t* out);
bool update_finish(const char* owner, const char* id, bool confirm,
                   update_result_t* out);
typedef enum { UPDATE_JOBS_OBSERVED, UPDATE_JOBS_BUSY, UPDATE_JOBS_UNKNOWN } update_jobs_observation_t;
typedef struct {
    char native_id[65]; // Private correlation only; never exposed as an update capability.
    uint64_t received, expected;
    int64_t expires_unix; // Existing deadline, not a fabricated progress timestamp.
    bool current_present, uncertain, pending_observed, receiving;
} update_jobs_snapshot_t;
// Pure trylock snapshot. pending_observed is an in-memory observation, not a disk check.
update_jobs_observation_t update_jobs_snapshot(update_jobs_snapshot_t* out);

typedef enum { UPDATE_RESTART_NONE, UPDATE_RESTART_SENT, UPDATE_RESTART_FAILED } update_restart_outcome_t;
// Uses the calling HTTP handler's admission; never acquires a competing lease.
bool update_restart_request(life_snapshot_fn snapshot, life_snapshot_t* state,
                            update_result_t* out);
// Call only after the complete RESTART_ACCEPTED header and body were sent.
void update_restart_response_sent(void);
// Main calls this only after stop_web_cooperatively has returned successfully.
update_restart_outcome_t update_restart_after_stop(void);
#endif
