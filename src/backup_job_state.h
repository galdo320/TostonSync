#ifndef TOSTONSYNC_BACKUP_JOB_STATE_H
#define TOSTONSYNC_BACKUP_JOB_STATE_H

#include <stdbool.h>
#include <stdint.h>
#include <string.h>

typedef struct {
    unsigned long job_id;
    int64_t started_at;
    int64_t completed_at;
    char run_id[48];
    char user_uid[16];
    char title_id[16];
    char reason[16];
    char source[24];
    char destination[64];
    char fingerprint[65];
    char detail[768];
    char status[16];
} backup_job_state_t;

bool backup_job_state_read(const char* path, backup_job_state_t* state);
bool backup_job_state_write(const char* path,
                            const backup_job_state_t* state);

static inline bool backup_job_state_needs_retry(
    const backup_job_state_t* state, const char* current_run_id) {
    return state &&
           (strcmp(state->status, "running") == 0 ||
            strcmp(state->status, "pending") == 0) &&
           strcmp(state->reason, "GameClose") == 0 &&
           (!current_run_id || strcmp(state->run_id, current_run_id) != 0);
}

#endif
