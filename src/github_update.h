// Signed release controller. GET snapshots never schedule or authorize work.
#ifndef TOSTONSYNC_GITHUB_UPDATE_H
#define TOSTONSYNC_GITHUB_UPDATE_H
#include <stdbool.h>
#include <stdint.h>
#include "config.h"
#define GITHUB_UPDATE_NOTES_MAX 4096
typedef struct {
    char state[24], version[32], build[64], notes[GITHUB_UPDATE_NOTES_MAX + 1];
    char candidate_id[65], error[64], detail[192], saved_version[32], saved_sha256[65];
    int64_t last_attempt_unix, last_success_unix, next_check_unix;
    bool auto_check, automatic_paused, notes_verified;
} github_update_status_t;
void github_update_init(const config_t* cfg);
void github_update_tick(void);
void github_update_status(github_update_status_t* out);
bool github_update_check(void);
bool github_update_install(const char* candidate_id);
#endif
