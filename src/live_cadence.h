#ifndef TOSTONSYNC_LIVE_CADENCE_H
#define TOSTONSYNC_LIVE_CADENCE_H

#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#define LIVE_BALANCED_MIN_SECONDS 900

static inline bool live_backup_due(const char* mode, int64_t now,
                                   int64_t last_upload) {
    if (mode && strcmp(mode, "aggressive") == 0) return true;
    if (mode && strcmp(mode, "game_close") == 0) return false;
    return last_upload <= 0 || now - last_upload >= LIVE_BALANCED_MIN_SECONDS;
}

#endif
