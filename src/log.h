// TostónSync — logging + system notifications.
//
// Two outputs:
//   1. A rotating log file at <state_dir>/sync.log.
//   2. A toast on the PS5 screen for high-signal events (sign-in,
//      upload complete, errors). Toasts go through libSceNotification.
//
// Log lines include an ISO-8601 UTC timestamp and a level prefix.

#ifndef TOSTONSYNC_LOG_H
#define TOSTONSYNC_LOG_H

#include "config.h"

#ifdef __cplusplus
extern "C" {
#endif

void log_init(const config_t* cfg);

void log_info (const char* fmt, ...) __attribute__((format(printf,1,2)));
void log_warn (const char* fmt, ...) __attribute__((format(printf,1,2)));
void log_error(const char* fmt, ...) __attribute__((format(printf,1,2)));
void log_debug(const char* fmt, ...) __attribute__((format(printf,1,2)));

// Bypasses the level filter; true only after fprintf, fflush and fsync succeed.
// Preserves caller errno, including on failure.
bool log_durable(const char* fmt, ...) __attribute__((format(printf,1,2)));

// On-screen toast. Also writes an INFO line to the log.
void log_notify(const char* text);
void log_notify_level(int required_level, const char* text);
void log_notify_level_quiet(int required_level, const char* text);

#ifdef __cplusplus
}
#endif
#endif
