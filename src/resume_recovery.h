#ifndef TOSTONSYNC_RESUME_RECOVERY_H
#define TOSTONSYNC_RESUME_RECOVERY_H

#include <stdbool.h>
#include <string.h>

// Keep the policy testable and boring: resume, a dead local server, or a
// newly available/changed LAN address requires a rebind.
static inline bool resume_http_restart_needed(bool resumed,
                                               bool http_healthy,
                                               const char* old_ip,
                                               const char* new_ip) {
    if (resumed || !http_healthy) return true;
    return new_ip && new_ip[0] &&
           (!old_ip || !old_ip[0] || strcmp(old_ip, new_ip) != 0);
}

static inline bool resume_lan_notice_needed(bool had_lan, bool has_lan,
                                            long long now,
                                            long long last_notice,
                                            int cooldown_seconds) {
    return !had_lan && has_lan &&
           (last_notice == 0 || now - last_notice >= cooldown_seconds);
}

static inline bool resume_local_notice_needed(bool has_lan, long long now,
                                              long long last_notice,
                                              int cooldown_seconds) {
    return !has_lan &&
           (last_notice == 0 || now - last_notice >= cooldown_seconds);
}

#endif
