// TostónSync — retention policy enforcement.
//
// Called after every successful upload to prune older versions that
// fall outside the configured policy. Ordinary cleanup captures its current
// target; post-copy cleanup must retain the identity accepted by the provider.
//
// Policies (any combination):
//   - max_versions          → keep the newest N per title
//   - max_total_size_per_title → keep newest while sum < cap
//   - max_total_size_global → reject upload if all-titles sum > cap
//
// Strategy: list versions newest-first, walk and accumulate. Anything
// past the cut (by count or by size) is deleted.

#ifndef TOSTONSYNC_RETENTION_H
#define TOSTONSYNC_RETENTION_H

#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>

#include "config.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    int      pruned_count;
    uint64_t pruned_bytes;
    bool     deferred; // incomplete/changed/unreachable proof: stop deleting
} retention_result_t;

// Enforce retention for one (stable user UID, title_id) pair on Drive.
// Safe to call at any time; idempotent. Prioritize keep_file_id (the just-
// uploaded archive) for this pass only; NULL uses ordinary newest-first order.
retention_result_t retention_enforce_title(const config_t* cfg,
                                           const char* user_uid,
                                           const char* title_id,
                                           const char* keep_file_id);

retention_result_t retention_enforce_title_identified(const config_t* cfg,
                                           const char* user_uid,
                                           const char* title_id,
                                           const char* keep_file_id,
                                           const char* expected_identity);

// Enforce for every (user, title) backed up on Drive.
retention_result_t retention_enforce_all(const config_t* cfg);

// Pre-upload check: returns true if uploading `incoming_bytes` more
// would exceed max_total_size_global. The caller should refuse and
// surface a toast.
typedef struct {
    uint64_t cap_bytes;
    uint64_t counted_bytes;
    size_t counted_files;
    uint64_t incoming_bytes;
    bool count_known;
    bool blocked;
} retention_global_decision_t;
bool retention_check_global(const config_t* cfg, uint64_t incoming_bytes,
                             retention_global_decision_t* decision);
bool retention_would_exceed_global(const config_t* cfg,
                                   uint64_t incoming_bytes);

// Parse "5GB" / "500MB" / "0" into bytes. Returns 0 on "0" or invalid.
uint64_t retention_parse_size(const char* s);

#ifdef __cplusplus
}
#endif
#endif
