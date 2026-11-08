// TostónSync — retention policy implementation.

#include "retention.h"
#include "gdrive.h"
#include "log.h"
#include "protect.h"
#include "watcher.h"

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

uint64_t retention_parse_size(const char* s) {
    if (!s || !*s) return 0;
    char* end = NULL;
    double v = strtod(s, &end);
    if (v <= 0) return 0;
    while (end && *end && isspace((unsigned char)*end)) end++;
    if (!end || !*end) return (uint64_t)v;
    uint64_t mult = 1;
    char unit = (char)toupper((unsigned char)*end);
    switch (unit) {
        case 'K': mult = 1024ULL; break;
        case 'M': mult = 1024ULL * 1024; break;
        case 'G': mult = 1024ULL * 1024 * 1024; break;
        case 'T': mult = 1024ULL * 1024 * 1024 * 1024; break;
        default:  return (uint64_t)v;
    }
    return (uint64_t)(v * (double)mult);
}

static const char* fmt_human(uint64_t n, char buf[32]) {
    static const char* u[] = {"B","KB","MB","GB","TB"};
    int i = 0; double d = (double)n;
    while (d >= 1024.0 && i < 4) { d /= 1024.0; i++; }
    snprintf(buf, 32, "%.1f %s", d, u[i]);
    return buf;
}

// --------------------------------------------------------------------
// Per-title enforcement.
// --------------------------------------------------------------------

retention_result_t retention_enforce_title(const config_t* cfg,
                                           const char* user_uid,
                                           const char* title_id,
                                           const char* keep_file_id) {
    return retention_enforce_title_identified(cfg, user_uid, title_id,
                                               keep_file_id, NULL);
}

retention_result_t retention_enforce_title_identified(const config_t* cfg,
                                           const char* user_uid,
                                           const char* title_id,
                                           const char* keep_file_id,
                                           const char* expected_identity) {
    retention_result_t res = {0};
    if (!cfg || !title_id || !*title_id) return res;

    enum { MAX = 512 };
    gdrive_version_t list[MAX];
    size_t n = 0;
    gdrive_retention_scope_t scope;
    if (!gdrive_retention_list(user_uid, title_id, expected_identity,
                               list, MAX, &n, &scope)) {
        res.deferred = true;
        log_warn("retention: destination or complete listing unconfirmed; cleanup deferred");
        return res;
    }
    if (keep_file_id && keep_file_id[0]) {
        bool found = false;
        for (size_t i = 0; i < n; i++)
            if (!strcmp(list[i].file_id, keep_file_id)) found = true;
        if (!found) {
            res.deferred = true;
            log_warn("retention: just-confirmed archive absent from listing; cleanup deferred");
            return res;
        }
    }
    if (n == 0) return res;
    // Retention must not immediately delete the upload it is finalizing, even
    // if equal/future timestamps or older favorites distort the usual order.
    if (keep_file_id && keep_file_id[0])
        for (size_t i = 0; i < n; i++)
            if (strcmp(list[i].file_id, keep_file_id) == 0) {
                gdrive_version_t fresh = list[i];
                memmove(list + 1, list, i * sizeof(*list));
                list[0] = fresh;
                break;
            }

    int      max_versions = cfg->retention.max_versions;
    uint64_t max_per_size = retention_parse_size(
                              cfg->retention.max_total_size_per_title_str);

    uint64_t running = 0;
    for (size_t i = 0; i < n; i++) {
        // A protected (favorite) backup is never auto-deleted and doesn't count
        // toward the size budget being freed — keep it and move on.
        if ((keep_file_id && strcmp(list[i].file_id, keep_file_id) == 0) ||
            protect_is(list[i].name)) { running += list[i].size_bytes; continue; }
        bool prune = false;
        if (max_versions > 0 && (int)i >= max_versions) prune = true;
        if (!prune && max_per_size > 0
            && running + list[i].size_bytes > max_per_size) {
            prune = true;
        }
        if (prune) {
            if (gdrive_retention_delete(user_uid, title_id, &list[i],
                                        keep_file_id && keep_file_id[0] ? &list[0] : NULL,
                                        &scope)) {
                res.pruned_count++;
                res.pruned_bytes += list[i].size_bytes;
            } else {
                res.deferred = true;
                log_warn("retention: destination/file unconfirmed or delete failed; remaining cleanup deferred");
                break;
            }
        } else {
            running += list[i].size_bytes;
        }
    }
    if (res.pruned_count) {
        char hb[32];
        log_info("retention: pruned %d version(s) (%s) for %s/%s",
                 res.pruned_count, fmt_human(res.pruned_bytes, hb),
                 (user_uid && user_uid[0]) ? user_uid : "default",
                 title_id);
    }
    return res;
}

// --------------------------------------------------------------------
// Global enforcement.
// --------------------------------------------------------------------

typedef struct {
    const config_t*     cfg;
    retention_result_t* total;
} enforce_all_ctx_t;

static void enforce_all_cb(const char* user_alias,
                           const char* user_uid,
                           const char* title_id,
                           const char* game_name,
                           bool included,
                           void* ud) {
    (void)user_alias;
    (void)game_name;
    (void)included;
    enforce_all_ctx_t* ctx = (enforce_all_ctx_t*)ud;
    retention_result_t r = retention_enforce_title(ctx->cfg,
                                                   user_uid, title_id, NULL);
    ctx->total->pruned_count += r.pruned_count;
    ctx->total->pruned_bytes += r.pruned_bytes;
    ctx->total->deferred |= r.deferred;
}

retention_result_t retention_enforce_all(const config_t* cfg) {
    retention_result_t total = {0};
    enforce_all_ctx_t  ctx   = { cfg, &total };
    // Walks every title the watcher has seen since boot. On a fresh
    // boot before the watcher has scanned, this is a no-op — which is
    // fine; the next per-title enforcement happens after the next
    // successful upload.
    watcher_enumerate_saves(enforce_all_cb, &ctx);
    return total;
}

bool retention_would_exceed_global(const config_t* cfg,
                                   uint64_t incoming_bytes) {
    return retention_check_global(cfg, incoming_bytes, NULL);
}

bool retention_check_global(const config_t* cfg, uint64_t incoming_bytes,
                             retention_global_decision_t* decision) {
    retention_global_decision_t d = {0};
    d.incoming_bytes = incoming_bytes;
    d.cap_bytes = cfg ? retention_parse_size(cfg->retention.max_total_size_global_str) : 0;
    if (d.cap_bytes) {
        d.count_known = gdrive_estimate_backup_usage(&d.counted_bytes, &d.counted_files);
        d.blocked = d.count_known && (d.counted_bytes > d.cap_bytes ||
            incoming_bytes > d.cap_bytes - d.counted_bytes);
    }
    log_info("retention: Drive global limit=%llu counted_bytes=%llu counted_files=%zu incoming_bytes=%llu count=%s decision=%s",
        (unsigned long long)d.cap_bytes, (unsigned long long)d.counted_bytes,
        d.counted_files, (unsigned long long)d.incoming_bytes,
        !d.cap_bytes ? "not_required" : d.count_known ? "known" : "unknown",
        d.blocked ? "blocked" : "allowed");
    if (decision) *decision = d;
    return d.blocked;
}
