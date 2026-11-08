// Public, display-only metadata. Never reads saves, accounts or auth tokens.
#ifndef TOSTONSYNC_PUBLIC_METADATA_H
#define TOSTONSYNC_PUBLIC_METADATA_H

#include <stdbool.h>
#include <stdint.h>

typedef struct {
    char title_id[16];
    char name[96];
    char region[16]; // explicit source label only; empty means unknown
    char content_id[64];
    char source_url[128];
    char source[32];
    char artwork_url[256]; // only a same-title CDN URL announced by verified HTML
    char status[32]; // available, unavailable, busy
    int64_t checked_unix;
    int64_t retry_after_unix;
    // Request-local evidence, saved before releasing the HTTP response. Zero
    // codes mean not supplied, not proof of working DNS/TLS. No guessed causes.
    char reason[32];
    int http_status;
    int transport_error;
    int ssl_error;
    unsigned long ssl_detail;
    char cache_state[24];
    int cache_errno;
    bool cached;
} public_metadata_t;

// All three return true only for verified, available metadata. Invalid inputs
// return false and an unavailable result. IDs must be exactly PPSA + 5 digits.
// cached is strictly offline, including when a negative cache has expired.
bool public_metadata_cached(const char* title_id, public_metadata_t* out);
// Explicit user action only. Success with an artwork URL stays cached; legacy
// text-only success can refresh after 24 hours to discover artwork. Failures
// back off for 24 hours across restarts. Pre-diagnostic negatives and old-policy
// TLS failures revalidate once with a durable pending marker. Concurrent lookup
// returns busy.
bool public_metadata_lookup(const char* title_id, public_metadata_t* out);
// Bounded server-rendered Prospero HTML parser, also used by offline tests.
bool public_metadata_parse(const char* title_id, const char* html,
                           public_metadata_t* out);

#endif
