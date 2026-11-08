// Public cover cache only. Never opens saves, accounts or auth tokens.
#ifndef TOSTONSYNC_PUBLIC_ARTWORK_H
#define TOSTONSYNC_PUBLIC_ARTWORK_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

typedef struct {
    char title_id[16];
    char source_url[256];
    char path[400];
    char mime[24];
    char status[32]; // available, unavailable, busy
    char reason[32];
    char cache_state[24];
    int cache_errno;
    int http_status;
    int transport_error;
    int ssl_error;
    unsigned long ssl_detail;
    int64_t checked_unix;
    int64_t retry_after_unix;
    uint32_t width, height;
    size_t size;
    bool cached;
} public_artwork_t;

// Exact public CDN URL announced by a verified page for this same title.
// No redirects, other hosts, guessed URL or path traversal are accepted.
bool public_artwork_valid_url(const char* title_id, const char* url);
// Bounded structural WebP validation. It does not trust the HTTP MIME alone.
bool public_artwork_validate(const void* body, size_t len,
                             uint32_t* width, uint32_t* height);
// Offline, including when a persisted failure's retry time has expired.
bool public_artwork_cached(const char* title_id, public_artwork_t* out);
// Explicit action only; positive cache wins without contacting the CDN.
// Independent 24-hour persistent failure backoff; never affects title names.
bool public_artwork_lookup(const char* title_id, const char* verified_url,
                           public_artwork_t* out);

#endif
