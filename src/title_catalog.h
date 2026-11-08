// Public display metadata only. No saves, accounts, credentials or artwork.
#ifndef TOSTONSYNC_TITLE_CATALOG_H
#define TOSTONSYNC_TITLE_CATALOG_H

#include "public_metadata.h"
#include <stdbool.h>
#include <stddef.h>

#define TITLE_CATALOG_URL "https://raw.githubusercontent.com/andshrew/PlayStation-Titles/main/PS5_Titles.tsv"
#define TITLE_CATALOG_LIMIT (4 * 1024 * 1024)

typedef struct {
    char status[32];
    char reason[40];
    int http_status, transport_error, ssl_error, cache_errno;
    unsigned long ssl_detail;
    int64_t checked_unix, retry_after_unix;
    size_t rows;
    char etag[128];
    bool cached;
} title_catalog_status_t;

// Strictly offline; rejects conflicting exact IDs, never searches by name.
bool title_catalog_lookup(const char* title_id, public_metadata_t* out);
// Explicit metadata request only. No thread, polling or retry loop. A durable
// attempt marker enforces the 24-hour TTL/backoff even after interruption.
// Old-policy TLS failures revalidate once under the approved direct GitHub root;
// positive caches and ordinary v2 failures keep their existing backoff.
bool title_catalog_refresh(title_catalog_status_t* out);

#endif
