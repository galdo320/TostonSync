// TostónSync — backup history / audit log.
//
// Every backup outcome appends one JSON line to
// <state_dir>/history.jsonl. The UI reads it back (newest first) so you
// always have a record of what was backed up, when, how big, and to
// which destinations.

#ifndef TOSTONSYNC_HISTORY_H
#define TOSTONSYNC_HISTORY_H

#include <stddef.h>
#include <stdint.h>

#include "config.h"

#ifdef __cplusplus
extern "C" {
#endif

void history_init(const config_t* cfg);

typedef enum {
    HISTORY_LAST_EMPTY = 0,
    HISTORY_LAST_FOUND,
    HISTORY_LAST_CORRUPT,
    HISTORY_LAST_UNREADABLE
} history_last_state_t;

typedef struct {
    history_last_state_t state;
    int error;                 // errno for unreadable history
    int64_t when;
    char title[64];
    char outcome[16];           // ok, warning, partial, failed
} history_last_backup_t;

// Startup observation only: no reads, replay, retries or destination validation.
void history_last_backup(history_last_backup_t* out);

typedef struct {
    char raw_completeness[40];
    size_t active_images;
    size_t service_images;
    size_t missing_service_images;
    char first_missing_service_image[128];
    char status[16];          // ok, warning, partial, failed
    bool canceled, cancel_unknown;
    char canceled_dests[64]; // Attempted/current or pending destinations explicitly canceled.
    char failed_dests[64];    // comma-separated destination tokens
} history_meta_t;

// Append one record. `user_alias` is the friendly name (or raw UID
// when unset). `game` is the human title name (may be "" / NULL).
// `dests` is a short tag list, e.g. "usb,drive".
void history_record(const char* user_alias,
                    const char* title_id, const char* game,
                    const char* filename, const char* backup_type,
                    const char* trigger, uint64_t size_bytes,
                    uint32_t crc, const char* dests,
                    const history_meta_t* meta);

// Build a JSON object {"items":[ ... ]} of the most recent records,
// newest first, into out. Returns the number of bytes written.
size_t history_to_json(char* out, size_t out_sz);

#ifdef __cplusplus
}
#endif
#endif // TOSTONSYNC_HISTORY_H
