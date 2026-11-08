#ifndef TOSTONSYNC_BACKUP_RETRY_H
#define TOSTONSYNC_BACKUP_RETRY_H

#include <stdbool.h>
#include <stdint.h>

typedef struct {
    bool active;
    bool retired_ftp; // Load-only diagnostic; bit 2 is retired, never reassigned.
    bool cancel_guard; // Durable pre-admission fence: never replay an uncertain cancelable attempt.
    bool usb_no_replay; // Durable one-attempt boundary for this dirty generation.
    unsigned planned_mask, pending_mask, failures;
    int64_t retry_at, dirty_unix, last_upload_unix;
    char user_uid[16], title_id[16], reason[16], fingerprint[65];
    char completed_identity[3][65]; /* USB=0, Drive=1, retired slot=2; legacy wire layout. */
} backup_retry_t;

/* Failed reads always zero the whole output. Only canonical v1/v2 is accepted. */
bool backup_retry_read(const char* path, backup_retry_t* out);
bool backup_retry_write(const char* path, const backup_retry_t* state);
/* A pending bit is scheduling, never proof; the receipt binds target + data.
 * The caller must bypass matches for manual/forced backups. */
bool backup_retry_matches(const backup_retry_t* state, int index,
                          const char* current_identity,
                          const char* current_fingerprint);
/* Call after an actual successful copy or a freshly validated receipt of one.
 * Unknown identity clears pending, but cannot create a reusable confirmation. */
void backup_retry_confirm(backup_retry_t* state, int index,
                          const char* actual_identity);

#endif
