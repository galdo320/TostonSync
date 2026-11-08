// Worker-owned cancellation, separate from the observational jobs registry.
#ifndef TOSTONSYNC_BACKUP_CONTROL_H
#define TOSTONSYNC_BACKUP_CONTROL_H
#include <stdbool.h>
#include <stdint.h>
#include <stdatomic.h>

typedef struct backup_control {
    uint64_t id;
    atomic_uint published;
    int cancel_result; // Owner only: 0 unattempted, 1 durable, -1 persistence failed.
    atomic_int state; // 0 running, 1 cancel requested, 2 publishing, 3 published, 4 finalizing
    struct backup_control* next;
} backup_control_t;
typedef struct { bool active, requested, publishing; unsigned saved; } backup_control_status_t;
// The owner must unregister only after all I/O and durable terminal writes end.
bool backup_control_begin(backup_control_t* control, uint64_t id);
void backup_control_end(backup_control_t* control);
backup_control_t* backup_control_bind(backup_control_t* control);
backup_control_t* backup_control_bound(void);
bool backup_control_request(uint64_t id);
bool backup_control_observe(uint64_t id, backup_control_status_t* status);
bool backup_control_cancelled(void);
bool backup_control_finish_begin(void);
// CAS closes the cancel-versus-rename race; rejected late requests are not canceled.
bool backup_control_publish_begin(void);
void backup_control_publish_end(bool published, unsigned destination_mask);
unsigned backup_control_saved(void);
#endif
