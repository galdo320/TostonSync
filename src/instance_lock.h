#ifndef TOSTONSYNC_INSTANCE_LOCK_H
#define TOSTONSYNC_INSTANCE_LOCK_H

#include <stdbool.h>

#define INSTANCE_LOCK_DIRECTORY "/data/tostonsync"
#define INSTANCE_LOCK_PATH INSTANCE_LOCK_DIRECTORY "/instance.lock"

typedef struct {
    const char* stage;
    const char* operation;
    const char* reason;
    int result, error;
    bool result_known, error_known;
} instance_lock_diagnostic_t;

// Cooperative exclusivity only. PIDfile, HTTP and file contents are not authority.
bool instance_lock_acquire(instance_lock_diagnostic_t* out);
// After operational shutdown; never unlink the persistent lock inode.
bool instance_lock_release(void);

#endif
