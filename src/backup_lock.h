#ifndef TOSTONSYNC_BACKUP_LOCK_H
#define TOSTONSYNC_BACKUP_LOCK_H

#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdio.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <signal.h>
#include <time.h>
#include <unistd.h>

// Cross-process final guard. O_EXCL is the lock; the PID only lets a later
// daemon remove a stale file left by a crashed process.
static inline bool backup_lock_acquire(const char* path) {
    for (int attempt = 0; attempt < 3; attempt++) {
        int fd = open(path, O_WRONLY | O_CREAT | O_EXCL, 0600);
        if (fd >= 0) {
            char pid[32];
            int n = snprintf(pid, sizeof(pid), "%ld\n", (long)getpid());
            if (n > 0) (void)write(fd, pid, (size_t)n);
            close(fd);
            return true;
        }
        if (errno != EEXIST) return false;
        long owner = 0;
        FILE* f = fopen(path, "r");
        if (f) { (void)fscanf(f, "%ld", &owner); fclose(f); }
        if (owner > 1 && (kill((pid_t)owner, 0) == 0 || errno == EPERM))
            return false;
        if (owner <= 1) {
            struct stat st;
            if (stat(path, &st) == 0 && time(NULL) - st.st_mtime < 300)
                return false; // creator may not have written its PID yet
        }
        if (unlink(path) != 0 && errno != ENOENT) return false;
    }
    return false;
}

static inline void backup_lock_release(const char* path) { unlink(path); }

#endif
