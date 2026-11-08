// Descriptor-relative I/O: the pinned PS5 SDK's *at stubs return raw BSD
// syscall results. Carry, not the positive return value, distinguishes errno
// from a valid file descriptor. Keep the caller's POSIX contract on PS5.
#ifndef TOSTONSYNC_AT_IO_H
#define TOSTONSYNC_AT_IO_H

#include <errno.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <stddef.h>
#include <stdint.h>

// Guard native output before any caller reads the received stat fields.
typedef struct {
    volatile uint64_t before;
    struct stat value;
    volatile uint64_t after;
} toston_stat_guard_t;
#define TOSTON_STAT_GUARD_INIT {UINT64_C(0x8d23f19ac46be075), {0}, UINT64_C(0x75e06bc49af1238d)}
_Static_assert(offsetof(toston_stat_guard_t, value) == sizeof(uint64_t), "stat guard prefix adjacency");
_Static_assert(offsetof(toston_stat_guard_t, after) == sizeof(uint64_t) + sizeof(struct stat), "stat guard suffix adjacency");

static inline int toston_stat_guard_valid(const toston_stat_guard_t* guard) {
    return guard->before == UINT64_C(0x8d23f19ac46be075) &&
           guard->after == UINT64_C(0x75e06bc49af1238d);
}

static inline int toston_at_result(long result, unsigned char failed) {
    if (failed) {
        errno = (int)result;
        return -1;
    }
    return (int)result;
}

#if defined(__PROSPERO__)
#include <stddef.h>
#include <sys/syscall.h>

// Raw stat syscalls require the pinned v0.43 BSD layout, not a libc adapter.
_Static_assert(sizeof(struct stat) == 120, "PS5 SDK v0.43 stat size");
_Static_assert(sizeof(toston_stat_guard_t) == 136, "PS5 stat guard size");
_Static_assert(_Alignof(struct stat) == 8, "PS5 SDK v0.43 stat alignment");
_Static_assert(offsetof(struct stat, st_dev) == 0, "PS5 stat dev offset");
_Static_assert(offsetof(struct stat, st_ino) == 4, "PS5 stat ino offset");
_Static_assert(offsetof(struct stat, st_mode) == 8, "PS5 stat mode offset");
_Static_assert(offsetof(struct stat, st_size) == 72, "PS5 stat size offset");
_Static_assert(offsetof(struct stat, st_mtim) == 40, "PS5 stat mtime offset");

// The BSD return path may overwrite argument/scratch registers as well as rcx/r11.
static inline int toston_at_call(long number, int dirfd, const char* path,
                                 long third, long fourth) {
    register long arg4 __asm__("r10") = fourth;
    long result;
    unsigned char failed;
    __asm__ volatile("syscall"
                     : "=a"(result), "=@ccc"(failed), "+d"(third), "+r"(arg4)
                     : "0"(number), "D"((long)dirfd), "S"(path)
                     : "rcx", "r8", "r9", "r11", "memory", "cc");
    return toston_at_result(result, failed);
}

static inline int toston_mkdirat(int dirfd, const char* path, mode_t mode) {
    return toston_at_call(SYS_mkdirat, dirfd, path, (long)mode, 0);
}

static inline int toston_openat(int dirfd, const char* path, int flags,
                               mode_t mode) {
    return toston_at_call(SYS_openat, dirfd, path, (long)flags, (long)mode);
}

static inline int toston_fstatat(int dirfd, const char* path,
                                struct stat* statbuf, int flags) {
    return toston_at_call(SYS_fstatat, dirfd, path, (long)statbuf, (long)flags);
}

// Match the BSD stat layout used by fstatat, not an imported libc adapter.
static inline int toston_fstat(int fd, struct stat* statbuf) {
    long argument_fd = fd, result, secondary = 0;
    struct stat* argument_stat = statbuf;
    unsigned char failed;
    __asm__ volatile("syscall"
                     : "=a"(result), "=@ccc"(failed), "+D"(argument_fd),
                       "+S"(argument_stat), "+d"(secondary)
                     : "0"((long)SYS_fstat)
                     : "rcx", "r8", "r9", "r10", "r11", "memory", "cc");
    (void)secondary;
    return toston_at_result(result, failed);
}
#else
// Use native libc (and its test hooks) on the host.
#define toston_mkdirat mkdirat
#define toston_openat openat
#define toston_fstatat fstatat
#define toston_fstat fstat
#endif

#endif
