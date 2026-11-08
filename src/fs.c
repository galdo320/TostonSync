// TostónSync — filesystem helpers + sandbox escape.

#include "fs.h"
#include "log.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

// Sandbox-escape primitives provided by ps5-payload-sdk.
// These walk the current process's filedesc / root pointer up to the
// kernel root, giving us access to the full filesystem.
extern intptr_t kernel_get_root_vnode(void);
extern int      kernel_set_proc_rootdir(intptr_t vnode);
extern int      kernel_set_proc_jaildir(intptr_t vnode);

bool fs_escape_sandbox(void) {
    intptr_t root = kernel_get_root_vnode();
    if (!root) return false;
    if (kernel_set_proc_rootdir(root) != 0) return false;
    // Some firmwares also gate by jaildir; ignore failure here.
    kernel_set_proc_jaildir(root);
    return true;
}

uint64_t fs_dir_size(const char* path) {
    if (!path || !*path) return 0;
    struct stat top;
    if (lstat(path, &top) != 0) return 0;
    if (S_ISREG(top.st_mode)) return (uint64_t)top.st_size;
    if (!S_ISDIR(top.st_mode)) return 0;

    DIR* d = opendir(path);
    if (!d) return 0;
    uint64_t total = 0;
    struct dirent* e;
    while ((e = readdir(d)) != NULL) {
        if (e->d_name[0] == '.' &&
            (e->d_name[1] == '\0' ||
             (e->d_name[1] == '.' && e->d_name[2] == '\0'))) continue;
        char p[1024];
        snprintf(p, sizeof(p), "%s/%s", path, e->d_name);
        struct stat st;
        if (lstat(p, &st) != 0) continue;
        if (S_ISDIR(st.st_mode))       total += fs_dir_size(p);
        else if (S_ISREG(st.st_mode))  total += (uint64_t)st.st_size;
    }
    closedir(d);
    return total;
}

static bool fs_backup_estimate_fail(fs_backup_estimate_t* out,
                                     const char* reason, int error) {
    out->estimated_bytes = 0;
    out->reason = reason;
    out->error = error;
    return false;
}

static bool fs_backup_estimate_same(const struct stat* a, const struct stat* b) {
#if defined(__APPLE__)
    const struct timespec am = a->st_mtimespec, bm = b->st_mtimespec;
    const struct timespec ac = a->st_ctimespec, bc = b->st_ctimespec;
#else
    const struct timespec am = a->st_mtim, bm = b->st_mtim;
    const struct timespec ac = a->st_ctim, bc = b->st_ctim;
#endif
    return a->st_dev == b->st_dev && a->st_ino == b->st_ino &&
           a->st_mode == b->st_mode && a->st_size == b->st_size &&
           am.tv_sec == bm.tv_sec && am.tv_nsec == bm.tv_nsec &&
           ac.tv_sec == bc.tv_sec && ac.tv_nsec == bc.tv_nsec;
}

static bool fs_backup_estimate_walk(const char* path, unsigned depth,
                                    size_t* nodes, fs_backup_estimate_t* out) {
    if (depth > 16 || ++*nodes > 16384)
        return fs_backup_estimate_fail(out, "limit", EOVERFLOW);
    struct stat before;
    if (lstat(path, &before) != 0)
        return fs_backup_estimate_fail(out, "unreadable", errno);
    if (S_ISREG(before.st_mode)) {
        if (before.st_size < 0)
            return fs_backup_estimate_fail(out, "overflow", EOVERFLOW);
        uint64_t bytes = (uint64_t)before.st_size;
        // zip.c uses stored DEFLATE blocks (5 bytes per <=65535 bytes).
        // 4096 covers both headers/ZIP64, names and escaped checksum JSON.
        uint64_t overhead = 4096 + 5 * (bytes / 65535 + 1);
        if (bytes > UINT64_MAX - overhead ||
            bytes + overhead > UINT64_MAX - out->estimated_bytes ||
            bytes > UINT64_MAX - out->source_bytes)
            return fs_backup_estimate_fail(out, "overflow", EOVERFLOW);
        out->source_bytes += bytes;
        out->estimated_bytes += bytes + overhead;
        out->files++;
        return true;
    }
    if (!S_ISDIR(before.st_mode))
        return fs_backup_estimate_fail(out, "unsupported", EINVAL);
    DIR* dir = opendir(path);
    if (!dir) return fs_backup_estimate_fail(out, "unreadable", errno);
    struct stat held;
    bool ok = fstat(dirfd(dir), &held) == 0;
    if (!ok) fs_backup_estimate_fail(out, "unreadable", errno);
    else if (!fs_backup_estimate_same(&before, &held))
        ok = fs_backup_estimate_fail(out, "changed", ESTALE);
    while (ok) {
        errno = 0;
        struct dirent* entry = readdir(dir);
        if (!entry) {
            if (errno) ok = fs_backup_estimate_fail(out, "unreadable", errno);
            break;
        }
        if (!strcmp(entry->d_name, ".") || !strcmp(entry->d_name, "..")) continue;
        char child[1024];
        int n = snprintf(child, sizeof(child), "%s/%s", path, entry->d_name);
        if (n < 0 || (size_t)n >= sizeof(child)) {
            ok = fs_backup_estimate_fail(out, "limit", ENAMETOOLONG);
            break;
        }
        ok = fs_backup_estimate_walk(child, depth + 1, nodes, out);
    }
    if (closedir(dir) != 0 && ok)
        ok = fs_backup_estimate_fail(out, "unreadable", errno);
    if (ok) {
        struct stat after;
        if (lstat(path, &after) != 0)
            ok = fs_backup_estimate_fail(out, "unreadable", errno);
        else if (!fs_backup_estimate_same(&before, &after))
            ok = fs_backup_estimate_fail(out, "changed", ESTALE);
    }
    return ok;
}

bool fs_backup_size_estimate(const char* path, fs_backup_estimate_t* out) {
    if (!out) return false;
    memset(out, 0, sizeof(*out));
    out->reason = "unknown";
    if (!path || !path[0])
        return fs_backup_estimate_fail(out, "unreadable", EINVAL);
    // Manifest, checksum wrapper, their headers and ZIP64 end records.
    out->estimated_bytes = 32768;
    size_t nodes = 0;
    if (!fs_backup_estimate_walk(path, 0, &nodes, out)) return false;
    if (!out->files || !out->source_bytes)
        return fs_backup_estimate_fail(out, "empty", 0);
    out->reason = "observed";
    return true;
}

bool fs_mkdir_p(const char* path) {
    if (!path || !*path) return false;
    char tmp[512];
    snprintf(tmp, sizeof(tmp), "%s", path);
    size_t len = strlen(tmp);
    if (tmp[len - 1] == '/') tmp[len - 1] = '\0';
    for (char* p = tmp + 1; *p; p++) {
        if (*p == '/') {
            *p = '\0';
            if (mkdir(tmp, 0755) != 0 && errno != EEXIST) return false;
            *p = '/';
        }
    }
    if (mkdir(tmp, 0755) != 0 && errno != EEXIST) return false;
    return true;
}

size_t fs_list_users(const char* root, fs_dir_t* out, size_t max_out) {
    if (!root || !out || max_out == 0) return 0;
    DIR* d = opendir(root);
    if (!d) return 0;
    size_t n = 0;
    bool complete = true;
    struct dirent* e;
    for (;;) {
        errno = 0;
        e = readdir(d);
        if (!e) { if (errno) complete = false; break; }
        if (e->d_name[0] == '.') continue;
        char p[300];
        int len = snprintf(p, sizeof(p), "%s/%s", root, e->d_name);
        if (len < 0 || (size_t)len >= sizeof(p)) {
            complete = false;
            break;
        }
        struct stat st;
        if (stat(p, &st) != 0) { complete = false; break; }
        if (!S_ISDIR(st.st_mode)) continue;
        if (n == max_out || strlen(e->d_name) >= sizeof(out[n].user_uid) ||
            strlen(e->d_name) >= sizeof(out[n].name) ||
            (size_t)len >= sizeof(out[n].path)) {
            complete = false;
            break;
        }
        memset(&out[n], 0, sizeof(out[n]));
        strncpy(out[n].name,     e->d_name, sizeof(out[n].name)     - 1);
        strncpy(out[n].path,     p,         sizeof(out[n].path)     - 1);
        strncpy(out[n].user_uid, e->d_name, sizeof(out[n].user_uid) - 1);
        n++;
    }
    if (closedir(d) != 0) complete = false;
    // A partial list must never authorize automatic selection of its sole user.
    return complete ? n : 0;
}

size_t fs_list_save_titles(const char* root, fs_dir_t* out, size_t max_out) {
    if (!root || !out || max_out == 0) return 0;
    fs_dir_t users[16];
    size_t un = fs_list_users(root, users, 16);
    size_t n = 0;
    for (size_t i = 0; i < un && n < max_out; i++) {
        char base[300];
        snprintf(base, sizeof(base), "%s/savedata_prospero", users[i].path);
        DIR* d = opendir(base);
        if (!d) continue;
        struct dirent* e;
        while ((e = readdir(d)) != NULL && n < max_out) {
            if (e->d_name[0] == '.') continue;
            char p[400];
            snprintf(p, sizeof(p), "%s/%s", base, e->d_name);
            struct stat st;
            if (stat(p, &st) != 0 || !S_ISDIR(st.st_mode)) continue;
            memset(&out[n], 0, sizeof(out[n]));
            strncpy(out[n].name,     e->d_name,         sizeof(out[n].name)     - 1);
            strncpy(out[n].path,     p,                 sizeof(out[n].path)     - 1);
            // Tag the title entry with the PS5 user UID that owns it so
            // the watcher / destinations can keep saves separated per
            // user even when two profiles share the same game.
            strncpy(out[n].user_uid, users[i].user_uid, sizeof(out[n].user_uid) - 1);
            n++;
        }
        closedir(d);
    }
    return n;
}

// --------------------------------------------------------------------
// Running-title detection.
//
// The PS5 reports the foregrounded title's ID via system info APIs
// that vary across firmware. As a portable best-effort, we walk
// /mnt/sandbox/*/ and pick the directory whose name matches the
// "<TITLEID>_<random>" pattern and was modified most recently.
// Empty string when nothing matches (e.g. at the system menu).
// --------------------------------------------------------------------

void fs_get_running_title(char* out, size_t out_sz) {
    if (!out || out_sz == 0) return;
    out[0] = '\0';
    DIR* d = opendir("/mnt/sandbox");
    if (!d) return;
    char best_id[16] = {0};
    time_t best_mt = 0;
    struct dirent* e;
    while ((e = readdir(d)) != NULL) {
        if (e->d_name[0] == '.') continue;
        // PS5 sandbox dirs look like "CUSA00000_000" or "PPSA00001_000".
        if ((strncmp(e->d_name, "CUSA", 4) != 0
          && strncmp(e->d_name, "PPSA", 4) != 0)
          || strlen(e->d_name) < 9) continue;
        char p[256];
        snprintf(p, sizeof(p), "/mnt/sandbox/%s", e->d_name);
        struct stat st;
        if (stat(p, &st) != 0 || !S_ISDIR(st.st_mode)) continue;
        if (st.st_mtime > best_mt) {
            best_mt = st.st_mtime;
            // Take just the TITLE_ID prefix (up to underscore).
            size_t i = 0;
            while (i < sizeof(best_id) - 1 && e->d_name[i] && e->d_name[i] != '_') {
                best_id[i] = e->d_name[i]; i++;
            }
            best_id[i] = '\0';
        }
    }
    closedir(d);
    // Only count as "running" if modified within the last 15 seconds.
    // Otherwise we're at the menu and the last-foregrounded title has
    // gone idle.
    if (best_id[0] && (time(NULL) - best_mt) < 15) {
        strncpy(out, best_id, out_sz - 1);
        out[out_sz - 1] = '\0';
    }
}

// Existence-based "is this title running" check: true while the game's
// /mnt/sandbox/<title_id>_* directory exists, false once it is gone. Unlike
// fs_get_running_title() this does NOT use mtime, so a game that simply stops
// writing for a while (cutscene, idle, menu) is still correctly reported as
// running — preventing a "game closed" backup from firing mid-play.
// Newest modification time (unix) among the regular files directly inside
// `dir`. Used to detect that a game wrote to its save by changing one of the
// sdimg_* images — kqueue NOTE_WRITE on the directory does NOT fire for writes
// to existing files, so the watcher polls this instead. Returns 0 if the dir
// is missing/empty.
int64_t fs_dir_newest_mtime(const char* dir) {
    if (!dir || !dir[0]) return 0;
    DIR* d = opendir(dir);
    if (!d) return 0;
    int64_t newest = 0;
    struct dirent* e;
    while ((e = readdir(d)) != NULL) {
        if (e->d_name[0] == '.') continue;
        char p[512];
        snprintf(p, sizeof(p), "%s/%s", dir, e->d_name);
        struct stat st;
        if (stat(p, &st) != 0) continue;
        if ((int64_t)st.st_mtime > newest) newest = (int64_t)st.st_mtime;
    }
    closedir(d);
    return newest;
}

static bool title_running_state(const char* title_id, bool* running) {
    *running = false;
    if (!title_id || !title_id[0]) return false;
    DIR* d = opendir("/mnt/sandbox");
    if (!d) return false;
    size_t tlen = strlen(title_id);
    bool ok = true;
    struct dirent* e;
    for (;;) {
        errno = 0;
        e = readdir(d);
        if (!e) { if (errno) ok = false; break; }
        if (e->d_name[0] == '.') continue;
        if (strncmp(e->d_name, title_id, tlen) == 0 && e->d_name[tlen] == '_') {
            char p[256];
            int n = snprintf(p, sizeof(p), "/mnt/sandbox/%s", e->d_name);
            struct stat st;
            if (n < 0 || (size_t)n >= sizeof(p) || stat(p, &st) != 0) {
                ok = false;
                break;
            }
            if (S_ISDIR(st.st_mode)) { *running = true; break; }
        }
    }
    if (closedir(d) != 0) ok = false;
    return ok;
}

bool fs_title_is_running(const char* title_id) {
    bool running;
    (void)title_running_state(title_id, &running);
    return running;
}

bool fs_title_is_closed(const char* title_id) {
    bool running;
    return title_running_state(title_id, &running) && !running;
}
