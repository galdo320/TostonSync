// Original extracted members, pinned before any native metadata inspection.
#ifndef TOSTONSYNC_RESTORE_SOURCES_H
#define TOSTONSYNC_RESTORE_SOURCES_H
#include "sha256.h"
#include <dirent.h>
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

typedef struct {
    char path[1024], sha256[65];
    uint64_t bytes;
    bool directory;
} restore_source_entry_t;
typedef struct {
    restore_source_entry_t* entries;
    size_t count;
} restore_sources_t;

static inline void restore_sources_free(restore_sources_t* s) {
    free(s->entries); s->entries = NULL; s->count = 0;
}
static inline const restore_source_entry_t* restore_sources_find(
    const restore_sources_t* s, const char* path) {
    if (!s || !path) return NULL;
    for (size_t i = 0; i < s->count; i++)
        if (!strcmp(s->entries[i].path, path)) return &s->entries[i];
    return NULL;
}
static inline bool restore_sources_walk(restore_sources_t* s, const char* path,
                                        unsigned depth, bool capture, size_t* visited) {
    struct stat before, after;
    if (depth > 64 || strlen(path) >= 1024 || lstat(path, &before) ||
        (!S_ISREG(before.st_mode) && !S_ISDIR(before.st_mode))) return false;
    restore_source_entry_t entry = {0};
    strcpy(entry.path, path); entry.directory = S_ISDIR(before.st_mode);
    if (!entry.directory) {
        if (before.st_size < 0 || !sha256_file_hex(path, entry.sha256)) return false;
        entry.bytes = (uint64_t)before.st_size;
    }
    if (capture) {
        if (s->count == SIZE_MAX / sizeof(entry)) return false;
        void* next = realloc(s->entries, (s->count + 1) * sizeof(entry));
        if (!next) return false;
        s->entries = next; s->entries[s->count++] = entry;
    } else {
        const restore_source_entry_t* expected = restore_sources_find(s, path);
        if (!expected || expected->directory != entry.directory ||
            expected->bytes != entry.bytes || strcmp(expected->sha256, entry.sha256)) return false;
    }
    (*visited)++;
    if (entry.directory) {
        DIR* d = opendir(path); if (!d) return false;
        bool ok = true;
        for (;;) {
            errno = 0; struct dirent* e = readdir(d);
            if (!e) { if (errno) ok = false; break; }
            if (!strcmp(e->d_name, ".") || !strcmp(e->d_name, "..")) continue;
            char child[1024]; int n = snprintf(child, sizeof(child), "%s/%s", path, e->d_name);
            if (n < 0 || n >= (int)sizeof(child) ||
                !restore_sources_walk(s, child, depth + 1, capture, visited)) { ok = false; break; }
        }
        if (closedir(d)) ok = false;
        if (!ok) return false;
    }
    return !lstat(path, &after) && before.st_dev == after.st_dev &&
        before.st_ino == after.st_ino && before.st_mode == after.st_mode &&
        before.st_size == after.st_size && before.st_mtime == after.st_mtime &&
        before.st_ctime == after.st_ctime;
}
static inline bool restore_sources_capture(restore_sources_t* s, const char* root) {
    if (!s || s->entries || s->count || !root) return false;
    size_t visited = 0;
    if (restore_sources_walk(s, root, 0, true, &visited)) return true;
    restore_sources_free(s); return false;
}
static inline bool restore_sources_tree_matches(const restore_sources_t* s, const char* root) {
    if (!s || !root || !restore_sources_find(s, root)) return false;
    size_t n = strlen(root), expected = 0, visited = 0;
    for (size_t i = 0; i < s->count; i++)
        if (!strcmp(s->entries[i].path, root) ||
            (!strncmp(s->entries[i].path, root, n) && s->entries[i].path[n] == '/')) expected++;
    return restore_sources_walk((restore_sources_t*)s, root, 0, false, &visited) && visited == expected;
}
static inline bool restore_sources_file_matches(const restore_sources_t* s,
                                                const char* original, const char* published) {
    const restore_source_entry_t* e = restore_sources_find(s, original);
    struct stat st; char sha[65];
    return e && !e->directory && !lstat(published, &st) && S_ISREG(st.st_mode) &&
        st.st_size >= 0 && (uint64_t)st.st_size == e->bytes &&
        sha256_file_hex(published, sha) && !strcmp(sha, e->sha256);
}
#endif
