// TostónSync — protected (favorite) backups. See protect.h.

#include "protect.h"
#include "backup_names.h"
#include "config.h"

#include <errno.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define PROTECT_MAX 512
#define PROTECT_NAME_MAX 160
static pthread_mutex_t s_protect_lock = PTHREAD_MUTEX_INITIALIZER;

static bool protect_path(char* out, size_t n) {
    const config_t* c = config_get();
    const char* dir = (c && c->paths.state_dir[0]) ? c->paths.state_dir
                                                   : "/data/tostonsync";
    int used = snprintf(out, n, "%s/protected.lst", dir);
    return used > 0 && (size_t)used < n;
}

static const char* base_name(const char* p) {
    if (!p) return "";
    const char* s = strrchr(p, '/');
    return s ? s + 1 : p;
}

static bool protect_name(const char* name) {
    if (!name || !name[0] || strlen(name) >= PROTECT_NAME_MAX ||
        !strcmp(name, ".") || !strcmp(name, "..")) return false;
    for (const unsigned char* p = (const unsigned char*)name; *p; p++)
        if (*p < 0x20 || *p == 0x7f || *p == '/' || *p == '\\') return false;
    return true;
}

// One bounded, complete record. EOF=0, record=1, corruption/read error=-1.
// fgetc uses stdio buffering and catches embedded NULs that fgets/strlen hide.
static int protect_line(FILE* f, char line[PROTECT_NAME_MAX]) {
    size_t n = 0;
    for (;;) {
        int c = fgetc(f);
        if (c == EOF) {
            if (ferror(f)) return -1;
            if (!n) return 0;
            break;
        }
        if (c == '\n') break;
        if (c == '\r') {
            c = fgetc(f);
            if ((c != '\n' && c != EOF) || ferror(f)) return -1;
            break;
        }
        if (c < 0x20 || c == 0x7f || c == '/' || c == '\\' ||
            n + 1 >= PROTECT_NAME_MAX) return -1;
        line[n++] = (char)c;
    }
    line[n] = '\0';
    return !n || protect_name(line) ? 1 : -1;
}

bool protect_is(const char* filename) {
    if (!filename || !filename[0]) return false;
    const char* bn = base_name(filename);
    // SAFETY archives are protected by identity. Explicit single-delete still
    // works because only automatic/bulk paths call protect_is().
    if (backup_filename_safety(bn)) return true;
    char path[300];
    if (!protect_path(path, sizeof(path))) return true;
    FILE* f = fopen(path, "r");
    if (!f) return errno != ENOENT;
    char line[PROTECT_NAME_MAX];
    bool found = false;
    size_t n = 0;
    int result;
    while ((result = protect_line(f, line)) > 0) {
        if (!line[0]) continue;
        if (++n > PROTECT_MAX || strcmp(line, bn) == 0) { found = true; break; }
    }
    if (result < 0) found = true;
    if (fclose(f) != 0) found = true;
    return found;
}

bool protect_set(const char* filename, bool on) {
    if (!filename || !filename[0]) return false;
    const char* bn = base_name(filename);
    // basename only — never let a path/separator into the list.
    if (!protect_name(bn)) return false;

    char path[300];
    if (!protect_path(path, sizeof(path))) return false;

    char (*keep)[PROTECT_NAME_MAX] =
        malloc(PROTECT_MAX * PROTECT_NAME_MAX);
    if (!keep) return false;
    pthread_mutex_lock(&s_protect_lock);
    size_t k = 0;
    bool ok = true;
    FILE* f = fopen(path, "r");
    if (f) {
        char line[PROTECT_NAME_MAX];
        size_t records = 0;
        int result;
        while ((result = protect_line(f, line)) > 0) {
            if (!line[0]) continue;
            if (++records > PROTECT_MAX) { ok = false; break; }
            if (strcmp(line, bn) == 0) continue;   // drop existing copy
            snprintf(keep[k++], PROTECT_NAME_MAX, "%s", line);
        }
        if (fclose(f) != 0 || result < 0) ok = false;
    } else if (errno != ENOENT) ok = false;
    if (!ok || (on && k >= PROTECT_MAX)) { ok = false; goto done; }

    char tmp[316];
    snprintf(tmp, sizeof(tmp), "%s.tmp", path);
    FILE* o = fopen(tmp, "w");
    if (!o) { ok = false; goto done; }
    for (size_t i = 0; i < k && ok; i++) ok = fprintf(o, "%s\n", keep[i]) > 0;
    if (on && ok) ok = fprintf(o, "%s\n", bn) > 0;
    if (fclose(o) != 0) ok = false;
    if (ok) ok = (rename(tmp, path) == 0);
    if (!ok) unlink(tmp);
done:
    pthread_mutex_unlock(&s_protect_lock);
    free(keep);
    return ok;
}

bool protect_to_json(char* out, size_t out_sz) {
    if (out && out_sz) out[0] = '\0';
    if (!out || out_sz < 3) return false;
    char path[300];
    if (!protect_path(path, sizeof(path))) return false;
    size_t w = 0;
    out[w++] = '[';
    FILE* f = fopen(path, "r");
    if (f) {
        char line[PROTECT_NAME_MAX];
        size_t records = 0;
        int result;
        bool ok = true;
        while ((result = protect_line(f, line)) > 0) {
            if (!line[0]) continue;
            size_t escaped = strlen(line);
            for (const char* p = line; *p; p++) if (*p == '"') escaped++;
            if (++records > PROTECT_MAX || escaped + 4 + (records > 1) > out_sz - w) {
                ok = false; break;
            }
            if (records > 1) out[w++] = ',';
            out[w++] = '"';
            for (const char* p = line; *p; p++) {
                if (*p == '"') out[w++] = '\\';
                out[w++] = *p;
            }
            out[w++] = '"';
        }
        if (fclose(f) != 0 || result < 0) ok = false;
        if (!ok) { out[0] = '\0'; return false; }
    } else if (errno != ENOENT) { out[0] = '\0'; return false; }
    out[w++] = ']';
    out[w] = '\0';
    return true;
}
