// TostónSync — title metadata cache. See metacache.h.

#include "metacache.h"
#include "config.h"
#include "fs.h"
#include "json.h"
#include "titlename.h"
#include "public_metadata.h"

#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MC_MAX      1024
#define MC_LINE_MAX 256

static pthread_mutex_t s_names_lock = PTHREAD_MUTEX_INITIALIZER;

static void state_dir(char* out, size_t n) {
    const config_t* c = config_get();
    const char* d = (c && c->paths.state_dir[0]) ? c->paths.state_dir
                                                 : "/data/tostonsync";
    snprintf(out, n, "%s", d);
}

static void names_path(char* out, size_t n) {
    char d[256];
    state_dir(d, sizeof(d));
    snprintf(out, n, "%s/title_cache.jsonl", d);
}

// Title ids are alphanumeric; reject anything else so a crafted id can never
// build a path with "/" or "..".
static bool tid_ok(const char* t) {
    if (!t || !t[0]) return false;
    for (size_t i = 0; t[i]; i++) {
        char c = t[i];
        if (!((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
              (c >= '0' && c <= '9')))
            return false;
    }
    return true;
}

static void write_name(FILE* f, const char* name) {
    fputc('"', f);
    for (const unsigned char* p = (const unsigned char*)name; *p; p++) {
        if (*p == '"' || *p == '\\') { fputc('\\', f); fputc(*p, f); }
        else if (*p == '\n') fputs("\\n", f);
        else if (*p == '\r') fputs("\\r", f);
        else if (*p == '\t') fputs("\\t", f);
        else if (*p >= 0x20) fputc(*p, f);
    }
    fputc('"', f);
}

static void get_name_locked(const char* title_id, char* out, size_t out_sz) {
    if (out && out_sz) out[0] = '\0';
    if (!tid_ok(title_id) || !out || out_sz == 0) return;
    char path[300];
    names_path(path, sizeof(path));
    FILE* f = fopen(path, "r");
    if (!f) return;
    char line[MC_LINE_MAX];
    while (fgets(line, sizeof(line), f)) {
        char id[48], name[96];
        if (!json_get_string(line, "title_id", id, sizeof(id)) ||
            strcmp(id, title_id) != 0 ||
            !json_get_string(line, "name", name, sizeof(name))) continue;
        titlename_copy_utf8(out, out_sz, name);
        break;
    }
    fclose(f);
}

void metacache_get_name(const char* title_id, char* out, size_t out_sz) {
    pthread_mutex_lock(&s_names_lock);
    get_name_locked(title_id, out, out_sz);
    pthread_mutex_unlock(&s_names_lock);
}

void metacache_note_name(const char* title_id, const char* name) {
    if (!tid_ok(title_id) || !name || !name[0]) return;
    if (strcmp(name, title_id) == 0) return;        // only real names
    char clean[96];
    titlename_copy_utf8(clean, sizeof(clean), name);
    if (!clean[0]) return;
    pthread_mutex_lock(&s_names_lock);
    char cur[96];
    get_name_locked(title_id, cur, sizeof(cur));
    if (strcmp(cur, clean) == 0) {
        pthread_mutex_unlock(&s_names_lock);
        return;                                    // already cached
    }

    char path[300];
    names_path(path, sizeof(path));
    char (*keep)[MC_LINE_MAX] = malloc(MC_MAX * MC_LINE_MAX);
    if (!keep) { pthread_mutex_unlock(&s_names_lock); return; }
    size_t k = 0;
    char skip[48];
    snprintf(skip, sizeof(skip), "\"title_id\":\"%s\"", title_id);
    FILE* f = fopen(path, "r");
    if (f) {
        char line[MC_LINE_MAX];
        while (k < MC_MAX && fgets(line, sizeof(line), f)) {
            if (strstr(line, skip)) continue;
            size_t L = strlen(line);
            while (L && (line[L-1] == '\n' || line[L-1] == '\r')) line[--L] = '\0';
            if (!line[0]) continue;
            snprintf(keep[k++], MC_LINE_MAX, "%s", line);
        }
        fclose(f);
    }
    char tmp[316];
    snprintf(tmp, sizeof(tmp), "%s.tmp", path);
    FILE* o = fopen(tmp, "w");
    if (!o) { free(keep); pthread_mutex_unlock(&s_names_lock); return; }
    for (size_t i = 0; i < k; i++) fprintf(o, "%s\n", keep[i]);
    fprintf(o, "{\"title_id\":\"%s\",\"name\":", title_id);
    write_name(o, clean);
    fputs("}\n", o);
    bool ok = !ferror(o);
    if (fclose(o) != 0) ok = false;
    free(keep);
    if (ok) rename(tmp, path);
    else remove(tmp);
    pthread_mutex_unlock(&s_names_lock);
}

static bool resolve_name(const char* title_id, const char* fallback,
                         char* out, size_t out_sz, bool remember) {
    if (!out || !out_sz) return false;
    if (!tid_ok(title_id)) { out[0] = '\0'; return false; }
    char name[96] = {0};
    if (titlename_lookup(title_id, name, sizeof(name)) && name[0] &&
        strcmp(name, title_id) != 0) {
        if (remember) metacache_note_name(title_id, name);
    } else {
        metacache_get_name(title_id, name, sizeof(name));
        if (strcmp(name, title_id) == 0) name[0] = '\0';
        if (!name[0] && fallback && strcmp(fallback, title_id) != 0)
            titlename_copy_utf8(name, sizeof(name), fallback);
        // Disk-only fallback: public lookups are explicitly requested by the UI,
        // never by the watcher, backup worker or this shared resolver.
        public_metadata_t public;
        if (!name[0] && public_metadata_cached(title_id, &public))
            titlename_copy_utf8(name, sizeof(name), public.name);
    }
    bool real_name = name[0] != '\0';
    titlename_copy_utf8(out, out_sz, real_name ? name : title_id);
    return real_name;
}

bool metacache_resolve_name(const char* title_id, const char* fallback,
                            char* out, size_t out_sz) {
    return resolve_name(title_id, fallback, out, out_sz, true);
}

bool metacache_resolve_name_readonly(const char* title_id, const char* fallback,
                                     char* out, size_t out_sz) {
    return resolve_name(title_id, fallback, out, out_sz, false);
}

void metacache_icon_path(const char* title_id, char* out, size_t out_sz) {
    if (out && out_sz) out[0] = '\0';
    if (!tid_ok(title_id) || !out) return;
    char d[256];
    state_dir(d, sizeof(d));
    snprintf(out, out_sz, "%s/metadata/%s/icon0.png", d, title_id);
}

bool metacache_has_icon(const char* title_id) {
    char p[400];
    metacache_icon_path(title_id, p, sizeof(p));
    if (!p[0]) return false;
    FILE* f = fopen(p, "rb");
    if (!f) return false;
    fclose(f);
    return true;
}

void metacache_cache_icon(const char* title_id, const char* src_path) {
    if (!tid_ok(title_id) || !src_path || !src_path[0]) return;
    if (metacache_has_icon(title_id)) return;
    FILE* in = fopen(src_path, "rb");
    if (!in) return;
    char d[256];
    state_dir(d, sizeof(d));
    char dir[320];
    snprintf(dir, sizeof(dir), "%s/metadata/%s", d, title_id);
    fs_mkdir_p(dir);
    char dst[400], tmp[416];
    snprintf(dst, sizeof(dst), "%s/icon0.png", dir);
    snprintf(tmp, sizeof(tmp), "%s.tmp", dst);
    FILE* out = fopen(tmp, "wb");
    if (!out) { fclose(in); return; }
    char buf[8192];
    size_t r;
    bool ok = true;
    while ((r = fread(buf, 1, sizeof(buf), in)) > 0) {
        if (fwrite(buf, 1, r, out) != r) { ok = false; break; }
    }
    fclose(in);
    if (fclose(out) != 0) ok = false;
    if (ok) rename(tmp, dst);
    else    remove(tmp);
}
