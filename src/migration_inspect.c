#include "migration_inspect.h"
#include "json.h"
#include "log.h"
#include "paired_capture.h"
#include "pfs_resign.h"
#include "sha256.h"
#include "sfo.h"
#include "zip.h"

#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/stat.h>
#include <unistd.h>

static pthread_mutex_t s_inspect_lock = PTHREAD_MUTEX_INITIALIZER;

static bool inspect_zip_locked(const char* zip_path, const char* title_hint,
                               migration_report_t* out, const char* stage,
                               bool allow_capture);
static bool verify_capture_locked(const char* root, bool* present,
                                  paired_capture_t* capture,
                                  char* error, size_t error_sz,
                                  migration_report_t* report);

static void observe_scratch(const char* path,
                            migration_scratch_diagnostic_t* diagnostic) {
    struct stat st;
    errno = 0;
    int ret = lstat(path, &st);
    int error = ret < 0 ? errno : 0;
    if (!diagnostic) return;
    diagnostic->lstat_return = ret;
    diagnostic->errno_valid = ret < 0 && error > 0;
    diagnostic->error_number = error;
    diagnostic->state = ret == 0 ? MIGRATION_SCRATCH_REMAINS :
        error == ENOENT ? MIGRATION_SCRATCH_ABSENT : MIGRATION_SCRATCH_UNKNOWN;
}

static bool title_ok(const char* s) {
    if (!s) return false;
    size_t n = strlen(s);
    if (n < 5 || n > 15) return false;
    for (size_t i = 0; i < n; i++)
        if (!((s[i] >= 'A' && s[i] <= 'Z') || (s[i] >= '0' && s[i] <= '9')))
            return false;
    return true;
}

static bool component_ok(const char* s) {
    if (!s || !s[0] || strcmp(s, ".") == 0 || strcmp(s, "..") == 0) return false;
    for (const unsigned char* p = (const unsigned char*)s; *p; p++)
        if (*p < 0x20 || *p == '/' || *p == '\\') return false;
    return true;
}

static const char* base_name(const char* path) {
    const char* p = path ? strrchr(path, '/') : NULL;
    return p ? p + 1 : path;
}

static bool path_is_service(const char* path) {
    return path && (strstr(path, "/sdimg_sce_bu_") != NULL ||
                    strstr(path, "/service/") != NULL ||
                    strncmp(base_name(path), "sdimg_sce_bu_", 13) == 0);
}

static void set_reason(migration_report_t* r, const char* msg) {
    if (r && !r->reason[0]) snprintf(r->reason, sizeof(r->reason), "%s", msg);
}

static void set_title(migration_report_t* r, const char* id,
                      const char* hint) {
    if (!title_ok(id)) return;
    if (hint && hint[0] && strcmp(hint, "auto") != 0 && strcmp(hint, id) != 0) {
        set_reason(r, "Backup TITLE ID does not match the selected game");
        return;
    }
    if (r->title_id[0] && strcmp(r->title_id, id) != 0) {
        set_reason(r, "Backup mixes more than one TITLE ID");
        return;
    }
    snprintf(r->title_id, sizeof(r->title_id), "%s", id);
}

static void add_dir(migration_report_t* r, const char* dir) {
    if (!r || !component_ok(dir)) return;
    if (strlen(dir) >= sizeof(r->save_dirs[0])) {
        set_reason(r, "Save slot name exceeds the supported limit");
        return;
    }
    for (size_t i = 0; i < r->save_dir_count; i++)
        if (strcmp(r->save_dirs[i], dir) == 0) return;
    if (r->save_dir_count == MIGRATION_MAX_SLOTS) {
        set_reason(r, "Backup exceeds the supported save slot limit");
        return;
    }
    snprintf(r->save_dirs[r->save_dir_count++], 64, "%s", dir);
}

static void add_service_dir(migration_report_t* r, const char* dir) {
    if (!r || !component_ok(dir)) return;
    if (strlen(dir) >= sizeof(r->service_dirs[0])) {
        set_reason(r, "Service slot name exceeds the supported limit");
        return;
    }
    for (size_t i = 0; i < r->service_dir_count; i++)
        if (strcmp(r->service_dirs[i], dir) == 0) return;
    if (r->service_dir_count == MIGRATION_MAX_SLOTS) {
        set_reason(r, "Backup exceeds the supported service slot limit");
        return;
    }
    snprintf(r->service_dirs[r->service_dir_count++], 64, "%s", dir);
}

static bool count_plain_payload(const char* dir, unsigned depth,
                                 bool slot_root, size_t* count,
                                 migration_report_t* report) {
    DIR* d = opendir(dir);
    if (!d) {
        set_reason(report, "Save payload directory could not be read");
        return false;
    }
    bool ok = true;
    for (;;) {
        errno = 0;
        struct dirent* e = readdir(d);
        if (!e) {
            if (errno) {
                set_reason(report, "Save payload directory could not be read");
                ok = false;
            }
            break;
        }
        if (strcmp(e->d_name, ".") == 0 || strcmp(e->d_name, "..") == 0 ||
            (slot_root && strcmp(e->d_name, "sce_sys") == 0)) continue;
        char path[1024];
        int n = snprintf(path, sizeof(path), "%s/%s", dir, e->d_name);
        if (!component_ok(e->d_name) || n < 0 || (size_t)n >= sizeof(path)) {
            set_reason(report, "Save payload path is invalid or too long");
            ok = false;
            break;
        }
        struct stat st;
        if (lstat(path, &st) != 0 ||
            (!S_ISREG(st.st_mode) && !S_ISDIR(st.st_mode))) {
            set_reason(report, "Save payload contains an unreadable or unsafe entry");
            ok = false;
            break;
        }
        if (S_ISDIR(st.st_mode)) {
            if (!depth) {
                set_reason(report, "Save payload nesting exceeds the supported limit");
                ok = false;
            } else {
                ok = count_plain_payload(path, depth - 1, false, count, report);
            }
            if (!ok) break;
        } else if (st.st_size > 0) {
            (*count)++;
        }
    }
    if (closedir(d) != 0) {
        set_reason(report, "Save payload directory could not be closed");
        ok = false;
    }
    return ok;
}

bool migration_count_plain_payload(const char* dir, size_t* count) {
    if (!dir || !count) return false;
    migration_report_t report = {0};
    *count = 0;
    return count_plain_payload(dir, 8, true, count, &report);
}

static void inspect_plain_dir(const char* dir, const char* title_hint,
                              migration_report_t* r) {
    char sfo_path[1024], key_path[1024];
    snprintf(sfo_path, sizeof(sfo_path), "%s/sce_sys/param.sfo", dir);
    struct stat st;
    if (stat(sfo_path, &st) != 0 || !S_ISREG(st.st_mode)) return;
    if (st.st_size <= 0) { set_reason(r, "param.sfo is missing or empty"); return; }
    sfo_info_t sfo;
    if (sfo_parse(sfo_path, &sfo) != 0) {
        set_reason(r, "param.sfo is invalid");
        return;
    }
    set_title(r, sfo.title_id, title_hint);
    if (sfo.main_title[0] && !r->title_name[0])
        snprintf(r->title_name, sizeof(r->title_name), "%s", sfo.main_title);
    if (!sfo.dir_name[0] || !component_ok(sfo.dir_name)) {
        set_reason(r, "SAVEDATA_DIRECTORY is missing or invalid");
        return;
    }
    const char* folder = base_name(dir);
    const char* folder_slot = NULL;
    if (strncmp(folder, "sdimg_sce_bu_", 13) == 0) folder_slot = folder + 13;
    else if (strncmp(folder, "sdimg_", 6) == 0) folder_slot = folder + 6;
    if (folder_slot && strcmp(folder_slot, sfo.dir_name) != 0) {
        set_reason(r, "Save folder does not match SAVEDATA_DIRECTORY");
        return;
    }
    if (strncmp(sfo.title_id, "PPSA", 4) == 0 && strcmp(sfo.format, "ppr") != 0) {
        set_reason(r, "PS5 decrypted save does not declare FORMAT=ppr");
        return;
    }
    snprintf(key_path, sizeof(key_path), "%s/sce_sys/keystone", dir);
    if (stat(key_path, &st) != 0 || !S_ISREG(st.st_mode) || st.st_size != 96) {
        set_reason(r, "keystone is missing or is not 96 bytes");
        return;
    }
    size_t payloads = 0;
    if (!count_plain_payload(dir, 8, true, &payloads, r)) return;
    if (!payloads) {
        if (r->format == MIGRATION_FORMAT_INVALID)
            r->format = MIGRATION_FORMAT_METADATA_ONLY;
        set_reason(r, "Backup contains metadata but no playable save payload");
        return;
    }
    r->payload_files += payloads;
    if (!path_is_service(dir)) add_dir(r, sfo.dir_name);
}

static void inspect_tree(const char* dir, const char* title_hint,
                          migration_report_t* r, int depth,
                          const char* capture_title) {
    if (depth < 0 || r->reason[0]) return;
    size_t payloads_before = r->payload_files;
    inspect_plain_dir(dir, title_hint, r);
    // Once SFO identifies a slot, its already-inventoried children are game
    // data, not more title/slot roots (e.g. a directory named CHAPTER1).
    if (r->reason[0] || r->payload_files > payloads_before) return;
    DIR* d = opendir(dir);
    if (!d) return;
    struct dirent* e;
    while ((e = readdir(d)) != NULL && !r->reason[0]) {
        if (!component_ok(e->d_name)) continue;
        // Reserved only beside the active trees. A .capture *inside* an
        // identified slot is literal game data, already counted above.
        if (capture_title && !strcmp(dir, capture_title) &&
            !strcmp(e->d_name, ".capture")) continue;
        char path[1024];
        snprintf(path, sizeof(path), "%s/%s", dir, e->d_name);
        struct stat st;
        if (stat(path, &st) != 0) continue;
        if (S_ISDIR(st.st_mode)) {
            if (title_ok(e->d_name)) set_title(r, e->d_name, title_hint);
            inspect_tree(path, title_hint, r, depth - 1, capture_title);
        } else if (S_ISREG(st.st_mode) && strncmp(e->d_name, "sdimg_", 6) == 0) {
            if (strncmp(e->d_name, "sdimg_sce_bu_", 13) == 0) {
                r->service_images++;
                add_service_dir(r, e->d_name + 13);
            } else {
                r->active_images++;
                add_dir(r, e->d_name + 6);
            }
        }
    }
    closedir(d);
}

static void finish_raw_completeness(migration_report_t* r) {
    if (!r || !r->active_images) return;
    if (!r->service_images) {
        snprintf(r->raw_completeness, sizeof(r->raw_completeness),
                 "active_only_no_service_images");
        return;
    }
    for (size_t i = 0; i < r->save_dir_count; i++) {
        bool found = false;
        for (size_t j = 0; j < r->service_dir_count; j++)
            if (strcmp(r->save_dirs[i], r->service_dirs[j]) == 0) {
                found = true;
                break;
            }
        if (found) continue;
        r->missing_service_images++;
        if (!r->first_missing_service_image[0])
            snprintf(r->first_missing_service_image,
                     sizeof(r->first_missing_service_image),
                     "sdimg_sce_bu_%s", r->save_dirs[i]);
    }
    snprintf(r->raw_completeness, sizeof(r->raw_completeness), "%s",
             r->missing_service_images ? "active_only_warning" : "complete");
}

void migration_plan_report(migration_report_t* r) {
    if (!r) return;
    if (!r->valid) {
        snprintf(r->restore_strategy, sizeof(r->restore_strategy), "blocked");
        snprintf(r->strategy_reason, sizeof(r->strategy_reason), "%s",
                 r->reason[0] ? r->reason : "Backup preflight did not pass");
        return;
    }
    if (r->selected_containers) {
        snprintf(r->restore_strategy, sizeof(r->restore_strategy), "blocked");
        r->strategy_ready = false;
        snprintf(r->strategy_reason, sizeof(r->strategy_reason),
                 "Partial RAW export; restore is not enabled for this export scope");
        return;
    }
    if (r->format == MIGRATION_FORMAT_ENCRYPTED_IMAGE) {
        snprintf(r->restore_strategy, sizeof(r->restore_strategy), "exact");
        r->strategy_ready = true;
        r->target_identity_required = true;
        snprintf(r->strategy_reason, sizeof(r->strategy_reason),
                 "Target slot identity must match before any write");
        return;
    }
    if (r->format == MIGRATION_FORMAT_TOSTON_DECRYPTED && r->has_checksums) {
        snprintf(r->restore_strategy, sizeof(r->restore_strategy), "portable");
        r->strategy_ready = true;
        r->target_identity_required = true;
        snprintf(r->strategy_reason, sizeof(r->strategy_reason),
                 "Target slots are validated automatically before restore");
        return;
    }
    snprintf(r->restore_strategy, sizeof(r->restore_strategy), "blocked");
    snprintf(r->strategy_reason, sizeof(r->strategy_reason),
             "Only checksummed TostónSync backups can be restored across consoles");
}

static const char* scope_ws(const char* p) {
    while (*p && isspace((unsigned char)*p)) p++;
    return p;
}

// Selection authorities are literal UTF-8 strings, never escaped aliases.
static bool scope_string(const char** cursor, char* out, size_t cap) {
    const char* p = scope_ws(*cursor);
    if (*p++ != '"') return false;
    size_t n = 0;
    while (*p && *p != '"') {
        if ((unsigned char)*p < 0x20) return false;
        if (*p == '\\') {
            if (out) return false;
            if (*++p == 'u') {
                p++;
                for (int i = 0; i < 4; i++, p++)
                    if (!isxdigit((unsigned char)*p)) return false;
                continue;
            }
            if (!*p || !strchr("\"\\/bfnrt", *p)) return false;
        }
        if (out) { if (n + 1 >= cap) return false; out[n++] = *p; }
        p++;
    }
    if (*p++ != '"') return false;
    if (out) out[n] = '\0';
    *cursor = p;
    return true;
}

static bool scope_skip(const char** cursor, unsigned depth) {
    if (depth > 16) return false;
    const char* p = scope_ws(*cursor);
    if (*p == '"') { if (!scope_string(&p, NULL, 0)) return false; }
    else if (*p == '[' || *p == '{') {
        bool object = *p == '{'; char end = object ? '}' : ']';
        p = scope_ws(p + 1);
        if (*p != end) for (;;) {
            if (object) {
                if (!scope_string(&p, NULL, 0) || *(p = scope_ws(p)) != ':') return false;
                p++;
            }
            if (!scope_skip(&p, depth + 1)) return false;
            p = scope_ws(p);
            if (*p != ',') break;
            p = scope_ws(p + 1);
        }
        if (*p++ != end) return false;
    } else if (!strncmp(p, "true", 4)) p += 4;
    else if (!strncmp(p, "false", 5)) p += 5;
    else if (!strncmp(p, "null", 4)) p += 4;
    else {
        if (*p == '-') p++;
        if (*p == '0') p++;
        else { if (*p < '1' || *p > '9') return false; while (isdigit((unsigned char)*p)) p++; }
        if (*p == '.') { p++; if (!isdigit((unsigned char)*p)) return false; while (isdigit((unsigned char)*p)) p++; }
        if (*p == 'e' || *p == 'E') {
            p++; if (*p == '+' || *p == '-') p++;
            if (!isdigit((unsigned char)*p)) return false;
            while (isdigit((unsigned char)*p)) p++;
        }
    }
    *cursor = p;
    return true;
}

static bool scope_count(const char** cursor, size_t* out) {
    const char* p = scope_ws(*cursor);
    if (!isdigit((unsigned char)*p) || (*p == '0' && isdigit((unsigned char)p[1]))) return false;
    size_t n = 0;
    do { n = n * 10 + (size_t)(*p++ - '0'); if (n > 64) return false; }
    while (isdigit((unsigned char)*p));
    *out = n; *cursor = p;
    return true;
}

static bool scope_array(const char** cursor, char* values, size_t stride,
                         size_t limit, size_t* count) {
    const char* p = scope_ws(*cursor);
    if (*p++ != '[') return false;
    *count = 0;
    p = scope_ws(p);
    if (*p == ']') return false;
    for (;;) {
        char* value = values + *count * stride;
        if (*count == limit || !scope_string(&p, value, stride) || !component_ok(value)) return false;
        for (size_t i = 0; i < *count; i++) if (!strcmp(value, values + i * stride)) return false;
        (*count)++;
        p = scope_ws(p);
        if (*p != ',') break;
        p = scope_ws(p + 1);
    }
    if (*p++ != ']') return false;
    *cursor = p;
    return true;
}

static bool read_selected_scope(const char* json, migration_report_t* r) {
    r->selected_containers = true; // Invalid partial declarations also fail closed.
    const char* p = scope_ws(json);
    if (*p++ != '{') return false;
    char keys[64][64], format[64] = {0}; size_t nkeys = 0, selected = 0;
    unsigned fields = 0;
    p = scope_ws(p);
    if (*p == '}') return false;
    for (;;) {
        char key[64];
        if (nkeys == 64 || !scope_string(&p, key, sizeof(key))) return false;
        for (size_t i = 0; i < nkeys; i++) if (!strcmp(keys[i], key)) return false;
        snprintf(keys[nkeys++], sizeof(keys[0]), "%s", key);
        if (*(p = scope_ws(p)) != ':') return false;
        p++;
        if (!strcmp(key, "backup_scope")) {
            fields |= 1;
            if (!scope_string(&p, r->backup_scope, sizeof(r->backup_scope))) return false;
        } else if (!strcmp(key, "selected_slots")) {
            fields |= 2;
            if (!scope_array(&p, (char*)r->selected_slots, sizeof(r->selected_slots[0]),
                             MIGRATION_MAX_SLOTS, &selected)) return false;
        } else if (!strcmp(key, "included_images")) {
            fields |= 4;
            if (!scope_array(&p, (char*)r->included_images, sizeof(r->included_images[0]),
                             MIGRATION_MAX_SLOTS * 2, &r->included_image_count)) return false;
        } else if (!strcmp(key, "available_slots")) {
            fields |= 8;
            if (!scope_count(&p, &r->available_slots)) return false;
        } else if (!strcmp(key, "selected_slots_count")) {
            fields |= 16;
            if (!scope_count(&p, &r->selected_slots_count)) return false;
        } else if (!strcmp(key, "format")) {
            if (!scope_string(&p, format, sizeof(format))) return false;
        } else if (!scope_skip(&p, 0)) return false;
        p = scope_ws(p);
        if (*p != ',') break;
        p = scope_ws(p + 1);
    }
    return *p++ == '}' && !*scope_ws(p) && fields == 31 &&
           !strcmp(r->backup_scope, "selected_containers") &&
           !strcmp(format, "tostonsync.encrypted_image") && selected &&
           selected == r->selected_slots_count && r->available_slots >= selected &&
           r->available_slots <= MIGRATION_MAX_SLOTS;
}

static void read_manifest_one(const char* root, migration_report_t* r) {
    char path[1024];
    snprintf(path, sizeof(path), "%s/manifest.json", root);
    FILE* f = fopen(path, "rb");
    if (!f) {
        DIR* d = opendir(root);
        if (d) {
            struct dirent* e;
            while ((e = readdir(d)) != NULL) {
                if (!title_ok(e->d_name)) continue;
                snprintf(path, sizeof(path), "%s/%s/manifest.json", root, e->d_name);
                f = fopen(path, "rb");
                if (f) break;
            }
            closedir(d);
        }
    }
    if (!f) return;
    char buf[16384];
    size_t n = fread(buf, 1, sizeof(buf)-1, f);
    bool complete = n < sizeof(buf) - 1 || fgetc(f) == EOF;
    if (ferror(f)) complete = false;
    fclose(f); buf[n] = '\0';
    complete = complete && strlen(buf) == n; // Embedded NUL must not hide a scope declaration.
    r->has_manifest = true;
    if (!complete) {
        r->selected_containers = true; // Scope beyond the read limit is UNKNOWN, never permission.
        set_reason(r, "Manifest is unreadable or exceeds the bounded inspection limit");
        return;
    }
    char id[16] = {0}, name[128] = {0}, format[64] = {0};
    json_get_string(buf, "title_id", id, sizeof(id));
    json_get_string(buf, "title_name", name, sizeof(name));
    json_get_string(buf, "format", format, sizeof(format));
    json_get_string(buf, "source_console_name", r->source_console_name,
                    sizeof(r->source_console_name));
    json_get_string(buf, "source_console_type", r->source_console_type,
                    sizeof(r->source_console_type));
    if (!json_get_string(buf, "source_user_uid", r->source_user_uid,
                         sizeof(r->source_user_uid)))
        json_get_string(buf, "user_uid", r->source_user_uid,
                        sizeof(r->source_user_uid));
    json_get_string(buf, "created_at_utc", r->created_at_utc,
                    sizeof(r->created_at_utc));
    r->created_at_epoch = (int64_t)json_get_number(buf, "created_at_epoch");
    if (!format[0]) json_get_string(buf, "backup_format_name", format, sizeof(format));
    if (id[0]) set_title(r, id, NULL);
    if (name[0]) snprintf(r->title_name, sizeof(r->title_name), "%s", name);
    if (strcmp(format, "tostonsync.migration_decrypted") == 0)
        r->format = MIGRATION_FORMAT_TOSTON_DECRYPTED;
    if (strstr(buf, "\"backup_scope\"") || strstr(buf, "\"selected_slots\"") ||
        strstr(buf, "\"included_images\"") || strstr(buf, "\"selected_slots_count\"")) {
        r->selected_containers = true;
        if (!complete || !read_selected_scope(buf, r))
            set_reason(r, "Partial RAW export scope is invalid, incomplete or non-literal");
    }
}

static void read_manifest(const char* root, migration_report_t* r) {
    read_manifest_one(root, r);
    // Restore accepts both root metadata and title wrappers. A root manifest
    // must not hide a partial declaration inside one of those wrappers.
    char path[1200]; struct stat st;
    int n = snprintf(path, sizeof(path), "%s/manifest.json", root);
    size_t manifests = n > 0 && (size_t)n < sizeof(path) && lstat(path, &st) == 0 ? 1 : 0;
    DIR* dir = opendir(root);
    if (!dir) { set_reason(r, "Manifest authorities cannot be enumerated"); return; }
    for (;;) {
        errno = 0;
        struct dirent* e = readdir(dir);
        if (!e) { if (errno) set_reason(r, "Manifest authorities cannot be enumerated"); break; }
        if (!title_ok(e->d_name)) continue;
        char wrapper[1024];
        n = snprintf(wrapper, sizeof(wrapper), "%s/%s", root, e->d_name);
        if (n < 0 || (size_t)n >= sizeof(wrapper)) { set_reason(r, "Manifest authority path exceeds bounds"); break; }
        n = snprintf(path, sizeof(path), "%s/manifest.json", wrapper);
        if (n < 0 || (size_t)n >= sizeof(path)) { set_reason(r, "Manifest authority path exceeds bounds"); break; }
        if (lstat(path, &st) != 0) {
            if (errno != ENOENT && errno != ENOTDIR) set_reason(r, "Manifest authority metadata is unavailable");
            continue;
        }
        if (!S_ISREG(st.st_mode)) { set_reason(r, "Manifest authority is not a regular file"); break; }
        manifests++;
        migration_report_t other = {0};
        read_manifest_one(wrapper, &other);
        if (!other.has_manifest) set_reason(r, "Manifest authority cannot be read");
        if (other.selected_containers) r->selected_containers = true;
        if (other.reason[0]) set_reason(r, other.reason);
    }
    if (closedir(dir) != 0) set_reason(r, "Manifest authorities cannot be closed");
    if (r->selected_containers && manifests > 1)
        set_reason(r, "Partial RAW export has conflicting manifest authorities");
}

static bool scoped_name(const migration_report_t* r, const char* name, bool images) {
    size_t count = images ? r->included_image_count : r->selected_slots_count;
    for (size_t i = 0; i < count; i++)
        if (!strcmp(name, images ? r->included_images[i] : r->selected_slots[i])) return true;
    return false;
}

static void verify_selected_inventory(const char* root, migration_report_t* r) {
    if (!r->selected_containers || r->reason[0]) return;
    bool ok = r->active_images == r->selected_slots_count &&
              r->save_dir_count == r->selected_slots_count &&
              r->included_image_count == r->active_images + r->service_images;
    for (size_t i = 0; i < r->save_dir_count; i++)
        ok = ok && scoped_name(r, r->save_dirs[i], false);
    for (size_t i = 0; i < r->included_image_count; i++) {
        const char* image = r->included_images[i];
        const char* slot = !strncmp(image, "sdimg_sce_bu_", 13) ? image + 13 :
                           !strncmp(image, "sdimg_", 6) ? image + 6 : NULL;
        ok = ok && slot && scoped_name(r, slot, false);
    }
    char title_root[1024];
    int n = snprintf(title_root, sizeof(title_root), "%s/%s", root, r->title_id);
    DIR* dir = n > 0 && (size_t)n < sizeof(title_root) ? opendir(title_root) : NULL;
    if (!dir) ok = false;
    size_t found = 0;
    while (dir && ok) {
        errno = 0;
        struct dirent* e = readdir(dir);
        if (!e) { if (errno) ok = false; break; }
        if (!strcmp(e->d_name, ".") || !strcmp(e->d_name, "..")) continue;
        char path[1200]; struct stat st;
        n = snprintf(path, sizeof(path), "%s/%s", title_root, e->d_name);
        if (n < 0 || (size_t)n >= sizeof(path) || lstat(path, &st) != 0 || !S_ISREG(st.st_mode)) {
            ok = false; break;
        }
        if (!strcmp(e->d_name, "manifest.json") || !strcmp(e->d_name, "checksums.json")) continue;
        if (!scoped_name(r, e->d_name, true)) { ok = false; break; }
        found++;
    }
    if (dir && closedir(dir) != 0) ok = false;
    dir = opendir(root);
    if (!dir) ok = false;
    while (dir && ok) {
        errno = 0;
        struct dirent* e = readdir(dir);
        if (!e) { if (errno) ok = false; break; }
        if (!strcmp(e->d_name, ".") || !strcmp(e->d_name, "..")) continue;
        if (strcmp(e->d_name, r->title_id)) ok = false;
    }
    if (dir && closedir(dir) != 0) ok = false;
    if (!ok || found != r->included_image_count)
        set_reason(r, "Partial RAW export inventory does not match its exact declared selection");
}

static bool find_metadata_file(const char* root, const char* name,
                               char* out, size_t out_sz) {
    struct stat st;
    snprintf(out, out_sz, "%s/%s", root, name);
    if (stat(out, &st) == 0 && S_ISREG(st.st_mode)) return true;
    DIR* d = opendir(root);
    if (!d) return false;
    bool found = false;
    struct dirent* e;
    while ((e = readdir(d)) != NULL) {
        if (!title_ok(e->d_name)) continue;
        snprintf(out, out_sz, "%s/%s/%s", root, e->d_name, name);
        if (stat(out, &st) == 0 && S_ISREG(st.st_mode)) {
            found = true;
            break;
        }
    }
    closedir(d);
    return found;
}

typedef struct {
    char* path;
    char* hash;
} checksum_entry_t;

static void checksum_skip_ws(char** p) {
    while (**p == ' ' || **p == '\t' || **p == '\r' || **p == '\n') (*p)++;
}

// Read the string spelling emitted by our checksum writers (UTF-8 plus
// escaped quotes/slashes). Control characters are not valid save paths.
// ponytail: literal UTF-8 is the export format; add Unicode escapes if needed.
static char* checksum_string(char** p) {
    checksum_skip_ws(p);
    if (**p != '"') return NULL;
    char* out = ++*p;
    char* dst = out;
    while (**p && **p != '"') {
        unsigned char c = (unsigned char)*(*p)++;
        if (c == '\\') {
            if (!**p) return NULL;
            c = (unsigned char)*(*p)++;
            if (c != '"' && c != '\\' && c != '/') return NULL;
        }
        if (c < 0x20) return NULL;
        *dst++ = (char)c;
    }
    if (**p != '"') return NULL;
    (*p)++;
    *dst = '\0';
    return out;
}

static bool checksum_object(char** p, checksum_entry_t* entries,
                             size_t* count, bool envelope) {
    checksum_skip_ws(p);
    if (**p != '{') return false;
    (*p)++;
    checksum_skip_ws(p);
    bool algorithm = false, files = false, flat = false;
    if (**p == '}') { (*p)++; return true; }
    for (;;) {
        char* key = checksum_string(p);
        if (!key || !key[0] || strlen(key) >= 1024) return false;
        checksum_skip_ws(p);
        if (**p != ':') return false;
        (*p)++;
        checksum_skip_ws(p);
        if (envelope && strcmp(key, "files") == 0 && **p == '{') {
            if (files || flat || !checksum_object(p, entries, count, false))
                return false;
            files = true;
        } else {
            char* hash = checksum_string(p);
            if (!hash) return false;
            if (envelope && strcmp(key, "algorithm") == 0 &&
                strcmp(hash, "sha256") == 0) {
                if (algorithm || flat) return false;
                algorithm = true;
            } else {
                if (files || algorithm || *count >= 16384 ||
                    strlen(hash) != 64) return false;
                for (size_t i = 0; i < 64; i++)
                    if (!isxdigit((unsigned char)hash[i])) return false;
                entries[(*count)++] = (checksum_entry_t){key, hash};
                flat = true;
            }
        }
        checksum_skip_ws(p);
        if (**p == '}') { (*p)++; return algorithm == files; }
        if (**p != ',') return false;
        (*p)++;
    }
}

static int checksum_compare(const void* a, const void* b) {
    return strcmp(((const checksum_entry_t*)a)->path,
                  ((const checksum_entry_t*)b)->path);
}

static bool verify_checksum_tree(const char* root, const char* relative,
                                 const checksum_entry_t* entries, size_t count,
                                 const char* checksums, const char* manifest,
                                 int depth, size_t* checked) {
    if (depth < 0 || *checked >= 16384) return false;
    char dir[1024];
    int len = snprintf(dir, sizeof(dir), "%s%s%s", root,
             relative && relative[0] ? "/" : "", relative ? relative : "");
    if (len < 0 || (size_t)len >= sizeof(dir)) return false;
    DIR* d = opendir(dir);
    if (!d) return false;
    bool ok = true;
    struct dirent* e;
    while (ok && (e = readdir(d)) != NULL) {
        if (strcmp(e->d_name, ".") == 0 || strcmp(e->d_name, "..") == 0)
            continue;
        if (!component_ok(e->d_name)) { ok = false; break; }
        char rel[1024], path[1280];
        int n = snprintf(rel, sizeof(rel), "%s%s%s",
                 relative && relative[0] ? relative : "",
                 relative && relative[0] ? "/" : "", e->d_name);
        if (n < 0 || (size_t)n >= sizeof(rel)) { ok = false; break; }
        n = snprintf(path, sizeof(path), "%s/%s", root, rel);
        if (n < 0 || (size_t)n >= sizeof(path)) { ok = false; break; }
        struct stat st;
        if (lstat(path, &st) != 0) { ok = false; break; }
        if (S_ISDIR(st.st_mode)) {
            ok = verify_checksum_tree(root, rel, entries, count, checksums,
                                      manifest, depth - 1, checked);
        } else if (S_ISREG(st.st_mode)) {
            if (strcmp(path, checksums) == 0 || strcmp(path, manifest) == 0)
                continue;
            checksum_entry_t key = {.path = rel};
            const checksum_entry_t* entry = bsearch(&key, entries, count,
                sizeof(*entries), checksum_compare);
            char actual[65] = {0};
            if (!entry ||
                !sha256_file_hex(path, actual) ||
                strcasecmp(entry->hash, actual) != 0) {
                ok = false;
                break;
            }
            (*checked)++;
        } else {
            ok = false;
        }
    }
    closedir(d);
    return ok;
}

static bool verify_extracted_checksums(const char* root, bool* present,
                                       char* error, size_t error_sz, bool allow_partial) {
    if (present) *present = false;
    if (error && error_sz) error[0] = '\0';
    if (!allow_partial) {
        migration_report_t scope = {0};
        read_manifest(root, &scope);
        if (scope.selected_containers || scope.reason[0]) {
            if (error && error_sz) snprintf(error, error_sz,
                "%s", scope.selected_containers
                    ? "Selected RAW is partial; full recovery/Restore is blocked"
                    : scope.reason);
            return false;
        }
    }
    char path[1024];
    if (!find_metadata_file(root, "checksums.json", path, sizeof(path)))
        return true;
    if (present) *present = true;
    struct stat st;
    if (stat(path, &st) != 0 || st.st_size < 2 || st.st_size > 4 * 1024 * 1024) {
        if (error && error_sz) snprintf(error, error_sz,
                                        "checksums.json is invalid");
        return false;
    }
    char* json = (char*)malloc((size_t)st.st_size + 1);
    checksum_entry_t* entries = calloc(16384, sizeof(*entries));
    if (!json || !entries) {
        free(json);
        free(entries);
        if (error && error_sz) snprintf(error, error_sz,
                                        "Not enough memory to verify checksums");
        return false;
    }
    FILE* f = fopen(path, "rb");
    size_t n = f ? fread(json, 1, (size_t)st.st_size, f) : 0;
    if (f) fclose(f);
    json[n] = '\0';
    size_t checked = 0, count = 0;
    char* p = json;
    bool ok = n == (size_t)st.st_size && strlen(json) == n &&
              checksum_object(&p, entries, &count, true) && count;
    checksum_skip_ws(&p);
    ok = ok && !*p;
    if (ok) {
        qsort(entries, count, sizeof(*entries), checksum_compare);
        for (size_t i = 1; i < count; i++)
            if (strcmp(entries[i-1].path, entries[i].path) == 0) ok = false;
    }
    char manifest[1024] = {0};
    if (!find_metadata_file(root, "manifest.json", manifest, sizeof(manifest)))
        manifest[0] = '\0';
    ok = ok && verify_checksum_tree(root, "", entries, count, path, manifest,
                                    8, &checked) && checked == count;
    free(entries);
    free(json);
    if (!ok && error && error_sz)
        snprintf(error, error_sz, "Backup checksum verification failed");
    return ok;
}

bool migration_verify_extracted_checksums(const char* root, bool* present,
                                          char* error, size_t error_sz) {
    bool checksums = false;
    if (!verify_extracted_checksums(root, &checksums, error, error_sz, false)) {
        if (present) *present = checksums;
        return false;
    }
    if (present) *present = checksums;
    // Existing Restore callers revalidate the reserved pair before their
    // first write too; review-time success alone is never authority.
    bool capture = false;
    if (!migration_verify_extracted_capture(root, &capture, error, error_sz)) return false;
    if (capture && !checksums) {
        if (error && error_sz) snprintf(error, error_sz, "Paired Portable backup requires normal checksums");
        return false;
    }
    return true;
}

static void verify_checksums(const char* root, migration_report_t* r) {
    char error[128] = {0};
    if (!verify_extracted_checksums(root, &r->has_checksums,
                                   error, sizeof(error), true)) {
        set_reason(r, error);
    } else if (!r->has_checksums &&
               (r->format == MIGRATION_FORMAT_TOSTON_DECRYPTED || r->selected_containers)) {
        set_reason(r, r->selected_containers ? "Partial RAW export is missing checksums.json"
                       : "Portable backup manifest is missing checksums.json");
    }
}

/* Discover only the fixed TITLE/.capture reservation. Never recursively
 * search for sidecar archives. The complete slot inventory handles .capture
 * when it is legitimate data inside a save slot. */
static bool paired_title_ok(const char* name) {
    if (!name || strlen(name) != 9 || strncmp(name, "PPSA", 4)) return false;
    for (size_t i = 4; i < 9; i++) if (name[i] < '0' || name[i] > '9') return false;
    return true;
}

static bool extracted_slot_root(const char* root) {
    char path[1280]; struct stat st; sfo_info_t sfo;
    int n = snprintf(path, sizeof(path), "%s/sce_sys", root);
    if (n < 0 || (size_t)n >= sizeof(path) || lstat(path, &st) || !S_ISDIR(st.st_mode)) return false;
    n = snprintf(path, sizeof(path), "%s/sce_sys/param.sfo", root);
    if (n < 0 || (size_t)n >= sizeof(path) || lstat(path, &st) || !S_ISREG(st.st_mode) ||
        st.st_size <= 0 || sfo_parse(path, &sfo) || !title_ok(sfo.title_id) || !component_ok(sfo.dir_name) ||
        (!strncmp(sfo.title_id, "PPSA", 4) && strcmp(sfo.format, "ppr"))) return false;
    n = snprintf(path, sizeof(path), "%s/sce_sys/keystone", root);
    return n >= 0 && (size_t)n < sizeof(path) && !lstat(path, &st) &&
           S_ISREG(st.st_mode) && st.st_size == 96;
}

static bool find_capture_title(const char* root, char* title, size_t cap,
                               bool* present, char* error, size_t error_sz) {
    *present = false; title[0] = 0;
    // A legacy bare PFS slot may itself contain .capture or PPSA-named game
    // directories. Those are payload, not wrapper-level sidecar authorities.
    if (extracted_slot_root(root)) return true;
    char path[1280]; struct stat st;
    int n = snprintf(path, sizeof(path), "%s/.capture", root);
    if (n < 0 || (size_t)n >= sizeof(path)) goto invalid;
    if (lstat(path, &st) == 0) goto invalid; // New pairs require a TITLE wrapper.
    if (errno != ENOENT) goto invalid;
    DIR* d = opendir(root);
    if (!d) goto invalid;
    bool ok = true;
    for (;;) {
        errno = 0; struct dirent* e = readdir(d);
        if (!e) { if (errno) ok = false; break; }
        if (!paired_title_ok(e->d_name)) continue;
        n = snprintf(path, sizeof(path), "%s/%s", root, e->d_name);
        if (n < 0 || (size_t)n >= sizeof(path) || lstat(path, &st)) { ok = false; break; }
        if (!S_ISDIR(st.st_mode)) continue;
        char reserved[1400];
        n = snprintf(reserved, sizeof(reserved), "%s/.capture", path);
        if (n < 0 || (size_t)n >= sizeof(reserved)) { ok = false; break; }
        if (lstat(reserved, &st)) {
            if (errno != ENOENT) { ok = false; break; }
            continue;
        }
        if (*present || strlen(path) >= cap) { ok = false; break; }
        *present = true; snprintf(title, cap, "%s", path);
    }
    if (closedir(d)) ok = false;
    if (!ok) goto invalid;
    if (*present) {
        d = opendir(root);
        if (!d) goto invalid;
        const char* expected = base_name(title);
        for (;;) {
            errno = 0; struct dirent* e = readdir(d);
            if (!e) { if (errno) ok = false; break; }
            if (!strcmp(e->d_name, ".") || !strcmp(e->d_name, "..")) continue;
            if (strcmp(e->d_name, expected)) { ok = false; break; }
        }
        if (closedir(d)) ok = false;
        if (!ok) goto invalid;
    }
    return true;
invalid:
    if (error && error_sz) snprintf(error, error_sz, "Reserved capture must have one exact TITLE root");
    return false;
}

static bool verify_capture_locked(const char* root, bool* present,
                                  paired_capture_t* out,
                                  char* error, size_t error_sz,
                                  migration_report_t* diagnostics) {
    if (present) *present = false;
    if (error && error_sz) error[0] = 0;
    char title[1280]; bool found = false;
    if (!root || !find_capture_title(root, title, sizeof(title), &found, error, error_sz)) return false;
    if (present) *present = found;
    if (!found) return true;
    paired_capture_t capture; bool declared = false;
    paired_capture_diagnostic_t* title_diag = diagnostics ? &diagnostics->capture_title_diagnostic : NULL;
    paired_capture_diagnostic_t* raw_diag = diagnostics ? &diagnostics->capture_raw_diagnostic : NULL;
    if (diagnostics) {
        diagnostics->capture_diagnostic_attempted = true;
        paired_capture_diagnostic_init(title_diag);
        paired_capture_diagnostic_init(raw_diag);
    }
    if (!paired_capture_validate_title_diagnostic(title, &capture, &declared,
                                                  error, error_sz, title_diag) || !declared) return false;
    migration_report_t portable = {0};
    read_manifest(root, &portable);
    bool checksums = false;
    if (!portable.has_manifest || portable.reason[0] || portable.selected_containers ||
        portable.format != MIGRATION_FORMAT_TOSTON_DECRYPTED ||
        strcmp(portable.title_id, capture.title_id) ||
        strcmp(portable.source_user_uid, capture.source_uid) ||
        !verify_extracted_checksums(root, &checksums, error, error_sz, false) || !checksums) {
        if (error && error_sz && !error[0]) snprintf(error, error_sz, "Paired Portable metadata or normal checksums are invalid");
        return false;
    }
    // Sibling scratch is outside the checksum/inventory tree. Never call the
    // public locking inspector recursively or let a child discover captures.
    char scratch[1536], raw[1536];
    int n = snprintf(scratch, sizeof(scratch), "%s.capture_raw.XXXXXX", root);
    if (n < 0 || (size_t)n >= sizeof(scratch) || !mkdtemp(scratch)) {
        if (error && error_sz) snprintf(error, error_sz, "Could not create private fixed-RAW inspection scratch");
        return false;
    }
    struct stat scratch_created;
    if (lstat(scratch, &scratch_created) != 0 || !S_ISDIR(scratch_created.st_mode)) {
        if (error && error_sz) snprintf(error, error_sz, "Private fixed-RAW scratch ownership is uncertain; retained without inspection");
        return false;
    }
    n = snprintf(raw, sizeof(raw), "%s/.capture/raw.zip", title);
    migration_report_t report;
    bool ok = n >= 0 && (size_t)n < sizeof(raw) &&
              inspect_zip_locked(raw, capture.title_id, &report, scratch, false) &&
              report.format == MIGRATION_FORMAT_ENCRYPTED_IMAGE && report.has_checksums &&
              report.selected_containers && !report.strategy_ready &&
              !strcmp(report.title_id, capture.title_id) &&
              !strcmp(report.source_user_uid, capture.source_uid) &&
              paired_capture_validate_raw_diagnostic(scratch, &capture, error, error_sz, raw_diag);
    struct stat scratch_current;
    // The child owns only the newly created directory. Never remove a
    // replacement; lstat/check/cleanup is not atomic against external races.
    bool scratch_owned = lstat(scratch, &scratch_current) == 0 &&
        S_ISDIR(scratch_current.st_mode) &&
        scratch_current.st_dev == scratch_created.st_dev &&
        scratch_current.st_ino == scratch_created.st_ino;
    if (scratch_owned) pfs_fs_rmrf(scratch);
    else ok = false;
    migration_scratch_diagnostic_t cleanup = {0};
    observe_scratch(scratch, &cleanup);
    if (diagnostics) diagnostics->capture_raw_scratch_after_cleanup = cleanup;
    if (cleanup.state != MIGRATION_SCRATCH_ABSENT) ok = false;
    // Check the closed child again after extraction. Its descriptor-bound
    // bytes must not change while the two inventories are being compared.
    paired_capture_t after; bool still_present = false;
    if (ok) ok = paired_capture_validate_title_diagnostic(title, &after, &still_present,
                                                         error, error_sz, title_diag) &&
                 still_present && !strcmp(after.capture_id, capture.capture_id) &&
                 !strcmp(after.raw_zip_sha256, capture.raw_zip_sha256) &&
                 !strcmp(after.descriptor_sha256, capture.descriptor_sha256) &&
                 verify_extracted_checksums(root, &checksums, error, error_sz, false) && checksums;
    if (!ok && error && error_sz && !error[0])
        snprintf(error, error_sz, "Fixed RAW child inspection or capture binding failed");
    if (ok && out) *out = capture;
    return ok;
}

bool migration_verify_extracted_capture(const char* root, bool* present,
                                        char* error, size_t error_sz) {
    pthread_mutex_lock(&s_inspect_lock);
    bool ok = verify_capture_locked(root, present, NULL, error, error_sz, NULL);
    pthread_mutex_unlock(&s_inspect_lock);
    return ok;
}

/* Caller owns s_inspect_lock and an already NEW private stage. Child stages
 * intentionally remain until their literal image hashes have been checked. */
static bool inspect_zip_locked(const char* zip_path, const char* title_hint,
                               migration_report_t* out, const char* stage,
                               bool allow_capture) {
    memset(out, 0, sizeof(*out));
    char extraction_detail[192];
    if (!zip_extract_to_directory_checked(zip_path, stage,
                                          extraction_detail,
                                          sizeof(extraction_detail))) {
        set_reason(out, extraction_detail[0] ? extraction_detail
                       : "ZIP extraction failed; check Technical logs");
        return false;
    }
    read_manifest(stage, out);
    char capture_title[1280], capture_error[192] = {0}; bool capture = false;
    if (!find_capture_title(stage, capture_title, sizeof(capture_title),
                            &capture, capture_error, sizeof(capture_error)))
        set_reason(out, capture_error);
    if (capture && !allow_capture) set_reason(out, "Fixed RAW child cannot contain a nested capture");
    // Inventory the extracted save before checksum validation. A missing or
    // invalid checksum still blocks restore, but it must not turn six real
    // save folders into a misleading "0 folders" report.
    inspect_tree(stage, title_hint, out, 8, capture ? capture_title : NULL);
    finish_raw_completeness(out);
    verify_selected_inventory(stage, out);
    if (!out->selected_containers || !out->reason[0]) verify_checksums(stage, out);
    if (capture && !out->reason[0]) {
        paired_capture_t paired;
        bool present = false;
        if (out->format != MIGRATION_FORMAT_TOSTON_DECRYPTED || !out->has_checksums ||
            !verify_capture_locked(stage, &present, &paired, capture_error, sizeof(capture_error), out) ||
            !present || strcmp(out->title_id, paired.title_id) ||
            strcmp(out->source_user_uid, paired.source_uid)) {
            set_reason(out, capture_error[0] ? capture_error : "Paired Portable provenance or checksums do not match capture");
        } else {
            out->has_capture = true;
            snprintf(out->capture_id, sizeof(out->capture_id), "%s", paired.capture_id);
        }
    }
    if (!out->title_id[0] && title_hint && title_ok(title_hint))
        snprintf(out->title_id, sizeof(out->title_id), "%s", title_hint);
    if (!out->reason[0]) {
        if (out->active_images) {
            out->format = MIGRATION_FORMAT_ENCRYPTED_IMAGE;
            out->valid = out->title_id[0] && out->save_dir_count > 0;
            out->needs_kernel = false;
        } else if (out->payload_files && out->save_dir_count) {
            if (out->format != MIGRATION_FORMAT_TOSTON_DECRYPTED)
                out->format = MIGRATION_FORMAT_GARLIC_DECRYPTED;
            out->valid = out->title_id[0];
            out->needs_kernel = true;
        } else if (out->service_images) {
            set_reason(out, "Backup contains only service snapshots, not active saves");
        } else {
            set_reason(out, "Unknown or metadata-only ZIP format");
        }
    }
    if (!out->valid && !out->reason[0]) set_reason(out, "Restore preflight failed");
    migration_plan_report(out);
    return out->valid;
}

bool migration_inspect_zip(const char* zip_path, const char* title_hint,
                           migration_report_t* out) {
    if (!zip_path || !out) return false;
    pthread_mutex_lock(&s_inspect_lock);
    char stage[768];
    int n = snprintf(stage, sizeof(stage), "%s.inspect", zip_path);
    memset(out, 0, sizeof(*out));
    bool ok = n >= 0 && (size_t)n < sizeof(stage);
    bool made_stage = false;
    bool owned_stage = false;
    struct stat created_stage;
    int failure_errno = ENAMETOOLONG;
    migration_scratch_diagnostic_t before_create = {0};
    if (ok) {
        observe_scratch(stage, &before_create);
        ok = before_create.state == MIGRATION_SCRATCH_ABSENT;
        failure_errno = before_create.state == MIGRATION_SCRATCH_REMAINS ? EEXIST :
            before_create.errno_valid ? before_create.error_number : EIO;
    }
    if (ok) {
        errno = 0;
        ok = mkdir(stage, 0700) == 0;
        failure_errno = errno ? errno : EIO;
        made_stage = ok;
    }
    if (ok) {
        errno = 0;
        int ret = lstat(stage, &created_stage);
        failure_errno = ret < 0 ? (errno ? errno : EIO) : ENOTDIR;
        owned_stage = ret == 0 && S_ISDIR(created_stage.st_mode);
        ok = owned_stage;
    }
    if (!ok) {
        char detail[192];
        snprintf(detail, sizeof(detail), "Could not create ZIP inspection staging folder (errno %d: %s)",
                 failure_errno, strerror(failure_errno));
        log_warn("migration: %s", detail);
        set_reason(out, detail);
        migration_plan_report(out);
    } else ok = inspect_zip_locked(zip_path, title_hint, out, stage, true);
    out->scratch_before_create = before_create;
    if (made_stage) {
        struct stat current_stage;
        // shortcut: path checks cannot exclude all external replacement races; use fd-relative ownership and cleanup if that threat is admitted.
        if (owned_stage && lstat(stage, &current_stage) == 0 &&
            S_ISDIR(current_stage.st_mode) &&
            current_stage.st_dev == created_stage.st_dev &&
            current_stage.st_ino == created_stage.st_ino)
            pfs_fs_rmrf(stage);
        else log_warn("migration: inspection staging ownership uncertain; cleanup skipped");
        observe_scratch(stage, &out->scratch_after_cleanup);
    }
    pthread_mutex_unlock(&s_inspect_lock);
    return ok;
}

const char* migration_format_name(migration_format_t f) {
    switch (f) {
        case MIGRATION_FORMAT_ENCRYPTED_IMAGE: return "tostonsync.encrypted_image";
        case MIGRATION_FORMAT_TOSTON_DECRYPTED: return "tostonsync.migration_decrypted";
        case MIGRATION_FORMAT_GARLIC_DECRYPTED: return "external.decrypted_contents";
        case MIGRATION_FORMAT_METADATA_ONLY: return "metadata_only";
        default: return "invalid";
    }
}

static void json_escape_append(char** p, char* end, const char* s) {
    if (*p >= end) return;
    *(*p)++ = '"';
    for (; s && *s && *p + 2 < end; s++) {
        unsigned char c = (unsigned char)*s;
        if (c == '"' || c == '\\') { *(*p)++='\\'; *(*p)++=(char)c; }
        else if (c >= 0x20) *(*p)++=(char)c;
    }
    if (*p < end) *(*p)++='"';
    if (*p < end) **p='\0';
}

static void json_literal_append(char** p, char* end, const char* s) {
    while (s && *s && *p + 1 < end) *(*p)++ = *s++;
    if (*p < end) **p = '\0';
}

static void json_number_append(char** p, char* end, size_t value) {
    char number[32];
    snprintf(number, sizeof(number), "%zu", value);
    json_literal_append(p, end, number);
}

size_t migration_scratch_diagnostic_json(const migration_scratch_diagnostic_t* d,
                                         char* out, size_t out_sz) {
    const char* state = !d || d->state == MIGRATION_SCRATCH_UNCHECKED ? "SKIPPED" :
        d->state == MIGRATION_SCRATCH_ABSENT ? "ABSENT" :
        d->state == MIGRATION_SCRATCH_REMAINS ? "REMAINS" : "UNKNOWN";
    char ret[32] = "null", err[32] = "null";
    if (d && d->state != MIGRATION_SCRATCH_UNCHECKED)
        snprintf(ret, sizeof(ret), "%d", d->lstat_return);
    if (d && d->errno_valid) snprintf(err, sizeof(err), "%d", d->error_number);
    const char* err_name = !d || !d->errno_valid ? "null" :
        d->error_number == ENOENT ? "\"ENOENT\"" :
        d->error_number == EACCES ? "\"EACCES\"" :
        d->error_number == ENOTDIR ? "\"ENOTDIR\"" :
        d->error_number == ELOOP ? "\"ELOOP\"" :
        d->error_number == ENAMETOOLONG ? "\"ENAMETOOLONG\"" :
        d->error_number == EIO ? "\"EIO\"" : "\"UNKNOWN\"";
    char json[384];
    int n = snprintf(json, sizeof(json),
        "{\"state\":\"%s\",\"operation\":\"lstat\",\"return\":%s,"
        "\"errno\":%s,\"errno_name\":%s,\"expected\":\"absent\",\"observed\":\"%s\"}",
        state, ret, err, err_name,
        !d || d->state == MIGRATION_SCRATCH_UNCHECKED ? "UNKNOWN" :
        d->state == MIGRATION_SCRATCH_ABSENT ? "absent" :
        d->state == MIGRATION_SCRATCH_REMAINS ? "present" : "UNKNOWN");
    size_t len = n > 0 ? (size_t)n : 0;
    if (out && out_sz) {
        if (len < out_sz) memcpy(out, json, len + 1);
        else out[0] = 0;
    }
    return len;
}

static void json_scratch_append(char** p, char* end,
                                const migration_scratch_diagnostic_t* d) {
    char json[384];
    migration_scratch_diagnostic_json(d, json, sizeof(json));
    json_literal_append(p, end, json);
}

static void json_capture_diagnostic_append(char** p, char* end,
                                           const paired_capture_diagnostic_t* d) {
    size_t len = paired_capture_diagnostic_json(d, NULL, 0, false);
    // Keep the unchanged outcome/detail tail even in legacy small buffers.
    if ((size_t)(end - *p) > len + 1536) {
        paired_capture_diagnostic_json(d, *p, (size_t)(end - *p), false);
        *p += len;
    } else json_literal_append(p, end, "{\"state\":\"UNKNOWN\",\"reason\":\"diagnostic_capacity\"}");
}

void migration_report_json(const migration_report_t* r,
                           char* out, size_t out_sz) {
    if (!out || out_sz < 3 || !r) return;
    if (r->selected_containers) {
        // Bound escaping and all fixed JSON fields before emitting the partial inventory.
        const char* strings[] = {migration_format_name(r->format), r->title_id,
            r->title_name, r->source_console_name, r->source_console_type,
            r->source_user_uid, r->created_at_utc, r->raw_completeness,
            r->first_missing_service_image, r->backup_scope, r->restore_strategy,
            r->strategy_reason, r->reason};
        size_t needed = 2304;
        for (size_t i = 0; i < sizeof(strings) / sizeof(strings[0]); i++)
            needed += strlen(strings[i]) * 2 + 3;
        for (size_t i = 0; i < r->save_dir_count && i < MIGRATION_MAX_SLOTS; i++)
            needed += strlen(r->save_dirs[i]) * 2 + 3;
        for (size_t i = 0; i < r->selected_slots_count && i < MIGRATION_MAX_SLOTS; i++)
            needed += strlen(r->selected_slots[i]) * 2 + 3;
        for (size_t i = 0; i < r->included_image_count && i < MIGRATION_MAX_SLOTS * 2; i++)
            needed += strlen(r->included_images[i]) * 2 + 3;
        if (out_sz < needed) {
            static const char compact[] = "{\"selected_containers\":true,\"backup_scope\":\"selected_containers\",\"inventory_complete\":false,\"inventory\":\"UNKNOWN\",\"valid\":false,\"strategy_ready\":false,\"restore_strategy\":\"blocked\",\"reason\":\"Report capacity is insufficient for the complete selected RAW inventory\"}";
            if (out_sz >= sizeof(compact)) memcpy(out, compact, sizeof(compact));
            else memcpy(out, "{}", 3);
            return;
        }
    }
    char* p = out;
    char* end = out + out_sz;
    out[0] = '\0';
    json_literal_append(&p, end, "{\"format\":");
    json_escape_append(&p, end, migration_format_name(r->format));
    json_literal_append(&p, end, ",\"title_id\":");
    json_escape_append(&p, end, r->title_id);
    json_literal_append(&p, end, ",\"title_name\":");
    json_escape_append(&p, end, r->title_name);
    json_literal_append(&p, end, ",\"source_console_name\":");
    json_escape_append(&p, end, r->source_console_name);
    json_literal_append(&p, end, ",\"source_console_type\":");
    json_escape_append(&p, end, r->source_console_type);
    json_literal_append(&p, end, ",\"source_user_uid\":");
    json_escape_append(&p, end, r->source_user_uid);
    json_literal_append(&p, end, ",\"created_at_utc\":");
    json_escape_append(&p, end, r->created_at_utc);
    json_literal_append(&p, end, ",\"created_at_epoch\":");
    char epoch[32];
    snprintf(epoch, sizeof(epoch), "%lld", (long long)r->created_at_epoch);
    json_literal_append(&p, end, epoch);
    json_literal_append(&p, end, ",\"save_dirs\":[");
    for (size_t i = 0; i < r->save_dir_count; i++) {
        if (i) json_literal_append(&p, end, ",");
        json_escape_append(&p, end, r->save_dirs[i]);
    }
    json_literal_append(&p, end, "],\"active_images\":");
    json_number_append(&p, end, r->active_images);
    json_literal_append(&p, end, ",\"service_images\":");
    json_number_append(&p, end, r->service_images);
    json_literal_append(&p, end, ",\"raw_completeness\":");
    json_escape_append(&p, end, r->raw_completeness);
    json_literal_append(&p, end, ",\"missing_service_images\":");
    json_number_append(&p, end, r->missing_service_images);
    json_literal_append(&p, end, ",\"first_missing_service_image\":");
    json_escape_append(&p, end, r->first_missing_service_image);
    if (r->selected_containers) {
        json_literal_append(&p, end, ",\"backup_scope\":");
        json_escape_append(&p, end, r->backup_scope);
        json_literal_append(&p, end, ",\"selected_containers\":true,\"available_slots\":");
        json_number_append(&p, end, r->available_slots);
        json_literal_append(&p, end, ",\"selected_slots_count\":");
        json_number_append(&p, end, r->selected_slots_count);
        json_literal_append(&p, end, ",\"selected_slots\":[");
        for (size_t i = 0; i < r->selected_slots_count && i < MIGRATION_MAX_SLOTS; i++) {
            if (i) json_literal_append(&p, end, ",");
            json_escape_append(&p, end, r->selected_slots[i]);
        }
        json_literal_append(&p, end, "],\"included_images\":[");
        for (size_t i = 0; i < r->included_image_count && i < MIGRATION_MAX_SLOTS * 2; i++) {
            if (i) json_literal_append(&p, end, ",");
            json_escape_append(&p, end, r->included_images[i]);
        }
        json_literal_append(&p, end, "]");
    }
    json_literal_append(&p, end, ",\"payload_files\":");
    json_number_append(&p, end, r->payload_files);
    json_literal_append(&p, end, ",\"has_manifest\":");
    json_literal_append(&p, end, r->has_manifest ? "true" : "false");
    json_literal_append(&p, end, ",\"has_checksums\":");
    json_literal_append(&p, end, r->has_checksums ? "true" : "false");
    json_literal_append(&p, end, ",\"has_capture\":");
    json_literal_append(&p, end, r->has_capture ? "true" : "false");
    if (r->has_capture) {
        json_literal_append(&p, end, ",\"capture_id\":");
        json_escape_append(&p, end, r->capture_id);
    }
    json_literal_append(&p, end, ",\"inspection_diagnostic\":{\"scratch\":{\"before_create\":");
    json_scratch_append(&p, end, &r->scratch_before_create);
    json_literal_append(&p, end, ",\"after_cleanup\":");
    json_scratch_append(&p, end, &r->scratch_after_cleanup);
    json_literal_append(&p, end, ",\"raw_after_cleanup\":");
    json_scratch_append(&p, end, &r->capture_raw_scratch_after_cleanup);
    json_literal_append(&p, end, "}");
    if (r->capture_diagnostic_attempted) {
        json_literal_append(&p, end, ",\"title\":");
        json_capture_diagnostic_append(&p, end, &r->capture_title_diagnostic);
        json_literal_append(&p, end, ",\"raw\":");
        json_capture_diagnostic_append(&p, end, &r->capture_raw_diagnostic);
    }
    json_literal_append(&p, end, "}");
    json_literal_append(&p, end, ",\"valid\":");
    json_literal_append(&p, end, r->valid ? "true" : "false");
    json_literal_append(&p, end, ",\"needs_kernel\":");
    json_literal_append(&p, end, r->needs_kernel ? "true" : "false");
    json_literal_append(&p, end, ",\"restore_strategy\":");
    json_escape_append(&p, end, r->restore_strategy);
    json_literal_append(&p, end, ",\"strategy_ready\":");
    json_literal_append(&p, end, r->strategy_ready ? "true" : "false");
    json_literal_append(&p, end, ",\"target_identity_required\":");
    json_literal_append(&p, end,
                        r->target_identity_required ? "true" : "false");
    json_literal_append(&p, end, ",\"strategy_reason\":");
    json_escape_append(&p, end, r->strategy_reason);
    json_literal_append(&p, end, ",\"reason\":");
    json_escape_append(&p, end, r->reason);
    json_literal_append(&p, end, "}");
}
