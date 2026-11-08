#include "paired_backup.h"
#include "migration_inspect.h"
#include "sha256.h"
#include "version.h"
#include "zip.h"
#include <errno.h>
#include <ctype.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

typedef struct {
    char name[128], canonical[512];
    paired_backup_observation_t original, canonical_before;
} captured_image_t;

static bool json_escape_small(const char* s, char* out, size_t cap) {
    size_t used = 0;
    for (const unsigned char* p = (const unsigned char*)s; *p; ++p) {
        if (*p < 32) return false; // Literal request components never contain controls.
        size_t bytes = *p == '"' || *p == '\\' ? 2 : 1;
        if (bytes >= cap - used) return false;
        if (bytes == 2) out[used++] = '\\';
        out[used++] = (char)*p;
    }
    out[used] = 0; return true;
}
static void json_write_string(FILE* f, const char* s) {
    fputc('"', f);
    for (const unsigned char* p = (const unsigned char*)(s ? s : ""); *p; ++p) {
        if (*p == '"' || *p == '\\') { fputc('\\', f); fputc(*p, f); }
        else if (*p < 32) fprintf(f, "\\u%04x", *p);
        else fputc(*p, f);
    }
    fputc('"', f);
}

static size_t diagnostic_first_failure(const paired_capture_diagnostic_t* d,
                                      bool attempted, char* out, size_t cap) {
    const paired_capture_stage_diagnostic_t* first = NULL;
    paired_capture_stage_t stage = PAIR_DIAG_STAGE_COUNT;
    size_t failures = 0;
    for (size_t i = 0; attempted && i < PAIR_DIAG_STAGE_COUNT; ++i) {
        if (d->stages[i].state != PAIR_DIAG_FAIL) continue;
        ++failures;
        if (!first) { first = &d->stages[i]; stage = (paired_capture_stage_t)i; }
    }
    int n = snprintf(out, cap, "{\"attempted\":%s,\"failed_stages\":%zu,\"first_failure\":",
                     attempted ? "true" : "false", failures);
    if (n < 0 || (size_t)n >= cap) return cap;
    size_t used = (size_t)n;
    if (!first) n = snprintf(out + used, cap - used, "null}");
    else {
        char result[32] = "null", error[32] = "null", name[40] = "null";
        if (first->return_valid) snprintf(result, sizeof(result), "%lld", (long long)first->return_value);
        if (first->errno_valid) snprintf(error, sizeof(error), "%d", first->errno_code);
        if (first->errno_valid && first->errno_name[0]) snprintf(name, sizeof(name), "\"%s\"", first->errno_name);
        n = snprintf(out + used, cap - used,
            "{\"stage\":\"%s\",\"operation\":\"%s\",\"result\":%s,\"errno\":%s,\"errno_name\":%s}}",
            paired_capture_stage_name(stage), first->operation, result, error, name);
    }
    if (n < 0 || (size_t)n >= cap - used) return cap;
    return used + (size_t)n;
}

static bool diagnostic_has_observation(const paired_capture_diagnostic_t* d) {
    for (size_t i = 0; i < PAIR_DIAG_STAGE_COUNT; ++i)
        if (d->stages[i].state != PAIR_DIAG_UNKNOWN) return true;
    return false;
}

size_t paired_backup_diagnostic_summary(const paired_backup_report_t* r, char* out, size_t cap) {
    char writer[400], title[400], raw[400], before[256], after[256], nested[256];
    if (!r || !out || !cap ||
        diagnostic_first_failure(&r->capture_diagnostic, r->capture_diagnostic_attempted, writer, sizeof(writer)) >= sizeof(writer) ||
        diagnostic_first_failure(&r->inspector_title_diagnostic, r->inspector_diagnostic_attempted, title, sizeof(title)) >= sizeof(title) ||
        diagnostic_first_failure(&r->inspector_raw_diagnostic, diagnostic_has_observation(&r->inspector_raw_diagnostic), raw, sizeof(raw)) >= sizeof(raw) ||
        migration_scratch_diagnostic_json(&r->scratch_before_create, before, sizeof(before)) >= sizeof(before) ||
        migration_scratch_diagnostic_json(&r->scratch_after_cleanup, after, sizeof(after)) >= sizeof(after) ||
        migration_scratch_diagnostic_json(&r->capture_raw_scratch_after_cleanup, nested, sizeof(nested)) >= sizeof(nested)) return cap;
    int n = snprintf(out, cap, "{\"writer\":%s,\"inspector_title\":%s,\"inspector_raw\":%s,"
        "\"scratch\":{\"before_create\":%s,\"after_cleanup\":%s,\"raw_after_cleanup\":%s}}",
        writer, title, raw, before, after, nested);
    return n < 0 ? cap : (size_t)n;
}

static void write_capture_diagnostic(FILE* f, const paired_capture_diagnostic_t* d, bool attempted) {
    if (!attempted) { fputs("null", f); return; }
    size_t length = paired_capture_diagnostic_json(d, NULL, 0, true);
    char* json = length < 65536 ? malloc(length + 1) : NULL;
    if (!json) { fputs("{\"report_unavailable\":true}", f); return; }
    size_t written = paired_capture_diagnostic_json(d, json, length + 1, true);
    if (written == length) fwrite(json, 1, length, f);
    else fputs("{\"report_unavailable\":true}", f);
    free(json);
}

static bool component(const char* s, size_t cap) {
    if (!s || !memchr(s, 0, cap) || !s[0] || !strcmp(s, ".") || !strcmp(s, "..")) return false;
    for (const unsigned char* p = (const unsigned char*)s; *p; ++p)
        if (*p < 32 || *p == 127 || *p == '/' || *p == '\\') return false;
    return true;
}
static bool hash_valid(const char* s) {
    if (!s || strnlen(s, 65) != 64) return false;
    for (size_t i = 0; i < 64; ++i)
        if (!((s[i] >= '0' && s[i] <= '9') || (s[i] >= 'a' && s[i] <= 'f'))) return false;
    return true;
}
static void spaces(const char** p) { while (isspace((unsigned char)**p)) ++*p; }
static bool request_string(const char** p, char* out, size_t cap, bool service_text) {
    spaces(p); if (**p != '"') return false;
    ++*p; size_t used = 0;
    while (**p && **p != '"') {
        unsigned char c = (unsigned char)*(*p)++;
        if (c < 32) return false;
        if (c == '\\') {
            if (!service_text || **p != 'n') return false;
            ++*p; c = '\n';
        }
        if (used + 1 >= cap) return false;
        out[used++] = (char)c;
    }
    if (**p != '"') return false;
    ++*p; out[used] = 0; return true;
}
bool paired_backup_parse_manual(const char* body, paired_backup_manual_request_t* out,
                                char* err, size_t n) {
    if (!out) return false;
    memset(out, 0, sizeof(*out));
    if (!body || strnlen(body, 8193) > 8192) goto invalid;
    const char* p = body; spaces(&p); if (*p != '{') goto invalid;
    ++p; unsigned seen = 0;
    for (;;) {
        char key[40]; spaces(&p); if (*p == '}') { ++p; break; }
        if (!request_string(&p, key, sizeof(key), false)) goto invalid;
        spaces(&p); if (*p != ':') goto invalid;
        ++p; unsigned bit = !strcmp(key, "target_uid") ? 1 : !strcmp(key, "title_id") ? 2 :
            !strcmp(key, "selected_slots") ? 4 : !strcmp(key, "service_slots") ? 8 :
            !strcmp(key, "game_closed_confirmed") ? 16 : 0;
        if (!bit || (seen & bit)) goto invalid;
        seen |= bit;
        if (bit == 1) { if (!request_string(&p, out->uid, sizeof(out->uid), false)) goto invalid; }
        else if (bit == 2) { if (!request_string(&p, out->title_id, sizeof(out->title_id), false)) goto invalid; }
        else if (bit == 8) { if (!request_string(&p, out->service_slots, sizeof(out->service_slots), true)) goto invalid; }
        else if (bit == 16) {
            spaces(&p); if (strncmp(p, "true", 4)) goto invalid; p += 4;
        } else {
            spaces(&p); if (*p != '[') goto invalid;
            ++p; out->active.specified = true;
            for (;;) {
                if (out->active.count == RESTORE_SELECTION_MAX ||
                    !request_string(&p, out->active.slots[out->active.count], 64, false) ||
                    !component(out->active.slots[out->active.count], 64) ||
                    !strncmp(out->active.slots[out->active.count], "sdimg_", 6) ||
                    !strncmp(out->active.slots[out->active.count], "sce_bu_", 7)) goto invalid;
                for (size_t i = 0; i < out->active.count; ++i)
                    if (!strcmp(out->active.slots[i], out->active.slots[out->active.count])) goto invalid;
                ++out->active.count; spaces(&p);
                if (*p == ']') { ++p; break; }
                if (*p != ',') goto invalid;
                ++p;
            }
        }
        spaces(&p); if (*p == '}') { ++p; break; }
        if (*p != ',') goto invalid;
        ++p; spaces(&p); if (*p == '}') goto invalid;
    }
    spaces(&p);
    if (*p || seen != 31 || strlen(out->uid) != 8 || strlen(out->title_id) != 9 ||
        strncmp(out->title_id, "PPSA", 4)) goto invalid;
    for (size_t i = 0; i < 8; ++i)
        if (!((out->uid[i] >= '0' && out->uid[i] <= '9') || (out->uid[i] >= 'a' && out->uid[i] <= 'f'))) goto invalid;
    for (size_t i = 4; i < 9; ++i) if (!isdigit((unsigned char)out->title_id[i])) goto invalid;
    return true;
invalid:
    memset(out, 0, sizeof(*out));
    if (err && n) snprintf(err, n, "Exact UID/title, nonempty literal selected_slots, service_slots and boolean true game_closed_confirmed required");
    return false;
}
static bool join(char* out, size_t cap, const char* a, const char* b) {
    int n = snprintf(out, cap, "%s/%s", a, b);
    return n > 0 && (size_t)n < cap;
}
static bool private_directory(const char* path) {
    struct stat st; char* canonical = realpath(path, NULL);
    bool ok = canonical && !strcmp(canonical, path) && lstat(path, &st) == 0 && S_ISDIR(st.st_mode);
    free(canonical); return ok;
}
static bool sync_directory(const char* path) {
    int fd = open(path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW);
    bool ok = fd >= 0 && fsync(fd) == 0;
    if (fd >= 0 && close(fd) != 0) ok = false;
    return ok;
}
static bool same_observation(const paired_backup_observation_t* a,
                             const paired_backup_observation_t* b) {
    const struct stat* x = &a->stat; const struct stat* y = &b->stat;
    return !strcmp(a->sha256, b->sha256) && x->st_dev == y->st_dev &&
        x->st_ino == y->st_ino && x->st_size == y->st_size && x->st_mode == y->st_mode &&
        x->st_uid == y->st_uid && x->st_gid == y->st_gid && x->st_nlink == y->st_nlink &&
        x->st_mtime == y->st_mtime && x->st_ctime == y->st_ctime &&
#if defined(__APPLE__) || defined(__FreeBSD__)
        x->st_flags == y->st_flags &&
#endif
#ifdef __APPLE__
        x->st_mtimespec.tv_nsec == y->st_mtimespec.tv_nsec && x->st_ctimespec.tv_nsec == y->st_ctimespec.tv_nsec;
#else
        x->st_mtim.tv_nsec == y->st_mtim.tv_nsec && x->st_ctim.tv_nsec == y->st_ctim.tv_nsec;
#endif
}
static bool observe_regular(const paired_backup_callbacks_t* cb, const char* path,
                            paired_backup_observation_t* out, char* err, size_t n) {
    memset(out, 0, sizeof(*out));
    return cb->observe(cb->context, path, out, err, n) && S_ISREG(out->stat.st_mode) &&
        out->stat.st_size >= 0 && out->stat.st_nlink == 1 && hash_valid(out->sha256);
}
static bool check_acquisition(const paired_backup_request_t* req, const paired_backup_callbacks_t* cb,
                              const captured_image_t* images, size_t count, bool live,
                              char* err, size_t n) {
    for (size_t i = 0; i < count; ++i) {
        char path[512]; paired_backup_observation_t current;
        if (!join(path, sizeof(path), req->source, images[i].name) ||
            !observe_regular(cb, live ? path : images[i].canonical, &current, err, n)) return false;
        if (!same_observation(live ? &images[i].original : &images[i].canonical_before, &current)) {
            if (err && n) snprintf(err, n, "Acquired image changed: %s", images[i].name);
            errno = ESTALE; return false;
        }
    }
    return true;
}
static bool valid_request(const paired_backup_request_t* req, const paired_backup_callbacks_t* cb) {
    if (!req || !cb || !cb->observe || !cb->copy || !cb->convert || !cb->barrier ||
        !cb->revalidate || !cb->finalize_portable || !component(req->uid, sizeof(req->uid)) ||
        strlen(req->uid) != 8 || !component(req->title_id, sizeof(req->title_id)) ||
        strlen(req->title_id) != 9 || strncmp(req->title_id, "PPSA", 4) ||
        !req->active.specified || !req->active.count || req->active.count > RESTORE_SELECTION_MAX ||
        !req->services.specified || req->services.count > req->active.count ||
        req->available_slots < req->active.count || req->available_slots > RESTORE_SELECTION_MAX ||
        !memchr(req->source, 0, sizeof(req->source)) || !memchr(req->workspace, 0, sizeof(req->workspace)) ||
        !private_directory(req->source) || !private_directory(req->workspace)) return false;
    size_t a = strlen(req->source), b = strlen(req->workspace);
    if ((!strncmp(req->source, req->workspace, b) && (req->source[b] == '/' || !req->source[b])) ||
        (!strncmp(req->workspace, req->source, a) && (req->workspace[a] == '/' || !req->workspace[a]))) return false;
    for (size_t i = 0; i < 8; ++i)
        if (!((req->uid[i] >= '0' && req->uid[i] <= '9') || (req->uid[i] >= 'a' && req->uid[i] <= 'f'))) return false;
    for (size_t i = 4; i < 9; ++i) if (req->title_id[i] < '0' || req->title_id[i] > '9') return false;
    const restore_selection_t* selections[] = {&req->active, &req->services};
    for (size_t k = 0; k < 2; ++k) for (size_t i = 0; i < selections[k]->count; ++i) {
        const char* slot = selections[k]->slots[i];
        if (!component(slot, 64) || !strncmp(slot, "sdimg_", 6) || !strncmp(slot, "sce_bu_", 7) ||
            (k && !restore_selection_contains(&req->active, slot))) return false;
        for (size_t j = 0; j < i; ++j) if (!strcmp(slot, selections[k]->slots[j])) return false;
    }
    return true;
}
static bool raw_manifest(const paired_backup_request_t* req, const captured_image_t* images,
                         size_t count, const paired_capture_t* capture, char* out, size_t cap) {
    char utc[32]; time_t created = (time_t)capture->started_at; struct tm tm;
    if (!gmtime_r(&created, &tm) || !strftime(utc, sizeof(utc), "%Y-%m-%dT%H:%M:%SZ", &tm)) return false;
    uint64_t bytes = 0;
    for (size_t i = 0; i < count; ++i) {
        uint64_t size = (uint64_t)images[i].original.stat.st_size;
        if (UINT64_MAX - bytes < size) return false;
        bytes += size;
    }
    int n = snprintf(out, cap, "{\"format\":\"tostonsync.encrypted_image\",\"format_version\":1,"
        "\"tostonsync_version\":\"%s\",\"title_id\":\"%s\",\"user_uid\":\"%s\","
        "\"platform\":\"ps5\",\"backup_type\":\"RAW\",\"trigger\":\"Manual\","
        "\"capture_id\":\"%s\",\"created_at_utc\":\"%s\",\"created_at_epoch\":%lld,"
        "\"backup_scope\":\"selected_containers\",\"partial\":true,\"complete_recovery\":false,"
        "\"raw_completeness\":\"selected_partial\",\"available_slots\":%zu,\"selected_slots_count\":%zu,"
        "\"active_images\":%zu,\"service_images\":%zu,\"total_size\":%llu,\"selected_slots\":[",
        TOSTONSYNC_VERSION, req->title_id, req->uid, capture->capture_id, utc,
        (long long)capture->started_at, req->available_slots, req->active.count,
        req->active.count, req->services.count, (unsigned long long)bytes);
    if (n < 0 || (size_t)n >= cap) return false;
    size_t used = (size_t)n;
    for (size_t i = 0; i < req->active.count + count; ++i) {
        bool image = i >= req->active.count; size_t index = image ? i - req->active.count : i;
        char escaped[512];
        if (!json_escape_small(image ? images[index].name : req->active.slots[index], escaped, sizeof(escaped))) return false;
        n = snprintf(out + used, cap - used, "%s\"%s\"%s", index ? "," : "", escaped,
            !image && index + 1 == req->active.count ? "],\"included_images\":[" : "");
        if (n < 0 || (size_t)n >= cap - used) return false;
        used += (size_t)n;
    }
    if (used + 3 >= cap) return false;
    memcpy(out + used, "]}", 3); return true;
}
static bool raw_verified(const char* path, const paired_backup_request_t* req,
                         const captured_image_t* images, size_t count) {
    migration_report_t* r = calloc(1, sizeof(*r));
    if (!r) return false;
    bool ok = migration_inspect_zip(path, req->title_id, r) && r->valid && r->has_checksums &&
        r->selected_containers && !r->strategy_ready && r->format == MIGRATION_FORMAT_ENCRYPTED_IMAGE &&
        !strcmp(r->title_id, req->title_id) && !strcmp(r->source_user_uid, req->uid) &&
        r->save_dir_count == req->active.count && r->service_images == req->services.count &&
        r->included_image_count == count && r->selected_slots_count == req->active.count;
    for (size_t i = 0; ok && i < count; ++i) {
        size_t occurrences = 0;
        for (size_t j = 0; j < r->included_image_count; ++j) occurrences += !strcmp(images[i].name, r->included_images[j]);
        ok = occurrences == 1;
    }
    free(r); return ok;
}
static bool evidence(const paired_backup_report_t* r) {
    char path[512];
    if (!r->workspace[0] || !join(path, sizeof(path), r->workspace, "result.json")) return false;
    int fd = open(path, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW, 0600);
    if (fd < 0) return false;
    FILE* f = fdopen(fd, "w"); if (!f) { close(fd); return false; }
    fputs("{\"outcome\":", f); json_write_string(f, r->outcome);
    fputs(",\"detail\":", f); json_write_string(f, r->detail);
    fputs(",\"capture_id\":", f); json_write_string(f, r->capture_id);
    fputs(",\"uid\":", f); json_write_string(f, r->uid);
    fputs(",\"title_id\":", f); json_write_string(f, r->title_id);
    fputs(",\"raw_zip_path\":", f); json_write_string(f, r->raw_zip_path);
    fputs(",\"portable_zip_path\":", f); json_write_string(f, r->portable_zip_path);
    fprintf(f, ",\"atomic_snapshot\":false,\"acquisition_stable_observed\":%s",
            r->acquisition_stable_observed ? "true" : "false");
    fputs(",\"raw_zip_sha256\":", f); json_write_string(f, r->raw_zip_sha256);
    fputs(",\"portable_zip_sha256\":", f); json_write_string(f, r->portable_zip_sha256);
    fprintf(f, ",\"raw_verified\":%s,\"portable_verified\":%s,\"migration_ready\":%s,"
        "\"selected_active_slots\":%zu,\"selected_service_images\":%zu,\"acquired_images\":%zu,"
        "\"raw_zip_size\":%llu,\"portable_zip_size\":%llu,\"barrier_retained\":%s,"
        "\"unmount_uncertain\":%s", r->raw_verified ? "true" : "false", r->portable_verified ? "true" : "false",
        r->migration_ready ? "true" : "false", r->selected_active_slots, r->selected_service_images,
        r->acquired_images, (unsigned long long)r->raw_zip_size, (unsigned long long)r->portable_zip_size,
        r->barrier_retained ? "true" : "false", r->unmount_uncertain ? "true" : "false");
    fputs(",\"capture_diagnostic\":{\"writer\":", f);
    write_capture_diagnostic(f, &r->capture_diagnostic, r->capture_diagnostic_attempted);
    fputs(",\"inspector_title\":", f);
    write_capture_diagnostic(f, &r->inspector_title_diagnostic, r->inspector_diagnostic_attempted);
    fputs(",\"inspector_raw\":", f);
    write_capture_diagnostic(f, &r->inspector_raw_diagnostic, diagnostic_has_observation(&r->inspector_raw_diagnostic));
    char scratch[256];
    fputs(",\"scratch\":{\"before_create\":", f);
    migration_scratch_diagnostic_json(&r->scratch_before_create, scratch, sizeof(scratch)); fputs(scratch, f);
    fputs(",\"after_cleanup\":", f);
    migration_scratch_diagnostic_json(&r->scratch_after_cleanup, scratch, sizeof(scratch)); fputs(scratch, f);
    fputs(",\"raw_after_cleanup\":", f);
    migration_scratch_diagnostic_json(&r->capture_raw_scratch_after_cleanup, scratch, sizeof(scratch)); fputs(scratch, f);
    fputs("}}}\n", f);
    bool ok = fflush(f) == 0 && fsync(fd) == 0;
    if (fclose(f) != 0) ok = false;
    return sync_directory(r->workspace) && ok;
}

bool paired_backup_run(const paired_backup_request_t* req, const paired_backup_callbacks_t* cb,
                        paired_backup_report_t* out) {
    if (!out) return false;
    memset(out, 0, sizeof(*out)); snprintf(out->outcome, sizeof(out->outcome), "BLOCKED");
    snprintf(out->detail, sizeof(out->detail), "Explicit bounded selected capture and private workspace required");
    if (!valid_request(req, cb)) return false;
    snprintf(out->workspace, sizeof(out->workspace), "%s", req->workspace);
    snprintf(out->uid, sizeof(out->uid), "%s", req->uid); snprintf(out->title_id, sizeof(out->title_id), "%s", req->title_id);
    const char* leaf = strrchr(req->workspace, '/'); leaf = leaf ? leaf + 1 : req->workspace;
    if (!component(leaf, 64)) return false;
    snprintf(out->capture_id, sizeof(out->capture_id), "%s", leaf);
    out->selected_active_slots = req->active.count; out->selected_service_images = req->services.count;
    size_t count = req->active.count + req->services.count;
    captured_image_t* images = calloc(count, sizeof(*images));
    paired_capture_t* capture = calloc(1, sizeof(*capture));
    bool ok = false, guarded = false; char err[256] = {0};
    paired_backup_observation_t raw_closed = {0}, current_raw = {0};
    char canonical[512], clones[512], portable[512], title[512], reserved[512];
    if (!images || !capture || !join(canonical, sizeof(canonical), req->workspace, "canonical") ||
        !join(clones, sizeof(clones), req->workspace, "mount-input") ||
        !join(portable, sizeof(portable), req->workspace, "portable") ||
        !join(title, sizeof(title), portable, req->title_id) || !join(reserved, sizeof(reserved), title, ".capture") ||
        mkdir(canonical, 0700) || mkdir(clones, 0700) || mkdir(portable, 0700) || mkdir(title, 0700) ||
        mkdir(reserved, 0700) || !sync_directory(req->workspace)) goto done;
    snprintf(capture->capture_id, sizeof(capture->capture_id), "%s", out->capture_id);
    snprintf(capture->producer_version, sizeof(capture->producer_version), "%s", TOSTONSYNC_VERSION);
    snprintf(capture->title_id, sizeof(capture->title_id), "%s", req->title_id);
    snprintf(capture->source_uid, sizeof(capture->source_uid), "%s", req->uid);
    capture->started_at = (int64_t)time(NULL); capture->image_count = count;
    // Observe ALL selected originals before copying any of them. All copies are
    // acquired and globally rechecked before the first native mount is admitted.
    for (size_t i = 0; i < count; ++i) {
        bool service = i >= req->active.count; size_t index = service ? i - req->active.count : i;
        const char* slot = service ? req->services.slots[index] : req->active.slots[index];
        snprintf(images[i].name, sizeof(images[i].name), "sdimg_%s%s", service ? "sce_bu_" : "", slot);
        char live[512];
        if (!join(live, sizeof(live), req->source, images[i].name) ||
            !join(images[i].canonical, sizeof(images[i].canonical), canonical, images[i].name) ||
            !observe_regular(cb, live, &images[i].original, err, sizeof(err))) goto unstable;
        snprintf(capture->images[i].name, sizeof(capture->images[i].name), "%s", images[i].name);
        capture->images[i].size = (uint64_t)images[i].original.stat.st_size;
        snprintf(capture->images[i].sha256, 65, "%s", images[i].original.sha256);
    }
    for (size_t i = 0; i < count; ++i) {
        char live[512];
        if (!join(live, sizeof(live), req->source, images[i].name) ||
            !cb->copy(cb->context, live, images[i].canonical, images[i].original.sha256, err, sizeof(err))) goto unstable;
        if (!observe_regular(cb, images[i].canonical, &images[i].canonical_before, err, sizeof(err)) ||
            strcmp(images[i].original.sha256, images[i].canonical_before.sha256) ||
            images[i].original.stat.st_size != images[i].canonical_before.stat.st_size ||
            (images[i].original.stat.st_dev == images[i].canonical_before.stat.st_dev &&
             images[i].original.stat.st_ino == images[i].canonical_before.stat.st_ino)) goto unstable;
        ++out->acquired_images;
    }
    if (!sync_directory(canonical) || !check_acquisition(req, cb, images, count, true, err, sizeof(err)) ||
        !check_acquisition(req, cb, images, count, false, err, sizeof(err)) ||
        !cb->revalidate(cb->context, err, sizeof(err))) goto unstable;
    out->acquisition_stable_observed = true;
    char manifest[16384], hashes[PAIRED_CAPTURE_MAX_IMAGES][65]; const char* names[PAIRED_CAPTURE_MAX_IMAGES];
    for (size_t i = 0; i < count; ++i) { names[i] = images[i].name; snprintf(hashes[i], 65, "%s", images[i].original.sha256); }
    uint32_t crc; char content_sha[65];
    if (!join(out->raw_zip_path, sizeof(out->raw_zip_path), reserved, "raw.zip") ||
        !raw_manifest(req, images, count, capture, manifest, sizeof(manifest)) ||
        !zip_compress_files_top_manifest_sha256(canonical, req->title_id, out->raw_zip_path,
            names, count, req->deflate, &crc, &out->raw_zip_size, manifest, content_sha, hashes) ||
        !raw_verified(out->raw_zip_path, req, images, count) ||
        !observe_regular(cb, out->raw_zip_path, &raw_closed, err, sizeof(err)) ||
        (uint64_t)raw_closed.stat.st_size != out->raw_zip_size) {
        snprintf(err, sizeof(err), "Closed RAW archive CRC/checksum/inventory verification failed"); goto done;
    }
    snprintf(out->raw_zip_sha256, 65, "%s", raw_closed.sha256);
    out->raw_verified = true; capture->raw_zip_size = out->raw_zip_size;
    snprintf(capture->raw_zip_sha256, 65, "%s", out->raw_zip_sha256);
    if (!check_acquisition(req, cb, images, count, true, err, sizeof(err)) ||
        !check_acquisition(req, cb, images, count, false, err, sizeof(err)) ||
        !observe_regular(cb, out->raw_zip_path, &current_raw, err, sizeof(err)) ||
        !same_observation(&raw_closed, &current_raw) ||
        !cb->revalidate(cb->context, err, sizeof(err))) goto unstable;
    // A failed barrier arm is uncertain: never mount, retire, or deliver a pair.
    out->barrier_retained = true;
    if (!cb->barrier(cb->context, true, req->workspace, err, sizeof(err))) goto uncertain;
    guarded = true;
    for (size_t i = 0; i < req->active.count; ++i) {
        char clone[512], plain[512]; bool uncertain_mount = false;
        if (!join(clone, sizeof(clone), clones, images[i].name) || !join(plain, sizeof(plain), title, images[i].name) ||
            !cb->copy(cb->context, images[i].canonical, clone, images[i].original.sha256, err, sizeof(err))) goto raw_only;
        if (!cb->convert(cb->context, clone, plain, req->title_id, req->active.slots[i],
                         &uncertain_mount, err, sizeof(err))) {
            if (uncertain_mount) goto uncertain;
            goto raw_only;
        }
        if (uncertain_mount) goto uncertain;
        if (!check_acquisition(req, cb, images, count, false, err, sizeof(err))) goto unstable;
    }
    // Canonicals and source remain untouched; mount/unmount may change ONLY
    // disposable mount-input copies. Services never reach convert().
    if (!check_acquisition(req, cb, images, count, true, err, sizeof(err)) ||
        !check_acquisition(req, cb, images, count, false, err, sizeof(err)) ||
        !cb->revalidate(cb->context, err, sizeof(err))) goto unstable;
    capture->finished_at = (int64_t)time(NULL);
    if (!join(out->portable_zip_path, sizeof(out->portable_zip_path), req->workspace, "container-backup.zip") ||
        !cb->finalize_portable(cb->context, portable, title, capture, out->portable_zip_path, err, sizeof(err))) goto raw_only;
    paired_backup_observation_t zipped;
    if (!observe_regular(cb, out->portable_zip_path, &zipped, err, sizeof(err))) goto raw_only;
    out->portable_zip_size = (uint64_t)zipped.stat.st_size;
    snprintf(out->portable_zip_sha256, 65, "%s", zipped.sha256);
    if (!check_acquisition(req, cb, images, count, true, err, sizeof(err)) ||
        !check_acquisition(req, cb, images, count, false, err, sizeof(err)) ||
        !observe_regular(cb, out->raw_zip_path, &current_raw, err, sizeof(err)) ||
        !same_observation(&raw_closed, &current_raw) ||
        !cb->revalidate(cb->context, err, sizeof(err))) goto unstable;
    out->portable_verified = out->migration_ready = true;
    snprintf(out->outcome, sizeof(out->outcome), "PAIRED_VERIFIED");
    snprintf(out->detail, sizeof(out->detail), "Portable and encrypted RAW derive from one stable observed acquisition; not an atomic filesystem snapshot");
    snprintf(out->artifact, sizeof(out->artifact), "%s", out->portable_zip_path); ok = true; goto done;
raw_only:
    if (!check_acquisition(req, cb, images, count, true, err, sizeof(err)) ||
        !check_acquisition(req, cb, images, count, false, err, sizeof(err)) ||
        !observe_regular(cb, out->raw_zip_path, &current_raw, err, sizeof(err)) ||
        !same_observation(&raw_closed, &current_raw) ||
        !cb->revalidate(cb->context, err, sizeof(err))) goto unstable;
    snprintf(out->outcome, sizeof(out->outcome), "RAW_ONLY");
    snprintf(out->detail, sizeof(out->detail), "%s", err[0] ? err : "Portable derivation failed; encrypted RAW alone is verified, migration is not ready");
    snprintf(out->artifact, sizeof(out->artifact), "%s", out->raw_zip_path); ok = out->raw_verified; goto done;
unstable:
    snprintf(out->outcome, sizeof(out->outcome), "FAILED_UNSTABLE");
    out->raw_verified = false;
    out->migration_ready = out->portable_verified = false; out->artifact[0] = 0; ok = false; goto done;
uncertain:
    snprintf(out->outcome, sizeof(out->outcome), "BLOCKED_UNMOUNT_UNCERTAIN");
    out->unmount_uncertain = out->barrier_retained = true;
    out->migration_ready = out->portable_verified = false; out->artifact[0] = 0; ok = false;
done:
    if (guarded && !out->unmount_uncertain) {
        if (!cb->barrier(cb->context, false, req->workspace, err, sizeof(err))) {
            snprintf(out->outcome, sizeof(out->outcome), "BLOCKED_UNMOUNT_UNCERTAIN");
            out->unmount_uncertain = out->barrier_retained = true;
            out->migration_ready = out->portable_verified = false; out->artifact[0] = 0; ok = false;
        } else out->barrier_retained = false;
    }
    if (!ok && err[0]) snprintf(out->detail, sizeof(out->detail), "%s", err);
    if (!evidence(out)) {
        if (!out->unmount_uncertain && strcmp(out->outcome, "FAILED_UNSTABLE"))
            snprintf(out->outcome, sizeof(out->outcome), "BLOCKED");
        snprintf(out->detail, sizeof(out->detail), "Capture evidence durability failed; workspace and all artifacts retained");
        out->migration_ready = false; out->artifact[0] = 0; ok = false;
        out->portable_verified = false;
    }
    free(capture); free(images); return ok;
}
