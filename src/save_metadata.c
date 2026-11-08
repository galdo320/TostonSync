#include "save_metadata.h"
#include "third_party/sqlite3.h"

#include <dirent.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/stat.h>

#define PATH_CAP 1024

static bool join(char out[PATH_CAP], const char* parent, const char* name) {
    int n = snprintf(out, PATH_CAP, "%s/%s", parent, name);
    return n > 0 && n < PATH_CAP;
}

static bool component(const char* name) {
    return name && *name && strlen(name) < 243 && !strchr(name, '/') &&
           strcmp(name, ".") && strcmp(name, "..");
}

static bool same_stat(const struct stat* a, const struct stat* b) {
    return a->st_dev == b->st_dev && a->st_ino == b->st_ino &&
           a->st_mode == b->st_mode && a->st_size == b->st_size &&
           a->st_mtime == b->st_mtime && a->st_ctime == b->st_ctime &&
#ifdef __APPLE__
           a->st_mtimespec.tv_nsec == b->st_mtimespec.tv_nsec &&
           a->st_ctimespec.tv_nsec == b->st_ctimespec.tv_nsec;
#else
           a->st_mtim.tv_nsec == b->st_mtim.tv_nsec &&
           a->st_ctim.tv_nsec == b->st_ctim.tv_nsec;
#endif
}

static save_metadata_entry_t* entry(save_metadata_report_t* r,
                                    const char* name, bool service) {
    save_metadata_entry_t* entries = service ? r->service : r->active;
    size_t* count = service ? &r->service_count : &r->active_count;
    for (size_t i = 0; i < *count; i++)
        if (!strcmp(entries[i].name, name)) return &entries[i];
    if (!component(name) || *count == SAVE_METADATA_MAX_ENTRIES) return NULL;
    save_metadata_entry_t* e = &entries[(*count)++];
    memset(e, 0, sizeof(*e));
    snprintf(e->name, sizeof(e->name), "%s", name);
    snprintf(e->image_name, sizeof(e->image_name), "sdimg_%s%s",
             service ? "sce_bu_" : "", name);
    e->service = service;
    return e;
}

static void image_stat(const char* dir, save_metadata_entry_t* e) {
    char path[PATH_CAP]; struct stat s;
    e->metadata_available = false;
    if (!join(path, dir, e->image_name)) {
        e->stat_errno = ENAMETOOLONG; e->sdimg = SAVE_METADATA_UNKNOWN; return;
    }
    if (lstat(path, &s) != 0) {
        e->stat_errno = errno;
        e->sdimg = errno == ENOENT ? SAVE_METADATA_FAIL : SAVE_METADATA_UNKNOWN;
        return;
    }
    e->stat_errno = 0; e->metadata_available = true;
    e->sdimg = S_ISREG(s.st_mode) ? SAVE_METADATA_PASS : SAVE_METADATA_FAIL;
    snprintf(e->type, sizeof(e->type), "%s", S_ISREG(s.st_mode) ? "regular" :
             S_ISDIR(s.st_mode) ? "directory" : S_ISLNK(s.st_mode) ? "symlink" : "other");
    e->size = s.st_size < 0 ? 0 : (uint64_t)s.st_size;
    e->dev = (uint64_t)s.st_dev; e->inode = (uint64_t)s.st_ino;
    e->mode = (uint32_t)s.st_mode; e->mtime = s.st_mtime; e->ctime = s.st_ctime;
#ifdef __APPLE__
    e->mtime_nsec = s.st_mtimespec.tv_nsec; e->ctime_nsec = s.st_ctimespec.tv_nsec;
#else
    e->mtime_nsec = s.st_mtim.tv_nsec; e->ctime_nsec = s.st_ctim.tv_nsec;
#endif
}

static bool scan(const char* dir, save_metadata_report_t* r, int* error) {
    DIR* d = opendir(dir);
    if (!d) { *error = errno; return false; }
    bool ok = true; struct dirent* de;
    while (ok) {
        errno = 0; de = readdir(d);
        if (!de) { if (errno) { *error = errno; ok = false; } break; }
        if (strncmp(de->d_name, "sdimg_", 6)) continue;
        bool service = !strncmp(de->d_name, "sdimg_sce_bu_", 13);
        save_metadata_entry_t* e = entry(r, de->d_name + (service ? 13 : 6), service);
        if (!e) { *error = EOVERFLOW; ok = false; break; }
        image_stat(dir, e);
        if (e->sdimg == SAVE_METADATA_UNKNOWN) { *error = e->stat_errno; ok = false; }
    }
    if (closedir(d) != 0) { *error = errno; ok = false; }
    return ok;
}

static int compare_entries(const void* a, const void* b) {
    return strcmp(((const save_metadata_entry_t*)a)->name,
                  ((const save_metadata_entry_t*)b)->name);
}

static void sort_report(save_metadata_report_t* r) {
    qsort(r->active, r->active_count, sizeof(r->active[0]), compare_entries);
    qsort(r->service, r->service_count, sizeof(r->service[0]), compare_entries);
}

static bool same_entries(const save_metadata_report_t* a, const save_metadata_report_t* b) {
    return a->active_count == b->active_count && a->service_count == b->service_count &&
           !memcmp(a->active, b->active, a->active_count * sizeof(a->active[0])) &&
           !memcmp(a->service, b->service, a->service_count * sizeof(a->service[0]));
}

static bool sidecars_absent(const char* db, int* error) {
    const char* suffixes[] = { "-wal", "-journal" };
    for (size_t i = 0; i < 2; i++) {
        char path[PATH_CAP]; struct stat s;
        int n = snprintf(path, sizeof(path), "%s%s", db, suffixes[i]);
        if (n < 0 || n >= PATH_CAP) { *error = ENAMETOOLONG; return false; }
        if (lstat(path, &s) == 0) { *error = EBUSY; return false; }
        if (errno != ENOENT) { *error = errno; return false; }
    }
    return true;
}

static bool db_uri(const char* path, char* out, size_t cap) {
    const char* hex = "0123456789ABCDEF"; size_t n = 5;
    if (!path || path[0] != '/' || cap < 40) return false;
    memcpy(out, "file:", n);
    for (const unsigned char* p = (const unsigned char*)path; *p; p++) {
        if (n + 4 >= cap) return false;
        if ((*p >= 'a' && *p <= 'z') || (*p >= 'A' && *p <= 'Z') ||
            (*p >= '0' && *p <= '9') || strchr("/._-", *p)) out[n++] = (char)*p;
        else { out[n++] = '%'; out[n++] = hex[*p >> 4]; out[n++] = hex[*p & 15]; }
    }
    return snprintf(out + n, cap - n, "?mode=ro&immutable=1") < (int)(cap - n);
}

typedef struct {
    save_metadata_report_t* report;
    const char* rowid_alias;
} savedata_sql_context_t;

static int read_only_sql(void* context, int action, const char* a, const char* b,
                         const char* database, const char* trigger) {
    const savedata_sql_context_t* c = context;
    if (action == SQLITE_SELECT) return SQLITE_OK;
    if (action == SQLITE_READ && database && !strcmp(database, "main") && !trigger &&
        a && b && !strcmp(a, "savedata") &&
        (!strcasecmp(b, "rowid") || !strcmp(b, "dir_name") || !strcmp(b, "title_id") ||
         (c && c->rowid_alias && !strcmp(b, c->rowid_alias))))
        return SQLITE_OK;
    if (action == SQLITE_READ && database && !strcmp(database, "main") && !trigger &&
        a && !strcmp(a, "sqlite_master")) return SQLITE_OK;
    if (action == SQLITE_PRAGMA && !trigger && a && b && !strcmp(b, "savedata") &&
        ((database && !strcmp(database, "main") &&
          (!strcmp(a, "table_xinfo") || !strcmp(a, "table_list") || !strcmp(a, "index_list"))) ||
         (!database && !strcmp(a, "table_xinfo"))))
        return SQLITE_OK;
    return SQLITE_DENY;
}

static void diagnostic_text(char* out, size_t cap, const char* value, bool* truncated) {
    if (!value) return;
    int n = snprintf(out, cap, "%s", value);
    if (n < 0 || (size_t)n >= cap) *truncated = true;
}

static int read_only_sql_diagnostic(void* context, int action, const char* a, const char* b,
                                    const char* database, const char* trigger) {
    savedata_sql_context_t* c = context;
    int result = read_only_sql(c, action, a, b, database, trigger);
    save_metadata_report_t* r = c ? c->report : NULL;
    if (result == SQLITE_DENY && r && !r->registry_diagnostic.authorizer_denial.present) {
        save_metadata_authorizer_denial_t* d = &r->registry_diagnostic.authorizer_denial;
        d->present = true; d->action_code = action;
        d->argument1_present = a != NULL; d->argument2_present = b != NULL;
        d->database_present = database != NULL; d->context_present = trigger != NULL;
        diagnostic_text(d->argument1, sizeof(d->argument1), a, &d->truncated);
        diagnostic_text(d->argument2, sizeof(d->argument2), b, &d->truncated);
        diagnostic_text(d->database, sizeof(d->database), database, &d->truncated);
        diagnostic_text(d->context, sizeof(d->context), trigger, &d->truncated);
    }
    return result;
}

// Freeze the first error while its database handle is still valid. Cleanup
// may replace SQLite's connection error; it must not replace this evidence.
static void sql_failure(save_metadata_report_t* r, sqlite3* db,
                        const char* operation, const char* sql, int rc) {
    if (rc == SQLITE_OK || r->registry_diagnostic.sqlite_failure.present) return;
    save_metadata_sql_failure_t* d = &r->registry_diagnostic.sqlite_failure;
    d->present = true;
    snprintf(d->operation, sizeof(d->operation), "%s", operation);
    if (sql) snprintf(d->sql, sizeof(d->sql), "%s", sql);
    d->return_code = rc; d->primary_code = rc & 0xff;
    if (db) {
        d->database_error_available = true;
        d->extended_code = sqlite3_extended_errcode(db);
        diagnostic_text(d->message, sizeof(d->message), sqlite3_errmsg(db), &d->message_truncated);
    }
}

static void validation_rejection(save_metadata_report_t* r, const char* reason) {
    if (!r->registry_diagnostic.validation_rejection[0])
        snprintf(r->registry_diagnostic.validation_rejection,
                 sizeof(r->registry_diagnostic.validation_rejection), "%s", reason);
}

static void finish_statement(sqlite3* db, sqlite3_stmt* s, const char* sql,
                             save_metadata_report_t* r) {
    int rc = sqlite3_finalize(s);
    sql_failure(r, db, "sqlite3_finalize", sql, rc);
    // .217 ignored finalize's return. Diagnostic detail is not a new verdict.
}

static bool read_rows(sqlite3* db, const char* title, save_metadata_report_t* rows,
                      savedata_sql_context_t* context) {
    save_metadata_report_t* report = context->report;
    sqlite3_stmt* s = NULL;
    const char* schema_sql = "PRAGMA main.table_xinfo(savedata)";
    const char* table_sql = "PRAGMA main.table_list(savedata)";
    const char* index_sql = "PRAGMA main.index_list(savedata)";
    const char* rows_sql = "SELECT rowid,dir_name FROM savedata WHERE title_id=?";
    // Reject shadowed rowid, rather than calling a declared column a native ID.
    int prepare_rc = sqlite3_prepare_v2(db, schema_sql, -1, &s, NULL);
    if (prepare_rc != SQLITE_OK) {
        sql_failure(report, db, "sqlite3_prepare_v2", schema_sql, prepare_rc); return false;
    }
    int rc, pk_columns = 0; bool title_col = false, name_col = false, ok = true;
    char alias[PATH_CAP] = {0};
    while ((rc = sqlite3_step(s)) == SQLITE_ROW) {
        const char* name = (const char*)sqlite3_column_text(s, 1);
        if (!name || !strcasecmp(name, "rowid") || !strcasecmp(name, "_rowid_") || !strcasecmp(name, "oid")) {
            validation_rejection(report, name ? "ROWID_SHADOWED" : "SCHEMA_COLUMN_UNAVAILABLE");
            ok = false; break;
        }
        const char* type = (const char*)sqlite3_column_text(s, 2);
        if (!type || sqlite3_column_type(s, 5) != SQLITE_INTEGER ||
            sqlite3_column_type(s, 6) != SQLITE_INTEGER) {
            validation_rejection(report, "SCHEMA_COLUMN_FLAGS_UNAVAILABLE"); ok = false; break;
        }
        int pk = sqlite3_column_int(s, 5), hidden = sqlite3_column_int(s, 6);
        if (pk < 0 || hidden < 0 || hidden > 3) {
            validation_rejection(report, "SCHEMA_COLUMN_FLAGS_INVALID"); ok = false; break;
        }
        if (pk) pk_columns++;
        if (pk == 1 && !hidden && !strcasecmp(type, "INTEGER")) {
            if (strlen(name) >= sizeof(alias)) {
                validation_rejection(report, "ROWID_ALIAS_NAME_TOO_LONG"); ok = false; break;
            }
            snprintf(alias, sizeof(alias), "%s", name);
        }
        if (!strcmp(name, "title_id")) title_col = true;
        if (!strcmp(name, "dir_name")) name_col = true;
    }
    if (rc != SQLITE_ROW && rc != SQLITE_DONE) sql_failure(report, db, "sqlite3_step", schema_sql, rc);
    finish_statement(db, s, schema_sql, report); s = NULL;
    if (!ok || rc != SQLITE_DONE || !title_col || !name_col) {
        if (ok && rc == SQLITE_DONE) validation_rejection(report, "REQUIRED_SCHEMA_COLUMNS_MISSING");
        return false;
    }
    prepare_rc = sqlite3_prepare_v2(db, table_sql, -1, &s, NULL);
    if (prepare_rc != SQLITE_OK) {
        sql_failure(report, db, "sqlite3_prepare_v2", table_sql, prepare_rc); return false;
    }
    int table_rows = 0;
    while ((rc = sqlite3_step(s)) == SQLITE_ROW) {
        const char* schema = (const char*)sqlite3_column_text(s, 0);
        const char* name = (const char*)sqlite3_column_text(s, 1);
        const char* type = (const char*)sqlite3_column_text(s, 2);
        if (++table_rows != 1 || !schema || strcmp(schema, "main") ||
            !name || strcmp(name, "savedata") || !type || strcmp(type, "table")) {
            validation_rejection(report, "SAVEDATA_TABLE_TYPE_UNSUPPORTED"); ok = false; break;
        }
        if (sqlite3_column_type(s, 4) != SQLITE_INTEGER || sqlite3_column_int(s, 4) != 0) {
            validation_rejection(report, "NATIVE_ROWID_UNAVAILABLE"); ok = false; break;
        }
    }
    if (rc != SQLITE_ROW && rc != SQLITE_DONE) sql_failure(report, db, "sqlite3_step", table_sql, rc);
    finish_statement(db, s, table_sql, report); s = NULL;
    if (!ok || rc != SQLITE_DONE || table_rows != 1) {
        if (ok && rc == SQLITE_DONE) validation_rejection(report, "SAVEDATA_TABLE_UNAVAILABLE");
        return false;
    }
    if (pk_columns == 1 && alias[0]) {
        prepare_rc = sqlite3_prepare_v2(db, index_sql, -1, &s, NULL);
        if (prepare_rc != SQLITE_OK) {
            sql_failure(report, db, "sqlite3_prepare_v2", index_sql, prepare_rc); return false;
        }
        // Bundled SQLite gives non-alias primary keys (including inline DESC) a PK index.
        while ((rc = sqlite3_step(s)) == SQLITE_ROW) {
            const char* origin = (const char*)sqlite3_column_text(s, 3);
            if (!origin || (strcmp(origin, "c") && strcmp(origin, "u") && strcmp(origin, "pk"))) {
                validation_rejection(report, "SCHEMA_INDEX_ORIGIN_UNAVAILABLE"); ok = false; break;
            }
            if (!strcmp(origin, "pk")) alias[0] = '\0';
        }
        if (rc != SQLITE_ROW && rc != SQLITE_DONE) sql_failure(report, db, "sqlite3_step", index_sql, rc);
        finish_statement(db, s, index_sql, report); s = NULL;
        if (!ok || rc != SQLITE_DONE) return false;
    } else alias[0] = '\0';
    // Sorting is done in memory after collection, not by SQLite temporary files.
    context->rowid_alias = alias[0] ? alias : NULL;
    prepare_rc = sqlite3_prepare_v2(db, rows_sql, -1, &s, NULL);
    context->rowid_alias = NULL;
    if (prepare_rc != SQLITE_OK) {
        sql_failure(report, db, "sqlite3_prepare_v2", rows_sql, prepare_rc); return false;
    }
    int bind_rc = sqlite3_bind_text(s, 1, title, -1, SQLITE_TRANSIENT);
    ok = bind_rc == SQLITE_OK;
    if (!ok) sql_failure(report, db, "sqlite3_bind_text", rows_sql, bind_rc);
    while (ok && (rc = sqlite3_step(s)) == SQLITE_ROW) {
        const char* name = (const char*)sqlite3_column_text(s, 1);
        if (sqlite3_column_type(s, 0) != SQLITE_INTEGER || sqlite3_column_type(s, 1) != SQLITE_TEXT ||
            !name || (int)strlen(name) != sqlite3_column_bytes(s, 1)) {
            validation_rejection(report, "ROW_TYPES_OR_NAME_INVALID"); ok = false; break;
        }
        bool service = !strncmp(name, "sce_bu_", 7);
        save_metadata_entry_t* e = entry(rows, name + (service ? 7 : 0), service);
        if (!e || e->rowid_available) {
            validation_rejection(report, e ? "DUPLICATE_ROW" : "ROW_NAME_OR_CAPACITY_INVALID");
            ok = false; break;
        }
        e->registered = SAVE_METADATA_PASS; e->rowid_available = true;
        e->rowid = sqlite3_column_int64(s, 0);
    }
    if (ok && rc != SQLITE_ROW && rc != SQLITE_DONE) sql_failure(report, db, "sqlite3_step", rows_sql, rc);
    finish_statement(db, s, rows_sql, report); return ok && rc == SQLITE_DONE;
}

static void registry(const char* dir, const char* path, const char* title,
                     save_metadata_report_t* r) {
    struct stat before, after; int error = 0;
    int stat_rc = path && *path ? lstat(path, &before) : -1;
    if (stat_rc != 0 || !S_ISREG(before.st_mode)) {
        r->registry_errno = path && *path ? (stat_rc != 0 ? errno : EINVAL) : EINVAL;
        validation_rejection(r, "DATABASE_METADATA_UNAVAILABLE");
        snprintf(r->registry_detail, sizeof(r->registry_detail), "Database metadata unavailable; registration is unknown"); return;
    }
    if (!sidecars_absent(path, &error)) {
        validation_rejection(r, "SIDECAR_PRECHECK_REJECTED");
        r->registry_errno = error;
        snprintf(r->registry_detail, sizeof(r->registry_detail), "Live WAL/journal or inaccessible sidecar; no immutable database query attempted"); return;
    }
    sqlite3* db = NULL; char uri[PATH_CAP * 3 + 32];
    savedata_sql_context_t context = { .report = r };
    save_metadata_report_t* rows = calloc(1, sizeof(*rows));
    bool ok = rows && db_uri(path, uri, sizeof(uri));
    if (ok) {
        int rc = sqlite3_open_v2(uri, &db, SQLITE_OPEN_READONLY | SQLITE_OPEN_URI | SQLITE_OPEN_NOFOLLOW, NULL);
        ok = rc == SQLITE_OK;
        if (!ok) sql_failure(r, db, "sqlite3_open_v2", NULL, rc);
    } else validation_rejection(r, rows ? "DATABASE_URI_UNAVAILABLE" : "ROW_MEMORY_UNAVAILABLE");
    if (ok) {
        int rc = sqlite3_set_authorizer(db, read_only_sql_diagnostic, &context);
        sql_failure(r, db, "sqlite3_set_authorizer", NULL, rc);
        rc = sqlite3_busy_timeout(db, 0);
        sql_failure(r, db, "sqlite3_busy_timeout", NULL, rc);
        bool readonly = sqlite3_db_readonly(db, "main") == 1;
        if (!readonly) validation_rejection(r, "DATABASE_NOT_READONLY");
        ok = readonly && read_rows(db, title, rows, &context);
    }
    int sql_error = db && !ok ? sqlite3_errcode(db) : 0;
    if (db) {
        int rc = sqlite3_close(db);
        if (rc != SQLITE_OK) { sql_failure(r, db, "sqlite3_close", NULL, rc); ok = false; }
    }
    save_metadata_registry_diagnostic_t* diagnostic = &r->registry_diagnostic;
    diagnostic->post_query_stability_checked = true;
    if (lstat(path, &after) != 0) {
        error = errno; ok = false;
        snprintf(diagnostic->stability_operation, sizeof(diagnostic->stability_operation), "database_lstat_after");
    } else if (!same_stat(&before, &after)) {
        error = EAGAIN; ok = false;
        snprintf(diagnostic->stability_operation, sizeof(diagnostic->stability_operation), "database_stat_compare");
    } else if (!sidecars_absent(path, &error)) {
        ok = false;
        snprintf(diagnostic->stability_operation, sizeof(diagnostic->stability_operation), "sidecars_after");
    } else diagnostic->post_query_stable = true;
    diagnostic->stability_errno = error;
    if (!ok) {
        r->registry_errno = error;
        snprintf(r->registry_detail, sizeof(r->registry_detail), "Database changed, query failed (SQLite %d), or row inventory incomplete; registration is unknown", sql_error);
        free(rows); return;
    }
    // Validate union capacity before exposing any IDs as confirmed.
    for (int service = 0; service < 2 && ok; service++) {
        save_metadata_entry_t* es = service ? rows->service : rows->active;
        size_t count = service ? rows->service_count : rows->active_count;
        size_t total = service ? r->service_count : r->active_count;
        save_metadata_entry_t* current = service ? r->service : r->active;
        for (size_t i = 0; i < count; i++) {
            bool found = false;
            for (size_t j = 0; j < total; j++) if (!strcmp(current[j].name, es[i].name)) found = true;
            if (!found && ++total > SAVE_METADATA_MAX_ENTRIES) { ok = false; break; }
        }
    }
    if (!ok) {
        r->registry_errno = EOVERFLOW;
        validation_rejection(r, "COMBINED_INVENTORY_CAPACITY");
        snprintf(r->registry_detail, sizeof(r->registry_detail), "Combined image/row inventory exceeds diagnostic limit; registration is unknown");
        free(rows); return;
    }
    for (size_t i = 0; i < r->active_count; i++) r->active[i].registered = SAVE_METADATA_FAIL;
    for (size_t i = 0; i < r->service_count; i++) r->service[i].registered = SAVE_METADATA_FAIL;
    for (int service = 0; service < 2; service++) {
        save_metadata_entry_t* es = service ? rows->service : rows->active;
        size_t count = service ? rows->service_count : rows->active_count;
        for (size_t i = 0; i < count; i++) {
            save_metadata_entry_t* e = entry(r, es[i].name, service != 0);
            e->registered = SAVE_METADATA_PASS; e->rowid_available = true; e->rowid = es[i].rowid;
            if (!e->metadata_available && e->sdimg == SAVE_METADATA_UNKNOWN) image_stat(dir, e);
        }
    }
    r->registry = SAVE_METADATA_PASS;
    snprintf(r->registry_detail, sizeof(r->registry_detail), "Exact title rows observed read-only without WAL/journal; not an atomic image/database snapshot");
    free(rows);
}

void save_metadata_collect(const char* dir, const char* db_path,
                           const char* title, save_metadata_report_t* r) {
    if (!r) return;
    memset(r, 0, sizeof(*r));
    if (!dir || !*dir || !title || !*title) {
        r->filesystem_errno = EINVAL;
        snprintf(r->filesystem_detail, sizeof(r->filesystem_detail), "Resolved title directory is unavailable"); return;
    }
    struct stat before, after; int error = 0;
    int stat_rc = lstat(dir, &before);
    bool ok = stat_rc == 0 && S_ISDIR(before.st_mode);
    if (!ok) error = stat_rc != 0 ? errno : ENOTDIR;
    if (ok) ok = scan(dir, r, &error);
    sort_report(r);
    save_metadata_report_t* second = calloc(1, sizeof(*second));
    if (ok && !second) { error = ENOMEM; ok = false; }
    if (ok) ok = scan(dir, second, &error);
    if (ok) {
        sort_report(second);
        ok = lstat(dir, &after) == 0 && same_stat(&before, &after) && same_entries(r, second);
        if (!ok && !error) error = EAGAIN;
    }
    free(second);
    r->filesystem = ok ? SAVE_METADATA_PASS : error == ENOENT ? SAVE_METADATA_FAIL : SAVE_METADATA_UNKNOWN;
    r->filesystem_errno = error;
    snprintf(r->filesystem_detail, sizeof(r->filesystem_detail), "%s", ok ?
             "Two unchanged metadata enumerations; images were not opened" :
             "Directory metadata unavailable, partial, oversized, or changed; not a complete inventory");
    registry(dir, db_path, title, r);
    sort_report(r);
}
