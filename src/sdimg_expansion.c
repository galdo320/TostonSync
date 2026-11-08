#include "sdimg_expansion.h"
#include "sha256.h"
#include "third_party/sqlite3.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/stat.h>
#include <unistd.h>

// ponytail: bounded in-memory plans suit save-slot transactions, not bulk DB
// migration. Raise these limits only with representative host/memory fixtures.
#define MAX_ITEMS 128
#define MAX_COLS 64
#define MAX_RECORD (1024 * 1024)
#define MAX_PLAN (16 * 1024 * 1024)
#define PATH_CAP 1024
static const char required_text[] = "TostonSync expansion recovery required v1\n";

typedef struct { unsigned char* p; size_t n, cap; } bytes_t;
typedef struct { char name[128]; bool added; char sha[65]; } image_t;
typedef struct { char name[128]; bytes_t data; } row_t;
typedef struct {
    char uid[16], title[16], target[PATH_CAP], db_path[PATH_CAP], state[16];
    bytes_t schema;
    image_t images[MAX_ITEMS]; size_t image_count;
    row_t before[MAX_ITEMS], added[MAX_ITEMS]; size_t before_count, added_count;
} plan_t;

static bool fail(char* err, size_t n, const char* text) {
    if (err && n) snprintf(err, n, "Expansion recovery: %s", text);
    return false;
}

static bool path_join(char out[PATH_CAP], const char* root, const char* name) {
    int n = root ? snprintf(out, PATH_CAP, "%s/%s", root, name) : -1;
    return n > 0 && n < PATH_CAP;
}

static bool component(const char* p, size_t cap) {
    if (!p || !p[0] || strnlen(p, cap) == cap || !strcmp(p, ".") || !strcmp(p, "..")) return false;
    for (; *p; p++) if ((unsigned char)*p < 32 || *p == '/' || *p == '\\') return false;
    return true;
}

static bool image_name(const char* p) {
    return p && !strncmp(p, "sdimg_", 6) && component(p + 6, 122) && strlen(p) < 128;
}

static bool absent(const char* path) {
    struct stat st;
    return lstat(path, &st) != 0 && errno == ENOENT;
}

static bool safe_path(const char* path) {
    if(!path||path[0]!='/'||strlen(path)>=PATH_CAP)return false;
    char prefix[PATH_CAP];snprintf(prefix,sizeof(prefix),"%s",path);
    for(char* part=prefix+1;*part;) {
        char* end=strchr(part,'/');if(end)*end=0;
        struct stat st;
        bool ok=component(part,PATH_CAP)&&lstat(prefix,&st)==0&&!S_ISLNK(st.st_mode)&&(!end||S_ISDIR(st.st_mode));
        if(end)*end='/';if(!ok)return false;
        if(!end)break;part=end+1;if(!*part)return false;
    }
    return true;
}

static bool regular(const char* path, size_t max) {
    struct stat st;
    return safe_path(path) && lstat(path, &st) == 0 && S_ISREG(st.st_mode) && st.st_size > 0 &&
           (!max || (uint64_t)st.st_size <= max);
}

static bool directory(const char* path) {
    struct stat st;
    return safe_path(path) && lstat(path, &st) == 0 && S_ISDIR(st.st_mode);
}

static bool sync_path(const char* path) {
    int fd = open(path, O_RDONLY | O_NOFOLLOW);
    if (fd < 0) return false;
    bool ok = fsync(fd) == 0;
    if (close(fd) != 0) ok = false;
    return ok;
}

static bool sentinel_valid(const char* rollback) {
    char path[PATH_CAP], data[sizeof(required_text)];
    if (!path_join(path,rollback,SDIMG_EXPANSION_REQUIRED) || !regular(path,sizeof(required_text)-1)) return false;
    int fd = open(path,O_RDONLY|O_NOFOLLOW); if(fd<0)return false;
    ssize_t n=read(fd,data,sizeof(data));
    bool ok=n==(ssize_t)sizeof(required_text)-1 && !memcmp(data,required_text,sizeof(required_text)-1);
    if(close(fd)!=0)ok=false;return ok;
}

static bool sentinel_create(const char* rollback) {
    char path[PATH_CAP];if(!path_join(path,rollback,SDIMG_EXPANSION_REQUIRED))return false;
    int fd=open(path,O_CREAT|O_EXCL|O_WRONLY|O_NOFOLLOW,0600);if(fd<0)return false;
    bool ok=write(fd,required_text,sizeof(required_text)-1)==(ssize_t)sizeof(required_text)-1 && fsync(fd)==0;
    if(close(fd)!=0)ok=false;
    // Preserve even partial evidence: a missing/corrupt journal can never fall
    // back to the legacy count-only recovery once expansion was attempted.
    return ok&&sync_path(rollback);
}

static bool push(bytes_t* b, const void* p, size_t n) {
    if (n > MAX_PLAN || b->n > MAX_PLAN - n) return false;
    if (b->n + n > b->cap) {
        size_t cap = b->n + n;
        if (cap < 256) cap = 256;
        unsigned char* q = realloc(b->p, cap);
        if (!q) return false;
        b->p = q; b->cap = cap;
    }
    if (n) memcpy(b->p + b->n, p, n);
    b->n += n;
    return true;
}

static bool number(bytes_t* b, uint64_t n) {
    unsigned char v[8];
    for (int i = 0; i < 8; i++) { v[i] = (unsigned char)n; n >>= 8; }
    return push(b, v, sizeof(v));
}

static bool value(bytes_t* b, sqlite3_stmt* s, int col) {
    int type = sqlite3_column_type(s, col);
    unsigned char t = (unsigned char)type;
    if (!push(b, &t, 1)) return false;
    if (type == SQLITE_NULL) return true;
    if (type == SQLITE_INTEGER) return number(b, (uint64_t)sqlite3_column_int64(s, col));
    if (type == SQLITE_FLOAT) {
        double d = sqlite3_column_double(s, col); uint64_t bits;
        if (sizeof(d) != sizeof(bits)) return false;
        memcpy(&bits, &d, sizeof(bits)); return number(b, bits);
    }
    if (type != SQLITE_TEXT && type != SQLITE_BLOB) return false;
    int n = sqlite3_column_bytes(s, col);
    const void* p = type == SQLITE_TEXT ? (const void*)sqlite3_column_text(s, col) : sqlite3_column_blob(s, col);
    return n >= 0 && (n == 0 || p) && number(b, (uint64_t)n) && push(b, p, (size_t)n);
}

static bool same_bytes(const bytes_t* a, const bytes_t* b) {
    return a->n == b->n && (!a->n || !memcmp(a->p, b->p, a->n));
}

static void rows_free(row_t* rows, size_t n) {
    for (size_t i = 0; i < n; i++) free(rows[i].data.p);
}

static void plan_free(plan_t* p) {
    free(p->schema.p); rows_free(p->before, p->before_count); rows_free(p->added, p->added_count);
    memset(p, 0, sizeof(*p));
}

static bool exec(sqlite3* db, const char* sql) {
    return sqlite3_exec(db, sql, NULL, NULL, NULL) == SQLITE_OK;
}

static bool check_sqlite(sqlite3* db) {
    sqlite3_stmt* s = NULL;
    bool ok = sqlite3_prepare_v2(db, "PRAGMA quick_check", -1, &s, NULL) == SQLITE_OK &&
              sqlite3_step(s) == SQLITE_ROW && sqlite3_column_type(s, 0) == SQLITE_TEXT &&
              !strcmp((const char*)sqlite3_column_text(s, 0), "ok") && sqlite3_step(s) == SQLITE_DONE;
    sqlite3_finalize(s); return ok;
}

static bool open_db(const char* path, bool write, sqlite3** out) {
    *out = NULL;
    if (!regular(path, 0)) return false;
    if (sqlite3_open_v2(path, out, write ? SQLITE_OPEN_READWRITE : SQLITE_OPEN_READONLY, NULL) != SQLITE_OK) {
        if (*out) sqlite3_close(*out); *out = NULL; return false;
    }
    sqlite3_busy_timeout(*out, 1000);
    if (!exec(*out, "PRAGMA trusted_schema=OFF") || !check_sqlite(*out)) {
        sqlite3_close(*out); *out = NULL; return false;
    }
    return true;
}

static bool read_schema(sqlite3* db, bytes_t* out) {
    sqlite3_stmt* s = NULL;
    bool ok = sqlite3_prepare_v2(db, "SELECT 1 FROM sqlite_master WHERE type='trigger' LIMIT 1", -1, &s, NULL) == SQLITE_OK &&
              sqlite3_step(s) == SQLITE_DONE;
    sqlite3_finalize(s); s = NULL;
    if (!ok) return false; // No trigger, including an indirect write trigger, is approved.
    // A targeted DELETE must never cascade to a different table/title. Reject
    // foreign keys throughout this DB, even if this connection defaults them
    // off. Do not toggle enforcement or rewrite sqlite_sequence for recovery.
    if (sqlite3_prepare_v2(db, "SELECT name FROM sqlite_master WHERE type='table'", -1, &s, NULL) != SQLITE_OK) return false;
    int table_rc = SQLITE_ERROR; size_t tables_seen = 0;
    while (ok && (table_rc = sqlite3_step(s)) == SQLITE_ROW) {
        const char* name = (const char*)sqlite3_column_text(s,0);
        sqlite3_stmt* fk = NULL;
        char* sql = name ? sqlite3_mprintf("PRAGMA foreign_key_list(\"%w\")", name) : NULL;
        ok = ++tables_seen <= MAX_ITEMS && sql && sqlite3_prepare_v2(db,sql,-1,&fk,NULL) == SQLITE_OK && sqlite3_step(fk) == SQLITE_DONE;
        sqlite3_finalize(fk); sqlite3_free(sql);
    }
    ok = ok && table_rc == SQLITE_DONE; sqlite3_finalize(s); s = NULL;
    if (!ok) return false;
    ok = sqlite3_prepare_v2(db, "SELECT type,name,tbl_name,sql FROM sqlite_master WHERE tbl_name='savedata' ORDER BY type,name", -1, &s, NULL) == SQLITE_OK;
    int rc = SQLITE_ERROR; size_t objects = 0; bool table = false;
    while (ok && (rc = sqlite3_step(s)) == SQLITE_ROW) {
        if (++objects > MAX_ITEMS) { ok = false; break; }
        const char* type = (const char*)sqlite3_column_text(s, 0);
        const char* sql = (const char*)sqlite3_column_text(s, 3);
        if (type && !strcmp(type, "table")) {
            if (table || !sql || strncasecmp(sql, "CREATE TABLE", 12)) { ok = false; break; }
            table = true;
        } else if (!type || strcmp(type, "index")) { ok = false; break; }
        for (int i = 0; ok && i < 4; i++) ok = value(out, s, i);
    }
    ok = ok && rc == SQLITE_DONE && table && out->n <= MAX_RECORD;
    sqlite3_finalize(s); s = NULL;
    if (!ok || sqlite3_prepare_v2(db, "PRAGMA table_xinfo(savedata)", -1, &s, NULL) != SQLITE_OK) return false;
    size_t columns = 0; bool title = false, name = false;
    while ((rc = sqlite3_step(s)) == SQLITE_ROW) {
        const char* col = (const char*)sqlite3_column_text(s, 1);
        if (++columns > MAX_COLS || !col || sqlite3_column_int(s, 6) != 0 ||
            !strcasecmp(col,"rowid") || !strcasecmp(col,"_rowid_") || !strcasecmp(col,"oid")) { ok = false; break; }
        if (!strcmp(col, "title_id")) title = true;
        if (!strcmp(col, "dir_name")) name = true;
    }
    sqlite3_finalize(s); return ok && rc == SQLITE_DONE && columns && title && name;
}

static int row_find(const row_t* rows, size_t n, const char* name) {
    for (size_t i = 0; i < n; i++) if (!strcmp(rows[i].name, name)) return (int)i;
    return -1;
}

static bool read_rows(sqlite3* db, const char* title, row_t rows[MAX_ITEMS], size_t* count) {
    sqlite3_stmt* s = NULL; *count = 0;
    // Include implicit rowid as well as declared values. WITHOUT ROWID tables
    // and shadowed rowid identifiers are deliberately unsupported.
    if (sqlite3_prepare_v2(db, "SELECT rowid,* FROM savedata WHERE title_id=? ORDER BY dir_name COLLATE BINARY", -1, &s, NULL) != SQLITE_OK) return false;
    bool ok = sqlite3_bind_text(s, 1, title, -1, SQLITE_TRANSIENT) == SQLITE_OK;
    int columns = sqlite3_column_count(s), nc = -1, tc = -1;
    for (int i = 0; i < columns; i++) {
        if (!strcmp(sqlite3_column_name(s, i), "dir_name")) nc = i;
        if (!strcmp(sqlite3_column_name(s, i), "title_id")) tc = i;
    }
    ok = ok && columns > 1 && columns <= MAX_COLS+1 && nc >= 0 && tc >= 0;
    int rc = SQLITE_ERROR; size_t total = 0;
    while (ok && (rc = sqlite3_step(s)) == SQLITE_ROW) {
        const char* name = (const char*)sqlite3_column_text(s, nc);
        const char* tid = (const char*)sqlite3_column_text(s, tc);
        if (*count == MAX_ITEMS || sqlite3_column_type(s,0)!=SQLITE_INTEGER || sqlite3_column_type(s, nc) != SQLITE_TEXT ||
            sqlite3_column_type(s, tc) != SQLITE_TEXT || !tid || strcmp(tid, title) ||
            (int)strlen(tid) != sqlite3_column_bytes(s, tc) || !component(name, 128) ||
            (int)strlen(name) != sqlite3_column_bytes(s, nc) || row_find(rows, *count, name) >= 0) { ok = false; break; }
        row_t* row = &rows[(*count)++]; snprintf(row->name, sizeof(row->name), "%s", name);
        ok = number(&row->data, (uint64_t)columns);
        for (int i = 0; ok && i < columns; i++) ok = value(&row->data, s, i);
        total += row->data.n;
        if (row->data.n > MAX_RECORD || total > MAX_PLAN / 2) ok = false;
    }
    sqlite3_finalize(s); return ok && rc == SQLITE_DONE;
}

static int image_find(const plan_t* p, const char* name) {
    for (size_t i = 0; i < p->image_count; i++) if (!strcmp(p->images[i].name, name)) return (int)i;
    return -1;
}

static bool inventory(plan_t* p, const char* dir, bool capture, bool all_added) {
    DIR* d = opendir(dir); if (!d) return false;
    struct dirent* e; bool ok = true; size_t originals = 0, added = 0;
    while (ok) {
        errno = 0; e = readdir(d);
        if (!e) { if (errno) ok = false; break; }
        if (strncmp(e->d_name, "sdimg_", 6)) continue;
        char path[PATH_CAP];
        if (!image_name(e->d_name) || !path_join(path, dir, e->d_name) || !regular(path, 0)) { ok = false; break; }
        if (capture) {
            if (p->image_count == MAX_ITEMS) { ok = false; break; }
            image_t* im = &p->images[p->image_count++];
            snprintf(im->name, sizeof(im->name), "%s", e->d_name);
            ok = sha256_file_hex(path, im->sha); originals++;
        } else {
            int i = image_find(p, e->d_name);
            if (i < 0) { ok = false; break; }
            image_t* im = &p->images[i];
            if (im->added) {
                char hash[65]; ok = sha256_file_hex(path, hash) && !strcmp(hash, im->sha); added++;
            } else originals++;
        }
    }
    if (closedir(d) != 0) ok = false;
    if (capture) return ok && originals;
    size_t want = 0; for (size_t i = 0; i < p->image_count; i++) if (!p->images[i].added) want++;
    return ok && originals == want && (!all_added || added == p->added_count) &&
           (strcmp(p->state,"RECOVERED") || !added);
}

static bool snapshots_valid(const plan_t* p, const char* rollback, const char* target, bool exact) {
    DIR* d=opendir(rollback);if(!d)return false;
    bool ok=true;struct dirent* e;
    while(ok) {
        errno=0;e=readdir(d);if(!e){if(errno)ok=false;break;}
        if(strncmp(e->d_name,"sdimg_",6))continue;
        int i=image_find(p,e->d_name);
        if(i<0||p->images[i].added)ok=false;
    }
    if(closedir(d)!=0)ok=false;if(!ok)return false;
    for (size_t i = 0; i < p->image_count; i++) {
        const image_t* im = &p->images[i]; if (im->added) continue;
        char source[PATH_CAP], dest[PATH_CAP], hash[65];
        if (!path_join(source, rollback, im->name) || !path_join(dest, target, im->name) ||
            !regular(source, 0) || !regular(dest, 0) || !sha256_file_hex(source, hash) || strcmp(hash, im->sha)) return false;
        if (exact) { if (!sha256_file_hex(dest, hash) || strcmp(hash, im->sha)) return false; }
        else if (!sdimg_restore_images_share_key(source, dest)) return false;
    }
    return true;
}

static bool current_rows_valid(sqlite3* db, const plan_t* p, bool all_added) {
    bytes_t schema = {0}; row_t rows[MAX_ITEMS] = {0}; size_t count = 0;
    bool ok = read_schema(db, &schema) && same_bytes(&schema, &p->schema) && read_rows(db, p->title, rows, &count);
    size_t before = 0, added = 0;
    for (size_t i = 0; ok && i < count; i++) {
        int n = row_find(p->before, p->before_count, rows[i].name);
        if (n >= 0) { ok = same_bytes(&rows[i].data, &p->before[n].data); before++; }
        else {
            n = row_find(p->added, p->added_count, rows[i].name);
            if (n < 0) ok = false;
            else { ok = same_bytes(&rows[i].data, &p->added[n].data); added++; }
        }
    }
    free(schema.p); rows_free(rows, count);
    return ok && before == p->before_count && (!all_added || added == p->added_count) &&
           (strcmp(p->state,"RECOVERED") || !added);
}

static bool plan_relationships(const plan_t* p) {
    size_t originals = 0, added = 0;
    for(size_t i=0;i<p->image_count;i++) {
        const image_t* im=&p->images[i];
        if(!strncmp(im->name,"sdimg_sce_bu_",13)) {if(im->added)return false;continue;}
        if(im->added) {
            if(row_find(p->added,p->added_count,im->name+6)<0 || row_find(p->before,p->before_count,im->name+6)>=0)return false;
            added++;
        } else {
            if(row_find(p->before,p->before_count,im->name+6)<0)return false;
            originals++;
        }
    }
    return originals==p->before_count && added==p->added_count;
}

static const char* tables[] = {
    "CREATE TABLE meta(k TEXT PRIMARY KEY,v BLOB NOT NULL)",
    "CREATE TABLE images(name TEXT PRIMARY KEY,added INTEGER NOT NULL,sha TEXT NOT NULL)",
    "CREATE TABLE rows(added INTEGER NOT NULL,name TEXT NOT NULL,data BLOB NOT NULL,PRIMARY KEY(added,name))"
};

static bool journal_schema(sqlite3* db) {
    sqlite3_stmt* s = NULL;
    if (sqlite3_prepare_v2(db, "SELECT sql FROM sqlite_master WHERE sql IS NOT NULL ORDER BY name", -1, &s, NULL) != SQLITE_OK) return false;
    const int order[] = {1,0,2}; bool ok = true;
    for (int i = 0; i < 3; i++) {
        if (sqlite3_step(s) != SQLITE_ROW || sqlite3_column_type(s,0) != SQLITE_TEXT ||
            strcmp((const char*)sqlite3_column_text(s,0), tables[order[i]])) { ok = false; break; }
    }
    ok = ok && sqlite3_step(s) == SQLITE_DONE; sqlite3_finalize(s); return ok;
}

static bool bind_meta(sqlite3* db, const char* k, const void* v, size_t n) {
    sqlite3_stmt* s = NULL;
    bool ok = n <= MAX_RECORD && sqlite3_prepare_v2(db, "INSERT INTO meta VALUES(?,?)", -1, &s, NULL) == SQLITE_OK &&
              sqlite3_bind_text(s,1,k,-1,SQLITE_STATIC) == SQLITE_OK &&
              sqlite3_bind_blob(s,2,v,(int)n,SQLITE_TRANSIENT) == SQLITE_OK && sqlite3_step(s) == SQLITE_DONE;
    sqlite3_finalize(s); return ok;
}

static bool get_meta(sqlite3* db, const char* k, bytes_t* out) {
    sqlite3_stmt* s = NULL;
    bool ok = sqlite3_prepare_v2(db, "SELECT v FROM meta WHERE k=?", -1, &s, NULL) == SQLITE_OK &&
              sqlite3_bind_text(s,1,k,-1,SQLITE_STATIC) == SQLITE_OK && sqlite3_step(s) == SQLITE_ROW &&
              sqlite3_column_type(s,0) == SQLITE_BLOB;
    int n = ok ? sqlite3_column_bytes(s,0) : 0;
    ok = ok && n > 0 && n <= MAX_RECORD && push(out,sqlite3_column_blob(s,0),(size_t)n) && sqlite3_step(s) == SQLITE_DONE;
    sqlite3_finalize(s); return ok;
}

static bool get_text(sqlite3* db, const char* k, char* out, size_t cap) {
    bytes_t b = {0}; bool ok = get_meta(db,k,&b) && b.n < cap && !memchr(b.p,0,b.n);
    if (ok) { memcpy(out,b.p,b.n); out[b.n]=0; }
    free(b.p); return ok;
}

static bool digest(sqlite3* db, char out[65]) {
    const char* queries[] = {
        "SELECT k,v FROM meta WHERE k NOT IN ('state','digest') ORDER BY k",
        "SELECT name,added,sha FROM images ORDER BY name",
        "SELECT added,name,data FROM rows ORDER BY added,name"
    };
    sha256_ctx_t ctx; sha256_init(&ctx); bool ok = true;
    for (int i = 0; ok && i < 3; i++) {
        sqlite3_stmt* s = NULL;
        ok = sqlite3_prepare_v2(db,queries[i],-1,&s,NULL) == SQLITE_OK;
        int rc = SQLITE_ERROR; size_t count = 0;
        while (ok && (rc=sqlite3_step(s)) == SQLITE_ROW) {
            bytes_t b={0}; ok = ++count <= MAX_ITEMS * 2 && number(&b,(uint64_t)i);
            for (int c=0; ok && c<sqlite3_column_count(s); c++) ok=value(&b,s,c);
            if (ok) sha256_update(&ctx,b.p,b.n);
            free(b.p);
        }
        ok = ok && rc == SQLITE_DONE; sqlite3_finalize(s);
    }
    uint8_t raw[32]; sha256_final(&ctx,raw);
    for(int i=0;i<32;i++) snprintf(out+i*2,3,"%02x",raw[i]);
    return ok;
}

static bool sidecars_absent(const char* path) {
    const char* suffixes[]={"-journal","-wal","-shm"}; char p[PATH_CAP];
    for(size_t i=0;i<3;i++) {
        int n=snprintf(p,sizeof(p),"%s%s",path,suffixes[i]);
        if(n<0 || (size_t)n>=sizeof(p) || !absent(p)) return false;
    }
    return true;
}

static bool load_plan(const char* rollback, plan_t* p, sqlite3** db_out, char* err, size_t err_sz) {
    char path[PATH_CAP], tmp[PATH_CAP]; sqlite3* db=NULL; sqlite3_stmt* s=NULL;
    bool ok=path_join(path,rollback,SDIMG_EXPANSION_JOURNAL) && path_join(tmp,rollback,SDIMG_EXPANSION_JOURNAL ".tmp") &&
            sentinel_valid(rollback) && absent(tmp) && sidecars_absent(tmp) && sidecars_absent(path) && regular(path,MAX_PLAN) &&
            open_db(path,false,&db) && journal_schema(db);
    char version[8], wanted[65], actual[65];
    if(ok) ok=get_text(db,"version",version,sizeof(version)) && !strcmp(version,"1") &&
        get_text(db,"uid",p->uid,sizeof(p->uid)) && component(p->uid,sizeof(p->uid)) &&
        get_text(db,"title",p->title,sizeof(p->title)) && component(p->title,sizeof(p->title)) &&
        get_text(db,"target",p->target,sizeof(p->target)) && p->target[0]=='/' &&
        get_text(db,"db",p->db_path,sizeof(p->db_path)) && p->db_path[0]=='/' &&
        get_meta(db,"schema",&p->schema) && get_text(db,"state",p->state,sizeof(p->state)) &&
        (!strcmp(p->state,"ARMED") || !strcmp(p->state,"COMMITTED") || !strcmp(p->state,"RECOVERING") || !strcmp(p->state,"RECOVERED")) &&
        get_text(db,"digest",wanted,sizeof(wanted)) && strlen(wanted)==64 && digest(db,actual) && !strcmp(wanted,actual);
    if(ok) ok=sqlite3_prepare_v2(db,"SELECT count(*) FROM meta",-1,&s,NULL)==SQLITE_OK && sqlite3_step(s)==SQLITE_ROW && sqlite3_column_int(s,0)==8;
    sqlite3_finalize(s);s=NULL;
    if(ok) ok=sqlite3_prepare_v2(db,"SELECT name,added,sha FROM images ORDER BY name",-1,&s,NULL)==SQLITE_OK;
    int rc=SQLITE_ERROR;size_t originals=0,adds=0;
    while(ok && (rc=sqlite3_step(s))==SQLITE_ROW) {
        const char* name=(const char*)sqlite3_column_text(s,0),*sha=(const char*)sqlite3_column_text(s,2);
        int added=sqlite3_column_int(s,1);
        if(p->image_count==MAX_ITEMS || sqlite3_column_type(s,0)!=SQLITE_TEXT ||
           sqlite3_column_type(s,1)!=SQLITE_INTEGER || sqlite3_column_type(s,2)!=SQLITE_TEXT ||
           !image_name(name) || (int)strlen(name)!=sqlite3_column_bytes(s,0) || !sha || strlen(sha)!=64 ||
           sqlite3_column_bytes(s,2)!=64 || (added!=0&&added!=1) || (added && !strncmp(name,"sdimg_sce_bu_",13))) {ok=false;break;}
        for(int i=0;i<64;i++) if(!((sha[i]>='0'&&sha[i]<='9')||(sha[i]>='a'&&sha[i]<='f'))) ok=false;
        image_t* im=&p->images[p->image_count++];snprintf(im->name,sizeof(im->name),"%s",name);snprintf(im->sha,sizeof(im->sha),"%s",sha);im->added=added!=0;
        if(added)adds++;else originals++;
    }
    ok=ok&&rc==SQLITE_DONE&&originals&&adds;sqlite3_finalize(s);s=NULL;
    if(ok) ok=sqlite3_prepare_v2(db,"SELECT added,name,data FROM rows ORDER BY added,name",-1,&s,NULL)==SQLITE_OK;
    while(ok && (rc=sqlite3_step(s))==SQLITE_ROW) {
        int added=sqlite3_column_int(s,0),n=sqlite3_column_bytes(s,2);
        const char* name=(const char*)sqlite3_column_text(s,1);
        size_t* count=added?&p->added_count:&p->before_count;row_t* rows=added?p->added:p->before;
        if((added!=0&&added!=1) || sqlite3_column_type(s,0)!=SQLITE_INTEGER || sqlite3_column_type(s,1)!=SQLITE_TEXT ||
           sqlite3_column_type(s,2)!=SQLITE_BLOB || !component(name,128) || (int)strlen(name)!=sqlite3_column_bytes(s,1) ||
           *count==MAX_ITEMS || n<=0 || n>MAX_RECORD || row_find(rows,*count,name)>=0) {ok=false;break;}
        row_t* row=&rows[(*count)++];snprintf(row->name,sizeof(row->name),"%s",name);
        ok=push(&row->data,sqlite3_column_blob(s,2),(size_t)n);
    }
    ok=ok&&rc==SQLITE_DONE&&p->before_count&&p->added_count==adds;sqlite3_finalize(s);
    for(size_t i=0;ok&&i<p->added_count;i++) {
        char name[128];int n=snprintf(name,sizeof(name),"sdimg_%s",p->added[i].name);
        int k=(n>0&&(size_t)n<sizeof(name))?image_find(p,name):-1;
        ok=k>=0&&p->images[k].added&&row_find(p->before,p->before_count,p->added[i].name)<0;
    }
    ok=ok&&plan_relationships(p);
    if(!ok) {if(db)sqlite3_close(db);return fail(err,err_sz,"journal is incomplete, corrupt or has unexpected schema/sidecars");}
    if(db_out)*db_out=db;else sqlite3_close(db);
    return true;
}

static bool save_plan(const char* rollback,const plan_t* p) {
    char path[PATH_CAP],tmp[PATH_CAP];sqlite3* db=NULL;sqlite3_stmt* s=NULL;
    if(!path_join(path,rollback,SDIMG_EXPANSION_JOURNAL)||!path_join(tmp,rollback,SDIMG_EXPANSION_JOURNAL ".tmp")||
       !absent(path)||!absent(tmp)||!sidecars_absent(path)||!sidecars_absent(tmp))return false;
    int fd=open(tmp,O_CREAT|O_EXCL|O_WRONLY|O_NOFOLLOW,0600);if(fd<0)return false;if(close(fd)!=0)return false;
    bool ok=sqlite3_open_v2(tmp,&db,SQLITE_OPEN_READWRITE,NULL)==SQLITE_OK &&
            exec(db,"PRAGMA journal_mode=DELETE")&&exec(db,"PRAGMA synchronous=FULL")&&exec(db,"BEGIN IMMEDIATE");
    for(int i=0;ok&&i<3;i++)ok=exec(db,tables[i]);
    const char* keys[]={"version","uid","title","target","db","state"};
    const char* vals[]={"1",p->uid,p->title,p->target,p->db_path,"ARMED"};
    for(int i=0;ok&&i<6;i++)ok=bind_meta(db,keys[i],vals[i],strlen(vals[i]));
    if(ok)ok=bind_meta(db,"schema",p->schema.p,p->schema.n);
    if(ok)ok=sqlite3_prepare_v2(db,"INSERT INTO images VALUES(?,?,?)",-1,&s,NULL)==SQLITE_OK;
    for(size_t i=0;ok&&i<p->image_count;i++) {
        const image_t* im=&p->images[i];sqlite3_reset(s);sqlite3_clear_bindings(s);
        ok=sqlite3_bind_text(s,1,im->name,-1,SQLITE_TRANSIENT)==SQLITE_OK&&sqlite3_bind_int(s,2,im->added)==SQLITE_OK&&
           sqlite3_bind_text(s,3,im->sha,-1,SQLITE_TRANSIENT)==SQLITE_OK&&sqlite3_step(s)==SQLITE_DONE;
    }
    sqlite3_finalize(s);s=NULL;
    if(ok)ok=sqlite3_prepare_v2(db,"INSERT INTO rows VALUES(?,?,?)",-1,&s,NULL)==SQLITE_OK;
    for(int k=0;ok&&k<2;k++)for(size_t i=0;ok&&i<(k?p->added_count:p->before_count);i++) {
        const row_t* r=k?&p->added[i]:&p->before[i];sqlite3_reset(s);sqlite3_clear_bindings(s);
        ok=sqlite3_bind_int(s,1,k)==SQLITE_OK&&sqlite3_bind_text(s,2,r->name,-1,SQLITE_TRANSIENT)==SQLITE_OK&&
           sqlite3_bind_blob(s,3,r->data.p,(int)r->data.n,SQLITE_TRANSIENT)==SQLITE_OK&&sqlite3_step(s)==SQLITE_DONE;
    }
    sqlite3_finalize(s);char hash[65];if(ok)ok=digest(db,hash)&&bind_meta(db,"digest",hash,64)&&exec(db,"COMMIT");
    if(db&&sqlite3_close(db)!=SQLITE_OK)ok=false;
    if(ok)ok=regular(tmp,MAX_PLAN)&&sync_path(tmp)&&rename(tmp,path)==0&&sync_path(rollback);
    // A failed temporary journal is evidence, not garbage to delete/rearm.
    return ok;
}

static bool state_set(const char* rollback,const char* state) {
    char path[PATH_CAP];sqlite3* db=NULL;sqlite3_stmt* s=NULL;
    if(!path_join(path,rollback,SDIMG_EXPANSION_JOURNAL)||!open_db(path,true,&db))return false;
    bool ok=exec(db,"PRAGMA synchronous=FULL")&&exec(db,"BEGIN IMMEDIATE")&&
       sqlite3_prepare_v2(db,"UPDATE meta SET v=? WHERE k='state'",-1,&s,NULL)==SQLITE_OK&&
       sqlite3_bind_blob(s,1,state,(int)strlen(state),SQLITE_TRANSIENT)==SQLITE_OK&&sqlite3_step(s)==SQLITE_DONE&&sqlite3_changes(db)==1;
    sqlite3_finalize(s);if(ok)ok=exec(db,"COMMIT");else(void)exec(db,"ROLLBACK");
    if(sqlite3_close(db)!=SQLITE_OK)ok=false;
    return ok&&sync_path(path)&&sync_path(rollback);
}

bool sdimg_expansion_arm(const char* uid,const char* title,const char* target,const char* db_path,
                         const char* rollback,const char* approved,const char* rows_db,
                         const char names[][SDIMG_EXPANSION_NAME_MAX],size_t count,char* err,size_t err_sz) {
    if(err&&err_sz)err[0]=0;
    if(!component(uid,16)||!component(title,16)||!target||target[0]!='/'||!db_path||db_path[0]!='/'||
       strlen(target)>=PATH_CAP||strlen(db_path)>=PATH_CAP||!directory(target)||!directory(rollback)||
       !directory(approved)||!names||!count||count>=MAX_ITEMS||sdimg_expansion_exists(rollback))
        return fail(err,err_sz,"invalid identity/paths or an existing transaction must be preserved");
    plan_t p={0};sqlite3* db=NULL,*adb=NULL;bytes_t schema={0};
    snprintf(p.uid,sizeof(p.uid),"%s",uid);snprintf(p.title,sizeof(p.title),"%s",title);
    snprintf(p.target,sizeof(p.target),"%s",target);snprintf(p.db_path,sizeof(p.db_path),"%s",db_path);
    bool ok=open_db(db_path,false,&db)&&exec(db,"BEGIN")&&read_schema(db,&p.schema)&&read_rows(db,title,p.before,&p.before_count)&&p.before_count&&
       inventory(&p,rollback,true,false)&&inventory(&p,target,false,false)&&snapshots_valid(&p,rollback,target,true)&&
       open_db(rows_db,false,&adb)&&exec(adb,"BEGIN")&&read_schema(adb,&schema)&&same_bytes(&schema,&p.schema)&&
       read_rows(adb,title,p.added,&p.added_count)&&p.added_count==count;
    for(size_t i=0;ok&&i<count;i++) {
        char path[PATH_CAP],dest[PATH_CAP];
        if(!image_name(names[i])||!strncmp(names[i],"sdimg_sce_bu_",13)||image_find(&p,names[i])>=0||
           p.image_count==MAX_ITEMS||row_find(p.before,p.before_count,names[i]+6)>=0||row_find(p.added,p.added_count,names[i]+6)<0||
           !path_join(path,approved,names[i])||!regular(path,0)||!path_join(dest,target,names[i])||!absent(dest)) {ok=false;break;}
        image_t* im=&p.images[p.image_count++];snprintf(im->name,sizeof(im->name),"%s",names[i]);im->added=true;
        ok=sha256_file_hex(path,im->sha);
    }
    if(ok)ok=plan_relationships(&p)&&sentinel_create(rollback)&&save_plan(rollback,&p);
    if(adb)sqlite3_close(adb);if(db)sqlite3_close(db);free(schema.p);plan_free(&p);
    return ok?true:fail(err,err_sz,"could not arm immutable expansion plan; nothing may be published");
}

static bool live_valid(sqlite3* db,plan_t* p,const char* target,const char* db_path,const char* rollback,bool complete) {
    return target&&db_path&&!strcmp(target,p->target)&&!strcmp(db_path,p->db_path)&&
       inventory(p,target,false,complete)&&snapshots_valid(p,rollback,target,!strcmp(p->state,"RECOVERED"))&&current_rows_valid(db,p,complete);
}

bool sdimg_expansion_validate(const char* target,const char* db_path,const char* rollback,char* err,size_t err_sz) {
    if(err&&err_sz)err[0]=0;plan_t p={0};sqlite3* db=NULL;
    bool ok=load_plan(rollback,&p,NULL,err,err_sz)&&open_db(db_path,false,&db)&&exec(db,"BEGIN")&&live_valid(db,&p,target,db_path,rollback,false);
    if(db)sqlite3_close(db);plan_free(&p);
    return ok?true:fail(err,err_sz,"journal, original identity, image inventory or savedata rows do not match");
}

bool sdimg_expansion_commit(const char* target,const char* db_path,const char* rollback,char* err,size_t err_sz) {
    if(err&&err_sz)err[0]=0;plan_t p={0};sqlite3* db=NULL;
    bool ok=load_plan(rollback,&p,NULL,err,err_sz)&&(!strcmp(p.state,"ARMED")||!strcmp(p.state,"COMMITTED"))&&
        open_db(db_path,true,&db)&&exec(db,"BEGIN IMMEDIATE")&&live_valid(db,&p,target,db_path,rollback,true);
    if(ok)ok=state_set(rollback,"COMMITTED");
    if(db){(void)exec(db,"ROLLBACK");sqlite3_close(db);}plan_free(&p);
    return ok?true:fail(err,err_sz,"commit checkpoint requires the complete approved files and rows");
}

bool sdimg_expansion_recover(const char* target,const char* db_path,const char* rollback,char* err,size_t err_sz) {
    if(err&&err_sz)err[0]=0;plan_t p={0};sqlite3* db=NULL;sqlite3_stmt* s=NULL;
    bool ok=load_plan(rollback,&p,NULL,err,err_sz)&&open_db(db_path,true,&db)&&exec(db,"BEGIN IMMEDIATE")&&live_valid(db,&p,target,db_path,rollback,false);
    if(ok&&!strcmp(p.state,"RECOVERED")) {
        (void)exec(db,"ROLLBACK");sqlite3_close(db);plan_free(&p);return true;
    }
    if(ok)ok=state_set(rollback,"RECOVERING");
    for(size_t i=0;ok&&i<p.image_count;i++) {
        const image_t* im=&p.images[i];if(im->added)continue;
        char src[PATH_CAP],dst[PATH_CAP],hash[65];
        ok=path_join(src,rollback,im->name)&&path_join(dst,target,im->name)&&sdimg_restore_copy_verified(src,dst)&&
           sync_path(dst)&&sha256_file_hex(dst,hash)&&!strcmp(hash,im->sha);
    }
    for(size_t i=0;ok&&i<p.image_count;i++)if(p.images[i].added) {
        char dst[PATH_CAP];ok=path_join(dst,target,p.images[i].name);
        if(ok&&!absent(dst)) {char hash[65];ok=regular(dst,0)&&sha256_file_hex(dst,hash)&&!strcmp(hash,p.images[i].sha)&&unlink(dst)==0;}
    }
    if(ok)ok=sync_path(target)&&sqlite3_prepare_v2(db,"DELETE FROM savedata WHERE title_id=? COLLATE BINARY AND dir_name=? COLLATE BINARY",-1,&s,NULL)==SQLITE_OK;
    for(size_t i=0;ok&&i<p.added_count;i++) {
        sqlite3_reset(s);sqlite3_clear_bindings(s);
        ok=sqlite3_bind_text(s,1,p.title,-1,SQLITE_TRANSIENT)==SQLITE_OK&&sqlite3_bind_text(s,2,p.added[i].name,-1,SQLITE_TRANSIENT)==SQLITE_OK&&
           sqlite3_step(s)==SQLITE_DONE&&sqlite3_changes(db)<=1;
    }
    sqlite3_finalize(s);
    // Verify the whole result, not merely each individual copy. This also
    // detects observable external PFS writes before acknowledging recovery.
    snprintf(p.state,sizeof(p.state),"RECOVERED");
    if(ok)ok=live_valid(db,&p,target,db_path,rollback,false);
    if(ok)ok=exec(db,"COMMIT");else if(db)(void)exec(db,"ROLLBACK");
    if(db&&sqlite3_close(db)!=SQLITE_OK)ok=false;
    db=NULL;
    if(ok)ok=open_db(db_path,false,&db)&&exec(db,"BEGIN")&&live_valid(db,&p,target,db_path,rollback,false);
    if(db&&sqlite3_close(db)!=SQLITE_OK)ok=false;
    if(ok)ok=state_set(rollback,"RECOVERED");plan_free(&p);
    return ok?true:fail(err,err_sz,"recovery blocked or interrupted; keep journal and rollback evidence");
}

bool sdimg_expansion_identity(const char* rollback,char uid[16],char title[16],char* err,size_t err_sz) {
    if(uid)uid[0]=0;if(title)title[0]=0;plan_t p={0};
    bool ok=uid&&title&&load_plan(rollback,&p,NULL,err,err_sz);
    if(ok){snprintf(uid,16,"%s",p.uid);snprintf(title,16,"%s",p.title);}plan_free(&p);return ok;
}

bool sdimg_expansion_exists(const char* rollback) {
    char path[PATH_CAP],tmp[PATH_CAP],required[PATH_CAP];
    return !path_join(path,rollback,SDIMG_EXPANSION_JOURNAL)||!path_join(tmp,rollback,SDIMG_EXPANSION_JOURNAL ".tmp")||
           !path_join(required,rollback,SDIMG_EXPANSION_REQUIRED)||!absent(required)||
           !absent(path)||!absent(tmp)||!sidecars_absent(path)||!sidecars_absent(tmp);
}

bool sdimg_expansion_pending(const char* rollback) {
    if(!sdimg_expansion_exists(rollback))return false;
    plan_t p={0};sqlite3* db=NULL;
    bool done=load_plan(rollback,&p,NULL,NULL,0)&&!strcmp(p.state,"RECOVERED")&&
        open_db(p.db_path,false,&db)&&exec(db,"BEGIN")&&live_valid(db,&p,p.target,p.db_path,rollback,false);
    if(db)sqlite3_close(db);plan_free(&p);return !done;
}
