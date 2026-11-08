// TostónSync — ZIP store/deflate compressor + extractor (ZIP64-capable).
//
// Single-archive entries are written as:
//   [Local File Header][Filename][(ZIP64 extra)][Raw or Deflated Data]
// ...repeated, followed by:
//   [Central Directory Record][Filename][(ZIP64 extra)]
// ...for every entry, then optionally [ZIP64 EOCD][ZIP64 EOCD Locator]
// and finally [End Of Central Directory].
//
// The deflate codec is a *very* small fixed-Huffman literal-only encoder
// (BTYPE=00 stored blocks framed as a deflate stream). For uncompressible
// save data the size win is modest but real; for already-compressed
// game-save formats it's effectively store-mode with a little overhead. It
// is standards-compliant and any unzipper (the PS5's libSceZlib included)
// can decompress it.
//
// ZIP64: whenever an entry's uncompressed size, compressed size, or local
// header offset would not fit in 32 bits (>= 0xFFFFFFFF), the relevant
// fields are written as 0xFFFFFFFF sentinels and the true 64-bit values go
// into a ZIP64 extended-information extra field (id 0x0001). This removes
// the old 4 GB ceiling on individual saves and on the whole archive. The
// extractor understands the same records, so restores of large saves work.

#define _FILE_OFFSET_BITS 64

#include "zip.h"
#include "crc32.h"
#include "sha256.h"
#include "log.h"
#include "at_io.h"
#include "third_party/puff.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

// Threshold above which a field must use ZIP64. Overridable at build time
// so the test bench can force the ZIP64 path on small files.
#ifndef ZIP64_THRESHOLD
#define ZIP64_THRESHOLD 0xFFFFFFFFULL
#endif

// --------------------------------------------------------------------
// Byte writers / readers (little-endian).
// --------------------------------------------------------------------

static void put_u16(unsigned char* p, uint16_t v) { p[0]=v; p[1]=v>>8; }
static void put_u32(unsigned char* p, uint32_t v) { p[0]=v; p[1]=v>>8; p[2]=v>>16; p[3]=v>>24; }
static void put_u64(unsigned char* p, uint64_t v) { for (int i=0;i<8;i++) p[i]=(unsigned char)(v>>(8*i)); }

static uint16_t rd_u16(const unsigned char* p) { return (uint16_t)(p[0] | (p[1]<<8)); }
static uint32_t rd_u32(const unsigned char* p) {
    return (uint32_t)p[0] | ((uint32_t)p[1]<<8) | ((uint32_t)p[2]<<16) | ((uint32_t)p[3]<<24);
}
static uint64_t rd_u64(const unsigned char* p) {
    uint64_t v = 0; for (int i=0;i<8;i++) v |= (uint64_t)p[i] << (8*i); return v;
}

// DOS time/date from local clock.
static void dos_time(uint16_t* dt, uint16_t* dd) {
    time_t t = time(NULL);
    struct tm tm; localtime_r(&t, &tm);
    *dt = (tm.tm_hour << 11) | (tm.tm_min << 5) | (tm.tm_sec / 2);
    *dd = ((tm.tm_year - 80) << 9) | ((tm.tm_mon + 1) << 5) | tm.tm_mday;
}

// Stored block (BTYPE=00) deflate emitter for arbitrarily large data.
// One block per 65535 bytes, with the final block flagged BFINAL=1.
static bool deflate_store(FILE* in, FILE* out, uint64_t in_size,
                          uint32_t* crc_running, sha256_ctx_t* sha,
                          sha256_ctx_t* content_sha,
                          uint64_t* out_size) {
    uint64_t left = in_size;
    *out_size = 0;
    // 64 KB I/O buffer on the heap, not the stack: this runs on worker
    // threads and a buffer this large must not depend on stack headroom.
    unsigned char* buf = (unsigned char*)malloc(65536);
    if (!buf) return false;
    bool ok = true;
    while (left) {
        size_t chunk = left > 65535 ? 65535 : (size_t)left;
        if (fread(buf, 1, chunk, in) != chunk) { ok = false; break; }
        *crc_running = crc32_update(*crc_running, buf, chunk);
        if (sha) sha256_update(sha, buf, chunk);
        if (content_sha) sha256_update(content_sha, buf, chunk);
        unsigned char hdr[5];
        hdr[0] = (left == chunk) ? 0x01 : 0x00; // BFINAL on last
        hdr[1] =  chunk        & 0xff;
        hdr[2] = (chunk >> 8)  & 0xff;
        hdr[3] = (~chunk)      & 0xff;
        hdr[4] = ((~chunk) >> 8) & 0xff;
        if (fwrite(hdr, 1, 5, out) != 5) { ok = false; break; }
        if (fwrite(buf, 1, chunk, out) != chunk) { ok = false; break; }
        *out_size += 5 + chunk;
        left -= chunk;
    }
    free(buf);
    if (!ok) return false;
    if (in_size == 0) {
        // Emit one empty BFINAL stored block.
        unsigned char hdr[5] = {0x01, 0x00, 0x00, 0xff, 0xff};
        if (fwrite(hdr, 1, 5, out) != 5) return false;
        *out_size = 5;
    }
    return true;
}

// Same as above but without the deflate framing (compression method 0).
static bool store_copy(FILE* in, FILE* out, uint64_t in_size,
                       uint32_t* crc_running, sha256_ctx_t* sha,
                       sha256_ctx_t* content_sha) {
    enum { COPY_BUF = 65536 };
    unsigned char* buf = (unsigned char*)malloc(COPY_BUF);
    if (!buf) return false;
    uint64_t left = in_size;
    bool ok = true;
    while (left) {
        size_t chunk = left > COPY_BUF ? COPY_BUF : (size_t)left;
        if (fread(buf, 1, chunk, in) != chunk) { ok = false; break; }
        *crc_running = crc32_update(*crc_running, buf, chunk);
        if (sha) sha256_update(sha, buf, chunk);
        if (content_sha) sha256_update(content_sha, buf, chunk);
        if (fwrite(buf, 1, chunk, out) != chunk) { ok = false; break; }
        left -= chunk;
    }
    free(buf);
    return ok;
}

// --------------------------------------------------------------------
// Central directory entries are accumulated in memory while we stream
// file data to disk. Sizes/offsets are 64-bit for ZIP64.
// --------------------------------------------------------------------

typedef struct {
    char     name[260];
    uint16_t name_len;
    uint16_t method;
    uint16_t flags;
    uint32_t crc32;
    uint64_t comp_size;
    uint64_t orig_size;
    uint64_t local_off;
    uint16_t dt, dd;
    char     content_sha256[65];
} entry_t;

typedef struct {
    entry_t* items;
    size_t   count;
    size_t   cap;
} centraldir_t;

static bool cd_push(centraldir_t* cd, const entry_t* e) {
    if (cd->count == cd->cap) {
        size_t ncap = cd->cap ? cd->cap * 2 : 64;
        entry_t* ni = (entry_t*)realloc(cd->items, ncap * sizeof(entry_t));
        if (!ni) return false;
        cd->items = ni; cd->cap = ncap;
    }
    cd->items[cd->count++] = *e;
    return true;
}

// --------------------------------------------------------------------
// Recursive directory walker / single-file writer.
// --------------------------------------------------------------------

static bool zip_file_stream(FILE* zip, FILE* in,
                         const char* zip_name, bool deflate_on,
                         uint32_t* root_crc, uint8_t root_sha[32],
                         centraldir_t* cd, const struct stat* expected) {
    int end_rc = fseeko(in, 0, SEEK_END);
    off_t measured = ftello(in);
    int start_rc = fseeko(in, 0, SEEK_SET);
    if (expected && (end_rc || start_rc || measured < 0 ||
                     measured != expected->st_size)) { fclose(in); return false; }
    uint64_t in_size = (uint64_t)measured;

    entry_t e = {0};
    // Clamp the stored name to the entry buffer and keep name_len in sync
    // with what we actually hold, so the central-directory writer never
    // reads past the field and the LFH/CD always agree.
    size_t nlen = strlen(zip_name);
    if (nlen > sizeof(e.name) - 1) {
        log_warn("zip: entry name too long, truncating: %s", zip_name);
        nlen = sizeof(e.name) - 1;
    }
    memcpy(e.name, zip_name, nlen);
    e.name[nlen] = '\0';
    e.name_len  = (uint16_t)nlen;
    e.method    = deflate_on ? 8 : 0;
    e.flags     = expected ? 0x0800 : 0; // Only literal allowlist exports advertise UTF-8 names.
    e.orig_size = in_size;
    e.local_off = (uint64_t)ftello(zip);
    dos_time(&e.dt, &e.dd);

    // A save >= 4 GB needs ZIP64 in its local header. We know orig_size up
    // front; comp_size is patched in after streaming.
    bool z64 = in_size >= ZIP64_THRESHOLD;
    uint16_t verneed = z64 ? 45 : 20;
    uint16_t xlen    = z64 ? 20 : 0;   // 4 hdr + 16 (orig8 + comp8)

    unsigned char lfh[30];
    memset(lfh, 0, sizeof(lfh));
    put_u32(lfh + 0, 0x04034b50);
    put_u16(lfh + 4, verneed);
    put_u16(lfh + 6, e.flags);
    put_u16(lfh + 8, e.method);
    put_u16(lfh + 10, e.dt);
    put_u16(lfh + 12, e.dd);
    // crc (14) patched later.
    put_u32(lfh + 18, z64 ? 0xFFFFFFFF : 0);              // comp (placeholder)
    put_u32(lfh + 22, z64 ? 0xFFFFFFFF : (uint32_t)in_size); // orig
    put_u16(lfh + 26, e.name_len);
    put_u16(lfh + 28, xlen);
    if (fwrite(lfh, 1, 30, zip) != 30) { fclose(in); return false; }
    if (fwrite(e.name, 1, e.name_len, zip) != e.name_len) { fclose(in); return false; }

    off_t extra_pos = 0;
    if (z64) {
        unsigned char ex[20];
        memset(ex, 0, sizeof(ex));
        put_u16(ex + 0, 0x0001);
        put_u16(ex + 2, 16);
        put_u64(ex + 4, in_size);   // orig
        put_u64(ex + 12, 0);        // comp (placeholder)
        extra_pos = ftello(zip);
        if (fwrite(ex, 1, 20, zip) != 20) { fclose(in); return false; }
    }

    uint32_t crc = crc32_init();
    sha256_ctx_t entry_sha, content_sha;
    sha256_ctx_t* entry_sha_p = root_sha ? &entry_sha : NULL;
    sha256_ctx_t* content_sha_p = root_sha ? &content_sha : NULL;
    if (entry_sha_p) {
        uint8_t size_le[8], zero = 0;
        put_u64(size_le, in_size);
        sha256_init(entry_sha_p);
        sha256_update(entry_sha_p, zip_name, strlen(zip_name));
        sha256_update(entry_sha_p, &zero, 1);
        sha256_update(entry_sha_p, size_le, sizeof(size_le));
        sha256_init(content_sha_p);
    }
    bool ok;
    if (deflate_on) {
        uint64_t out_size = 0;
        ok = deflate_store(in, zip, in_size, &crc, entry_sha_p,
                           content_sha_p, &out_size);
        e.comp_size = out_size;
    } else {
        ok = store_copy(in, zip, in_size, &crc, entry_sha_p, content_sha_p);
        e.comp_size = in_size;
    }
    if (expected) {
        struct stat after;
        ok = ok && fstat(fileno(in), &after) == 0 &&
             after.st_dev == expected->st_dev && after.st_ino == expected->st_ino &&
             after.st_size == expected->st_size && after.st_mtime == expected->st_mtime;
    }
    int closed = fclose(in);
    if (expected && closed != 0) ok = false;
    if (!ok) return false;

    // Fingerprint with the *uncompressed* content so it's stable across runs
    // regardless of compression. Order-independent (readdir order must not
    // matter) but mixed with the entry NAME and SIZE so it cannot cancel to a
    // collision the way a bare XOR of content CRCs did — two identical or
    // paired entries XORed straight to 0, which made dedup skip a changed save.
    uint32_t fc = crc32_finish(crc);
    e.crc32 = fc;
    uint32_t namecrc = crc32_buf(zip_name, strlen(zip_name));
    *root_crc += (fc ^ (namecrc * 0x9E3779B1u)) +
                 ((uint32_t)e.orig_size * 0x85EBCA77u);
    if (entry_sha_p) {
        static const char hex[] = "0123456789abcdef";
        uint8_t digest[32], content_digest[32];
        sha256_final(entry_sha_p, digest);
        sha256_final(content_sha_p, content_digest);
        // Entry names are unique inside a ZIP, so XOR gives a stable,
        // readdir-order-independent 256-bit set fingerprint.
        for (size_t i = 0; i < sizeof(digest); i++) {
            root_sha[i] ^= digest[i];
            e.content_sha256[i * 2] = hex[content_digest[i] >> 4];
            e.content_sha256[i * 2 + 1] = hex[content_digest[i] & 15];
        }
        e.content_sha256[64] = '\0';
    }

    // Patch crc (always), and sizes (in the base header when 32-bit, or in
    // the ZIP64 extra when 64-bit).
    off_t after = ftello(zip);
    if (after < 0) return false;
    unsigned char c4[4];
    if (fseeko(zip, (off_t)e.local_off + 14, SEEK_SET) != 0) return false;
    put_u32(c4, e.crc32);
    if (fwrite(c4, 1, 4, zip) != 4) return false;
    if (!z64) {
        unsigned char patch[8];
        put_u32(patch + 0, (uint32_t)e.comp_size);
        put_u32(patch + 4, (uint32_t)e.orig_size);
        if (fwrite(patch, 1, 8, zip) != 8) return false;
    } else {
        unsigned char c8[8];
        if (fseeko(zip, extra_pos + 12, SEEK_SET) != 0) return false;
        put_u64(c8, e.comp_size);
        if (fwrite(c8, 1, 8, zip) != 8) return false;
    }
    if (fseeko(zip, after, SEEK_SET) != 0) return false;

    return cd_push(cd, &e);
}

static bool zip_one_file(FILE* zip, const char* src_path,
                         const char* zip_name, bool deflate_on,
                         uint32_t* root_crc, uint8_t root_sha[32],
                         centraldir_t* cd) {
    FILE* in = fopen(src_path, "rb");
    if (!in) { log_warn("zip: open %s failed", src_path); return false; }
    return zip_file_stream(zip, in, zip_name, deflate_on, root_crc, root_sha, cd, NULL);
}

static bool json_write_string(FILE* f, const char* s) {
    if (fputc('"', f) == EOF) return false;
    for (const unsigned char* p = (const unsigned char*)s; *p; p++) {
        if (*p == '"' || *p == '\\') {
            if (fputc('\\', f) == EOF || fputc(*p, f) == EOF) return false;
        } else if (*p < 0x20) {
            if (fprintf(f, "\\u%04x", *p) < 0) return false;
        } else if (fputc(*p, f) == EOF) {
            return false;
        }
    }
    return fputc('"', f) != EOF;
}

static bool write_checksums(FILE* f, const centraldir_t* cd) {
    if (fputs("{\n  \"algorithm\": \"sha256\",\n  \"files\": {\n", f) < 0)
        return false;
    bool first = true;
    for (size_t i = 0; i < cd->count; i++) {
        const entry_t* e = &cd->items[i];
        if (!e->content_sha256[0]) continue;
        if ((!first && fputs(",\n", f) < 0) || fputs("    ", f) < 0 ||
            !json_write_string(f, e->name) || fputs(": ", f) < 0 ||
            !json_write_string(f, e->content_sha256)) return false;
        first = false;
    }
    return fputs("\n  }\n}\n", f) >= 0;
}

// Build the name stored in the archive: `top/sub` when a top_folder is set,
// otherwise just `sub` (or a bare filename for a single-file source).
static void stored_name(char* out, size_t out_sz,
                        const char* top, const char* sub) {
    if (top && *top) snprintf(out, out_sz, "%s/%s", top, sub);
    else             snprintf(out, out_sz, "%s", sub);
}

static bool zip_empty_directory(FILE* zip, const char* name, centraldir_t* cd) {
    entry_t e = {0};
    int n = snprintf(e.name, sizeof(e.name), "%s/", name);
    if (n <= 1 || (size_t)n >= sizeof(e.name)) return false;
    e.name_len = (uint16_t)n;
    off_t offset = ftello(zip);
    if (offset < 0) return false;
    e.local_off = (uint64_t)offset;
    unsigned char header[30] = {0};
    put_u32(header, 0x04034b50);
    put_u16(header + 4, 20);
    put_u16(header + 26, e.name_len);
    return fwrite(header, 1, sizeof(header), zip) == sizeof(header) &&
           fwrite(e.name, 1, e.name_len, zip) == e.name_len && cd_push(cd, &e);
}

static bool walk(FILE* zip, const char* base_src, const char* top,
                 const char* sub, bool deflate_on,
                 uint32_t* root_crc, uint8_t root_sha[32], centraldir_t* cd,
                 bool complete_tree) {
    char real_path[600];
    if (sub && *sub)
        snprintf(real_path, sizeof(real_path), "%s/%s", base_src, sub);
    else
        snprintf(real_path, sizeof(real_path), "%s", base_src);

    struct stat st;
    if (stat(real_path, &st) != 0) return false;
    if (S_ISREG(st.st_mode)) {
        const char* leaf = (sub && *sub) ? sub : strrchr(real_path,'/') + 1;
        char name[300];
        stored_name(name, sizeof(name), top, leaf);
        return zip_one_file(zip, real_path, name, deflate_on, root_crc,
                            root_sha, cd);
    }
    if (!S_ISDIR(st.st_mode)) return false;

    DIR* d = opendir(real_path);
    if (!d) return false;
    struct dirent* e;
    bool ok = true;
    bool empty = true;
    for (;;) {
        errno = 0;
        e = readdir(d);
        if (!e) { if (complete_tree && errno) ok = false; break; }
        if (e->d_name[0] == '.' &&
            (e->d_name[1] == '\0' ||
             (e->d_name[1] == '.' && e->d_name[2] == '\0'))) continue;
        empty = false;
        char next[400];
        if (sub && *sub) snprintf(next, sizeof(next), "%s/%s", sub, e->d_name);
        else             snprintf(next, sizeof(next), "%s", e->d_name);
        if (!walk(zip, base_src, top, next, deflate_on, root_crc, root_sha,
                  cd, complete_tree)) {
            ok = false; break;
        }
    }
    if (closedir(d) != 0 && complete_tree) ok = false;
    if (ok && empty && complete_tree && sub && *sub) {
        char name[300];
        stored_name(name, sizeof(name), top, sub);
        ok = zip_empty_directory(zip, name, cd);
    }
    return ok;
}

static bool flat_component(const char* name) {
    if (!name || !name[0] || !strcmp(name, ".") || !strcmp(name, "..")) return false;
    for (const unsigned char* p = (const unsigned char*)name; *p; p++)
        if (*p < 0x20 || *p == '/' || *p == '\\') return false;
    return true;
}

static bool selected_files_valid(const char* top, const char* const* names,
                                  size_t count) {
    if (!flat_component(top) || !names || !count || count > 64) return false;
    for (size_t i = 0; i < count; i++) {
        if (!names[i] || strnlen(names[i], 128) >= 128 ||
            !flat_component(names[i]) || strncmp(names[i], "sdimg_", 6) ||
            strlen(top) + strlen(names[i]) + 1 >= 300) return false;
        const char* slot = !strncmp(names[i], "sdimg_sce_bu_", 13) ? names[i] + 13 : names[i] + 6;
        if (!flat_component(slot) || strlen(slot) >= 64) return false;
        for (size_t j = 0; j < i; j++) if (!strcmp(names[i], names[j])) return false;
    }
    return true;
}

static bool write_selected_files(FILE* zip, const char* src, const char* top,
                                  const char* const* names, size_t count,
                                  bool deflate, uint32_t* crc, uint8_t sha[32],
                                  centraldir_t* cd, const char (*expected)[65]) {
    int dirfd = open(src, O_RDONLY | O_DIRECTORY | O_NOFOLLOW);
    if (dirfd < 0) return false;
    bool ok = true;
    for (size_t i = 0; i < count && ok; i++) {
        char path[600], stored[300];
        struct stat before, opened;
        int n = snprintf(path, sizeof(path), "%s/%s", src, names[i]);
        if (n < 0 || (size_t)n >= sizeof(path) || lstat(path, &before) != 0 ||
            !S_ISREG(before.st_mode)) { ok = false; break; }
        int fd = toston_openat(dirfd, names[i], O_RDONLY | O_NOFOLLOW | O_NONBLOCK, 0);
        if (fd < 0) { ok = false; break; }
        if (fstat(fd, &opened) != 0 || !S_ISREG(opened.st_mode) ||
            before.st_dev != opened.st_dev || before.st_ino != opened.st_ino ||
            before.st_size != opened.st_size) {
            close(fd); ok = false; break;
        }
        FILE* input = fdopen(fd, "rb");
        if (!input) { close(fd); ok = false; break; }
        snprintf(stored, sizeof(stored), "%s/%s", top, names[i]);
        ok = zip_file_stream(zip, input, stored, deflate, crc, sha, cd, &opened);
        if (ok && expected) ok = !strcmp(cd->items[cd->count - 1].content_sha256, expected[i]);
    }
    close(dirfd);
    return ok;
}

// --------------------------------------------------------------------
// Compress entry point.
// --------------------------------------------------------------------

bool zip_compress_directory(const char* src_dir,
                            const char* out_path,
                            bool        deflate,
                            uint32_t*   out_crc,
                            uint64_t*   out_size) {
    return zip_compress_directory_top(src_dir, NULL, out_path,
                                      deflate, out_crc, out_size);
}

static bool compress_top_impl(const char* src_dir,
                              const char* top_folder,
                              const char* out_path,
                              bool        deflate,
                              uint32_t*   out_crc,
                              uint64_t*   out_size,
                              const char* manifest_json,
                              char out_sha256[65], bool complete_tree,
                              const char* const* names, size_t count,
                              const char (*expected)[65]) {
    FILE* zip = NULL;
    if (names) {
        if (!src_dir || !out_path || !manifest_json || !manifest_json[0] ||
            strlen(manifest_json) >= 16384 || !out_sha256 ||
            !selected_files_valid(top_folder, names, count)) return false;
        int fd = open(out_path, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW, 0600);
        if (fd >= 0) { zip = fdopen(fd, "wb"); if (!zip) close(fd); }
    } else zip = fopen(out_path, "wb");
    if (!zip) return false;
    centraldir_t cd = {0};
    uint32_t root_crc = 0;
    uint8_t root_sha[32] = {0};
    bool written = names
        ? write_selected_files(zip, src_dir, top_folder, names, count, deflate,
                               &root_crc, root_sha, &cd, expected)
        : walk(zip, src_dir, top_folder, "", deflate, &root_crc,
                out_sha256 ? root_sha : NULL, &cd, complete_tree);
    if (!written) {
        fclose(zip); free(cd.items); if (!names) unlink(out_path); return false;
    }

    // SHA-enabled backups get per-file checksums from the same streaming pass
    // used to create the ZIP. This avoids rereading large save images.
    if (out_sha256) {
        char ctmp[320], cname[300];
        snprintf(ctmp, sizeof(ctmp), "%s.checksums.tmp", out_path);
        snprintf(cname, sizeof(cname), "%s%schecksums.json",
                 top_folder && top_folder[0] ? top_folder : "",
                 top_folder && top_folder[0] ? "/" : "");
        FILE* cf = fopen(ctmp, "wb");
        bool cok = cf && write_checksums(cf, &cd);
        if (cf && fclose(cf) != 0) cok = false;
        uint32_t dummy_crc = 0;
        if (!cok || !zip_one_file(zip, ctmp, cname, false, &dummy_crc,
                                  NULL, &cd)) {
            if (cf && !cok) log_warn("zip: could not write checksums.json");
            unlink(ctmp);
            fclose(zip); free(cd.items); if (!names) unlink(out_path); return false;
        }
        unlink(ctmp);
    }

    // Optional manifest.json. STORED (no deflate) and deliberately NOT folded
    // into root_crc, so the content fingerprint / dedup-by-hash stays stable
    // (the manifest carries a timestamp and would otherwise change every run).
    // Written through a temp file so it reuses the proven single-file writer.
    if (manifest_json && manifest_json[0]) {
        char mtmp[320];
        snprintf(mtmp, sizeof(mtmp), "%s.manifest.tmp", out_path);
        FILE* mf = fopen(mtmp, "wb");
        bool mok = false;
        if (mf) {
            size_t ml = strlen(manifest_json);
            mok = (fwrite(manifest_json, 1, ml, mf) == ml);
            if (fclose(mf) != 0) mok = false;
        }
        if (mok) {
            char mname[300];
            if (top_folder && top_folder[0])
                snprintf(mname, sizeof(mname), "%s/manifest.json", top_folder);
            else
                snprintf(mname, sizeof(mname), "manifest.json");
            uint32_t dummy_crc = 0;
            if (!zip_one_file(zip, mtmp, mname, false, &dummy_crc, NULL, &cd)) {
                log_warn("zip: could not add manifest.json to %s", out_path);
                mok = false;
            }
        }
        unlink(mtmp);
        if (names && !mok) {
            fclose(zip); free(cd.items); return false;
        }
    }

    // Central directory. Track every write from here on: a full USB or a
    // yanked drive must fail the backup, not silently produce a truncated
    // archive that reports success.
    bool werr = false;
    off_t cd_start = ftello(zip);
    for (size_t i = 0; i < cd.count; i++) {
        entry_t* e = &cd.items[i];
        bool need_orig = e->orig_size >= ZIP64_THRESHOLD;
        bool need_comp = e->comp_size >= ZIP64_THRESHOLD;
        bool need_off  = e->local_off >= ZIP64_THRESHOLD;
        bool z64 = need_orig || need_comp || need_off;
        uint16_t verneed = z64 ? 45 : 20;

        // ZIP64 extra holds, in fixed order, only the fields that overflow.
        unsigned char ex[28];
        size_t exn = 0;
        if (z64) {
            unsigned char d[24]; size_t dn = 0;
            if (need_orig) { put_u64(d + dn, e->orig_size); dn += 8; }
            if (need_comp) { put_u64(d + dn, e->comp_size); dn += 8; }
            if (need_off)  { put_u64(d + dn, e->local_off); dn += 8; }
            put_u16(ex + 0, 0x0001);
            put_u16(ex + 2, (uint16_t)dn);
            memcpy(ex + 4, d, dn);
            exn = 4 + dn;
        }

        unsigned char rec[46]; memset(rec, 0, sizeof(rec));
        put_u32(rec + 0, 0x02014b50);
        put_u16(rec + 4, verneed);       // version made by
        put_u16(rec + 6, verneed);       // version needed
        put_u16(rec + 8, e->flags);
        put_u16(rec + 10, e->method);
        put_u16(rec + 12, e->dt);
        put_u16(rec + 14, e->dd);
        put_u32(rec + 16, e->crc32);
        put_u32(rec + 20, need_comp ? 0xFFFFFFFF : (uint32_t)e->comp_size);
        put_u32(rec + 24, need_orig ? 0xFFFFFFFF : (uint32_t)e->orig_size);
        put_u16(rec + 28, e->name_len);
        put_u16(rec + 30, (uint16_t)exn);
        put_u32(rec + 42, need_off ? 0xFFFFFFFF : (uint32_t)e->local_off);
        if (fwrite(rec, 1, 46, zip) != 46) werr = true;
        if (fwrite(e->name, 1, e->name_len, zip) != e->name_len) werr = true;
        if (exn && fwrite(ex, 1, exn, zip) != exn) werr = true;
    }
    off_t cd_end  = ftello(zip);
    uint64_t cd_size = (uint64_t)(cd_end - cd_start);
    uint64_t cd_off  = (uint64_t)cd_start;
    uint64_t n_ent   = cd.count;

    // ZIP64 EOCD + locator when counts/sizes/offsets overflow the classic
    // 16/32-bit EOCD fields.
    bool need_z64_eocd = n_ent > 0xFFFF ||
                         cd_size >= ZIP64_THRESHOLD ||
                         cd_off  >= ZIP64_THRESHOLD;
    if (need_z64_eocd) {
        off_t z64_pos = ftello(zip);
        unsigned char z[56]; memset(z, 0, sizeof(z));
        put_u32(z + 0, 0x06064b50);
        put_u64(z + 4, 44);            // size of this record minus 12
        put_u16(z + 12, 45);           // version made by
        put_u16(z + 14, 45);           // version needed
        // disk numbers (16,20) = 0
        put_u64(z + 24, n_ent);        // entries on this disk
        put_u64(z + 32, n_ent);        // total entries
        put_u64(z + 40, cd_size);
        put_u64(z + 48, cd_off);
        if (fwrite(z, 1, 56, zip) != 56) werr = true;

        unsigned char loc[20]; memset(loc, 0, sizeof(loc));
        put_u32(loc + 0, 0x07064b50);
        put_u32(loc + 4, 0);                       // disk of zip64 eocd
        put_u64(loc + 8, (uint64_t)z64_pos);
        put_u32(loc + 16, 1);                      // total disks
        if (fwrite(loc, 1, 20, zip) != 20) werr = true;
    }

    // Classic EOCD (with sentinels where ZIP64 takes over).
    unsigned char eocd[22]; memset(eocd, 0, sizeof(eocd));
    put_u32(eocd + 0, 0x06054b50);
    put_u16(eocd + 8,  n_ent  > 0xFFFF       ? 0xFFFF     : (uint16_t)n_ent);
    put_u16(eocd + 10, n_ent  > 0xFFFF       ? 0xFFFF     : (uint16_t)n_ent);
    put_u32(eocd + 12, cd_size >= ZIP64_THRESHOLD ? 0xFFFFFFFF : (uint32_t)cd_size);
    put_u32(eocd + 16, cd_off  >= ZIP64_THRESHOLD ? 0xFFFFFFFF : (uint32_t)cd_off);
    if (fwrite(eocd, 1, 22, zip) != 22) werr = true;

    off_t final_size = ftello(zip);
    if (fflush(zip) != 0 || ferror(zip)) werr = true;
    if (fclose(zip) != 0) werr = true;
    free(cd.items);
    if (werr) {
        log_warn("zip: write error finishing %s (drive full or removed?) — %s", out_path,
                 names ? "partial export retained as evidence" : "discarding incomplete archive");
        if (!names) unlink(out_path);
        return false;
    }
    if (out_crc)  *out_crc  = root_crc;
    if (out_size) *out_size = (uint64_t)final_size;
    if (out_sha256) {
        static const char hex[] = "0123456789abcdef";
        for (size_t i = 0; i < sizeof(root_sha); i++) {
            out_sha256[i * 2] = hex[root_sha[i] >> 4];
            out_sha256[i * 2 + 1] = hex[root_sha[i] & 15];
        }
        out_sha256[64] = '\0';
    }
    return true;
}

bool zip_compress_directory_top(const char* src_dir, const char* top_folder,
                                const char* out_path, bool deflate,
                                uint32_t* out_crc, uint64_t* out_size) {
    return compress_top_impl(src_dir, top_folder, out_path, deflate,
                             out_crc, out_size, NULL, NULL, false, NULL, 0, NULL);
}

bool zip_compress_directory_top_manifest(const char* src_dir,
                                         const char* top_folder,
                                         const char* out_path, bool deflate,
                                         uint32_t* out_crc, uint64_t* out_size,
                                         const char* manifest_json) {
    return compress_top_impl(src_dir, top_folder, out_path, deflate,
                             out_crc, out_size, manifest_json, NULL, false, NULL, 0, NULL);
}

bool zip_compress_directory_top_manifest_sha256(
    const char* src_dir, const char* top_folder, const char* out_path,
    bool deflate, uint32_t* out_crc, uint64_t* out_size,
    const char* manifest_json, char out_sha256[65]) {
    return compress_top_impl(src_dir, top_folder, out_path, deflate,
                             out_crc, out_size, manifest_json, out_sha256, false, NULL, 0, NULL);
}

bool zip_compress_files_top_manifest_sha256(
    const char* src_dir, const char* top_folder, const char* out_path,
    const char* const* names, size_t count, bool deflate,
    uint32_t* out_crc, uint64_t* out_size, const char* manifest_json,
    char out_sha256[65], const char (*expected_sha256)[65]) {
    if (out_sha256) out_sha256[0] = '\0';
    if (!names || !count || count > 64) return false; // Never fall back to a whole-directory export.
    if (expected_sha256) for (size_t i = 0; i < count; i++) {
        if (expected_sha256[i][64] != '\0') return false;
        for (size_t j = 0; j < 64; j++)
            if (!((expected_sha256[i][j] >= '0' && expected_sha256[i][j] <= '9') ||
                  (expected_sha256[i][j] >= 'a' && expected_sha256[i][j] <= 'f'))) return false;
    }
    return compress_top_impl(src_dir, top_folder, out_path, deflate,
                             out_crc, out_size, manifest_json, out_sha256, false,
                             names, count, expected_sha256);
}

bool zip_compress_directory_complete(const char* src_dir, const char* out_path,
                                     uint32_t* out_crc, uint64_t* out_size) {
    return compress_top_impl(src_dir, NULL, out_path, false,
                             out_crc, out_size, NULL, NULL, true, NULL, 0, NULL);
}

// --------------------------------------------------------------------
// Extract. Supports STORE and full DEFLATE (stored/fixed/dynamic blocks via
// the vendored puff() inflate), 32-bit and ZIP64, with CRC32 verification.
// --------------------------------------------------------------------

// puff() is intentionally tiny but inflates from memory. Keep that path
// bounded; TostónSync's own stored-block DEFLATE is streamed below and therefore
// still supports multi-GB save images without a multi-GB allocation.
#define ZIP_INMEM_ENTRY_MAX  (64ULL * 1024ULL * 1024ULL)
#define ZIP_EXTRACT_TOTAL_MAX (8ULL * 1024ULL * 1024ULL * 1024ULL)
#define ZIP_ENTRY_COUNT_MAX  16384ULL
#define ZIP_EXTRACT_FREE_MARGIN (64ULL * 1024ULL * 1024ULL)

// Stream the BTYPE=00 flavor emitted by TostónSync. Every block starts on a
// byte boundary, so memory stays at 64 KB regardless of the save size.
static bool inflate_stored_blocks(FILE* in, uint64_t comp_size, FILE* out,
                                  uint64_t orig_size,
                                  uint32_t expected_crc) {
    unsigned char* buf = (unsigned char*)malloc(65536);
    if (!buf) return false;

    uint64_t consumed = 0, produced = 0;
    uint32_t cs = crc32_init();
    bool ok = true, final = false;
    while (ok && !final) {
        unsigned char h[5];
        if (comp_size - consumed < sizeof(h) ||
            fread(h, 1, sizeof(h), in) != sizeof(h)) {
            ok = false;
            break;
        }
        consumed += sizeof(h);
        // BFINAL is bit 0. BTYPE=00 and the byte-alignment padding must be 0.
        if ((h[0] & 0xfe) != 0) { ok = false; break; }
        final = (h[0] & 1) != 0;
        uint16_t len = rd_u16(h + 1);
        uint16_t nlen = rd_u16(h + 3);
        if ((uint16_t)(len ^ nlen) != 0xffffU ||
            (uint64_t)len > comp_size - consumed ||
            produced > orig_size || (uint64_t)len > orig_size - produced) {
            ok = false;
            break;
        }

        uint32_t left = len;
        while (left) {
            size_t chunk = left > 65536 ? 65536 : (size_t)left;
            if (fread(buf, 1, chunk, in) != chunk) { ok = false; break; }
            cs = crc32_update(cs, buf, chunk);
            if (fwrite(buf, 1, chunk, out) != chunk) { ok = false; break; }
            left -= (uint32_t)chunk;
            consumed += chunk;
            produced += chunk;
        }
    }
    free(buf);

    if (!ok || !final || consumed != comp_size || produced != orig_size)
        return false;
    if (crc32_finish(cs) != expected_crc) {
        log_warn("zip: CRC32 mismatch on streamed deflate entry");
        return false;
    }
    return true;
}

// Decompress a method-8 (DEFLATE) entry of `comp_size` bytes into `out`,
// expecting exactly `orig_size` bytes whose CRC32 is `expected_crc` (0 = skip
// CRC check). Reads the whole compressed entry and inflates it in memory with
// puff(), which handles stored, fixed-Huffman and dynamic-Huffman blocks —
// so this also covers TostónSync's own stored-block backups.
static bool inflate_deflate_memory(FILE* in, uint64_t comp_size, FILE* out,
                                   uint64_t orig_size,
                                   uint32_t expected_crc) {
    if (comp_size > ZIP_INMEM_ENTRY_MAX || orig_size > ZIP_INMEM_ENTRY_MAX) {
        log_warn("zip: compressed entry too large for bounded inflate "
                 "(comp=%llu orig=%llu; TostónSync stored-block ZIPs stream)",
                 (unsigned long long)comp_size, (unsigned long long)orig_size);
        return false;
    }

    unsigned char* cbuf = (unsigned char*)malloc(comp_size ? comp_size : 1);
    unsigned char* obuf = (unsigned char*)malloc(orig_size ? orig_size : 1);
    if (!cbuf || !obuf) { free(cbuf); free(obuf); return false; }

    bool ok = false;
    if (comp_size == 0 || fread(cbuf, 1, comp_size, in) == comp_size) {
        unsigned long destlen = (unsigned long)orig_size;
        unsigned long srclen  = (unsigned long)comp_size;
        int r = puff(obuf, &destlen, cbuf, &srclen);
        if (r != 0) {
            log_warn("zip: inflate failed (puff=%d)", r);
        } else if (destlen != orig_size || srclen != comp_size) {
            log_warn("zip: inflate size mismatch (got %lu, expected %llu)",
                     destlen, (unsigned long long)orig_size);
        } else if (crc32_buf(obuf, (size_t)orig_size) != expected_crc) {
            log_warn("zip: CRC32 mismatch after inflate — refusing entry");
        } else {
            ok = orig_size == 0 ||
                 fwrite(obuf, 1, (size_t)orig_size, out) == (size_t)orig_size;
        }
    }
    free(cbuf);
    free(obuf);
    return ok;
}

static bool inflate_deflate(FILE* in, uint64_t comp_size, FILE* out,
                            uint64_t orig_size, uint32_t expected_crc) {
    off_t in_start = ftello(in);
    off_t out_start = ftello(out);
    int first = fgetc(in);
    if (first == EOF || fseeko(in, in_start, SEEK_SET) != 0) return false;

    // TostónSync writes only stored blocks. Try that streaming path first when
    // the first block advertises BTYPE=00. A legal mixed stream falls back to
    // puff after rewinding, provided it fits the bounded in-memory path.
    if ((((unsigned int)first >> 1) & 3U) == 0) {
        if (inflate_stored_blocks(in, comp_size, out, orig_size, expected_crc))
            return true;
        if (fseeko(in, in_start, SEEK_SET) != 0 ||
            ftruncate(fileno(out), out_start) != 0 ||
            fseeko(out, out_start, SEEK_SET) != 0)
            return false;
    }
    return inflate_deflate_memory(in, comp_size, out, orig_size, expected_crc);
}

static bool zip_name_is_unsafe(const char* name) {
    if (!name || !name[0] || name[0] == '/') return true;
    for (const unsigned char* q = (const unsigned char*)name; *q; q++)
        if (*q < 0x20 || *q == '\\') return true;
    const char* p = name;
    while (*p) {
        while (*p == '/') p++;
        const char* slash = strchr(p, '/');
        size_t len = slash ? (size_t)(slash - p) : strlen(p);
        if ((len == 1 && p[0] == '.') ||
            (len == 2 && p[0] == '.' && p[1] == '.')) return true;
        if (!slash) break;
        p = slash + 1;
    }
    return false;
}

// Extraction is only into a fresh private staging directory. Walk relative to
// directory descriptors so a pre-existing/replaced symlink cannot redirect a
// member outside that directory. O_EXCL also rejects duplicate ZIP files and
// prevents overwriting an existing file or hard link.
static int zip_open_output(const char* dest_dir, const char* name, bool is_dir,
                           const char** failure) {
    *failure = "Could not open ZIP output staging folder";
    int parent = open(dest_dir, O_RDONLY | O_DIRECTORY | O_NOFOLLOW);
    if (parent < 0) return -1;
    char relative[260];
    snprintf(relative, sizeof(relative), "%s", name);
    char* state = NULL;
    char* component = strtok_r(relative, "/", &state);
    while (component) {
        char* next = strtok_r(NULL, "/", &state);
        int fd;
        if (next || is_dir) {
            if (toston_mkdirat(parent, component, 0700) != 0 && errno != EEXIST) {
                int saved = errno;
                close(parent);
                errno = saved;
                *failure = "Could not create ZIP output directory";
                return -1;
            }
            *failure = "Could not open ZIP output directory";
            fd = toston_openat(parent, component, O_RDONLY | O_DIRECTORY | O_NOFOLLOW, 0);
        } else {
            *failure = "Could not create ZIP output file";
            fd = toston_openat(parent, component,
                        O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW, 0600);
        }
        int saved = errno;
        close(parent);
        if (fd < 0) { errno = saved; return -1; }
        parent = fd;
        component = next;
    }
    return parent;
}

// Cheap post-backup sanity check: open the finished archive, find the EOCD and
// return the central-directory entry count (>=0), or -1 when the file isn't a
// readable ZIP. No extraction, so it's safe to run after every backup.
int zip_entry_count(const char* zip_path) {
    FILE* zip = fopen(zip_path, "rb");
    if (!zip) return -1;
    fseeko(zip, 0, SEEK_END);
    off_t total = ftello(zip);
    if (total < 22) { fclose(zip); return -1; }
    enum { TAIL_CAP = 66000 };
    unsigned char* tail = (unsigned char*)malloc(TAIL_CAP);
    if (!tail) { fclose(zip); return -1; }
    off_t scan_len = total > (off_t)TAIL_CAP ? (off_t)TAIL_CAP : total;
    fseeko(zip, total - scan_len, SEEK_SET);
    if (fread(tail, 1, (size_t)scan_len, zip) != (size_t)scan_len) {
        free(tail); fclose(zip); return -1;
    }
    off_t eocd = -1;
    for (off_t i = scan_len - 22; i >= 0; i--) {
        if (tail[i] == 0x50 && tail[i+1] == 0x4b
         && tail[i+2] == 0x05 && tail[i+3] == 0x06) {
            eocd = total - scan_len + i; break;
        }
    }
    int count = -1;
    if (eocd >= 0) {
        unsigned char eo[22];
        fseeko(zip, eocd, SEEK_SET);
        if (fread(eo, 1, 22, zip) == 22) {
            uint64_t n = rd_u16(eo + 10);
            if (n == 0xFFFF && eocd >= 20) {           // ZIP64
                unsigned char loc[20];
                fseeko(zip, eocd - 20, SEEK_SET);
                if (fread(loc, 1, 20, zip) == 20 && rd_u32(loc) == 0x07064b50) {
                    off_t z64 = (off_t)rd_u64(loc + 8);
                    unsigned char z[56];
                    fseeko(zip, z64, SEEK_SET);
                    if (fread(z, 1, 56, zip) == 56 && rd_u32(z) == 0x06064b50)
                        n = rd_u64(z + 32);
                }
            }
            if (n <= ZIP_ENTRY_COUNT_MAX) count = (int)n;
        }
    }
    free(tail);
    fclose(zip);
    return count;
}

static bool zip_extraction_failure(FILE* zip, char* detail, size_t detail_sz,
                                   const char* reason, int io_error) {
    if (detail && detail_sz) {
        if (io_error)
            snprintf(detail, detail_sz, "%s (errno %d: %s)",
                     reason, io_error, strerror(io_error));
        else snprintf(detail, detail_sz, "%s", reason);
    }
    if (io_error) log_warn("zip: %s (errno %d: %s)", reason, io_error,
                            strerror(io_error));
    else log_warn("zip: %s", reason);
    if (zip) fclose(zip);
    return false;
}

bool zip_extract_to_directory_checked(const char* zip_path, const char* dest_dir,
                                      char* detail, size_t detail_sz) {
    if (detail && detail_sz) detail[0] = '\0';
#define ZIP_FAIL(message, code) \
    return zip_extraction_failure(zip, detail, detail_sz, (message), (code))
    FILE* zip = fopen(zip_path, "rb");
    if (!zip) { ZIP_FAIL("Could not open ZIP file", errno); }
    if (fseeko(zip, 0, SEEK_END) != 0) { ZIP_FAIL("Could not read ZIP footer", errno); }
    off_t total = ftello(zip);
    if (total < 0) { ZIP_FAIL("Could not read ZIP footer", errno); }

    // Find EOCD by scanning backwards.
    if (total < 22) { ZIP_FAIL("ZIP footer is missing or truncated", 0); }
    // 64 KB+ scan window on the heap, not the stack: the extractor runs on the
    // worker and must not park a buffer this large on the thread stack.
    enum { TAIL_CAP = 66000 };
    unsigned char* tail = (unsigned char*)malloc(TAIL_CAP);
    if (!tail) { ZIP_FAIL("Not enough memory to inspect ZIP footer", ENOMEM); }
    off_t scan_len = total > (off_t)TAIL_CAP ? (off_t)TAIL_CAP : total;
    if (fseeko(zip, total - scan_len, SEEK_SET) != 0) {
        free(tail); ZIP_FAIL("Could not read ZIP footer", errno);
    }
    if (fread(tail, 1, (size_t)scan_len, zip) != (size_t)scan_len) {
        free(tail); ZIP_FAIL("Could not read ZIP footer", ferror(zip) ? errno : 0);
    }
    off_t eocd = -1;
    for (off_t i = scan_len - 22; i >= 0; i--) {
        if (tail[i] == 0x50 && tail[i+1] == 0x4b
         && tail[i+2] == 0x05 && tail[i+3] == 0x06) {
            eocd = total - scan_len + i; break;
        }
    }
    free(tail);
    if (eocd < 0) { ZIP_FAIL("ZIP footer is missing or truncated", 0); }
    unsigned char eo[22];
    if (fseeko(zip, eocd, SEEK_SET) != 0 || fread(eo, 1, 22, zip) != 22) {
        ZIP_FAIL("Could not read ZIP footer", ferror(zip) ? errno : 0);
    }
    uint64_t n      = rd_u16(eo + 10);
    uint64_t cd_off = rd_u32(eo + 16);

    // If the classic fields are saturated, consult the ZIP64 EOCD via its
    // locator, which sits immediately before the EOCD.
    if ((rd_u16(eo + 10) == 0xFFFF) || (rd_u32(eo + 16) == 0xFFFFFFFF)) {
        if (eocd >= 20) {
            unsigned char loc[20];
            fseeko(zip, eocd - 20, SEEK_SET);
            if (fread(loc, 1, 20, zip) == 20 && rd_u32(loc) == 0x07064b50) {
                off_t z64_pos = (off_t)rd_u64(loc + 8);
                unsigned char z[56];
                fseeko(zip, z64_pos, SEEK_SET);
                if (fread(z, 1, 56, zip) == 56 && rd_u32(z) == 0x06064b50) {
                    n      = rd_u64(z + 32);
                    cd_off = rd_u64(z + 48);
                }
            }
        }
    }

    if (n > ZIP_ENTRY_COUNT_MAX || cd_off >= (uint64_t)total) {
        log_warn("zip: archive limits exceeded (entries=%llu cd=%llu)",
                 (unsigned long long)n, (unsigned long long)cd_off);
        ZIP_FAIL("ZIP archive exceeds entry or size limits", 0);
    }

    uint64_t extracted_total = 0;
    if (fseeko(zip, (off_t)cd_off, SEEK_SET) != 0) {
        ZIP_FAIL("Could not read ZIP central directory", errno);
    }
    for (uint64_t i = 0; i < n; i++) {
        unsigned char rec[46];
        if (fread(rec, 1, 46, zip) != 46 || rd_u32(rec) != 0x02014b50) {
            ZIP_FAIL("ZIP central directory is missing or truncated", ferror(zip) ? errno : 0);
        }
        uint16_t method   = rd_u16(rec + 10);
        uint32_t crc      = rd_u32(rec + 16);
        uint32_t comp32   = rd_u32(rec + 20);
        uint32_t orig32   = rd_u32(rec + 24);
        uint16_t name_len = rd_u16(rec + 28);
        uint16_t extra    = rd_u16(rec + 30);
        uint16_t cmt      = rd_u16(rec + 32);
        uint32_t local32  = rd_u32(rec + 42);
        uint16_t flags    = rd_u16(rec + 8);

        if (flags & 1) {
            log_warn("zip: encrypted entries are not supported");
            ZIP_FAIL("Encrypted ZIP entries are not supported", 0);
        }

        if (name_len >= 260) {
            log_warn("zip: refusing overlong entry name (%u bytes)", name_len);
            ZIP_FAIL("ZIP entry name exceeds the supported length", 0);
        }

        char name[260] = {0};
        uint16_t copy_n = name_len;
        if (fread(name, 1, copy_n, zip) != copy_n) {
            ZIP_FAIL("ZIP central directory is missing or truncated", ferror(zip) ? errno : 0);
        }
        if (memchr(name, '\0', copy_n) != NULL) {
            log_warn("zip: embedded NUL in entry name");
            ZIP_FAIL("ZIP entry path or file type is unsafe", 0);
        }

        // Read the extra field block and resolve any ZIP64 overrides. We
        // don't need the uncompressed size to extract (stored blocks are
        // self-delimiting and method-0 uses the compressed size), so the
        // ZIP64 "original size" slot is consumed for ordering but skipped.
        uint64_t comp_sz = comp32, orig_sz = orig32, local = local32;
        unsigned char xbuf[1024];
        uint16_t xread = extra > sizeof(xbuf) ? sizeof(xbuf) : extra;
        if (xread && fread(xbuf, 1, xread, zip) != xread) {
            ZIP_FAIL("ZIP central directory is missing or truncated", ferror(zip) ? errno : 0);
        }
        if ((extra > xread && fseeko(zip, extra - xread, SEEK_CUR) != 0) ||
            (cmt && fseeko(zip, cmt, SEEK_CUR) != 0)) {
            ZIP_FAIL("Could not read ZIP central directory", errno);
        }

        for (size_t o = 0; o + 4 <= xread; ) {
            uint16_t tag = rd_u16(xbuf + o);
            uint16_t sz  = rd_u16(xbuf + o + 2);
            if ((size_t)o + 4 + sz > xread) break;
            if (tag == 0x0001) {
                size_t d = o + 4, lim = o + 4 + sz;
                if (orig32 == 0xFFFFFFFF && d + 8 <= lim) { orig_sz = rd_u64(xbuf + d); d += 8; }
                if (comp32 == 0xFFFFFFFF && d + 8 <= lim) { comp_sz = rd_u64(xbuf + d); d += 8; }
                if (local32 == 0xFFFFFFFF && d + 8 <= lim) local = rd_u64(xbuf + d);
                break;
            }
            o += 4 + sz;
        }

        off_t after_cd = ftello(zip);

        if (orig_sz > ZIP_EXTRACT_TOTAL_MAX - extracted_total) {
            log_warn("zip: extracted data exceeds %llu-byte safety cap",
                     (unsigned long long)ZIP_EXTRACT_TOTAL_MAX);
            ZIP_FAIL("ZIP archive exceeds entry or size limits", 0);
        }
        extracted_total += orig_sz;

        // Reject path traversal: an absolute path or any ".." component
        // could otherwise let a crafted archive write outside dest_dir.
        if (zip_name_is_unsafe(name)) {
            log_warn("zip: refusing unsafe entry name '%s'", name);
            ZIP_FAIL("ZIP entry path or file type is unsafe", 0);
        }
        bool is_dir = name[copy_n - 1] == '/';
        // UNIX and macOS ZIP attributes can describe symlinks or other special
        // files. Save archives may contain regular files/directories only.
        unsigned int creator = rec[5];
        unsigned int type = (rd_u32(rec + 38) >> 16) & S_IFMT;
        if ((creator == 3 || creator == 19) && type != 0 &&
            type != (unsigned int)(is_dir ? S_IFDIR : S_IFREG)) {
            log_warn("zip: refusing special or inconsistent entry '%s'", name);
            ZIP_FAIL("ZIP entry path or file type is unsafe", 0);
        }
        // Directory entries carry no save data.
        if (is_dir) {
            const char* reason;
            int fd = zip_open_output(dest_dir, name, true, &reason);
            if (fd < 0) { ZIP_FAIL(reason, errno); }
            if (close(fd) != 0) { ZIP_FAIL("Could not close ZIP output directory", errno); }
            if (fseeko(zip, after_cd, SEEK_SET) != 0) {
                ZIP_FAIL("Could not read ZIP central directory", errno);
            }
            continue;
        }

        // Seek to local file header, skip its (possibly ZIP64) name+extra.
        if (local >= (uint64_t)total ||
            fseeko(zip, (off_t)local, SEEK_SET) != 0) {
            ZIP_FAIL("ZIP local entry header is missing or truncated", 0);
        }
        unsigned char lfh[30];
        if (fread(lfh, 1, 30, zip) != 30 || rd_u32(lfh) != 0x04034b50) {
            ZIP_FAIL("ZIP local entry header is missing or truncated", ferror(zip) ? errno : 0);
        }
        uint16_t lf_nlen = rd_u16(lfh + 26);
        uint16_t lf_xlen = rd_u16(lfh + 28);
        if (rd_u16(lfh + 8) != method ||
            fseeko(zip, lf_nlen + lf_xlen, SEEK_CUR) != 0) {
            ZIP_FAIL("ZIP local entry header does not match its directory", 0);
        }
        off_t data_pos = ftello(zip);
        if (data_pos < 0 || comp_sz > (uint64_t)total - (uint64_t)data_pos) {
            ZIP_FAIL("ZIP entry data is missing or truncated", 0);
        }

        // A highly-compressed archive may be much larger after extraction.
        // Check the target filesystem before every entry and retain headroom
        // so an import cannot fill USB or /data to the last block.
        struct statvfs sv;
        if (statvfs(dest_dir, &sv) == 0) {
            uint64_t avail = (uint64_t)sv.f_bavail * (uint64_t)sv.f_frsize;
            if (orig_sz > avail || avail - orig_sz < ZIP_EXTRACT_FREE_MARGIN) {
                log_warn("zip: not enough free space for entry '%s' (%llu bytes)",
                         name, (unsigned long long)orig_sz);
                ZIP_FAIL("Not enough free space to extract ZIP entry", 0);
            }
        }

        const char* reason;
        int out_fd = zip_open_output(dest_dir, name, false, &reason);
        if (out_fd < 0) {
            ZIP_FAIL(reason, errno);
        }
        FILE* out = fdopen(out_fd, "wb");
        if (!out) {
            int saved = errno; close(out_fd);
            ZIP_FAIL("Could not open ZIP output stream", saved);
        }
        bool ok;
        const char* entry_failure = "Could not read or write ZIP entry";
        errno = 0;
        if (method == 0) {
            if (orig_sz != comp_sz) {
                fclose(out); ZIP_FAIL("ZIP stored entry size does not match its directory", 0);
            }
            // STORE: copy bytes through, verifying CRC32 as we stream.
            unsigned char* cbuf = (unsigned char*)malloc(65536);
            if (!cbuf) { ok = false; }
            else {
                uint64_t left = comp_sz;
                uint32_t cs = crc32_init();
                ok = true;
                while (left) {
                    size_t want = left > 65536 ? 65536 : (size_t)left;
                    if (fread(cbuf, 1, want, zip) != want) { ok = false; break; }
                    cs = crc32_update(cs, cbuf, want);
                    if (fwrite(cbuf, 1, want, out) != want) { ok = false; break; }
                    left -= want;
                }
                free(cbuf);
                if (ok && crc32_finish(cs) != crc) {
                    log_warn("zip: CRC32 mismatch on stored entry — refusing");
                    entry_failure = "ZIP entry checksum verification failed";
                    ok = false;
                }
            }
        } else if (method == 8) {
            ok = inflate_deflate(zip, comp_sz, out, orig_sz, crc);
            if (!ok && !ferror(zip) && !ferror(out))
                entry_failure = "ZIP entry decompression or checksum verification failed";
        } else {
            log_warn("zip: unsupported compression method %u", method);
            ok = false;
            entry_failure = "ZIP compression method is not supported";
        }
        int io_error = !ok && (ferror(zip) || ferror(out)) ? errno : 0;
        if (fclose(out) != 0) {
            ok = false; io_error = errno;
            entry_failure = "Could not close ZIP output file";
        }
        if (!ok) { ZIP_FAIL(entry_failure, io_error); }

        if (fseeko(zip, after_cd, SEEK_SET) != 0) {
            ZIP_FAIL("Could not read ZIP central directory", errno);
        }
    }
    if (fclose(zip) != 0) {
        zip = NULL; ZIP_FAIL("Could not close ZIP input file", errno);
    }
#undef ZIP_FAIL
    return true;
}

bool zip_extract_to_directory(const char* zip_path, const char* dest_dir) {
    return zip_extract_to_directory_checked(zip_path, dest_dir, NULL, 0);
}
