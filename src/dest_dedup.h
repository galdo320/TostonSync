#ifndef TOSTONSYNC_DEST_DEDUP_H
#define TOSTONSYNC_DEST_DEDUP_H

#include <stdbool.h>
#include <stdio.h>
#include <stdint.h>
#include <inttypes.h>
#include <string.h>
#include "sha256.h"

typedef struct {
    char identity[65];
    char sha256[65];
    char ref[128];
    uint64_t size_bytes;
} dest_fingerprint_t;

// Hash only non-secret provider identity fields. Length prefixes keep field
// boundaries unambiguous ("ab", "c" must differ from "a", "bc").
static inline bool dest_identity_hash(const char* const* parts, size_t count,
                                      char out[65]) {
    if (!out) return false;
    out[0] = '\0';
    if (!parts || !count) return false;
    sha256_ctx_t ctx;
    sha256_init(&ctx);
    for (size_t i = 0; i < count; i++) {
        if (!parts[i]) return false;
        size_t n = strlen(parts[i]);
        uint64_t length = (uint64_t)n;
        unsigned char prefix[8];
        for (int j = 7; j >= 0; j--) { prefix[j] = length & 255; length >>= 8; }
        sha256_update(&ctx, prefix, sizeof(prefix));
        sha256_update(&ctx, parts[i], n);
    }
    unsigned char digest[32];
    sha256_final(&ctx, digest);
    for (size_t i = 0; i < sizeof(digest); i++)
        snprintf(out + i * 2, 3, "%02x", digest[i]);
    return true;
}

static inline bool dest_fingerprint_hex(const char* value) {
    if (!value) return false;
    for (size_t i = 0; i < 64; i++)
        if (!((value[i] >= '0' && value[i] <= '9') ||
              (value[i] >= 'a' && value[i] <= 'f'))) return false;
    return value[64] == '\0';
}

// A receipt points to one archive filename or provider ID, never a path.
static inline bool dest_fingerprint_ref_bytes(const char* ref, size_t n) {
    if (!ref || !n || n >= sizeof(((dest_fingerprint_t*)0)->ref) ||
        (n == 1 && ref[0] == '.') || (n == 2 && !memcmp(ref, "..", 2))) return false;
    for (size_t i = 0; i < n;) {
        unsigned char c = (unsigned char)ref[i];
        size_t width = c < 0x80 ? 1 : c >= 0xc2 && c <= 0xdf ? 2 :
            c >= 0xe0 && c <= 0xef ? 3 : c >= 0xf0 && c <= 0xf4 ? 4 : 0;
        if (!width || width > n - i) return false;
        uint32_t cp = c & (width == 1 ? 0x7f : width == 2 ? 0x1f : width == 3 ? 0x0f : 7);
        for (size_t j = 1; j < width; j++) {
            unsigned char next = (unsigned char)ref[i + j];
            if ((next & 0xc0) != 0x80) return false;
            cp = (cp << 6) | (next & 0x3f);
        }
        if ((width == 2 && cp < 0x80) || (width == 3 && cp < 0x800) ||
            (width == 4 && cp < 0x10000) || cp > 0x10ffff ||
            (cp >= 0xd800 && cp <= 0xdfff) || cp < 0x20 ||
            (cp >= 0x7f && cp <= 0x9f) ||
            (cp < 0x80 && strchr("\\/:*?\"<>|", (int)cp))) return false;
        i += width;
    }
    return true;
}

static inline bool dest_fingerprint_ref(const char* ref) {
    return ref && dest_fingerprint_ref_bytes(ref, strnlen(ref, 128));
}

// Failed automatic copies wait between attempts; the worker never sleeps
// here, so a disconnected destination cannot hold up a restore.
static inline unsigned dest_retry_delay_seconds(unsigned failures) {
    return failures >= 5 ? 300U : 30U << (failures ? failures - 1 : 0);
}

static inline bool dest_retry_due(int64_t retry_at, unsigned pending,
                                  unsigned available, int64_t now) {
    return retry_at > 0 && now >= retry_at && (pending & available) != 0;
}

static inline int dest_fingerprint_index(const char* dest) {
    if (dest && strcmp(dest, "usb") == 0) return 0;
    if (dest && strcmp(dest, "drive") == 0) return 1;
    // Index 2 is retired FTP. Never reassign the persisted slot.
    return -1;
}

static inline bool dest_fingerprint_matches(const dest_fingerprint_t* state,
                                            const char* identity,
                                            const char sha256[65],
                                            bool force, bool dedup) {
    return !force && dedup && state && dest_fingerprint_hex(identity) &&
           dest_fingerprint_hex(sha256) && dest_fingerprint_ref(state->ref) &&
           state->size_bytes > 0 &&
           strcmp(state->identity, identity) == 0 &&
           strcmp(state->sha256, sha256) == 0;
}

static inline bool dest_fingerprint_record(dest_fingerprint_t* state,
                                           const char* identity,
                                           const char sha256[65],
                                           const char* ref, uint64_t size_bytes,
                                           bool copy_succeeded) {
    if (!state || !copy_succeeded || !dest_fingerprint_hex(identity) ||
        !dest_fingerprint_hex(sha256) || !dest_fingerprint_ref(ref) ||
        !size_bytes) return false;
    dest_fingerprint_t next = {0};
    memcpy(next.identity, identity, 65);
    memcpy(next.sha256, sha256, 65);
    memcpy(next.ref, ref, strlen(ref) + 1);
    next.size_bytes = size_bytes;
    *state = next;
    return true;
}

static inline bool dest_fingerprint_checksum(const dest_fingerprint_t* state,
                                              char out[65]) {
    if (!state || !dest_fingerprint_hex(state->identity) ||
        !dest_fingerprint_hex(state->sha256) ||
        !dest_fingerprint_ref(state->ref) || !state->size_bytes) return false;
    char size[21];
    snprintf(size, sizeof(size), "%" PRIu64, state->size_bytes);
    const char* parts[] = {"v3", state->identity, state->sha256, state->ref, size};
    return dest_identity_hash(parts, sizeof(parts) / sizeof(parts[0]), out);
}

// v1/v2 entries lack an archive reference and cannot confirm its presence.
// Accept one bounded, canonical, checksummed line; any failure clears out.
static inline bool dest_fingerprint_read(FILE* f, dest_fingerprint_t* out) {
    if (!out) return false;
    memset(out, 0, sizeof(*out));
    if (!f) return false;
    char line[348], checksum[65];
    size_t length = fread(line, 1, sizeof(line), f);
    if (ferror(f) || length < 202 || length == sizeof(line) ||
        memchr(line, '\0', length) || line[length - 1] != '\n' ||
        memcmp(line, "v3 ", 3) || line[67] != ' ' || line[132] != ' ')
        return false;
    line[length - 1] = line[67] = line[132] = '\0';
    char* ref = line + 133;
    // v3 references can contain spaces; only the final two fields delimit them.
    char* digest = strrchr(ref, ' ');
    if (!digest) return false;
    *digest++ = '\0';
    char* size = strrchr(ref, ' ');
    if (!size) return false;
    *size++ = '\0';
    if (!dest_fingerprint_hex(digest) || size[0] < '1' || size[0] > '9')
        return false;
    uint64_t size_bytes = 0;
    for (const char* p = size; *p; p++) {
        if (*p < '0' || *p > '9' || size_bytes > (UINT64_MAX - (*p - '0')) / 10)
            return false;
        size_bytes = size_bytes * 10 + (*p - '0');
    }
    dest_fingerprint_t next = {0};
    if (!dest_fingerprint_record(&next, line + 3, line + 68, ref, size_bytes, true) ||
        !dest_fingerprint_checksum(&next, checksum) || strcmp(digest, checksum))
        return false;
    *out = next;
    return true;
}

static inline bool dest_fingerprint_write(FILE* f,
                                          const dest_fingerprint_t* state) {
    char checksum[65];
    return f && dest_fingerprint_checksum(state, checksum) &&
           fprintf(f, "v3 %s %s %s %" PRIu64 " %s\n", state->identity,
                   state->sha256, state->ref, state->size_bytes, checksum) > 0;
}

#endif
