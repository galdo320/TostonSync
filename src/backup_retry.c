#define _DEFAULT_SOURCE 1
#define _DARWIN_C_SOURCE 1

#include "backup_retry.h"
#include "dest_dedup.h"

#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <limits.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <unistd.h>

#define RETRY_TEXT_MAX 1024

static bool optional_hash(const char value[65]) {
    return memchr(value, '\0', 65) &&
           (!value[0] || dest_fingerprint_hex(value));
}

static bool valid_state(const backup_retry_t* s) {
    if (!s || s->planned_mask > 7 || s->pending_mask > 7 ||
        (s->pending_mask & ~s->planned_mask) || (!s->active && s->pending_mask) ||
        (s->usb_no_replay && (s->pending_mask & 1U)) ||
        s->failures > 5 ||
        s->retry_at < 0 || s->dirty_unix < 0 || s->last_upload_unix < 0 ||
        !memchr(s->user_uid, '\0', sizeof(s->user_uid)) ||
        !memchr(s->title_id, '\0', sizeof(s->title_id)) ||
        !memchr(s->reason, '\0', sizeof(s->reason)) ||
        strlen(s->user_uid) != 8 || strlen(s->title_id) != 9 ||
        (strncmp(s->title_id, "CUSA", 4) && strncmp(s->title_id, "PPSA", 4)) ||
        !optional_hash(s->fingerprint)) return false;
    for (size_t i = 0; i < 8; i++)
        if (!((s->user_uid[i] >= '0' && s->user_uid[i] <= '9') ||
              (s->user_uid[i] >= 'a' && s->user_uid[i] <= 'f') ||
              (s->user_uid[i] >= 'A' && s->user_uid[i] <= 'F'))) return false;
    for (size_t i = 4; i < 9; i++)
        if (s->title_id[i] < '0' || s->title_id[i] > '9') return false;
    for (int i = 0; i < 3; i++)
        if (!optional_hash(s->completed_identity[i]) ||
            (!s->fingerprint[0] && s->completed_identity[i][0])) return false;
    const char* reasons[] = {"Auto", "Live", "GameClose", "Shutdown", "Idle",
                             "Interval", "Manual"};
    for (size_t i = 0; i < sizeof(reasons) / sizeof(reasons[0]); i++)
        if (!strcmp(s->reason, reasons[i])) return true;
    return false;
}

static size_t encode(char out[RETRY_TEXT_MAX], const backup_retry_t* s) {
    if (!valid_state(s)) return 0;
    int n = snprintf(out, RETRY_TEXT_MAX,
        "version=%u\nactive=%u\nplanned_mask=%u\npending_mask=%u\nfailures=%u\n"
        "retry_at=%" PRId64 "\ndirty_unix=%" PRId64 "\nlast_upload_unix=%" PRId64 "\n"
        "user_uid=%s\ntitle_id=%s\nreason=%s\nfingerprint=%s\n"
        "completed_usb=%s\ncompleted_drive=%s\ncompleted_ftp=%s\n%s%s",
        s->cancel_guard ? 3U : s->usb_no_replay ? 2U : 1U, (unsigned)s->active, s->planned_mask, s->pending_mask, s->failures,
        s->retry_at, s->dirty_unix, s->last_upload_unix,
        s->user_uid, s->title_id, s->reason, s->fingerprint,
        s->completed_identity[0], s->completed_identity[1],
        s->completed_identity[2], s->usb_no_replay ? "usb_no_replay=1\n" : s->cancel_guard ? "usb_no_replay=0\n" : "",
        s->cancel_guard ? "cancel_guard=1\n" : "");
    return n > 0 && n < RETRY_TEXT_MAX ? (size_t)n : 0;
}

static void digest_hex(const char* data, size_t length, char out[65]) {
    sha256_ctx_t ctx;
    unsigned char digest[32];
    sha256_init(&ctx);
    sha256_update(&ctx, data, length);
    sha256_final(&ctx, digest);
    for (size_t i = 0; i < sizeof(digest); i++)
        snprintf(out + i * 2, 3, "%02x", digest[i]);
}

static bool take_field(char** cursor, const char* key, char* out, size_t cap) {
    size_t key_len = strlen(key);
    if (strncmp(*cursor, key, key_len)) return false;
    char* value = *cursor + key_len;
    char* end = strchr(value, '\n');
    if (!end || (size_t)(end - value) >= cap) return false;
    memcpy(out, value, (size_t)(end - value));
    out[end - value] = '\0';
    *cursor = end + 1;
    return true;
}

static bool take_number(char** cursor, const char* key, uint64_t max,
                         uint64_t* out) {
    char value[24];
    if (!take_field(cursor, key, value, sizeof(value)) || !value[0] ||
        (value[0] == '0' && value[1])) return false;
    uint64_t result = 0;
    for (const char* p = value; *p; p++) {
        if (*p < '0' || *p > '9' || (uint64_t)(*p - '0') > max ||
            result > (max - (uint64_t)(*p - '0')) / 10) return false;
        result = result * 10 + (uint64_t)(*p - '0');
    }
    *out = result;
    return true;
}

bool backup_retry_read(const char* path, backup_retry_t* out) {
    if (!out) return false;
    memset(out, 0, sizeof(*out));
    if (!path || !path[0]) return false;
    int fd = open(path, O_RDONLY | O_NOFOLLOW | O_NONBLOCK);
    if (fd < 0) return false;
    struct stat st;
    if (fstat(fd, &st) || !S_ISREG(st.st_mode) || st.st_size <= 0 ||
        st.st_size >= RETRY_TEXT_MAX) { close(fd); return false; }
    FILE* f = fdopen(fd, "rb");
    if (!f) { close(fd); return false; }
    char text[RETRY_TEXT_MAX], digest[65], recorded[65];
    size_t n = fread(text, 1, sizeof(text), f);
    bool ok = !ferror(f) && n < sizeof(text) && n > 74;
    if (fclose(f)) ok = false;
    if (!ok || memchr(text, '\0', n) ||
        memcmp(text + n - 74, "checksum=", 9) || text[n - 1] != '\n') return false;
    memcpy(recorded, text + n - 65, 64); recorded[64] = '\0';
    digest_hex(text, n - 74, digest);
    if (!dest_fingerprint_hex(recorded) || strcmp(recorded, digest)) return false;
    text[n - 74] = '\0';
    bool v3 = !strncmp(text, "version=3\n", 10);
    bool v2 = !strncmp(text, "version=2\n", 10);
    if (!v3 && !v2 && strncmp(text, "version=1\n", 10)) return false;
    char* cursor = text + 10;
    backup_retry_t s = {0};
    uint64_t active, planned, pending, failures, retry, dirty, uploaded;
    if (!take_number(&cursor, "active=", 1, &active) ||
        !take_number(&cursor, "planned_mask=", 7, &planned) ||
        !take_number(&cursor, "pending_mask=", 7, &pending) ||
        !take_number(&cursor, "failures=", 5, &failures) ||
        !take_number(&cursor, "retry_at=", INT64_MAX, &retry) ||
        !take_number(&cursor, "dirty_unix=", INT64_MAX, &dirty) ||
        !take_number(&cursor, "last_upload_unix=", INT64_MAX, &uploaded) ||
        !take_field(&cursor, "user_uid=", s.user_uid, sizeof(s.user_uid)) ||
        !take_field(&cursor, "title_id=", s.title_id, sizeof(s.title_id)) ||
        !take_field(&cursor, "reason=", s.reason, sizeof(s.reason)) ||
        !take_field(&cursor, "fingerprint=", s.fingerprint, sizeof(s.fingerprint)) ||
        !take_field(&cursor, "completed_usb=", s.completed_identity[0], 65) ||
        !take_field(&cursor, "completed_drive=", s.completed_identity[1], 65) ||
        !take_field(&cursor, "completed_ftp=", s.completed_identity[2], 65)) return false;
    uint64_t no_replay = 0;
    if ((v2||v3) && (!take_number(&cursor, "usb_no_replay=", 1, &no_replay) ||
               (v2 && no_replay != 1))) return false;
    uint64_t guard=0;
    if(v3 && (!take_number(&cursor,"cancel_guard=",1,&guard)||guard!=1))return false;
    s.cancel_guard=guard!=0;
    if (*cursor) return false;
    s.usb_no_replay = no_replay != 0;
    s.active = active != 0;
    s.planned_mask = (unsigned)planned; s.pending_mask = (unsigned)pending;
    s.failures = (unsigned)failures; s.retry_at = (int64_t)retry;
    s.dirty_unix = (int64_t)dirty; s.last_upload_unix = (int64_t)uploaded;
    if (!valid_state(&s)) return false;
    // Validate the original bytes first; only scheduling for retired FTP changes.
    s.retired_ftp = ((s.planned_mask | s.pending_mask) & 4U) != 0;
    s.planned_mask &= 3U;
    s.pending_mask &= 3U;
    if (s.retired_ftp && !s.planned_mask) s.active = false;
    *out = s;
    return true;
}

static bool regular_or_missing(const char* path) {
    struct stat st;
    return lstat(path, &st) == 0 ? S_ISREG(st.st_mode) : errno == ENOENT;
}

bool backup_retry_write(const char* path, const backup_retry_t* state) {
    char text[RETRY_TEXT_MAX], digest[65], temp[PATH_MAX], parent[PATH_MAX];
    size_t length = encode(text, state);
    if (!length || !path || !path[0] || !regular_or_missing(path)) return false;
    int n = snprintf(temp, sizeof(temp), "%s.tmp.XXXXXX", path);
    if (n < 0 || (size_t)n >= sizeof(temp)) return false;
    const char* slash = strrchr(path, '/');
    if (slash && !slash[1]) return false;
    size_t parent_len = slash ? (size_t)(slash - path) : 0;
    if (parent_len >= sizeof(parent)) return false;
    if (parent_len) { memcpy(parent, path, parent_len); parent[parent_len] = '\0'; }
    else snprintf(parent, sizeof(parent), "%s", slash ? "/" : ".");
    int dirfd = open(parent, O_RDONLY | O_DIRECTORY | O_NOFOLLOW);
    if (dirfd < 0) return false;
    int fd = mkstemp(temp); /* O_EXCL prevents following an existing temp link. */
    if (fd < 0) { close(dirfd); return false; }
    bool ok = fchmod(fd, 0600) == 0;
    FILE* f = fdopen(fd, "wb");
    if (!f) { close(fd); unlink(temp); close(dirfd); return false; }
    digest_hex(text, length, digest);
    ok = ok && fwrite(text, 1, length, f) == length &&
         fprintf(f, "checksum=%s\n", digest) == 74 && fflush(f) == 0 &&
         fsync(fileno(f)) == 0;
    if (fclose(f)) ok = false;
    if (ok) ok = regular_or_missing(path) && rename(temp, path) == 0;
    if (ok && fsync(dirfd)) {
        /* Some target filesystems cannot sync directories. File data is synced;
         * tolerate only explicit unsupported errors, never ordinary I/O failure. */
        ok = errno == EINVAL || errno == ENOTSUP;
    }
    if (close(dirfd)) ok = false;
    if (!ok) unlink(temp);
    return ok;
}

bool backup_retry_matches(const backup_retry_t* state, int index,
                          const char* current_identity,
                          const char* current_fingerprint) {
    return state && index >= 0 && index < 2 &&
           (state->planned_mask & (1U << index)) &&
           optional_hash(state->completed_identity[index]) &&
           optional_hash(state->fingerprint) &&
           dest_fingerprint_hex(current_identity) &&
           dest_fingerprint_hex(current_fingerprint) &&
           !strcmp(state->completed_identity[index], current_identity) &&
           !strcmp(state->fingerprint, current_fingerprint);
}

void backup_retry_confirm(backup_retry_t* state, int index,
                          const char* actual_identity) {
    if (!state || index < 0 || index >= 2) return;
    state->pending_mask &= ~(1U << index);
    if (dest_fingerprint_hex(actual_identity)) {
        memmove(state->completed_identity[index], actual_identity, 65);
        if (index == 0) state->usb_no_replay = false;
    }
    else memset(state->completed_identity[index], 0, 65);
}
