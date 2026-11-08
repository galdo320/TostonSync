#include "restore_selection.h"
#include "sha256.h"

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static const char* ws(const char* p) { while (p && isspace((unsigned char)*p)) p++; return p; }
static bool fail(char* out, size_t n, const char* message) {
    if (out && n) snprintf(out, n, "%s", message);
    return false;
}
static bool selection_bool_valid(const restore_selection_t* selection) {
    // Durable plans/authority may be untrusted bytes. Reject an invalid wire
    // bool before a typed read (which is undefined for other representations).
    return selection && ((const unsigned char*)selection)
        [offsetof(restore_selection_t, specified)] <= 1;
}

// Raw literal strings for keys/slot names. Escapes are accepted only in
// unrelated values; a client cannot disguise a duplicate authority field.
static bool string(const char** cursor, char* out, size_t cap) {
    const char* p = *cursor;
    if (*p++ != '"') return false;
    size_t n = 0;
    while (*p && *p != '"') {
        if ((unsigned char)*p < 32) return false;
        if (*p == '\\') {
            if (out) return false;
            p++;
            if (*p == 'u') {
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

static bool value(const char** cursor, unsigned depth, bool legacy) {
    if (depth > 16) return false;
    const char* p = ws(*cursor);
    if (*p == '"') { if (!string(&p, NULL, 0)) return false; }
    else if (*p == '[' || *p == '{') {
        bool object = *p == '{'; char end = object ? '}' : ']';
        p = ws(p + 1);
        if (*p != end) for (;;) {
            if (object) {
                char key[64];
                if (!string(&p, legacy ? key : NULL, legacy ? sizeof(key) : 0) ||
                    *(p = ws(p)) != ':') return false;
                if (legacy && (!strcmp(key, "selected_slots") ||
                               !strcmp(key, "selection_receipt") ||
                               !strcmp(key, "restore_mode") ||
                               !strcmp(key, "source_uid"))) return false;
                p++;
            }
            if (!value(&p, depth + 1, legacy)) return false;
            p = ws(p);
            if (*p != ',') break;
            p = ws(p + 1);
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
    *cursor = p; return true;
}

bool restore_selection_legacy_request(const char* body) {
    if (!body || !body[0]) return true; // legacy restore-all defaults to best
    if (strlen(body) > 160 * 1024) return false;
    const char* p = ws(body);
    return *p == '{' && value(&p, 0, true) && !*ws(p);
}

bool restore_uid_valid(const char* uid) {
    if (!uid || strlen(uid) != 8) return false;
    for (size_t i = 0; i < 8; i++)
        if (!isxdigit((unsigned char)uid[i])) return false;
    return true;
}

static bool request_uid_identity(const char* body, char uid[16], bool* explicit_uid, bool* source_uid) {
    if (!uid || !explicit_uid) return false;
    uid[0] = '\0'; *explicit_uid = false;
    if (source_uid) *source_uid = false;
    if (!body || strlen(body) > 160 * 1024) return false;
    const char* p = ws(body);
    bool have_user = false;
    char keys[32][64]; size_t key_count = 0;
    if (*p++ != '{') return false;
    p = ws(p);
    if (*p != '}') for (;;) {
        char key[64];
        if (key_count == 32 || !string(&p, key, sizeof(key)) || *(p = ws(p)) != ':') return false;
        for (size_t i = 0; i < key_count; i++) if (!strcmp(keys[i], key)) return false;
        snprintf(keys[key_count++], sizeof(keys[0]), "%s", key);
        if (!strcmp(key, "target_uid") || !strcmp(key, "selected_slots") ||
            !strcmp(key, "selection_receipt") || !strcmp(key, "restore_mode")) return false;
        p = ws(p + 1);
        if (!strcmp(key, "uid") || !strcmp(key, "source_uid")) {
            bool provenance = !strcmp(key, "source_uid");
            if ((provenance && !source_uid) || *explicit_uid ||
                (source_uid && *source_uid) ||
                !string(&p, uid, 16) || !restore_uid_valid(uid)) return false;
            if (provenance) *source_uid = true;
            else *explicit_uid = true;
        } else {
            if (!strcmp(key, "user")) { have_user = true; if (*p != '"') return false; }
            // Each Restore/rollback item is flat; nested selectors cannot shadow it.
            if (*p == '{' || *p == '[' || !value(&p, 0, false)) return false;
        }
        p = ws(p);
        if (*p != ',') break;
        p = ws(p + 1);
    }
    return *p++ == '}' && !*ws(p) &&
        !((*explicit_uid || (source_uid && *source_uid)) && have_user);
}

bool restore_request_uid(const char* body, char uid[16], bool* explicit_uid) {
    return request_uid_identity(body, uid, explicit_uid, NULL);
}

bool import_request_uid(const char* body, char uid[16], bool* explicit_uid, bool* source_uid) {
    return source_uid && request_uid_identity(body, uid, explicit_uid, source_uid);
}

// Only use this iterator after validating the complete immutable batch.
bool restore_batch_item(const char** cursor, char object[1024]) {
    if (!cursor || !*cursor || !object) return false;
    const char* start = ws(*cursor), *end = start;
    if (*start != '{' || !value(&end, 0, true) || end - start >= 1024) return false;
    memcpy(object, start, (size_t)(end - start)); object[end - start] = '\0';
    end = ws(end);
    if (*end == ',') end = ws(end + 1);
    else if (*end != ']') return false;
    *cursor = end;
    return true;
}

bool restore_batch_request(const char* body, const char** items) {
    if (!body || !items || strlen(body) > 160 * 1024) return false;
    const char* p = ws(body); char key[16];
    if (*p++ != '{') return false;
    p = ws(p);
    if (!string(&p, key, sizeof(key)) || strcmp(key, "items") || *(p = ws(p)) != ':') return false;
    p = ws(p + 1);
    if (*p++ != '[') return false;
    *items = p = ws(p);
    size_t count = 0;
    if (*p == ']') return false;
    for (;;) {
        const char* end = p;
        char object[1024], uid[16]; bool explicit_uid;
        if (++count > 128 || *p != '{' || !value(&end, 0, true) || end - p >= 1024) return false;
        memcpy(object, p, (size_t)(end - p)); object[end - p] = '\0';
        if (!restore_request_uid(object, uid, &explicit_uid)) return false;
        p = ws(end);
        if (*p != ',') break;
        p = ws(p + 1);
    }
    if (*p++ != ']' || *(p = ws(p)) != '}') return false;
    return !*ws(p + 1);
}

bool restore_all_request(const char* body, char source[16]) {
    if (!source) return false;
    snprintf(source, 16, "best");
    if (!body || !*body) return true;
    if (strlen(body) > 160 * 1024) return false;
    const char* p = ws(body); char key[16];
    if (*p++ != '{') return false;
    p = ws(p);
    if (*p != '}') {
        if (!string(&p, key, sizeof(key)) || strcmp(key, "source") || *(p = ws(p)) != ':') return false;
        p = ws(p + 1);
        if (!string(&p, source, 16)) return false;
        p = ws(p);
    }
    if (*p++ != '}' || *ws(p)) return false;
    if (!source[0]) snprintf(source, 16, "best");
    return !strcmp(source, "best") || !strcmp(source, "usb") || !strcmp(source, "drive");
}

bool restore_selection_request_parse(const char* body,
                                     restore_selection_request_t* request,
                                     char* error, size_t error_sz) {
    if (!request) return fail(error, error_sz, "Invalid restore request");
    memset(request, 0, sizeof(*request));
    if (!body || strlen(body) > 160 * 1024)
        return fail(error, error_sz, "Invalid restore request");
    restore_selection_t* out = &request->selection;
    memset(out, 0, sizeof(*out));
    const char* p = ws(body);
    char keys[32][64]; size_t key_count = 0;
    bool receipt_present = false, mode_present = false, uid_present = false;
    if (*p++ != '{') goto invalid;
    p = ws(p);
    if (*p != '}') for (;;) {
        char key[64];
        if (key_count == 32 || !string(&p, key, sizeof(key))) goto invalid;
        for (size_t i = 0; i < key_count; i++) if (!strcmp(keys[i], key)) goto invalid;
        snprintf(keys[key_count++], sizeof(keys[0]), "%s", key);
        if (*(p = ws(p)) != ':') goto invalid;
        p = ws(p + 1);
        if (!strcmp(key, "source_uid")) goto invalid; // preparation-only provenance
        if (!strcmp(key, "uid")) uid_present = true;
        if (!strcmp(key, "selected_slots")) {
            out->specified = true;
            if (*p++ != '[') goto invalid;
            p = ws(p);
            if (*p == ']') goto invalid;
            for (;;) {
                if (out->count == RESTORE_SELECTION_MAX ||
                    !string(&p, out->slots[out->count], sizeof(out->slots[0])) ||
                    !out->slots[out->count][0]) goto invalid;
                out->count++;
                p = ws(p);
                if (*p != ',') break;
                p = ws(p + 1);
            }
            if (*p++ != ']') goto invalid;
        } else {
            // These APIs accept a flat envelope. The older JSON getters scan
            // recursively, so rejecting nested authority fields here prevents
            // a hidden id/UID/token from shadowing the explicit top-level one.
            if (*p == '{' || *p == '[') goto invalid;
            if (!strcmp(key, "id") || !strcmp(key, "phase") ||
                !strcmp(key, "target_uid") || !strcmp(key, "selection_receipt") ||
                !strcmp(key, "user") || !strcmp(key, "restore_mode")) {
                char* authority = request->restore_mode;
                size_t cap = sizeof(request->restore_mode);
                if (!strcmp(key, "id")) { authority = request->id; cap = sizeof(request->id); }
                else if (!strcmp(key, "phase")) { authority = request->phase; cap = sizeof(request->phase); }
                else if (!strcmp(key, "target_uid")) { authority = request->target_uid; cap = sizeof(request->target_uid); }
                else if (!strcmp(key, "user")) { authority = request->user; cap = sizeof(request->user); }
                else if (!strcmp(key, "selection_receipt")) { authority = request->selection_receipt; cap = sizeof(request->selection_receipt); }
                if (!string(&p, authority, cap)) goto invalid;
                // This is the portable-selected envelope, not RAW authority.
                // Existing clients may omit the mode; explicit RAW modes can
                // never fall through to the portable/legacy commit routes.
                if (!strcmp(key, "restore_mode") &&
                    strcmp(authority, RESTORE_MODE_PORTABLE_SELECTED)) goto invalid;
                if (!strcmp(key, "restore_mode")) mode_present = true;
                if (!strcmp(key, "selection_receipt")) receipt_present = true;
            } else if (!value(&p, 0, false)) goto invalid;
        }
        p = ws(p);
        if (*p != ',') break;
        p = ws(p + 1);
    }
    if (*p++ != '}' || *ws(p)) goto invalid;
    if ((receipt_present || mode_present) && !out->specified) goto invalid;
    if (uid_present && out->specified) goto invalid;
    return true;
invalid:
    memset(request, 0, sizeof(*request));
    return fail(error, error_sz, "Invalid, duplicate, empty or non-literal selected_slots request");
}

bool restore_selection_parse(const char* body, restore_selection_t* out,
                             char* error, size_t error_sz) {
    if (!out) return fail(error, error_sz, "Invalid restore request");
    restore_selection_request_t request;
    bool ok = restore_selection_request_parse(body, &request, error, error_sz);
    if (ok) *out = request.selection;
    else memset(out, 0, sizeof(*out));
    return ok;
}

static int compare_slot(const void* a, const void* b) { return strcmp(a, b); }

bool restore_selection_resolve(restore_selection_t* selection,
                               const char available[][64], size_t count,
                               char* error, size_t error_sz) {
    if (!selection_bool_valid(selection) || !available || !count || count > RESTORE_SELECTION_MAX)
        return fail(error, error_sz, "Restore inventory is unavailable");
    if (!selection->specified) {
        selection->count = count;
        memcpy(selection->slots, available, count * sizeof(selection->slots[0]));
    }
    if (!selection->count || selection->count > RESTORE_SELECTION_MAX)
        return fail(error, error_sz, "Empty or oversized slot selection");
    for (size_t i = 0; i < selection->count; i++) {
        if (!memchr(selection->slots[i], '\0', sizeof(selection->slots[i])) ||
            !selection->slots[i][0]) return fail(error, error_sz, "Invalid slot name");
        bool found = false;
        for (size_t j = 0; j < count; j++)
            if (!strcmp(selection->slots[i], available[j])) found = true;
        if (!found) return fail(error, error_sz, "Selected slot is not present literally in this title's import");
        for (size_t j = 0; j < i; j++)
            if (!strcmp(selection->slots[i], selection->slots[j]))
                return fail(error, error_sz, "Duplicate selected slot");
    }
    qsort(selection->slots, selection->count, sizeof(selection->slots[0]), compare_slot);
    return true;
}

bool restore_selection_contains(const restore_selection_t* selection, const char* slot) {
    if (!selection_bool_valid(selection) || !slot || selection->count > RESTORE_SELECTION_MAX) return false;
    for (size_t i = 0; i < selection->count; i++)
        if (!memchr(selection->slots[i], '\0', sizeof(selection->slots[i]))) return false;
    for (size_t i = 0; i < selection->count; i++)
        if (!strcmp(selection->slots[i], slot)) return true;
    return false;
}

bool restore_selection_equal(const restore_selection_t* a, const restore_selection_t* b) {
    if (!selection_bool_valid(a) || !selection_bool_valid(b) ||
        a->specified != b->specified || a->count != b->count ||
        a->count > RESTORE_SELECTION_MAX) return false;
    for (size_t i = 0; i < a->count; i++)
        if (!memchr(a->slots[i], '\0', sizeof(a->slots[i])) ||
            !memchr(b->slots[i], '\0', sizeof(b->slots[i])) ||
            strcmp(a->slots[i], b->slots[i])) return false;
    return true;
}

static void digest_number(sha256_ctx_t* ctx, size_t n) {
    unsigned char bytes[8];
    for (unsigned i = 0; i < 8; i++) bytes[i] = (unsigned char)((uint64_t)n >> (i * 8));
    sha256_update(ctx, bytes, sizeof(bytes));
}
static void digest_string(sha256_ctx_t* ctx, const char* s) {
    digest_number(ctx, strlen(s)); sha256_update(ctx, s, strlen(s));
}
static bool bounded(const char* s, size_t cap, bool empty) {
    return memchr(s, '\0', cap) && (empty || s[0]);
}
static bool hash_text(const char* s, bool empty) {
    if (!bounded(s, 65, empty)) return false;
    if (empty && !s[0]) return true;
    return strlen(s) == 64 && strspn(s, "0123456789abcdef") == 64;
}
bool restore_scope_digest(const restore_scope_t* scope, char out[65]) {
    if (!scope || !out || !selection_bool_valid(&scope->selection) ||
        !scope->selection.specified || !scope->selection.count ||
        scope->selection.count > RESTORE_SELECTION_MAX ||
        scope->available_slots < scope->selection.count || scope->available_slots > RESTORE_SELECTION_MAX ||
        !bounded(scope->import_id, sizeof(scope->import_id), false) ||
        !bounded(scope->title_id, sizeof(scope->title_id), false) ||
        !bounded(scope->target_uid, sizeof(scope->target_uid), false) ||
        !bounded(scope->restore_mode, sizeof(scope->restore_mode), false) ||
        strcmp(scope->restore_mode, RESTORE_MODE_PORTABLE_SELECTED) ||
        !hash_text(scope->source_sha256, false) ||
        !hash_text(scope->portable_sha256, true) ||
        !hash_text(scope->target_state_sha256, false)) return false;
    sha256_ctx_t ctx; sha256_init(&ctx);
    digest_string(&ctx, "TostonSync portable_selected server approval v2");
    digest_string(&ctx, scope->restore_mode);
    digest_string(&ctx, scope->import_id); digest_string(&ctx, scope->title_id);
    digest_string(&ctx, scope->target_uid); digest_string(&ctx, scope->source_sha256);
    digest_string(&ctx, scope->portable_sha256);
    digest_string(&ctx, scope->target_state_sha256);
    digest_number(&ctx, scope->available_slots); digest_number(&ctx, scope->selection.count);
    for (size_t i = 0; i < scope->selection.count; i++) {
        if (!bounded(scope->selection.slots[i], 64, false) ||
            (i && strcmp(scope->selection.slots[i - 1], scope->selection.slots[i]) >= 0)) return false;
        digest_string(&ctx, scope->selection.slots[i]);
    }
    unsigned char raw[32]; sha256_final(&ctx, raw);
    static const char hex[] = "0123456789abcdef";
    for (size_t i = 0; i < 32; i++) { out[2*i] = hex[raw[i] >> 4]; out[2*i+1] = hex[raw[i] & 15]; }
    out[64] = '\0'; return true;
}
bool restore_scope_valid(const restore_scope_t* scope) {
    char digest[65]; return scope && bounded(scope->receipt, sizeof(scope->receipt), false) &&
        restore_scope_digest(scope, digest) && !strcmp(digest, scope->receipt);
}
bool restore_scope_equal(const restore_scope_t* a, const restore_scope_t* b) {
    return restore_scope_valid(a) && restore_scope_valid(b) && !strcmp(a->receipt, b->receipt);
}
