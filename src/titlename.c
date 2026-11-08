// TostónSync — best-effort game name resolver. See titlename.h.

#include "titlename.h"
#include "config.h"

#include <ctype.h>
#include <dirent.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

// Where the system mounts a running title's app image. Overridable for
// tests with -DSANDBOX_BASE="\"/some/path\"".
#ifndef SANDBOX_BASE
#define SANDBOX_BASE "/mnt/sandbox"
#endif

// Installed-game metadata paths vary a bit across firmware and install
// method. Try persistent appmeta/app locations first so names/icons work
// even when the game is closed, then fall back to the live sandbox mount.
static const char* SCE_SYS_PATTERNS[] = {
#ifdef TITLENAME_METADATA_BASE
    // Tests redirect all installed metadata reads to disposable fixtures.
    TITLENAME_METADATA_BASE "/%s",
    TITLENAME_METADATA_BASE "/%s/sce_sys",
#else
    "/user/appmeta/%s",
    "/system_data/priv/appmeta/%s",
    "/user/appmeta/%s/sce_sys",
    "/system_data/priv/appmeta/%s/sce_sys",
    "/user/appmeta/%s-app/sce_sys",
    "/system_data/priv/appmeta/%s-app/sce_sys",
    "/user/appmeta/%s-app0/sce_sys",
    "/system_data/priv/appmeta/%s-app0/sce_sys",
    "/user/app/%s/sce_sys",
    "/user/app/%s-app/sce_sys",
    "/user/app/%s-app0/sce_sys",
    "/system_ex/app/%s/sce_sys",
#endif
};

// --------------------------------------------------------------------
// Small helpers.
// --------------------------------------------------------------------

static char* read_whole_file(const char* path, size_t* out_len) {
    FILE* f = fopen(path, "rb");
    if (!f) return NULL;
    if (fseek(f, 0, SEEK_END) != 0) { fclose(f); return NULL; }
    long sz = ftell(f);
    if (sz <= 0 || sz > 1 * 1024 * 1024) { fclose(f); return NULL; }
    if (fseek(f, 0, SEEK_SET) != 0) { fclose(f); return NULL; }
    char* buf = (char*)malloc((size_t)sz + 1);
    if (!buf) { fclose(f); return NULL; }
    size_t n = fread(buf, 1, (size_t)sz, f);
    bool complete = n == (size_t)sz && !ferror(f);
    if (fclose(f) != 0) complete = false;
    if (!complete) { free(buf); return NULL; }
    buf[n] = '\0';
    if (out_len) *out_len = n;
    return buf;
}

static void trim_ws(char* s) {
    size_t L = strlen(s);
    while (L && (s[L-1] == ' ' || s[L-1] == '\t' || s[L-1] == '\r' ||
                 s[L-1] == '\n')) s[--L] = '\0';
}

static bool valid_title_id(const char* s) {
    if (!s || !s[0]) return false;
    for (size_t i = 0; s[i]; i++) {
        unsigned char c = (unsigned char)s[i];
        if (!isalnum(c) && c != '_') return false;
    }
    return true;
}

static bool valid_asset_name(const char* s) {
    if (!s || !s[0]) return false;
    for (size_t i = 0; s[i]; i++) {
        unsigned char c = (unsigned char)s[i];
        if (!isalnum(c) && c != '_' && c != '-' && c != '.') return false;
    }
    return true;
}

// --------------------------------------------------------------------
// UTF-8 and a bounded param.json reader. Only direct object members count;
// a title inside another locale or an unrelated object is never a fallback.
// Kept local so name metadata cannot change OAuth's JSON handling.
// --------------------------------------------------------------------

static size_t utf8_scalar(const char* p, const char* end, uint32_t* scalar) {
    if (p == end) return 0;
    unsigned char first = (unsigned char)*p;
    size_t n;
    uint32_t cp, min;
    if (first < 0x80) { n = 1; cp = first; min = 0; }
    else if (first >= 0xc2 && first <= 0xdf) { n = 2; cp = first & 0x1f; min = 0x80; }
    else if (first >= 0xe0 && first <= 0xef) { n = 3; cp = first & 0x0f; min = 0x800; }
    else if (first >= 0xf0 && first <= 0xf4) { n = 4; cp = first & 0x07; min = 0x10000; }
    else return 0;
    if ((size_t)(end - p) < n) return 0;
    for (size_t i = 1; i < n; i++) {
        unsigned char c = (unsigned char)p[i];
        if ((c & 0xc0) != 0x80) return 0;
        cp = (cp << 6) | (c & 0x3f);
    }
    if (cp < min || cp > 0x10ffff || (cp >= 0xd800 && cp <= 0xdfff)) return 0;
    *scalar = cp;
    return n;
}

size_t titlename_copy_utf8(char* out, size_t out_sz, const char* name) {
    if (!out || !out_sz) return 0;
    size_t n = 0;
    if (name) {
        const char* end = name + strlen(name);
        for (const char* p = name; p < end;) {
            uint32_t cp;
            size_t width = utf8_scalar(p, end, &cp);
            if (!width || width > out_sz - 1 - n) break;
            memmove(out + n, p, width);
            n += width;
            p += width;
        }
    }
    out[n] = '\0';
    return n;
}

typedef struct { const char* begin; const char* end; } name_json_t;

static void name_ws(const char** p, const char* end) {
    while (*p < end && (**p == ' ' || **p == '\t' || **p == '\r' || **p == '\n')) (*p)++;
}

static bool name_hex4(const char** p, const char* end, uint32_t* cp) {
    if ((size_t)(end - *p) < 4) return false;
    *cp = 0;
    for (int i = 0; i < 4; i++) {
        unsigned char c = (unsigned char)*(*p)++;
        unsigned digit;
        if (c >= '0' && c <= '9') digit = c - '0';
        else if (c >= 'a' && c <= 'f') digit = c - 'a' + 10;
        else if (c >= 'A' && c <= 'F') digit = c - 'A' + 10;
        else return false;
        *cp = (*cp << 4) | digit;
    }
    return true;
}

static size_t name_encode(uint32_t cp, char bytes[4]) {
    if (cp < 0x80) { bytes[0] = (char)cp; return 1; }
    if (cp < 0x800) {
        bytes[0] = (char)(0xc0 | (cp >> 6)); bytes[1] = (char)(0x80 | (cp & 0x3f)); return 2;
    }
    if (cp < 0x10000) {
        bytes[0] = (char)(0xe0 | (cp >> 12)); bytes[1] = (char)(0x80 | ((cp >> 6) & 0x3f));
        bytes[2] = (char)(0x80 | (cp & 0x3f)); return 3;
    }
    bytes[0] = (char)(0xf0 | (cp >> 18)); bytes[1] = (char)(0x80 | ((cp >> 12) & 0x3f));
    bytes[2] = (char)(0x80 | ((cp >> 6) & 0x3f)); bytes[3] = (char)(0x80 | (cp & 0x3f)); return 4;
}

// Validate the entire string even when the display buffer is already full.
static bool name_string(const char** p, const char* end, char* out,
                        size_t cap, size_t* decoded_size) {
    if (*p == end || *(*p)++ != '"') return false;
    size_t written = 0, total = 0;
    bool full = !out || !cap;
    while (*p < end) {
        if (**p == '"') {
            (*p)++;
            if (out && cap) out[written] = '\0';
            if (decoded_size) *decoded_size = total;
            return true;
        }
        uint32_t cp;
        if (**p == '\\') {
            if (++(*p) == end) return false;
            char escape = *(*p)++;
            switch (escape) {
                case '"': case '\\': case '/': cp = (unsigned char)escape; break;
                case 'b': cp = '\b'; break;
                case 'f': cp = '\f'; break;
                case 'n': cp = '\n'; break;
                case 'r': cp = '\r'; break;
                case 't': cp = '\t'; break;
                case 'u': {
                    if (!name_hex4(p, end, &cp)) return false;
                    if (cp >= 0xd800 && cp <= 0xdbff) {
                        uint32_t low;
                        if ((size_t)(end - *p) < 2 || (*p)[0] != '\\' || (*p)[1] != 'u') return false;
                        *p += 2;
                        if (!name_hex4(p, end, &low) || low < 0xdc00 || low > 0xdfff) return false;
                        cp = 0x10000 + ((cp - 0xd800) << 10) + low - 0xdc00;
                    } else if (cp >= 0xdc00 && cp <= 0xdfff) return false;
                    if (!cp) return false; // metadata names/keys must not contain embedded NUL
                    break;
                }
                default: return false;
            }
        } else {
            size_t width = utf8_scalar(*p, end, &cp);
            if (!width || cp < 0x20) return false;
            *p += width;
        }
        char bytes[4];
        size_t width = name_encode(cp, bytes);
        total += width;
        if (!full && width <= cap - 1 - written) {
            memcpy(out + written, bytes, width);
            written += width;
        } else full = true;
    }
    return false;
}

static bool name_value(const char** p, const char* end, unsigned depth) {
    name_ws(p, end);
    if (*p == end || depth > 16) return false;
    char c = **p;
    if (c == '"') return name_string(p, end, NULL, 0, NULL);
    if (c == '{' || c == '[') {
        bool object = c == '{';
        char close = object ? '}' : ']';
        (*p)++;
        name_ws(p, end);
        if (*p < end && **p == close) { (*p)++; return true; }
        for (;;) {
            if (object) {
                if (!name_string(p, end, NULL, 0, NULL)) return false;
                name_ws(p, end);
                if (*p == end || *(*p)++ != ':') return false;
            }
            if (!name_value(p, end, depth + 1)) return false;
            name_ws(p, end);
            if (*p == end) return false;
            if (**p == close) { (*p)++; return true; }
            if (*(*p)++ != ',') return false;
            name_ws(p, end);
        }
    }
    const char* literal = c == 't' ? "true" : c == 'f' ? "false" : c == 'n' ? "null" : NULL;
    if (literal) {
        size_t len = strlen(literal);
        if ((size_t)(end - *p) < len || memcmp(*p, literal, len)) return false;
        *p += len;
        return true;
    }
    // Unknown metadata numeric fields still need valid JSON syntax.
    if (c == '-') (*p)++;
    if (*p == end) return false;
    if (**p == '0') (*p)++;
    else {
        if (**p < '1' || **p > '9') return false;
        while (*p < end && **p >= '0' && **p <= '9') (*p)++;
    }
    if (*p < end && **p == '.') {
        (*p)++;
        if (*p == end || **p < '0' || **p > '9') return false;
        while (*p < end && **p >= '0' && **p <= '9') (*p)++;
    }
    if (*p < end && (**p == 'e' || **p == 'E')) {
        (*p)++;
        if (*p < end && (**p == '+' || **p == '-')) (*p)++;
        if (*p == end || **p < '0' || **p > '9') return false;
        while (*p < end && **p >= '0' && **p <= '9') (*p)++;
    }
    return true;
}

static bool name_member(name_json_t object, const char* key, name_json_t* value) {
    const char* p = object.begin;
    if (p == object.end || *p++ != '{') return false;
    bool found = false;
    for (;;) {
        name_ws(&p, object.end);
        if (p == object.end || *p == '}') return found;
        char member[96];
        size_t len;
        if (!name_string(&p, object.end, member, sizeof(member), &len)) return false;
        name_ws(&p, object.end);
        if (p == object.end || *p++ != ':') return false;
        name_ws(&p, object.end);
        name_json_t candidate = { p, NULL };
        if (!name_value(&p, object.end, 0)) return false;
        candidate.end = p;
        if (len < sizeof(member) && strcmp(member, key) == 0) {
            if (found) return false; // duplicate selected members are ambiguous
            *value = candidate;
            found = true;
        }
        name_ws(&p, object.end);
        if (p == object.end || *p == '}') return found;
        if (*p++ != ',') return false;
    }
}

static bool name_field(name_json_t object, const char* key, char* out,
                       size_t cap, bool allow_truncation) {
    name_json_t value;
    if (!name_member(object, key, &value)) return false;
    const char* p = value.begin;
    size_t decoded;
    if (!name_string(&p, value.end, out, cap, &decoded) || p != value.end ||
        (!allow_truncation && decoded >= cap)) return false;
    trim_ws(out);
    return out[0] != '\0';
}

static bool name_locale(name_json_t localized, const char* locale, char* out, size_t cap) {
    name_json_t object;
    return name_member(localized, locale, &object) && name_field(object, "titleName", out, cap, true);
}

static bool read_param_json(const char* path, const char* language, char* out, size_t out_sz) {
    size_t len;
    char* buf = read_whole_file(path, &len);
    if (!buf) return false;
    const char* end = buf + len;
    const char* p = buf;
    name_ws(&p, end);
    name_json_t root = { p, end }, localized;
    bool ok = p < end && *p == '{' && name_value(&p, end, 0);
    name_ws(&p, end);
    if (!ok || p != end) { free(buf); return false; }
    ok = false;
    if (name_member(root, "localizedParameters", &localized)) {
        static const char* spanish[] = { "es-ES", "es-LA", "es-MX", "es-419", "es" };
        static const char* english[] = { "en-US", "en-GB", "en" };
        if (strcmp(language, "es") == 0)
            for (size_t i = 0; !ok && i < sizeof(spanish)/sizeof(spanish[0]); i++)
                ok = name_locale(localized, spanish[i], out, out_sz);
        for (size_t i = 0; !ok && i < sizeof(english)/sizeof(english[0]); i++)
            ok = name_locale(localized, english[i], out, out_sz);
        char declared[32];
        if (!ok && (name_field(localized, "defaultLanguage", declared, sizeof(declared), false) ||
                    name_field(root, "defaultLanguage", declared, sizeof(declared), false)))
            ok = name_locale(localized, declared, out, out_sz);
    }
    if (!ok) ok = name_field(root, "titleName", out, out_sz, true);
    if (!ok) ok = name_field(root, "TITLE", out, out_sz, true);
    free(buf);
    if (!ok) out[0] = '\0';
    return ok;
}

// --------------------------------------------------------------------
// param.sfo (older): a binary key/value blob. Pull the "TITLE" string.
// Format: 20-byte header, then N×16-byte index entries, a key table and
// a data table. All little-endian.
// --------------------------------------------------------------------

static uint16_t rd16(const unsigned char* p) { return (uint16_t)(p[0] | (p[1] << 8)); }
static uint32_t rd32(const unsigned char* p) {
    return (uint32_t)(p[0] | (p[1] << 8) | (p[2] << 16) | (p[3] << 24));
}

static bool read_param_sfo(const char* path, char* out, size_t out_sz) {
    size_t len = 0;
    unsigned char* buf = (unsigned char*)read_whole_file(path, &len);
    if (!buf) return false;
    bool ok = false;
    if (len >= 20 && rd32(buf) == 0x46535000u) {   // "\0PSF"
        uint32_t key_tab  = rd32(buf + 8);
        uint32_t data_tab = rd32(buf + 12);
        uint32_t n        = rd32(buf + 16);
        if (n > 1024) n = 1024;                    // sanity bound
        for (uint32_t i = 0; i < n; i++) {
            size_t index = 20 + (size_t)i * 16;
            if (index > len || len - index < 16) break;
            const unsigned char* e = buf + index;
            uint16_t koff = rd16(e + 0);
            uint16_t fmt  = rd16(e + 2);
            uint32_t plen = rd32(e + 4);
            uint32_t doff = rd32(e + 12);
            size_t kpos = (size_t)key_tab + koff;
            if (kpos >= len) continue;
            // Bounded key compare against "TITLE".
            const char* k = (const char*)(buf + kpos);
            size_t kmax = len - kpos;
            if (strnlen(k, kmax) >= kmax) continue;
            if (strcmp(k, "TITLE") != 0) continue;
            if (fmt != 0x0204 && fmt != 0x0004) break;   // not a UTF-8 string
            size_t dpos = (size_t)data_tab + doff;
            if (dpos >= len) break;
            size_t avail = len - dpos;
            size_t cpy = plen < avail ? plen : avail;
            // The file buffer has one extra NUL, so this bounded value can
            // use the shared scalar-safe copy without editing source bytes.
            buf[dpos + cpy] = '\0';
            titlename_copy_utf8(out, out_sz, (const char*)buf + dpos);
            trim_ws(out);
            ok = out[0] != '\0';
            break;
        }
    }
    free(buf);
    return ok;
}

// Try param.json then param.sfo at a given sce_sys directory.
static bool try_sce_sys(const char* sce_sys_dir, const char* language,
                        char* out, size_t out_sz) {
    char p[512];
    snprintf(p, sizeof(p), "%s/param.json", sce_sys_dir);
    if (read_param_json(p, language, out, out_sz)) return true;
    snprintf(p, sizeof(p), "%s/param.sfo", sce_sys_dir);
    if (read_param_sfo(p, out, out_sz)) return true;
    return false;
}

static bool lookup_from_installed_metadata(const char* title_id, const char* language,
                                           char* out, size_t out_sz) {
    for (size_t i = 0; i < sizeof(SCE_SYS_PATTERNS)/sizeof(SCE_SYS_PATTERNS[0]); i++) {
        char dir[512];
        snprintf(dir, sizeof(dir), SCE_SYS_PATTERNS[i], title_id);
        if (try_sce_sys(dir, language, out, out_sz)) return true;
    }
    return false;
}

static bool lookup_from_sandbox(const char* title_id, const char* language,
                                char* out, size_t out_sz) {
    DIR* d = opendir(SANDBOX_BASE);
    if (!d) return false;
    size_t idlen = strlen(title_id);
    bool found = false;
    struct dirent* e;
    while (!found && (e = readdir(d)) != NULL) {
        if (strncmp(e->d_name, title_id, idlen) != 0) continue;  // CUSAxxxxx_xxx
        // Candidate sce_sys locations inside a mounted app image.
        const char* sub[] = { "app0/sce_sys", "sce_sys", "app/sce_sys" };
        for (size_t i = 0; i < sizeof(sub)/sizeof(sub[0]); i++) {
            char dir[512];
            snprintf(dir, sizeof(dir), "%s/%s/%s", SANDBOX_BASE, e->d_name, sub[i]);
            if (try_sce_sys(dir, language, out, out_sz)) { found = true; break; }
        }
    }
    closedir(d);
    return found && out[0];
}

bool titlename_lookup(const char* title_id, char* out, size_t out_sz) {
    if (!out || out_sz == 0) return false;
    out[0] = '\0';
    if (!valid_title_id(title_id)) return false;

    config_t cfg;
    const char* language = config_snapshot(&cfg) && strcmp(cfg.general.language, "es") == 0 ? "es" : "en";
    if (lookup_from_installed_metadata(title_id, language, out, out_sz)) return true;
    return lookup_from_sandbox(title_id, language, out, out_sz);
}

static bool asset_exists(const char* dir, const char* asset_name,
                         char* out, size_t out_sz) {
    char p[512];
    snprintf(p, sizeof(p), "%s/%s", dir, asset_name);
    struct stat st;
    if (stat(p, &st) != 0 || !S_ISREG(st.st_mode)) return false;
    snprintf(out, out_sz, "%s", p);
    return out[0] != '\0';
}

static bool find_asset_in_installed_metadata(const char* title_id,
                                             const char* asset_name,
                                             char* out, size_t out_sz) {
    for (size_t i = 0; i < sizeof(SCE_SYS_PATTERNS)/sizeof(SCE_SYS_PATTERNS[0]); i++) {
        char dir[512];
        snprintf(dir, sizeof(dir), SCE_SYS_PATTERNS[i], title_id);
        if (asset_exists(dir, asset_name, out, out_sz)) return true;
    }
    return false;
}

static bool find_asset_in_sandbox(const char* title_id,
                                  const char* asset_name,
                                  char* out, size_t out_sz) {
    DIR* d = opendir(SANDBOX_BASE);
    if (!d) return false;
    size_t idlen = strlen(title_id);
    bool found = false;
    struct dirent* e;
    while (!found && (e = readdir(d)) != NULL) {
        if (strncmp(e->d_name, title_id, idlen) != 0) continue;
        const char* sub[] = { "app0/sce_sys", "sce_sys", "app/sce_sys" };
        for (size_t i = 0; i < sizeof(sub)/sizeof(sub[0]); i++) {
            char dir[512];
            snprintf(dir, sizeof(dir), "%s/%s/%s", SANDBOX_BASE, e->d_name, sub[i]);
            if (asset_exists(dir, asset_name, out, out_sz)) { found = true; break; }
        }
    }
    closedir(d);
    return found;
}

bool titlename_find_asset(const char* title_id, const char* asset_name,
                          char* out, size_t out_sz) {
    if (!out || out_sz == 0) return false;
    out[0] = '\0';
    if (!valid_title_id(title_id) || !valid_asset_name(asset_name)) return false;

    if (find_asset_in_installed_metadata(title_id, asset_name, out, out_sz))
        return true;
    return find_asset_in_sandbox(title_id, asset_name, out, out_sz);
}
