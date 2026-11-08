// TostónSync — libSceHttp2 wrapper.
//
// The PS5 ships a full HTTP/HTTPS stack. We use it directly to avoid
// pulling in libcurl + wolfSSL just to get TLS — the system stack is
// already validated against Google's CA chain and the SDK exposes the
// bindings we need.
//
// All requests follow the same skeleton: create_ssl_ctx → create_lib →
// create_template → create_connection → create_request → set_headers →
// send_request → read_response_headers → read_response_body → free.

#include "http_client.h"
#include "at_io.h"
#include "jobs.h"
#include "log.h"
#include "pem.h"
#include "version.h"
#include "google_matrix.h"
#include "google_cert_bundle.h"
#include "public_metadata_cert_bundle.h"
#include "release_cert_bundle.h"

#include <dirent.h>
#include <errno.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

// --- SDK bindings (libSceHttp2 / libSceSsl / libSceNet).
//
// These signatures match the names the ps5-payload-sdk actually exports
// (verified against the SDK's samples/http2_get). Notably there is NO
// "connection" object — you go straight from a template to a request —
// the request method is a STRING ("GET"/"POST"/...), and sceHttp2Init
// takes a real net memory pool id and SSL context id, not zeros.
int   sceNetInit(void);
int   sceNetPoolCreate(const char* name, int size, int flags);
int   sceNetPoolDestroy(int memId);

int   sceSslInit(size_t poolSize);
int   sceSslTerm(int ctx);

int   sceHttp2Init(int netMemId, int sslCtxId, size_t poolSize, int isShared);
int   sceHttp2Term(int libHandle);
int   sceHttp2CreateTemplate(int libHandle, const char* userAgent, int httpVer, int isShared);
int   sceHttp2DeleteTemplate(int tmpl);
int   sceHttp2CreateRequestWithURL(int tmpl, const char* method, const char* url,
                                   uint64_t contentLength);
int   sceHttp2DeleteRequest(int req);
int   sceHttp2AddRequestHeader(int req, const char* name, const char* value, int mode);
int   sceHttp2SendRequest(int req, const void* postData, size_t size);
int   sceHttp2GetStatusCode(int req, int* status);
int   sceHttp2ReadData(int req, void* data, size_t size);
int   sceHttp2GetAllResponseHeaders(int req, char** headers, size_t* size);

// Network timeouts (microseconds). Declared WEAK: if this SDK build does not
// export them, the symbols resolve to NULL at link and we simply skip the
// calls — so a missing symbol can never break the build. They stop a wedged
// server from hanging a worker thread forever (the lock fix already keeps such
// a hang off the status path, this is defense-in-depth).
__attribute__((weak)) int sceHttp2SetResolveTimeOut(int id, uint32_t usec);
__attribute__((weak)) int sceHttp2SetConnectTimeOut(int id, uint32_t usec);
__attribute__((weak)) int sceHttp2SetSendTimeOut(int id, uint32_t usec);
__attribute__((weak)) int sceHttp2SetRecvTimeOut(int id, uint32_t usec);

// Request method is passed as a string to sceHttp2CreateRequestWithURL.
#define HTTP_GET    "GET"
#define HTTP_POST   "POST"
#define HTTP_PUT    "PUT"
#define HTTP_DELETE "DELETE"

#define HDR_MODE_OVERWRITE 0

// ASCII User-Agent. The previous value "TostónSync/0.5" carried a raw UTF-8
// 'ó' (0xC3 0xB3), which is an illegal byte in an HTTP header value. Keep this
// pure ASCII and pinned to the build version.
#define HTTP_USER_AGENT "TostonSync/" TOSTONSYNC_VERSION

// --------------------------------------------------------------------
// TLS trust configuration (daemon-side HTTPS to Google).
//
// PROBLEM this addresses: on a PS5 payload, sceSslInit() alone does not
// guarantee a usable public-root trust store, so verifying Google's server
// certificate can fail and sceHttp2SendRequest() returns an SSL-band error
// (0x8095Fxxx) even though DNS and TCP are fine. We give the SSL context an
// explicit CA bundle loaded from disk.
//
// Symbols verified exported by the ps5-payload-sdk (nm -D libSceSsl.so /
// libSceHttp2.so). The CA store lives on the SSL context, so it must be loaded
// AFTER sceSslInit() and BEFORE sceHttp2Init() binds that context. Declared
// WEAK so a missing symbol resolves to NULL at link (never breaks the build).
//
// CA bundle path on the PS5: /data/tostonsync/cacert.pem (PEM; Google's roots
// from https://pki.goog/roots.pem). Ship it next to the daemon.
// --------------------------------------------------------------------
#define HTTP_CA_BUNDLE_PATH "/data/tostonsync/cacert.pem"

// libSceSsl: load a root CA (PEM/DER blob) into an SSL context, toggle the
// context's server-verify option. NOTE the capitalisation: RootCACert.
__attribute__((weak)) int sceSslLoadRootCACert(int sslCtxId, const void* cert, size_t certLen);
__attribute__((weak)) int sceSslEnableVerifyOption(int sslCtxId, uint32_t flags);
__attribute__((weak)) int sceSslDisableVerifyOption(int sslCtxId, uint32_t flags);
// libSceHttp2: toggle server verification on the HTTP2 context.
__attribute__((weak)) int sceHttp2SslEnableOption(int id, uint32_t flag);
__attribute__((weak)) int sceHttp2SslDisableOption(int id, uint32_t flag);

// Server-certificate verification flag (SCE_HTTPS/SCE_SSL FLAG_SERVER_VERIFY).
#define SSL_FLAG_SERVER_VERIFY 0x01u

// --------------------------------------------------------------------
// EXPERIMENTAL libSceHttp (v1) trust path — DIAGNOSTIC ONLY.
//
// libSceHttp exposes sceHttpsLoadCert, which may be the intended way to add a
// CA to the HTTP/HTTPS trust store (as opposed to sceSslLoadRootCACert on the
// raw SSL context, which destabilised the daemon). This whole path runs only
// from the isolated self-test below, with its own throwaway contexts, so it can
// never affect normal startup or the http2 request path. All symbols WEAK.
//
// Signatures follow the documented PS4/PS5 libSceHttp API but are UNVERIFIED on
// this SDK — that is exactly what the self-test exists to check. A wrong
// signature could crash the *diagnostic* (never the daemon's normal flow).
// --------------------------------------------------------------------
typedef struct { void* ptr; size_t size; } sce_ssl_data_t;

__attribute__((weak)) int sceHttpInit(int netMemId, int sslCtxId, size_t poolSize);
__attribute__((weak)) int sceHttpTerm(int httpCtxId);
__attribute__((weak)) int sceHttpCreateTemplate(int httpCtxId, const char* ua, int ver, int autoProxy);
__attribute__((weak)) int sceHttpDeleteTemplate(int tmplId);
__attribute__((weak)) int sceHttpCreateConnectionWithURL(int tmplId, const char* url, int keepalive);
__attribute__((weak)) int sceHttpDeleteConnection(int connId);
__attribute__((weak)) int sceHttpCreateRequestWithURL(int connId, int method, const char* url, uint64_t clen);
__attribute__((weak)) int sceHttpDeleteRequest(int reqId);
__attribute__((weak)) int sceHttpSendRequest(int reqId, const void* postData, size_t size);
__attribute__((weak)) int sceHttpGetStatusCode(int reqId, int* status);
__attribute__((weak)) int sceHttpsLoadCert(int httpCtxId, int caCertNum,
                                           const sce_ssl_data_t* const* caList,
                                           const sce_ssl_data_t* const* cert,
                                           const sce_ssl_data_t* const* privKey);
__attribute__((weak)) int sceHttpsGetSslError(int reqId, int* errNum, unsigned long* detail);
__attribute__((weak)) int sceHttpsSetMinSslVersion(int httpCtxId, int version);
// Used by the production libSceHttp transport (below).
__attribute__((weak)) int sceHttpReadData(int reqId, void* data, size_t size);
__attribute__((weak)) int sceHttpAddRequestHeader(int reqId, const char* name, const char* value, int mode);
__attribute__((weak)) int sceHttpGetAllResponseHeaders(int reqId, char** header, size_t* size);
__attribute__((weak)) int sceHttpSetConnectTimeOut(int id, uint32_t usec);
__attribute__((weak)) int sceHttpSetSendTimeOut(int id, uint32_t usec);
__attribute__((weak)) int sceHttpSetRecvTimeOut(int id, uint32_t usec);
__attribute__((weak)) int sceHttpSetResolveTimeOut(int id, uint32_t usec);
__attribute__((weak)) int sceHttpSetAutoRedirect(int id, int enable);

// libSceHttp method enum + version + header mode (PS4/PS5 values).
#define SCE_HTTP_METHOD_GET_    0
#define SCE_HTTP_METHOD_POST_   1
#define SCE_HTTP_METHOD_PUT_    4
#define SCE_HTTP_METHOD_DELETE_ 5
#define SCE_HTTP_VERSION_1_1_  2
#define SCE_HTTP_HEADER_OVERWRITE_ 0
#define SCE_SSL_VERSION_TLS1_2_ 0x0303

static int http_method_enum(const char* m) {
    if (!m) return SCE_HTTP_METHOD_GET_;
    if (strcmp(m, "POST") == 0)   return SCE_HTTP_METHOD_POST_;
    if (strcmp(m, "PUT") == 0)    return SCE_HTTP_METHOD_PUT_;
    if (strcmp(m, "DELETE") == 0) return SCE_HTTP_METHOD_DELETE_;
    return SCE_HTTP_METHOD_GET_;
}

// Diagnostic override: when true we DISABLE server-certificate verification.
// Default false (secure). This exists ONLY to *prove* on hardware that a
// verification/CA failure is the root cause: if enabling it makes Drive work,
// the fix is the CA bundle above, not the network. NEVER leave it on for real
// token traffic. Toggled at runtime via http_tls_set_insecure().
static bool s_tls_insecure = false;

// CUSTOM CA LOADING IS OFF BY DEFAULT. On hardware, calling sceSslLoadRootCACert
// from the daemon corrupted state and killed the process shortly after — even
// with a single small certificate. So the normal startup and every connectivity
// check MUST NOT touch that symbol. It is only exercised from the isolated,
// opt-in self-test (http_ca_selftest) or when an advanced user explicitly turns
// on the config flag (http_tls_set_custom_ca(true)). Release rule: a present or
// missing cacert.pem must never be able to kill the daemon.
static bool s_ca_custom_enabled = false;

// Last trust-configuration outcome, surfaced to the UI/logs.
//   0 = not attempted, 1 = CA bundle loaded, 2 = system store only,
//  -1 = insecure (verification disabled).
static int  s_tls_trust_state = 0;

void http_tls_set_insecure(bool insecure) { s_tls_insecure = insecure; }
void http_tls_set_custom_ca(bool enabled) { s_ca_custom_enabled = enabled; }
int  http_tls_trust_state(void) { return s_tls_trust_state; }

// Read a small file fully into a malloc'd buffer. Caller frees. NULL on error.
static char* read_file_alloc(const char* path, size_t* out_len) {
    FILE* f = fopen(path, "rb");
    if (!f) return NULL;
    if (fseek(f, 0, SEEK_END) != 0) { fclose(f); return NULL; }
    long sz = ftell(f);
    if (sz <= 0 || sz > 4 * 1024 * 1024) { fclose(f); return NULL; }
    rewind(f);
    char* buf = (char*)malloc((size_t)sz + 1);
    if (!buf) { fclose(f); return NULL; }
    size_t got = fread(buf, 1, (size_t)sz, f);
    fclose(f);
    if (got != (size_t)sz) { free(buf); return NULL; }
    buf[sz] = '\0';
    if (out_len) *out_len = (size_t)sz;
    return buf;
}

#define HTTP_GOOGLE_CERT_VERIFIED_PATH "/data/tostonsync/google-certs.verified"

// 0 = not tested this run, 1 = matrix passed, -1 = matrix failed.
static atomic_int s_google_cert_matrix_state = 0;

static int pem_block_count(const char* pem, size_t len) {
    int blocks = 0;
    const char* cursor = pem;
    const char* end = pem + len;
    size_t block_len = 0;
    while (pem_next_cert(&cursor, end, &block_len)) blocks++;
    return blocks;
}

static bool write_embedded_google_certs(bool overwrite) {
    if (!overwrite && access(HTTP_CA_BUNDLE_PATH, F_OK) == 0) return true;

    char tmp[320];
    snprintf(tmp, sizeof(tmp), "%s.tmp.%ld", HTTP_CA_BUNDLE_PATH,
             (long)getpid());
    FILE* f = fopen(tmp, "wb");
    if (!f) {
        log_warn("gdrive-http: cannot create certificate bundle %s", tmp);
        return false;
    }
    bool ok = fwrite(GOOGLE_CERT_BUNDLE, 1, GOOGLE_CERT_BUNDLE_LEN, f) ==
              GOOGLE_CERT_BUNDLE_LEN;
    if (ok) ok = fflush(f) == 0;
    if (ok) ok = fsync(fileno(f)) == 0;
    if (fclose(f) != 0) ok = false;
    if (ok) ok = rename(tmp, HTTP_CA_BUNDLE_PATH) == 0;
    if (!ok) {
        unlink(tmp);
        log_warn("gdrive-http: failed to install certificate bundle at %s",
                 HTTP_CA_BUNDLE_PATH);
        return false;
    }
    chmod(HTTP_CA_BUNDLE_PATH, 0600);
    log_info("gdrive-http: %s Google certificate bundle WE2 + WR2 at %s",
             overwrite ? "repaired" : "installed",
             HTTP_CA_BUNDLE_PATH);
    return true;
}

bool http_google_cert_ensure(void) {
    return write_embedded_google_certs(false);
}

bool http_google_cert_repair(void) {
    atomic_store(&s_google_cert_matrix_state, 0);
    unlink(HTTP_GOOGLE_CERT_VERIFIED_PATH);
    return write_embedded_google_certs(true);
}

static int64_t google_cert_last_verified(void) {
    FILE* f = fopen(HTTP_GOOGLE_CERT_VERIFIED_PATH, "rb");
    if (!f) return 0;
    long long value = 0;
    bool ok = fscanf(f, "%lld", &value) == 1;
    fclose(f);
    return ok && value > 0 ? (int64_t)value : 0;
}

static void google_cert_note_matrix_result(bool ok) {
    atomic_store(&s_google_cert_matrix_state, ok ? 1 : -1);
    if (!ok) return;
    FILE* f = fopen(HTTP_GOOGLE_CERT_VERIFIED_PATH, "wb");
    if (!f) return;
    fprintf(f, "%lld\n", (long long)time(NULL));
    fclose(f);
}

void http_google_cert_status(char* status, size_t status_sz, int* blocks,
                             int64_t* last_verified_unix) {
    size_t len = 0;
    char* pem = read_file_alloc(HTTP_CA_BUNDLE_PATH, &len);
    int count = pem ? pem_block_count(pem, len) : 0;
    bool bundled = pem && len == GOOGLE_CERT_BUNDLE_LEN &&
                   memcmp(pem, GOOGLE_CERT_BUNDLE, len) == 0;
    free(pem);
    const char* value = "missing";
    if (count > 0)
        value = ((bundled && count == 2) ||
                 atomic_load(&s_google_cert_matrix_state) == 1)
                    ? "working" : "needs_repair";
    if (status && status_sz) snprintf(status, status_sz, "%s", value);
    if (blocks) *blocks = count;
    if (last_verified_unix)
        *last_verified_unix = google_cert_last_verified();
}

#define HTTP_CA_DER_DIR "/data/tostonsync/certs"

// Human-readable report of the last CA-load attempt, for /api/test/internet.
static char s_ca_diag[640] = "CA load not attempted";

// Checked child/parent cleanup shared by production and isolated diagnostics.
static bool http_objects_delete(int req, int conn, int tmpl);
static bool http_context_clear(int* hc, int* ssl, int* net);

int http_ca_diag(char* out, size_t out_sz) {
    if (out && out_sz) snprintf(out, out_sz, "%s", s_ca_diag);
    return s_tls_trust_state;
}

// Load DER certs from HTTP_CA_DER_DIR one by one. Returns count loaded.
static int http_tls_load_der_dir(int ssl_ctx) {
    if (!sceSslLoadRootCACert) return 0;
    DIR* d = opendir(HTTP_CA_DER_DIR);
    if (!d) return 0;
    int ok = 0;
    struct dirent* ent;
    while ((ent = readdir(d)) != NULL) {
        size_t nlen = strlen(ent->d_name);
        if (nlen < 5 || strcasecmp(ent->d_name + nlen - 4, ".der") != 0) continue;
        char path[512];
        if ((size_t)snprintf(path, sizeof(path), "%s/%s", HTTP_CA_DER_DIR,
                             ent->d_name) >= sizeof(path)) continue;
        size_t dlen = 0;
        char* der = read_file_alloc(path, &dlen);
        if (!der) continue;
        int rc = sceSslLoadRootCACert(ssl_ctx, der, dlen);
        free(der);
        if (rc == 0) ok++;
        else log_warn("http: DER cert %s failed rc=0x%x", ent->d_name,
                      (unsigned)rc);
    }
    closedir(d);
    return ok;
}

// Load CA trust into the SSL context. MUST run after sceSslInit() and before
// sceHttp2Init(). Tries, in order: (A) the whole PEM bundle in one call,
// (B) each PEM certificate individually, (C) DER files under certs/. Records a
// diagnostic string for the UI. In insecure mode, skips loading entirely.
static void http_tls_load_ca(int ssl_ctx) {
    s_tls_trust_state = 0;
    if (s_tls_insecure) {
        s_tls_trust_state = -1;
        snprintf(s_ca_diag, sizeof(s_ca_diag),
                 "insecure diagnostic mode: CA load skipped, verification off");
        return;
    }
    if (!sceSslLoadRootCACert) {
        s_tls_trust_state = 2;
        snprintf(s_ca_diag, sizeof(s_ca_diag),
                 "sceSslLoadRootCACert not exported; using system store");
        log_warn("http: %s", s_ca_diag);
        return;
    }

    size_t pem_len = 0;
    char* pem = read_file_alloc(HTTP_CA_BUNDLE_PATH, &pem_len);
    if (!pem) {
        // No PEM bundle: still try DER dir before giving up.
        int der_ok = http_tls_load_der_dir(ssl_ctx);
        s_tls_trust_state = der_ok > 0 ? 1 : 2;
        snprintf(s_ca_diag, sizeof(s_ca_diag),
                 "no PEM at %s; DER loaded=%d", HTTP_CA_BUNDLE_PATH, der_ok);
        if (der_ok > 0) log_info("http: CA loaded from DER dir (%d certs)", der_ok);
        else log_warn("http: no CA bundle (%s) and no DER certs — system store",
                      HTTP_CA_BUNDLE_PATH);
        return;
    }

    // Count PEM blocks up front for the diagnostic.
    int blocks = 0;
    { const char* c = pem; const char* end = pem + pem_len; size_t bl;
      while (pem_next_cert(&c, end, &bl)) blocks++; }

    // Strategy A: whole bundle in one call.
    int rcA = sceSslLoadRootCACert(ssl_ctx, pem, pem_len);
    if (rcA == 0) {
        free(pem);
        s_tls_trust_state = 1;
        snprintf(s_ca_diag, sizeof(s_ca_diag),
                 "bundle OK (strategy A): bytes=%zu blocks=%d rc=0x0",
                 pem_len, blocks);
        log_info("http: CA %s", s_ca_diag);
        return;
    }
    log_warn("http: CA load failed strategy=A bytes=%zu blocks=%d rc=0x%x — "
             "retrying per-certificate", pem_len, blocks, (unsigned)rcA);

    // Strategy B: load each certificate on its own. Keep going past failures.
    int ok = 0, fail = 0, first_fail = -1, idx = 0;
    { const char* c = pem; const char* end = pem + pem_len; size_t bl;
      const char* blk;
      while ((blk = pem_next_cert(&c, end, &bl)) != NULL) {
          int rc = sceSslLoadRootCACert(ssl_ctx, blk, bl);
          if (rc == 0) ok++;
          else { fail++; if (first_fail < 0) first_fail = idx; }
          idx++;
      } }
    free(pem);

    if (ok > 0) {
        s_tls_trust_state = 1;
        snprintf(s_ca_diag, sizeof(s_ca_diag),
                 "per-cert OK (strategy B): loaded=%d failed=%d firstFail=%d "
                 "blocks=%d A_rc=0x%x", ok, fail, first_fail, blocks,
                 (unsigned)rcA);
        log_info("http: CA %s", s_ca_diag);
        return;
    }

    // Strategy C: DER files.
    int der_ok = http_tls_load_der_dir(ssl_ctx);
    s_tls_trust_state = der_ok > 0 ? 1 : 2;
    snprintf(s_ca_diag, sizeof(s_ca_diag),
             "CA load FAILED: A_rc=0x%x B_failed=%d/%d DER_loaded=%d (%s)",
             (unsigned)rcA, fail, blocks, der_ok,
             der_ok > 0 ? "DER fallback OK" : "system store");
    if (der_ok > 0) log_info("http: CA loaded from DER dir (%d certs)", der_ok);
    else log_warn("http: %s", s_ca_diag);
}

// Load the CA bundle into the libSceHttp context via sceHttpsLoadCert. This is
// the PRODUCTION trust path — proven safe on hardware (rc=0x0, HTTPS 204), unlike
// sceSslLoadRootCACert. Missing/bad bundle never crashes: requests just fail TLS.
// Named files are loaded first in chain order, then cacert.pem as the fallback.
// Every PEM block is a separate sceHttpsLoadCert call; the API does not split a
// concatenated bundle for us.
#define HTTP_CA_PEM_DIR "/data/tostonsync/certs"

typedef struct {
    int blocks;
    int ok;
    int fail;
    int first_fail;
    int first_fail_rc;
    size_t bytes;
} ca_load_stats_t;

static void http_libhttp_load_pem_file(int http_ctx, const char* path,
                                       ca_load_stats_t* st) {
    size_t pem_len = 0;
    char* pem = read_file_alloc(path, &pem_len);
    if (!pem) return;

    int blocks = 0;
    const char* cursor = pem;
    const char* end = pem + pem_len;
    size_t block_len = 0;
    while (pem_next_cert(&cursor, end, &block_len)) blocks++;
    log_info("gdrive-http: CA bundle blocks=%d path=%s", blocks, path);

    cursor = pem;
    const char* block;
    while ((block = pem_next_cert(&cursor, end, &block_len)) != NULL) {
        sce_ssl_data_t data = { (void*)block, block_len };
        const sce_ssl_data_t* ca = &data;
        int index = ++st->blocks;
        int rc = sceHttpsLoadCert(http_ctx, 1, &ca, NULL, NULL);
        st->bytes += block_len;
        log_info("gdrive-http: sceHttpsLoadCert block=%d bytes=%zu rc=0x%x",
                 index, block_len, (unsigned)rc);
        if (rc == 0) st->ok++;
        else {
            st->fail++;
            if (st->first_fail < 0) {
                st->first_fail = index;
                st->first_fail_rc = rc;
            }
        }
    }
    free(pem);
}

static void http_libhttp_load_ca(int http_ctx) {
    if (!sceHttpsLoadCert) {
        s_tls_trust_state = 2;
        snprintf(s_ca_diag, sizeof(s_ca_diag),
                 "sceHttpsLoadCert not exported; using system store");
        log_warn("gdrive-http: %s", s_ca_diag);
        return;
    }

    ca_load_stats_t st = { .first_fail = -1 };
    static const char* paths[] = {
        HTTP_CA_PEM_DIR "/google-we2.pem",
        HTTP_CA_PEM_DIR "/google-wr2.pem",
        HTTP_CA_PEM_DIR "/google-roots.pem",
        HTTP_CA_BUNDLE_PATH
    };
    for (size_t i = 0; i < sizeof(paths) / sizeof(paths[0]); i++)
        http_libhttp_load_pem_file(http_ctx, paths[i], &st);

    if (st.blocks == 0) {
        s_tls_trust_state = 2;
        snprintf(s_ca_diag, sizeof(s_ca_diag),
                 "Automatic Drive requires Google CA PEM files under %s or %s",
                 HTTP_CA_PEM_DIR, HTTP_CA_BUNDLE_PATH);
        log_warn("gdrive-http: %s", s_ca_diag);
        return;
    }

    log_info("gdrive-http: CA load complete certs=%d loaded_ok=%d loaded_fail=%d "
             "firstFailIndex=%d firstFailRc=0x%x",
             st.blocks, st.ok, st.fail, st.first_fail,
             (unsigned)st.first_fail_rc);
    s_tls_trust_state = st.ok > 0 ? 1 : 2;
    snprintf(s_ca_diag, sizeof(s_ca_diag),
             "libSceHttp CA load certs=%d bytes=%zu loaded=%d failed=%d (%s)",
             st.blocks, st.bytes, st.ok, st.fail,
             st.ok > 0 ? "trusted" : "system store");
}

// EXPERIMENTAL, isolated self-test for sceSslLoadRootCACert. Triggered ONLY by
// the "Test custom CA loading" diagnostic — never during startup or sign-in.
// Uses its own throwaway SSL context so it cannot corrupt the live one, and
// emits breadcrumbs so the last log line before a crash names the culprit.
// Returns the trust-ish result (1 loaded, 0 failed) and fills a report.
int http_ca_selftest(char* out, size_t out_sz) {
    char msg[512];
    int result = 0;

    if (!sceSslLoadRootCACert) {
        snprintf(msg, sizeof(msg),
                 "sceSslLoadRootCACert not exported by this SDK");
        goto done;
    }
    size_t pem_len = 0;
    char* pem = read_file_alloc(HTTP_CA_BUNDLE_PATH, &pem_len);
    if (!pem) {
        snprintf(msg, sizeof(msg), "no PEM at %s", HTTP_CA_BUNDLE_PATH);
        goto done;
    }
    int blocks = 0;
    { const char* c = pem; const char* end = pem + pem_len; size_t bl;
      while (pem_next_cert(&c, end, &bl)) blocks++; }

    log_warn("ca-selftest: before sceSslInit");
    int ctx = sceSslInit(1024 * 1024);
    log_warn("ca-selftest: after sceSslInit ctx=%d", ctx);
    if (ctx < 0) {
        free(pem);
        snprintf(msg, sizeof(msg), "sceSslInit failed rc=%d", ctx);
        goto done;
    }

    log_warn("ca-selftest: before sceSslLoadRootCACert (bundle) bytes=%zu "
             "blocks=%d", pem_len, blocks);
    int rcA = sceSslLoadRootCACert(ctx, pem, pem_len);
    log_warn("ca-selftest: after sceSslLoadRootCACert (bundle) rc=0x%x",
             (unsigned)rcA);

    int ok = 0, fail = 0, first_fail = -1, idx = 0;
    if (rcA != 0) {
        const char* c = pem; const char* end = pem + pem_len; size_t bl;
        const char* blk;
        while ((blk = pem_next_cert(&c, end, &bl)) != NULL) {
            log_warn("ca-selftest: before per-cert #%d (len=%zu)", idx, bl);
            int rc = sceSslLoadRootCACert(ctx, blk, bl);
            log_warn("ca-selftest: after per-cert #%d rc=0x%x", idx,
                     (unsigned)rc);
            if (rc == 0) ok++;
            else { fail++; if (first_fail < 0) first_fail = idx; }
            idx++;
        }
    }

    log_warn("ca-selftest: before sceSslTerm");
    int term_rc = sceSslTerm(ctx);
    log_warn("ca-selftest: after sceSslTerm");
    free(pem);

    result = term_rc == 0 && (rcA == 0 || ok > 0) ? 1 : 0;
    snprintf(msg, sizeof(msg),
             "bytes=%zu blocks=%d bundle_rc=0x%x per_cert_ok=%d fail=%d "
             "firstFail=%d term_rc=0x%x — %s (EXPERIMENTAL: may destabilize; restart if odd)",
             pem_len, blocks, (unsigned)rcA, ok, fail, first_fail, (unsigned)term_rc,
             term_rc != 0 ? "cleanup failed; restart daemon"
                          : result ? "some certs accepted" : "all rejected");

done:
    snprintf(s_ca_diag, sizeof(s_ca_diag), "%s", msg);
    if (out && out_sz) snprintf(out, out_sz, "%s", msg);
    return result;
}

// EXPERIMENTAL, isolated self-test of the libSceHttp (v1) trust path. Builds its
// own net pool + SSL ctx + HTTP ctx, loads the CA bundle via sceHttpsLoadCert,
// sets TLS>=1.2, then does one HTTPS GET to Google infra and reports the status
// and sceHttpsGetSslError. Never runs at startup; own contexts, so a bad call
// hits only this diagnostic. Returns 1 when the HTTPS GET reaches Google (2xx).
int http_https_selftest(char* out, size_t out_sz) {
    char msg[600];
    int result = 0;
    int net = -1, ssl = -1, hc = -1, tmpl = -1, conn = -1, req = -1;

    // Report which libSceHttp symbols resolved. If the ELF is not linked with
    // -lSceHttp, these are all NULL and the test cannot run.
    log_warn("https-selftest: symbols — sceHttpInit=%s sceHttpsLoadCert=%s "
             "sceHttpsGetSslError=%s sceHttpsSetMinSslVersion=%s "
             "CreateTemplate=%s CreateConnection=%s CreateRequest=%s "
             "SendRequest=%s",
             sceHttpInit ? "yes" : "no",
             sceHttpsLoadCert ? "yes" : "no",
             sceHttpsGetSslError ? "yes" : "no",
             sceHttpsSetMinSslVersion ? "yes" : "no",
             sceHttpCreateTemplate ? "yes" : "no",
             sceHttpCreateConnectionWithURL ? "yes" : "no",
             sceHttpCreateRequestWithURL ? "yes" : "no",
             sceHttpSendRequest ? "yes" : "no");

    if (!sceHttpInit || !sceHttpsLoadCert || !sceHttpCreateTemplate ||
        !sceHttpCreateConnectionWithURL || !sceHttpCreateRequestWithURL ||
        !sceHttpSendRequest) {
        snprintf(msg, sizeof(msg),
                 "libSceHttp not linked (Init=%s LoadCert=%s CreateReq=%s "
                 "Send=%s) — add -lSceHttp to the daemon link flags",
                 sceHttpInit ? "yes" : "no",
                 sceHttpsLoadCert ? "yes" : "no",
                 sceHttpCreateRequestWithURL ? "yes" : "no",
                 sceHttpSendRequest ? "yes" : "no");
        goto done;
    }

    log_warn("https-selftest: before sceNetPoolCreate");
    net = sceNetPoolCreate("tsca-https", 64 * 1024, 0);
    log_warn("https-selftest: after sceNetPoolCreate rc=%d", net);
    if (net < 0) { snprintf(msg, sizeof(msg), "sceNetPoolCreate rc=%d", net);
                   goto done; }

    log_warn("https-selftest: before sceSslInit");
    ssl = sceSslInit(1024 * 1024);
    log_warn("https-selftest: after sceSslInit rc=%d", ssl);
    if (ssl < 0) { snprintf(msg, sizeof(msg), "sceSslInit rc=%d", ssl);
                   goto done; }

    log_warn("https-selftest: before sceHttpInit");
    hc = sceHttpInit(net, ssl, 256 * 1024);
    log_warn("https-selftest: after sceHttpInit rc=%d", hc);
    if (hc < 0) { snprintf(msg, sizeof(msg), "sceHttpInit rc=%d", hc);
                  goto done; }

    int minver_rc = -1;
    if (sceHttpsSetMinSslVersion) {
        minver_rc = sceHttpsSetMinSslVersion(hc, SCE_SSL_VERSION_TLS1_2_);
        log_warn("https-selftest: sceHttpsSetMinSslVersion rc=0x%x",
                 (unsigned)minver_rc);
    }

    log_warn("https-selftest: before production CA loader");
    http_libhttp_load_ca(hc);
    int load_rc = s_tls_trust_state == 1 ? 0 : -1;
    log_warn("https-selftest: after production CA loader result=%d", load_rc);

    const char* url = "https://connectivitycheck.gstatic.com/generate_204";
    tmpl = sceHttpCreateTemplate(hc, HTTP_USER_AGENT, SCE_HTTP_VERSION_1_1_, 1);
    if (tmpl < 0) { snprintf(msg, sizeof(msg),
                    "loadCert rc=0x%x; sceHttpCreateTemplate rc=%d",
                    (unsigned)load_rc, tmpl); goto done; }
    conn = sceHttpCreateConnectionWithURL(tmpl, url, 1);
    if (conn < 0) { snprintf(msg, sizeof(msg),
                    "loadCert rc=0x%x; CreateConnection rc=%d",
                    (unsigned)load_rc, conn); goto done; }
    req = sceHttpCreateRequestWithURL(conn, SCE_HTTP_METHOD_GET_, url, 0);
    if (req < 0) { snprintf(msg, sizeof(msg),
                   "loadCert rc=0x%x; CreateRequest rc=%d",
                   (unsigned)load_rc, req); goto done; }

    log_warn("https-selftest: before sceHttpSendRequest");
    int send_rc = sceHttpSendRequest(req, NULL, 0);
    log_warn("https-selftest: after sceHttpSendRequest rc=0x%x",
             (unsigned)send_rc);

    int status = 0;
    if (send_rc >= 0 && sceHttpGetStatusCode)
        sceHttpGetStatusCode(req, &status);

    int ssl_err = 0; unsigned long ssl_detail = 0;
    if (send_rc < 0 && sceHttpsGetSslError) {
        int gerc = sceHttpsGetSslError(req, &ssl_err, &ssl_detail);
        log_warn("https-selftest: sceHttpsGetSslError rc=0x%x errNum=%d "
                 "detail=0x%lx", (unsigned)gerc, ssl_err, ssl_detail);
    }

    result = (send_rc >= 0 && (status == 204 || status == 200)) ? 1 : 0;
    snprintf(msg, sizeof(msg),
             "loadCert rc=0x%x minVer rc=0x%x send rc=0x%x status=%d "
             "sslErr=%d/0x%lx — %s (EXPERIMENTAL)",
             (unsigned)load_rc, (unsigned)minver_rc, (unsigned)send_rc, status,
             ssl_err, ssl_detail,
             result ? "HTTPS OK via libSceHttp" : "HTTPS still failing");

done:
    if (!http_objects_delete(req, conn, tmpl) ||
        !http_context_clear(&hc, &ssl, &net)) {
        result = 0;
        snprintf(msg, sizeof(msg),
                 "HTTPS diagnostic cleanup failed; uncertain resources retained until daemon restart");
    }
    snprintf(s_ca_diag, sizeof(s_ca_diag), "%s", msg);
    if (out && out_sz) snprintf(out, out_sz, "%s", msg);
    log_warn("https-selftest: %s", msg);
    return result;
}

// Decode an SCE error into a short hint. Sub-codes in the 0xFxxx band are
// SSL/TLS-originated (handshake or certificate verification); the 0x8095 error
// band is shared between libSceHttp and libSceHttp2.
static const char* sce_err_hint(unsigned rc) {
    // High sub-code band => SSL/TLS layer (cert verify / handshake).
    if ((rc & 0xF000u) == 0xF000u)
        return "TLS handshake / certificate verification (check CA bundle, "
               "system date/time)";
    return "network / connection";
}

// --------------------------------------------------------------------
// Lazy global init.
// --------------------------------------------------------------------

static int s_net  = -1;  // net memory pool
static int s_ssl  = -1;  // SSL context
static int s_http = -1;  // libSceHttp (v1) context — the production HTTPS path
static bool s_net_initialized = false;
static bool s_context_stale = false;
static unsigned s_http_users = 0;
static bool s_cleanup_failed = false;
static pthread_mutex_t s_init_lock = PTHREAD_MUTEX_INITIALIZER;
static _Atomic bool s_drive_reconnect_pending = false;
static _Atomic bool s_drive_reconnected = false;

// Production transport uses libSceHttp (v1), NOT libSceHttp2. On this hardware
// libSceHttp2 always fails TLS with 0x8095f00c, while libSceHttp + sceHttpsLoadCert
// completes HTTPS to Google (verified: status=204, sslErr=0). Init sequence is the
// one proven by the self-test: net pool -> SSL ctx -> sceHttpInit -> load CA.
static void http_lib_init_once(void) {
    if (!s_net_initialized) {
        sceNetInit();
        s_net_initialized = true;
    }
    s_net = sceNetPoolCreate("tostonsync", 64 * 1024, 0);
    if (s_net < 0) { log_warn("http: sceNetPoolCreate failed (%d)", s_net); return; }
    log_info("gdrive-http: init breadcrumb — before sceSslInit");
    s_ssl = sceSslInit(1024 * 1024);
    log_info("gdrive-http: init breadcrumb — after sceSslInit (ctx=%d)", s_ssl);
    if (s_ssl < 0) { log_warn("http: sceSslInit failed (%d)", s_ssl); return; }

    // Experimental raw-SSL CA path stays OFF by default (it crashed the daemon).
    // sceSslLoadRootCACert is NEVER called here unless explicitly enabled.
    if (s_ca_custom_enabled && !s_tls_insecure) {
        log_warn("gdrive-http: before sceSslLoadRootCACert (experimental, enabled)");
        http_tls_load_ca(s_ssl);
        log_warn("gdrive-http: after experimental CA load (%s)", s_ca_diag);
    }

    if (!sceHttpInit) {
        log_warn("http: libSceHttp not linked (sceHttpInit=NULL) — add -lSceHttp");
        return;
    }
    log_info("gdrive-http: init breadcrumb — before sceHttpInit");
    s_http = sceHttpInit(s_net, s_ssl, 256 * 1024);
    log_info("gdrive-http: init breadcrumb — after sceHttpInit (ctx=%d)", s_http);
    if (s_http < 0) { log_warn("http: sceHttpInit failed (%d)", s_http); return; }

    // TLS >= 1.2 is best-effort: on hardware this returned an error yet the
    // request still succeeded, so a failure here is non-fatal.
    if (sceHttpsSetMinSslVersion) {
        int mv = sceHttpsSetMinSslVersion(s_http, SCE_SSL_VERSION_TLS1_2_);
        log_info("gdrive-http: sceHttpsSetMinSslVersion rc=0x%x (non-fatal)",
                 (unsigned)mv);
    }
    // PROVEN-SAFE production trust: load the CA bundle into the libSceHttp ctx.
    http_libhttp_load_ca(s_http);
    log_info("gdrive-http: using libSceHttp; %s", s_ca_diag);
}

// Stop at the first failed delete/Term: never free an uncertain child's parent.
// For the shared context the caller holds s_init_lock and has no live leases.
static bool http_objects_delete(int req, int conn, int tmpl) {
    if (req >= 0 && (!sceHttpDeleteRequest || sceHttpDeleteRequest(req) != 0))
        return false;
    if (conn >= 0 && (!sceHttpDeleteConnection || sceHttpDeleteConnection(conn) != 0))
        return false;
    return tmpl < 0 || (sceHttpDeleteTemplate && sceHttpDeleteTemplate(tmpl) == 0);
}

static bool http_context_clear(int* hc, int* ssl, int* net) {
    if (*hc >= 0) {
        if (!sceHttpTerm || sceHttpTerm(*hc) != 0) return false;
        *hc = -1;
    }
    if (*ssl >= 0) {
        if (sceSslTerm(*ssl) != 0) return false;
        *ssl = -1;
    }
    if (*net >= 0) {
        if (sceNetPoolDestroy(*net) != 0) return false;
        *net = -1;
    }
    return true;
}

// Each successful acquisition owns a lease through the last SDK object delete.
// ponytail: one shared generation; stale acquisitions fail temporarily rather
// than waiting on slow SDK calls or maintaining multiple TLS generations.
static int http_lib(void) {
    pthread_mutex_lock(&s_init_lock);
    int result;
    if (s_cleanup_failed) {
        result = -EIO; // Unknown SDK object ownership: restart, not unsafe reuse.
    } else if (s_context_stale && s_http_users) {
        result = -EAGAIN; // Existing backoff retries after owners have drained.
    } else if ((s_context_stale || s_http < 0) &&
               !http_context_clear(&s_http, &s_ssl, &s_net)) {
        result = -EIO;
        log_warn("gdrive-http: context cleanup failed; rebuild deferred");
    } else {
        s_context_stale = false;
        if (s_http < 0) http_lib_init_once();
        result = s_http;
        if (result >= 0) s_http_users++;
    }
    pthread_mutex_unlock(&s_init_lock);
    return result;
}

static void http_lib_release(bool clean, bool drive_success) {
    pthread_mutex_lock(&s_init_lock);
    if (!clean) {
        s_cleanup_failed = true;
        log_warn("gdrive-http: SDK object cleanup failed; transport blocked until daemon restart");
    }
    // A request from the pre-resume generation cannot announce reconnection.
    if (clean && drive_success && !s_context_stale && !s_cleanup_failed &&
        atomic_exchange(&s_drive_reconnect_pending, false))
        atomic_store(&s_drive_reconnected, true);
    s_http_users--;
    pthread_mutex_unlock(&s_init_lock);
}

static bool http_request_close(int req, int conn, int tmpl, bool drive_success) {
    bool clean = http_objects_delete(req, conn, tmpl);
    http_lib_release(clean, drive_success);
    return clean;
}

// Public metadata never borrows or changes Drive's trust store. Each explicit
// bounded request owns a private native context until all its children drain.
// ponytail: short-lived contexts avoid another persistent generation/lease pool.
typedef struct { int net, ssl, http; } public_http_context_t;
static atomic_bool s_public_cleanup_failed = false;

static bool http_buffered_close(public_http_context_t* public_ctx,
                                int req, int conn, int tmpl, bool drive_success,
                                http_response_t* out) {
    if (!public_ctx) return http_request_close(req, conn, tmpl, drive_success);
    bool clean = http_objects_delete(req, conn, tmpl) &&
        http_context_clear(&public_ctx->http, &public_ctx->ssl, &public_ctx->net);
    if (!clean) {
        atomic_store(&s_public_cleanup_failed, true);
        if (out) out->transport_error = -EIO;
        log_warn("public-metadata-http: uncertain cleanup; private resources retained until daemon restart");
    }
    return clean;
}

static int http_public_context_open(public_http_context_t* ctx) {
    // No disk trust files, config flags or insecure options are used here.
    pthread_mutex_lock(&s_init_lock);
    int rc = atomic_load(&s_public_cleanup_failed) ? -EIO :
        (s_tls_insecure || s_tls_trust_state == -1) ? -EPERM : 0;
    if (!rc && !s_net_initialized) {
        rc = sceNetInit();
        if (!rc) s_net_initialized = true;
    }
    pthread_mutex_unlock(&s_init_lock);
    if (rc) return rc;
    if (!sceHttpInit || !sceHttpsLoadCert) return -ENOSYS;

    ctx->net = sceNetPoolCreate("tostonsync-public", 64 * 1024, 0);
    if (ctx->net < 0) return ctx->net;
    ctx->ssl = sceSslInit(1024 * 1024);
    if (ctx->ssl < 0) { rc = ctx->ssl; goto failed; }
    ctx->http = sceHttpInit(ctx->net, ctx->ssl, 256 * 1024);
    if (ctx->http < 0) { rc = ctx->http; goto failed; }
    if (sceHttpsSetMinSslVersion)
        sceHttpsSetMinSslVersion(ctx->http, SCE_SSL_VERSION_TLS1_2_);

    // pem_next_cert() uses strstr: terminate a bounded copy rather than reading
    // past the generated byte array. Loading copies roots, never private keys.
    char pem[PUBLIC_METADATA_CERT_BUNDLE_LEN + 1];
    memcpy(pem, PUBLIC_METADATA_CERT_BUNDLE, PUBLIC_METADATA_CERT_BUNDLE_LEN);
    pem[PUBLIC_METADATA_CERT_BUNDLE_LEN] = '\0';
    const char* cursor = pem; const char* end = pem + PUBLIC_METADATA_CERT_BUNDLE_LEN;
    enum { PUBLIC_ROOT_COUNT = 3 };
    sce_ssl_data_t roots[PUBLIC_ROOT_COUNT];
    const sce_ssl_data_t* ca[PUBLIC_ROOT_COUNT];
    size_t length = 0; const char* block; unsigned loaded = 0;
    while ((block = pem_next_cert(&cursor, end, &length)) != NULL) {
        if (loaded == PUBLIC_ROOT_COUNT) { rc = -EINVAL; goto failed; }
        roots[loaded] = (sce_ssl_data_t){ (void*)block, length };
        ca[loaded] = &roots[loaded];
        loaded++;
    }
    if (loaded != PUBLIC_ROOT_COUNT) { rc = -EINVAL; goto failed; }
    // Supply the complete list once; do not depend on repeated calls appending
    // rather than replacing the native context's certificate store.
    rc = sceHttpsLoadCert(ctx->http, PUBLIC_ROOT_COUNT, ca, NULL, NULL);
    if (rc) {
        log_warn("public-metadata-http: approved root list failed rc=0x%x", (unsigned)rc);
        goto failed;
    }
    log_debug("public-metadata-http: %u approved embedded roots loaded into private context", loaded);
    return 0;
failed:
    if (!http_buffered_close(ctx, -1, -1, -1, false, NULL)) return -EIO;
    return rc;
}

const char* http_transport_local_detail(int error) {
    if (error == -EAGAIN)
        return "HTTPS contexts are waiting for active requests to finish. Retry shortly.";
    if (error == -EIO)
        return "HTTPS resource cleanup failed. Retry, or restart TostonSync if it persists.";
    return NULL;
}

static void http_client_mark_stale_for(bool drive_was_ready,
                                       const char* reason) {
    pthread_mutex_lock(&s_init_lock);
    s_context_stale = true;
    atomic_store(&s_drive_reconnect_pending, drive_was_ready);
    atomic_store(&s_drive_reconnected, false);
    pthread_mutex_unlock(&s_init_lock);
    log_info("gdrive-http: contexts marked stale %s", reason);
}

void http_client_mark_stale(bool drive_was_ready) {
    http_client_mark_stale_for(drive_was_ready, "after resume");
}

void http_client_rebuild_after_cert_repair(void) {
    http_client_mark_stale_for(false, "after certificate repair");
}

bool http_client_take_drive_reconnected(void) {
    return atomic_exchange(&s_drive_reconnected, false);
}

// --------------------------------------------------------------------
// Internal common path (libSceHttp v1).
// --------------------------------------------------------------------

typedef struct {
    const char* name;
    const char* value;
} hdr_t;

// Best-effort timeouts on a libSceHttp id: DNS/connect 20 s, send/recv 60 s.
static void apply_http_timeouts(int id) {
    if (sceHttpSetResolveTimeOut) sceHttpSetResolveTimeOut(id, 20u * 1000000u);
    if (sceHttpSetConnectTimeOut) sceHttpSetConnectTimeOut(id, 20u * 1000000u);
    if (sceHttpSetSendTimeOut)    sceHttpSetSendTimeOut(id, 60u * 1000000u);
    if (sceHttpSetRecvTimeOut)    sceHttpSetRecvTimeOut(id, 60u * 1000000u);
}

// One buffered HTTPS request over libSceHttp. template -> connection -> request
// -> headers -> send -> status -> headers -> body. Same public contract as
// before, so gdrive.c is unchanged. Cleans up every object it created.
static int send_request_impl(const char* url, const char* method,
                        const hdr_t* extra, size_t extra_count,
                        const void* body, size_t body_len,
                        http_response_t* out, size_t response_limit, bool public_only) {
    if (out) { out->transport_error = 0; out->ssl_error = 0; out->ssl_detail = 0; }
    public_http_context_t private_ctx = { .net = -1, .ssl = -1, .http = -1 };
    public_http_context_t* public_ctx = public_only ? &private_ctx : NULL;
    int hc;
    if (public_ctx) {
        int rc = http_public_context_open(public_ctx);
        if (rc) { if (out) out->transport_error = rc; return -1; }
        hc = public_ctx->http;
    } else hc = http_lib();
    if (hc < 0) {
        if (out) out->transport_error = hc;
        return -1;
    }
    if (public_only && (s_tls_insecure || s_tls_trust_state == -1)) {
        if (out) out->transport_error = -EPERM;
        http_buffered_close(public_ctx, -1, -1, -1, false, out);
        return -1;
    }
    int tmpl = sceHttpCreateTemplate(hc, HTTP_USER_AGENT, SCE_HTTP_VERSION_1_1_, 1);
    if (tmpl < 0) {
        if (out) out->transport_error = tmpl;
        http_buffered_close(public_ctx, -1, -1, -1, false, out);
        return -1;
    }
    if (public_only) {
        if (sceHttpSetResolveTimeOut) sceHttpSetResolveTimeOut(tmpl, 10u * 1000000u);
        if (sceHttpSetConnectTimeOut) sceHttpSetConnectTimeOut(tmpl, 10u * 1000000u);
        if (sceHttpSetSendTimeOut) sceHttpSetSendTimeOut(tmpl, 10u * 1000000u);
        if (sceHttpSetRecvTimeOut) sceHttpSetRecvTimeOut(tmpl, 10u * 1000000u);
        int redirect = sceHttpSetAutoRedirect ? sceHttpSetAutoRedirect(tmpl, 0) : -ENOSYS;
        if (redirect != 0) {
            bool clean = http_buffered_close(public_ctx, -1, -1, tmpl, false, out);
            if (out) out->transport_error = clean ? redirect : -EIO;
            return -1;
        }
    } else apply_http_timeouts(tmpl);
    int conn = sceHttpCreateConnectionWithURL(tmpl, url, 1);
    if (conn < 0) {
        if (out) out->transport_error = conn;
        http_buffered_close(public_ctx, -1, -1, tmpl, false, out);
        return -1;
    }
    int req = sceHttpCreateRequestWithURL(conn, http_method_enum(method), url,
                                          (uint64_t)body_len);
    if (req < 0) {
        if (out) out->transport_error = req;
        http_buffered_close(public_ctx, -1, conn, tmpl, false, out);
        return -1;
    }
    for (size_t i = 0; i < extra_count; i++) {
        int header_rc = sceHttpAddRequestHeader ?
            sceHttpAddRequestHeader(req, extra[i].name, extra[i].value,
                                    SCE_HTTP_HEADER_OVERWRITE_) : -ENOSYS;
        if (public_only && header_rc < 0) {
            bool clean = http_buffered_close(public_ctx, req, conn, tmpl, false, out);
            if (out) out->transport_error = clean ? header_rc : -EIO;
            return -1;
        }
    }

    log_debug("gdrive-http: request %s %s", method ? method : "GET", url);
    int rc = sceHttpSendRequest(req, body, body_len);
    if (rc < 0) {
        int ssl_err = 0; unsigned long ssl_detail = 0;
        if (sceHttpsGetSslError &&
            sceHttpsGetSslError(req, &ssl_err, &ssl_detail) < 0 && public_only) {
            // Failed diagnostic queries are not evidence of a TLS cause.
            ssl_err = 0; ssl_detail = 0;
        }
        if (out) { out->ssl_error = ssl_err; out->ssl_detail = ssl_detail; }
        // This is the libSceHttp (v1) path — label it correctly (the 0x8095
        // error band is shared with libSceHttp2 but we are NOT using http2 here).
        log_warn("gdrive-http: sceHttpSendRequest(%s) failed rc=0x%x "
                 "[libSceHttp %s] sslErr=%d/0x%lx", url, (unsigned)rc,
                 sce_err_hint((unsigned)rc), ssl_err, ssl_detail);
        if (out) out->transport_error = rc;
        http_buffered_close(public_ctx, req, conn, tmpl, false, out);
        return -1;
    }

    int status = 0;
    if (sceHttpGetStatusCode) sceHttpGetStatusCode(req, &status);
    // Public diagnostics retain an observed status even if later body reading
    // or SDK cleanup fails. Existing authenticated callers are unchanged.
    if (public_only && out) out->status = status;
    log_debug("gdrive-http: status=%d %s", status, url);

    char* response_headers = NULL;
    size_t response_headers_len = 0;
    char* raw_headers = NULL;
    size_t raw_headers_len = 0;
    if (sceHttpGetAllResponseHeaders &&
        sceHttpGetAllResponseHeaders(req, &raw_headers, &raw_headers_len) >= 0 &&
        raw_headers && raw_headers_len) {
        if (public_only && raw_headers_len > 8192) {
            bool clean = http_buffered_close(public_ctx, req, conn, tmpl, false, out);
            if (out) out->transport_error = clean ? -EFBIG : -EIO;
            return -1;
        }
        response_headers = (char*)malloc(raw_headers_len + 1);
        if (response_headers) {
            memcpy(response_headers, raw_headers, raw_headers_len);
            response_headers[raw_headers_len] = '\0';
            response_headers_len = raw_headers_len;
        }
    }

    // Stream body into a growable buffer.
    size_t cap = response_limit ? response_limit + 1 : 8192, len = 0;
    char*  buf = (char*)malloc(cap);
    if (!buf) {
        free(response_headers);
        if (out) out->transport_error = -ENOMEM;
        http_buffered_close(public_ctx, req, conn, tmpl, false, out);
        return -1;
    }
    for (;;) {
        if (!response_limit && len + 4096 > cap) {
            cap *= 2;
            char* nb = (char*)realloc(buf, cap);
            if (!nb) {
                free(buf);
                free(response_headers);
                if (out) out->transport_error = -ENOMEM;
                http_buffered_close(public_ctx, req, conn, tmpl, false, out);
                return -1;
            }
            buf = nb;
        }
        size_t read_limit = response_limit && cap - len < 4096 ? cap - len : 4096;
        int n = sceHttpReadData ? sceHttpReadData(req, buf + len, read_limit) : -1;
        if (n < 0) {
            free(buf);
            free(response_headers);
            if (out) out->transport_error = n;
            http_buffered_close(public_ctx, req, conn, tmpl, false, out);
            return -1;
        }
        if (n == 0) break;
        if (response_limit && ((size_t)n > read_limit || (size_t)n > response_limit - len)) {
            free(buf);
            free(response_headers);
            bool clean = http_buffered_close(public_ctx, req, conn, tmpl, false, out);
            if (out) out->transport_error = clean ? -EFBIG : -EIO;
            return -1;
        }
        len += (size_t)n;
    }
    buf[len < cap ? len : cap - 1] = '\0';
    log_debug("gdrive-http: body length=%zu %s", len, url);
    bool drive_success = !public_only && status >= 200 && status < 300 &&
        (strstr(url, "https://www.googleapis.com/drive/v3/") ||
         strstr(url, "https://www.googleapis.com/upload/drive/v3/"));
    if (!http_buffered_close(public_ctx, req, conn, tmpl, drive_success, out)) {
        free(buf);
        free(response_headers);
        if (out) out->transport_error = -EIO;
        return -1;
    }
    if (out) {
        out->status   = status;
        out->body     = buf;
        out->body_len = len;
        out->headers = response_headers;
        out->headers_len = response_headers_len;
    } else {
        free(buf);
        free(response_headers);
    }
    return 0;
}

// Existing callers retain their original buffering and timeout behavior.
static int send_request(const char* url, const char* method,
                        const hdr_t* extra, size_t extra_count,
                        const void* body, size_t body_len,
                        http_response_t* out) {
    return send_request_impl(url, method, extra, extra_count, body, body_len, out, 0, false);
}

void http_response_free(http_response_t* r) {
    if (!r) return;
    free(r->body);
    free(r->headers);
    r->body = NULL;
    r->body_len = 0;
    r->headers = NULL;
    r->headers_len = 0;
    r->status = 0;
    r->transport_error = 0;
    r->ssl_error = 0;
    r->ssl_detail = 0;
}

static bool response_header(const http_response_t* r, const char* name,
                            char* out, size_t out_sz) {
    if (!r || !r->headers || !name || !out || out_sz == 0) return false;
    size_t name_len = strlen(name);
    const char* p = r->headers;
    const char* end = p + r->headers_len;
    while (p < end) {
        const char* line_end = p;
        while (line_end < end && *line_end != '\r' && *line_end != '\n') line_end++;
        const char* colon = p;
        while (colon < line_end && *colon != ':') colon++;
        if (colon < line_end && (size_t)(colon - p) == name_len &&
            strncasecmp(p, name, name_len) == 0) {
            const char* value = colon + 1;
            while (value < line_end && (*value == ' ' || *value == '\t')) value++;
            size_t n = (size_t)(line_end - value);
            if (n >= out_sz) n = out_sz - 1;
            memcpy(out, value, n);
            out[n] = '\0';
            return true;
        }
        p = line_end;
        while (p < end && (*p == '\r' || *p == '\n')) p++;
    }
    return false;
}

// --------------------------------------------------------------------
// Public helpers.
// --------------------------------------------------------------------

bool http_get_auth(const char* url, const char* bearer,
                   http_response_t* out) {
    char auth[2200];
    snprintf(auth, sizeof(auth), "Bearer %s", bearer);
    hdr_t h[1] = {{"Authorization", auth}};
    return send_request(url, HTTP_GET, h, 1, NULL, 0, out) == 0;
}

bool http_get_public_catalog(const char* url, const char* etag,
                             size_t max_bytes, http_response_t* out) {
    if (!out) return false;
    memset(out, 0, sizeof(*out));
    if (!url || strcmp(url, "https://raw.githubusercontent.com/andshrew/PlayStation-Titles/main/PS5_Titles.tsv") ||
        !max_bytes || max_bytes > 4u * 1024u * 1024u) {
        out->transport_error = -EINVAL; return false;
    }
    size_t n = etag ? strlen(etag) : 0;
    const char* value = etag ? etag : "";
    size_t start = n > 2 && !strncmp(value, "W/", 2) ? 2 : 0;
    if (n && (n >= 128 || n < start + 2 || value[start] != '"' || value[n - 1] != '"')) {
        out->transport_error = -EINVAL; return false;
    }
    for (size_t i = start + 1; n && i < n - 1; i++) {
        if ((unsigned char)value[i] < 0x21 || (unsigned char)value[i] > 0x7e || value[i] == '"') {
            out->transport_error = -EINVAL; return false;
        }
    }
    hdr_t header = {"If-None-Match", value};
    return send_request_impl(url, HTTP_GET, &header, n ? 1 : 0, NULL, 0,
                             out, max_bytes, true) == 0;
}

bool http_get_public_limited(const char* url, size_t max_bytes,
                             http_response_t* out) {
    if (!out) return false;
    memset(out, 0, sizeof(*out));
    if (!url || strncmp(url, "https://", 8) || !max_bytes || max_bytes > 512u * 1024u) {
        out->transport_error = -EINVAL;
        return false;
    }
    size_t authority_len = strcspn(url + 8, "/?#");
    bool invalid_url = !authority_len || memchr(url + 8, '@', authority_len) || strchr(url, '\\');
    for (const unsigned char* p = (const unsigned char*)url; *p; p++)
        if (*p <= 0x20 || *p == 0x7f) invalid_url = true;
    if (invalid_url) { out->transport_error = -EINVAL; return false; }
    if (s_tls_insecure || s_tls_trust_state == -1) {
        out->transport_error = -EPERM;
        return false;
    }
    return send_request_impl(url, HTTP_GET, NULL, 0, NULL, 0, out, max_bytes, true) == 0;
}

bool http_get_auth_to_file(const char* url, const char* bearer,
                           const char* local_path) {
    return http_get_auth_to_file_limited(url, bearer, local_path, 0);
}

bool http_get_auth_to_file_limited(const char* url, const char* bearer,
                                   const char* local_path,
                                   uint64_t max_bytes) {
    int hc = http_lib(); if (hc < 0) return false;
    int tmpl = sceHttpCreateTemplate(hc, HTTP_USER_AGENT, SCE_HTTP_VERSION_1_1_, 1);
    if (tmpl < 0) { http_lib_release(true, false); return false; }
    apply_http_timeouts(tmpl);
    int conn = sceHttpCreateConnectionWithURL(tmpl, url, 1);
    if (conn < 0) { http_request_close(-1, -1, tmpl, false); return false; }
    int req  = sceHttpCreateRequestWithURL(conn, SCE_HTTP_METHOD_GET_, url, 0);
    if (req < 0) { http_request_close(-1, conn, tmpl, false);
                   return false; }

    char auth[2200];
    snprintf(auth, sizeof(auth), "Bearer %s", bearer);
    if (sceHttpAddRequestHeader)
        sceHttpAddRequestHeader(req, "Authorization", auth,
                                SCE_HTTP_HEADER_OVERWRITE_);

    int rc = sceHttpSendRequest(req, NULL, 0);
    int status = 0;
    if (rc >= 0 && sceHttpGetStatusCode) sceHttpGetStatusCode(req, &status);
    if (rc < 0 || status != 200) {
        log_warn("gdrive-http: download failed (status=%d rc=0x%x)", status,
                 (unsigned)rc);
        http_request_close(req, conn, tmpl, false);
        return false;
    }

    FILE* f = fopen(local_path, "wb");
    if (!f) {
        http_request_close(req, conn, tmpl, false);
        return false;
    }

    bool ok = true;
    uint64_t total = 0;
    char buf[64 * 1024];
    for (;;) {
        int n = sceHttpReadData ? sceHttpReadData(req, buf, sizeof(buf)) : -1;
        if (n < 0) { ok = false; break; }
        if (n == 0) break;
        if (max_bytes && total + (uint64_t)n > max_bytes) {
            log_warn("http: download exceeded cap (%llu bytes)",
                     (unsigned long long)max_bytes);
            ok = false;
            break;
        }
        if (fwrite(buf, 1, (size_t)n, f) != (size_t)n) {
            ok = false;
            break;
        }
        total += (uint64_t)n;
    }
    if (fclose(f) != 0) ok = false;
    if (!http_request_close(req, conn, tmpl, false)) ok = false;
    if (!ok) unlink(local_path);
    return ok;
}

bool http_get_auth_to_file_resumable(const char* url, const char* bearer,
                                     const char* local_path,
                                     uint64_t expected_bytes,
                                     uint64_t max_bytes) {
    if (!url || !bearer || !local_path || !expected_bytes ||
        (max_bytes && expected_bytes > max_bytes)) return false;
    char part[1024];
    if (snprintf(part, sizeof(part), "%s.part", local_path) >= (int)sizeof(part))
        return false;

    struct stat st;
    uint64_t offset = 0;
    if (stat(part, &st) == 0 && st.st_size >= 0)
        offset = (uint64_t)st.st_size;
    if (offset > expected_bytes) {
        unlink(part);
        offset = 0;
    }

    for (int attempt = 0; attempt < 4 && offset < expected_bytes; attempt++) {
        int hc = http_lib();
        if (hc < 0) break;
        int tmpl = sceHttpCreateTemplate(hc, HTTP_USER_AGENT,
                                         SCE_HTTP_VERSION_1_1_, 1);
        if (tmpl < 0) { http_lib_release(true, false); break; }
        apply_http_timeouts(tmpl);
        int conn = sceHttpCreateConnectionWithURL(tmpl, url, 1);
        if (conn < 0) { http_request_close(-1, -1, tmpl, false); break; }
        int req = sceHttpCreateRequestWithURL(conn, SCE_HTTP_METHOD_GET_, url, 0);
        if (req < 0) { http_request_close(-1, conn, tmpl, false);
                       break; }

        char auth[2200], range[96];
        snprintf(auth, sizeof(auth), "Bearer %s", bearer);
        if (sceHttpAddRequestHeader)
            sceHttpAddRequestHeader(req, "Authorization", auth,
                                    SCE_HTTP_HEADER_OVERWRITE_);
        if (offset && sceHttpAddRequestHeader) {
            snprintf(range, sizeof(range), "bytes=%llu-",
                     (unsigned long long)offset);
            sceHttpAddRequestHeader(req, "Range", range,
                                    SCE_HTTP_HEADER_OVERWRITE_);
        }
        int rc = sceHttpSendRequest(req, NULL, 0);
        int status = 0;
        if (rc >= 0 && sceHttpGetStatusCode) sceHttpGetStatusCode(req, &status);
        if (rc < 0 || (status != 200 && status != 206)) {
            log_warn("gdrive-http: resumable download failed (status=%d rc=0x%x)",
                     status, (unsigned)rc);
            if (!http_request_close(req, conn, tmpl, false)) return false;
            continue;
        }

        // A 200 response ignored Range. Restart the partial file so bytes are
        // never duplicated.
        const char* mode = (offset && status == 206) ? "ab" : "wb";
        if (status == 200) offset = 0;
        FILE* f = fopen(part, mode);
        if (!f) {
            http_request_close(req, conn, tmpl, false);
            break;
        }
        bool io_ok = true;
        char buf[64 * 1024];
        for (;;) {
            int n = sceHttpReadData ? sceHttpReadData(req, buf, sizeof(buf)) : -1;
            if (n == 0) break;
            if (n < 0 || offset + (uint64_t)n > expected_bytes ||
                (max_bytes && offset + (uint64_t)n > max_bytes)) {
                io_ok = false;
                break;
            }
            if (fwrite(buf, 1, (size_t)n, f) != (size_t)n) {
                // A short fwrite may have appended some bytes. Roll back to
                // the last byte count acknowledged in `offset` before retry.
                ftruncate(fileno(f), (off_t)offset);
                io_ok = false;
                break;
            }
            offset += (uint64_t)n;
        }
        if (fflush(f) != 0 || fsync(fileno(f)) != 0) io_ok = false;
        if (fclose(f) != 0) io_ok = false;
        if (!http_request_close(req, conn, tmpl, false)) return false;
        if (!io_ok) {
            if (offset == expected_bytes) return false;
            continue;
        }
    }

    if (offset != expected_bytes) {
        log_warn("http: resumable download incomplete (%llu/%llu bytes)",
                 (unsigned long long)offset,
                 (unsigned long long)expected_bytes);
        return false; // keep .part so a later retry can resume
    }
    // A previous attempt may have received every byte but failed to flush.
    // Reconfirm persistence even when the loop reused an already-full .part.
    FILE* complete = fopen(part, "r+b");
    if (!complete) return false;
    bool durable = fsync(fileno(complete)) == 0;
    if (fclose(complete) != 0) durable = false;
    if (!durable) return false;
    unlink(local_path);
    if (rename(part, local_path) != 0) return false;
    return true;
}

bool http_post_form(const char* url, const char* form_body,
                    http_response_t* out) {
    hdr_t h[1] = {{"Content-Type", "application/x-www-form-urlencoded"}};
    return send_request(url, HTTP_POST, h, 1,
                        form_body, strlen(form_body), out) == 0;
}

bool http_post_json_auth(const char* url, const char* bearer,
                         const char* json_body, http_response_t* out) {
    char auth[2200];
    snprintf(auth, sizeof(auth), "Bearer %s", bearer);
    hdr_t h[2] = {{"Authorization", auth},
                  {"Content-Type",  "application/json; charset=UTF-8"}};
    return send_request(url, HTTP_POST, h, 2,
                        json_body, strlen(json_body), out) == 0;
}

bool http_delete_auth(const char* url, const char* bearer,
                      http_response_t* out) {
    char auth[2200];
    snprintf(auth, sizeof(auth), "Bearer %s", bearer);
    hdr_t h[1] = {{"Authorization", auth}};
    return send_request(url, HTTP_DELETE, h, 1, NULL, 0, out) == 0;
}

bool http_patch_json_auth(const char* url, const char* bearer,
                          const char* json_body, http_response_t* out) {
    char auth[2200];
    snprintf(auth, sizeof(auth), "Bearer %s", bearer);
    // Google supports method override; libSceHttp's enum has no PATCH verb.
    hdr_t h[3] = {{"Authorization", auth},
                  {"Content-Type", "application/json; charset=UTF-8"},
                  {"X-HTTP-Method-Override", "PATCH"}};
    return send_request(url, HTTP_POST, h, 3,
                        json_body, strlen(json_body), out) == 0;
}

static bool committed_offset(const http_response_t* r, uint64_t* next) {
    char range[128];
    if (!response_header(r, "Range", range, sizeof(range))) return false;
    const char* dash = strrchr(range, '-');
    if (!dash || !dash[1]) return false;
    char* tail = NULL;
    unsigned long long last = strtoull(dash + 1, &tail, 10);
    if (tail == dash + 1) return false;
    *next = (uint64_t)last + 1;
    return true;
}

bool http_post_resumable_file_auth(const char* init_url, const char* bearer,
                                   const char* json_metadata,
                                   const char* content_type,
                                   const char* file_path,
                                   size_t chunk_bytes,
                                   uint64_t max_bytes,
                                   http_response_t* out) {
    if (!init_url || !bearer || !json_metadata || !file_path ||
        chunk_bytes == 0 || chunk_bytes % (256 * 1024) != 0) return false;
    struct stat st;
    if (stat(file_path, &st) != 0 || st.st_size < 0) return false;
    uint64_t total = (uint64_t)st.st_size;
    if (!total || (max_bytes && total > max_bytes)) return false;

    char auth[2200], total_s[32];
    snprintf(auth, sizeof(auth), "Bearer %s", bearer);
    snprintf(total_s, sizeof(total_s), "%llu", (unsigned long long)total);
    const char* ctype = (content_type && content_type[0])
        ? content_type : "application/octet-stream";
    hdr_t init_headers[4] = {
        {"Authorization", auth},
        {"Content-Type", "application/json; charset=UTF-8"},
        {"X-Upload-Content-Type", ctype},
        {"X-Upload-Content-Length", total_s},
    };
    http_response_t init = {0};
    if (send_request(init_url, HTTP_POST, init_headers, 4,
                     json_metadata, strlen(json_metadata), &init) != 0 ||
        (init.status != 200 && init.status != 201)) {
        log_warn("http: resumable upload session failed (status=%d)", init.status);
        http_response_free(&init);
        return false;
    }
    char session[2048];
    bool have_session = response_header(&init, "Location", session, sizeof(session));
    http_response_free(&init);
    if (!have_session || strncmp(session, "https://", 8) != 0) {
        log_warn("http: resumable upload returned no HTTPS session URL");
        return false;
    }

    FILE* f = fopen(file_path, "rb");
    char* chunk = (char*)malloc(chunk_bytes);
    if (!f || !chunk) { if (f) fclose(f); free(chunk); return false; }
    uint64_t offset = 0;
    int stalled_retries = 0;
    bool ok = false;
    http_response_t final = {0};
    jobs_progress(0, total, true);
    while (offset < total) {
        size_t want = (size_t)((total - offset < chunk_bytes)
            ? total - offset : chunk_bytes);
        if (fseeko(f, (off_t)offset, SEEK_SET) != 0 ||
            fread(chunk, 1, want, f) != want) break;
        char content_range[128];
        snprintf(content_range, sizeof(content_range), "bytes %llu-%llu/%llu",
                 (unsigned long long)offset,
                 (unsigned long long)(offset + want - 1),
                 (unsigned long long)total);
        hdr_t h[3] = {
            {"Authorization", auth},
            {"Content-Type", ctype},
            {"Content-Range", content_range},
        };
        http_response_t r = {0};
        int request_ok = send_request(session, HTTP_PUT, h, 3,
                                      chunk, want, &r) == 0;
        if (request_ok && (r.status == 200 || r.status == 201)) {
            final = r;
            memset(&r, 0, sizeof(r));
            offset = total;
            jobs_progress(offset, total, true);
            ok = true;
            break;
        }
        if (request_ok && r.status == 308) {
            uint64_t next = 0;
            if (!committed_offset(&r, &next) || next <= offset || next > total) {
                http_response_free(&r);
                break;
            }
            offset = next;
            jobs_progress(offset, total, true);
            stalled_retries = 0;
            http_response_free(&r);
            continue;
        }
        log_warn("http: resumable upload chunk failed at %llu (status=%d)",
                 (unsigned long long)offset, r.status);
        http_response_free(&r);

        // Ask Drive how much it committed before retrying. This makes a lost
        // 308 response safe: already accepted bytes are not uploaded twice.
        char query_range[96];
        snprintf(query_range, sizeof(query_range), "bytes */%llu",
                 (unsigned long long)total);
        hdr_t qh[3] = {
            {"Authorization", auth},
            {"Content-Type", ctype},
            {"Content-Range", query_range},
        };
        http_response_t q = {0};
        if (send_request(session, HTTP_PUT, qh, 3, NULL, 0, &q) != 0) {
            http_response_free(&q);
            break;
        }
        if (q.status == 200 || q.status == 201) {
            final = q;
            memset(&q, 0, sizeof(q));
            offset = total;
            jobs_progress(offset, total, true);
            ok = true;
            break;
        }
        uint64_t next = 0;
        bool have_range = committed_offset(&q, &next);
        bool resume = q.status == 308 && (!have_range || next <= total);
        if (!have_range) next = 0; // 308 without Range means nothing committed
        http_response_free(&q);
        if (!resume) break;
        if (next <= offset) {
            if (++stalled_retries > 3) break;
        } else {
            stalled_retries = 0;
        }
        offset = next;
        jobs_progress(offset, total, true);
    }
    free(chunk);
    fclose(f);
    if (!ok) {
        http_response_free(&final);
        return false;
    }
    if (out) *out = final;
    else http_response_free(&final);
    return true;
}

// Connectivity probe used by the "Test PS5 internet" button and by the Drive
// failure path to classify what actually broke. The plain-HTTP leg has no TLS,
// so it isolates DNS+TCP from the TLS layer: if plain succeeds but TLS fails,
// the problem is certificate/handshake, not the network.
bool http_connectivity_probe(http_probe_t* out) {
    if (out) memset(out, 0, sizeof(*out));

    http_response_t r = {0};
    int prc = send_request("http://connectivitycheck.gstatic.com/generate_204",
                           HTTP_GET, NULL, 0, NULL, 0, &r);
    bool plain_ok = (prc == 0) && (r.status == 204 || r.status == 200);
    if (out) {
        out->plain_ok = plain_ok;
        out->plain_status = r.status;
        out->plain_transport_error = r.transport_error;
    }
    http_response_free(&r);

    http_response_t s = {0};
    int src = send_request("https://connectivitycheck.gstatic.com/generate_204",
                          HTTP_GET, NULL, 0, NULL, 0, &s);
    bool tls_ok = (src == 0) && (s.status == 204 || s.status == 200);
    if (out) {
        out->tls_ok = tls_ok;
        out->tls_status = s.status;
        out->tls_transport_error = s.transport_error;
        out->trust_state = s_tls_trust_state;
    }
    http_response_free(&s);

    return plain_ok && tls_ok;
}

// --------------------------------------------------------------------
// EXPERIMENTAL OAuth HTTPS matrix — DIAGNOSTIC ONLY.
//
// Runs the exact request shapes OAuth needs, over the live libSceHttp transport
// (send_request creates a fresh template/connection/request per call and uses
// the CA already loaded at init). Isolates whether the failure is TLS/host,
// GET-vs-POST, or body/Content-Length handling for oauth2.googleapis.com. Never
// runs at startup; triggered only by the diagnostic button.
// --------------------------------------------------------------------
static int matrix_one(const char* prefix, const char* tag, const char* url,
                       const char* method, const hdr_t* h, size_t hn,
                       const char* body, int expected_status,
                       char** cur, char* end) {
    http_response_t r = {0};
    int rc = send_request(url, method, h, hn, body,
                          body ? strlen(body) : 0, &r);
    int transport = (rc == 0) ? 0 : r.transport_error;
    unsigned terr = (unsigned)transport;
    bool ok = google_matrix_result_ok(transport, r.ssl_error,
                                      r.status, expected_status);
    if (ok)
        log_info("%s: %s OK rc=0x%x status=%d sslErr=%d/0x%lx bodyLen=%zu",
                 prefix, tag, terr, r.status, r.ssl_error,
                 r.ssl_detail, r.body_len);
    else
        log_warn("%s: %s FAILED expected=%d rc=0x%x status=%d "
                 "sslErr=%d/0x%lx bodyLen=%zu", prefix, tag, expected_status,
                 terr, r.status, r.ssl_error, r.ssl_detail, r.body_len);
    if (cur && *cur && end && *cur < end)
        *cur += snprintf(*cur, (size_t)(end - *cur),
                         "%s: %s expected=%d rc=0x%x status=%d "
                         "sslErr=%d/0x%lx len=%zu\n",
                         tag, ok ? "OK" : "FAILED", expected_status, terr,
                         r.status, r.ssl_error, r.ssl_detail, r.body_len);
    int result = http_transport_local_detail(transport) ? transport : (ok ? 1 : 0);
    http_response_free(&r);
    return result;
}
#define oauth_matrix_one(tag, url, method, h, hn, body, expected, cur, end) \
    matrix_one("oauth-matrix", (tag), (url), (method), (h), (hn), (body), \
               (expected), (cur), (end))

int http_oauth_matrix(char* out, size_t out_sz) {
    char* c   = out;
    char* end = out ? out + out_sz : NULL;
    if (out && out_sz) out[0] = '\0';

    static const char* FORM =
        "client_id=tostonsync-connectivity-test.invalid&"
        "scope=https%3A%2F%2Fwww.googleapis.com%2Fauth%2Fdrive.file";
    static const char* TOKENFORM =
        "grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Adevice_code&"
        "client_id=tostonsync-connectivity-test.invalid&device_code=dummy";
    char clen[32];
    snprintf(clen, sizeof(clen), "%zu", strlen(FORM));

    hdr_t post_h[3] = {
        {"Content-Type", "application/x-www-form-urlencoded"},
        {"Accept", "application/json"},
        {"Connection", "close"},
    };
    hdr_t post_h_len[4] = {
        {"Content-Type", "application/x-www-form-urlencoded"},
        {"Accept", "application/json"},
        {"Connection", "close"},
        {"Content-Length", clen},
    };
    hdr_t token_h[2] = {
        {"Content-Type", "application/x-www-form-urlencoded"},
        {"Accept", "application/json"},
    };

    int rc = oauth_matrix_one("GET gstatic",
        "https://connectivitycheck.gstatic.com/generate_204",
        "GET", NULL, 0, NULL, 204, &c, end);
    if (rc < 0) return rc;
    rc = oauth_matrix_one("GET oauth-root",
        "https://oauth2.googleapis.com/", "GET", NULL, 0, NULL, 404, &c, end);
    if (rc < 0) return rc;
    rc = oauth_matrix_one("GET device-code",
        "https://oauth2.googleapis.com/device/code", "GET", NULL, 0, NULL,
        404, &c, end);
    if (rc < 0) return rc;
    rc = oauth_matrix_one("POST device-code no-length",
        "https://oauth2.googleapis.com/device/code", "POST", post_h, 3, FORM,
        401, &c, end);
    if (rc < 0) return rc;
    rc = oauth_matrix_one("POST device-code with-length",
        "https://oauth2.googleapis.com/device/code", "POST", post_h_len, 4, FORM,
        401, &c, end);
    if (rc < 0) return rc;
    rc = oauth_matrix_one("POST token dummy",
        "https://oauth2.googleapis.com/token", "POST", token_h, 2, TOKENFORM,
        400, &c, end);
    if (rc < 0) return rc;
    return 0;
}

// EXPERIMENTAL Google host TLS matrix — DIAGNOSTIC ONLY. One fresh
// template/connection/request per host over the live libSceHttp transport (CA
// already loaded). Isolates whether the TLS handshake failure is specific to
// oauth2.googleapis.com, to all *.googleapis.com API frontends, or broader.
int http_google_host_matrix(char* out, size_t out_sz) {
    char* c   = out;
    char* end = out ? out + out_sz : NULL;
    if (out && out_sz) out[0] = '\0';

    static const struct { const char* label; const char* url; int expected; } hosts[] = {
        { "gstatic-conncheck", "https://connectivitycheck.gstatic.com/generate_204", 204 },
        { "google-204",        "https://www.google.com/generate_204", 204 },
        { "www.googleapis",    "https://www.googleapis.com/", 404 },
        { "drive-about",       "https://www.googleapis.com/drive/v3/about", 401 },
        { "oauth2.googleapis", "https://oauth2.googleapis.com/", 404 },
        { "accounts.google",   "https://accounts.google.com/", 200 },
        { "www.gstatic-204",   "https://www.gstatic.com/generate_204", 204 },
        { "storage.googleapis","https://storage.googleapis.com/", 400 },
    };
    bool all_ok = true;
    for (size_t i = 0; i < sizeof(hosts) / sizeof(hosts[0]); i++) {
        int rc = matrix_one("google-host-matrix", hosts[i].label, hosts[i].url,
                            "GET", NULL, 0, NULL, hosts[i].expected, &c, end);
        if (rc < 0) return rc; // Busy/uncertain cleanup is not a CA verdict.
        if (!rc) all_ok = false;
    }

    // Variant: oauth2.googleapis.com with explicit headers, still GET.
    hdr_t explicit_h[4] = {
        {"Host", "oauth2.googleapis.com"},
        {"Connection", "close"},
        {"User-Agent", HTTP_USER_AGENT},
        {"Accept", "*/*"},
    };
    int rc = matrix_one("google-host-matrix", "oauth2 explicit-hdrs",
                        "https://oauth2.googleapis.com/", "GET", explicit_h, 4,
                        NULL, 404, &c, end);
    if (rc < 0) return rc;
    if (!rc) all_ok = false;
    google_cert_note_matrix_result(all_ok);
    return all_ok ? 1 : 0;
}

// Signed release transport: anonymous HTTPS with private embedded trust.
#define RELEASE_URL_MAX 4096u
#define RELEASE_HEADER_MAX 8192u
#define RELEASE_BODY_MAX (512u * 1024u)
#define RELEASE_FILE_MAX (16u * 1024u * 1024u)
static atomic_bool s_release_cleanup_failed = false;

static int release_hex(unsigned char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

static bool release_url_allowed(const char* url, bool redirected) {
    if (!url || strnlen(url, RELEASE_URL_MAX + 1) > RELEASE_URL_MAX ||
        strncmp(url, "https://", 8)) return false;
    for (const unsigned char* p = (const unsigned char*)url; *p; p++) {
        if (*p <= 0x20 || *p >= 0x7f || *p == '\\' || *p == '#') return false;
        if (*p == '%') {
            if (!p[1] || !p[2]) return false;
            int a = release_hex(p[1]), b = release_hex(p[2]);
            if (a < 0 || b < 0) return false;
            int c = (a << 4) | b;
            if (c < 0x20 || c == 0x7f || c == '\\') return false;
            p += 2;
        }
    }
    const char* path = strchr(url + 8, '/');
    if (!path) return false;
    size_t authority = (size_t)(path - (url + 8));
    if (authority >= 4 && !memcmp(path - 4, ":443", 4)) authority -= 4;
    const char* host = url + 8;
    if (redirected)
        return ((authority == 36 && !memcmp(host, "release-assets.githubusercontent.com", 36)) ||
                (authority == 29 && !memcmp(host, "objects.githubusercontent.com", 29))) && path[1];
    if (authority == 14 && !memcmp(host, "api.github.com", 14))
        return !strcmp(path, "/repos/galdo320/TostonSync/releases/latest");
    static const char prefix[] = "/galdo320/TostonSync/releases/download/v";
    if (authority != 10 || memcmp(host, "github.com", 10) ||
        strncmp(path, prefix, sizeof(prefix) - 1)) return false;
    const char* p = path + sizeof(prefix) - 1;
    for (unsigned part = 0; part < 3; part++) {
        unsigned digits = 0;
        while (*p >= '0' && *p <= '9') { if (++digits > 10) return false; p++; }
        if (!digits || *p++ != (part == 2 ? '/' : '.')) return false;
    }
    size_t count = 0; bool only_dots = true;
    while (*p) {
        unsigned char c = (unsigned char)*p++;
        if (c == '%') {
            if (!p[0] || !p[1]) return false;
            int a = release_hex((unsigned char)p[0]), b = release_hex((unsigned char)p[1]);
            if (a < 0 || b < 0) return false;
            c = (unsigned char)((a << 4) | b); p += 2;
        } else if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
                     (c >= '0' && c <= '9') || c == '-' || c == '_' || c == '.' || c == '~'))
            return false;
        if (c < 0x20 || c == 0x7f || c == '/' || c == '\\' || ++count > 255) return false;
        if (c != '.') only_dots = false;
    }
    return count && !(only_dots && count <= 2);
}

static bool release_close(public_http_context_t* ctx, int req, int conn, int tmpl) {
    bool clean = http_objects_delete(req, conn, tmpl) &&
        http_context_clear(&ctx->http, &ctx->ssl, &ctx->net);
    if (!clean) atomic_store(&s_release_cleanup_failed, true);
    return clean;
}

static int release_context_open(public_http_context_t* ctx) {
    if (atomic_load(&s_release_cleanup_failed)) return -EIO;
    if (!sceHttpInit || !sceHttpTerm || !sceHttpsLoadCert || !sceHttpCreateTemplate ||
        !sceHttpDeleteTemplate || !sceHttpCreateConnectionWithURL || !sceHttpDeleteConnection ||
        !sceHttpCreateRequestWithURL || !sceHttpDeleteRequest || !sceHttpSendRequest ||
        !sceHttpGetStatusCode || !sceHttpGetAllResponseHeaders || !sceHttpReadData ||
        !sceHttpAddRequestHeader || !sceHttpSetAutoRedirect || !sceHttpSetResolveTimeOut ||
        !sceHttpSetConnectTimeOut || !sceHttpSetSendTimeOut || !sceHttpSetRecvTimeOut) return -ENOSYS;
    pthread_mutex_lock(&s_init_lock);
    int rc = 0;
    if (!s_net_initialized) { rc = sceNetInit(); if (!rc) s_net_initialized = true; }
    pthread_mutex_unlock(&s_init_lock);
    if (rc) return rc;
    ctx->net = sceNetPoolCreate("tostonsync-release", 64 * 1024, 0);
    if (ctx->net < 0) return ctx->net;
    ctx->ssl = sceSslInit(1024 * 1024);
    if (ctx->ssl < 0) return ctx->ssl;
    ctx->http = sceHttpInit(ctx->net, ctx->ssl, 256 * 1024);
    if (ctx->http < 0) return ctx->http;
    // Fresh native defaults retain certificate checks; no diagnostic settings or callbacks.
    if (sceHttpsSetMinSslVersion) sceHttpsSetMinSslVersion(ctx->http, SCE_SSL_VERSION_TLS1_2_);
    char pem[RELEASE_CERT_BUNDLE_LEN + 1];
    memcpy(pem, RELEASE_CERT_BUNDLE, RELEASE_CERT_BUNDLE_LEN);
    pem[RELEASE_CERT_BUNDLE_LEN] = '\0';
    const char* cursor = pem; const char* end = pem + RELEASE_CERT_BUNDLE_LEN;
    sce_ssl_data_t roots[2]; const sce_ssl_data_t* list[2]; size_t len;
    for (unsigned i = 0; i < 2; i++) {
        const char* block = pem_next_cert(&cursor, end, &len);
        if (!block) return -EINVAL;
        roots[i] = (sce_ssl_data_t){(void*)block, len}; list[i] = &roots[i];
    }
    if (pem_next_cert(&cursor, end, &len)) return -EINVAL;
    return sceHttpsLoadCert(ctx->http, 2, list, NULL, NULL);
}

typedef struct {
    char location[RELEASE_URL_MAX + 1];
    uint64_t length;
    bool has_length;
} release_headers_t;

static bool release_headers_parse(const char* headers, size_t n, release_headers_t* out) {
    memset(out, 0, sizeof(*out));
    if (!headers || !n || n > RELEASE_HEADER_MAX) return false;
    if (!headers[n - 1]) n--;
    bool location = false, encoding = false, transfer = false;
    size_t pos = 0;
    while (pos < n) {
        size_t start = pos;
        while (pos < n && headers[pos] != '\r' && headers[pos] != '\n') {
            unsigned char c = (unsigned char)headers[pos++];
            if ((c < 0x20 && c != '\t') || c >= 0x7f) return false;
        }
        size_t end = pos;
        if (pos + 1 >= n || headers[pos] != '\r' || headers[pos + 1] != '\n') return false;
        pos += 2;
        if (end == start) { if (pos != n) return false; break; }
        if (!start && end - start >= 5 && !memcmp(headers, "HTTP/", 5)) continue;
        const char* colon = memchr(headers + start, ':', end - start);
        if (!colon || colon == headers + start) return false;
        for (const char* p = headers + start; p < colon; p++)
            if (!((*p >= 'a' && *p <= 'z') || (*p >= 'A' && *p <= 'Z') ||
                  (*p >= '0' && *p <= '9') || strchr("!#$%&'*+-.^_`|~", *p))) return false;
        const char* value = colon + 1; const char* last = headers + end;
        while (value < last && (*value == ' ' || *value == '\t')) value++;
        while (last > value && (last[-1] == ' ' || last[-1] == '\t')) last--;
        size_t key_len = (size_t)(colon - headers - start), len = (size_t)(last - value);
        if (key_len == 8 && !strncasecmp(headers + start, "Location", 8)) {
            if (location || !len || len > RELEASE_URL_MAX) return false;
            memcpy(out->location, value, len); out->location[len] = '\0'; location = true;
        } else if (key_len == 14 && !strncasecmp(headers + start, "Content-Length", 14)) {
            if (out->has_length || !len) return false;
            for (size_t i = 0; i < len; i++) {
                unsigned char c = (unsigned char)value[i];
                if (c < '0' || c > '9' || out->length > (UINT64_MAX - (c - '0')) / 10) return false;
                out->length = out->length * 10 + (c - '0');
            }
            out->has_length = true;
        } else if (key_len == 16 && !strncasecmp(headers + start, "Content-Encoding", 16)) {
            if (encoding || len != 8 || strncasecmp(value, "identity", 8)) return false;
            encoding = true;
        } else if (key_len == 17 && !strncasecmp(headers + start, "Transfer-Encoding", 17)) {
            if (transfer || len != 7 || strncasecmp(value, "chunked", 7)) return false;
            transfer = true;
        }
    }
    return !(transfer && out->has_length);
}

static bool release_deadline(const struct timespec* start) {
    struct timespec now;
    return clock_gettime(CLOCK_MONOTONIC, &now) == 0 && now.tv_sec - start->tv_sec < 60;
}

static bool release_get(const char* url, int fd, uint64_t limit, http_response_t* out) {
    public_http_context_t ctx = {.net = -1, .ssl = -1, .http = -1};
    int tmpl = -1, conn = -1, req = -1;
    char current[RELEASE_URL_MAX + 1]; strcpy(current, url);
    char* body = NULL; char* copied_headers = NULL;
    size_t total = 0, header_len = 0;
    struct timespec start;
    int rc = clock_gettime(CLOCK_MONOTONIC, &start) ? -EIO : release_context_open(&ctx);
    if (rc) goto done;
    tmpl = sceHttpCreateTemplate(ctx.http, HTTP_USER_AGENT, SCE_HTTP_VERSION_1_1_, 0);
    if (tmpl < 0) { rc = tmpl; goto done; }
    if ((rc = sceHttpSetAutoRedirect(tmpl, 0)) ||
        (rc = sceHttpSetResolveTimeOut(tmpl, 10u * 1000000u)) ||
        (rc = sceHttpSetConnectTimeOut(tmpl, 10u * 1000000u)) ||
        (rc = sceHttpSetSendTimeOut(tmpl, 10u * 1000000u)) ||
        (rc = sceHttpSetRecvTimeOut(tmpl, 10u * 1000000u))) goto done;
    for (unsigned hop = 0;; hop++) {
        if (!release_deadline(&start)) { rc = -ETIMEDOUT; goto done; }
        conn = sceHttpCreateConnectionWithURL(tmpl, current, 0);
        if (conn < 0) { rc = conn; goto done; }
        req = sceHttpCreateRequestWithURL(conn, SCE_HTTP_METHOD_GET_, current, 0);
        if (req < 0) { rc = req; goto done; }
        const char* accept = !strncmp(current, "https://api.github.com", 22) ?
            "application/vnd.github+json" : "application/octet-stream";
        if ((rc = sceHttpAddRequestHeader(req, "Accept", accept, SCE_HTTP_HEADER_OVERWRITE_)) ||
            (rc = sceHttpAddRequestHeader(req, "Accept-Encoding", "identity", SCE_HTTP_HEADER_OVERWRITE_))) goto done;
        rc = sceHttpSendRequest(req, NULL, 0);
        if (rc) {
            if (sceHttpsGetSslError && sceHttpsGetSslError(req, &out->ssl_error, &out->ssl_detail))
                out->ssl_error = 0, out->ssl_detail = 0;
            goto done;
        }
        if ((rc = sceHttpGetStatusCode(req, &out->status))) goto done;
        char* raw = NULL; size_t raw_len = 0; release_headers_t headers;
        if ((rc = sceHttpGetAllResponseHeaders(req, &raw, &raw_len))) goto done;
        if (!release_headers_parse(raw, raw_len, &headers)) { rc = -EPROTO; goto done; }
        if (out->status == 301 || out->status == 302 || out->status == 303 ||
            out->status == 307 || out->status == 308) {
            if (hop == 3) { rc = -ELOOP; goto done; }
            if (!release_url_allowed(headers.location, true)) { rc = -EPERM; goto done; }
            strcpy(current, headers.location);
            if (!http_objects_delete(req, conn, -1)) {
                atomic_store(&s_release_cleanup_failed, true);
                // Unknown child ownership: retain every parent until daemon restart.
                req = conn = tmpl = -1; ctx.http = ctx.ssl = ctx.net = -1;
                rc = -EIO; goto done;
            }
            req = conn = -1;
            continue;
        }
        if (out->status != 200) { rc = -EPROTO; goto done; }
        if (headers.has_length && (headers.length > limit || (fd >= 0 && headers.length != limit))) {
            rc = -EFBIG; goto done;
        }
        header_len = raw_len;
        copied_headers = malloc(header_len + 1);
        if (!copied_headers) { rc = -ENOMEM; goto done; }
        memcpy(copied_headers, raw, header_len); copied_headers[header_len] = '\0';
        if (fd < 0) { body = malloc((size_t)limit + 1); if (!body) { rc = -ENOMEM; goto done; } }
        for (;;) {
            if (!release_deadline(&start)) { rc = -ETIMEDOUT; goto done; }
            char chunk[16 * 1024];
            int n = sceHttpReadData(req, chunk, sizeof(chunk));
            if (n < 0) { rc = n; goto done; }
            if (!n) break;
            if ((size_t)n > sizeof(chunk) || (uint64_t)n > limit - total) { rc = -EFBIG; goto done; }
            if (fd >= 0) {
                size_t written = 0;
                while (written < (size_t)n) {
                    if (!release_deadline(&start)) { rc = -ETIMEDOUT; goto done; }
                    ssize_t count = write(fd, chunk + written, (size_t)n - written);
                    if (count < 0 && errno == EINTR) continue;
                    if (count <= 0) { rc = count ? -errno : -EIO; goto done; }
                    written += (size_t)count;
                }
            } else memcpy(body + total, chunk, (size_t)n);
            total += (size_t)n;
        }
        if ((fd >= 0 && total != limit) || (headers.has_length && total != headers.length)) rc = -EBADMSG;
        break;
    }
done:
    if (!release_close(&ctx, req, conn, tmpl)) rc = -EIO;
    if (rc) { free(body); free(copied_headers); out->transport_error = rc < 0 ? rc : -EIO; return false; }
    if (body) body[total] = '\0';
    out->body = body; out->body_len = total;
    out->headers = copied_headers; out->headers_len = header_len;
    return true;
}

bool http_get_release_limited(const char* url, size_t max_bytes, http_response_t* out) {
    if (!out) return false;
    memset(out, 0, sizeof(*out));
    if (!max_bytes || max_bytes > RELEASE_BODY_MAX || !release_url_allowed(url, false)) {
        out->transport_error = -EINVAL; return false;
    }
    return release_get(url, -1, max_bytes, out);
}

bool http_get_release_to_fd(const char* url, int fd, uint64_t expected_bytes, http_response_t* out) {
    if (!out) return false;
    memset(out, 0, sizeof(*out));
    toston_stat_guard_t st = TOSTON_STAT_GUARD_INIT;
    if (fd < 0 || !expected_bytes || expected_bytes > RELEASE_FILE_MAX ||
        !release_url_allowed(url, false) || toston_fstat(fd, &st.value) ||
        !toston_stat_guard_valid(&st) || !S_ISREG(st.value.st_mode) || st.value.st_size != 0 || lseek(fd, 0, SEEK_CUR) != 0) {
        out->transport_error = -EINVAL; return false;
    }
    return release_get(url, fd, expected_bytes, out);
}
