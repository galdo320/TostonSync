// TostónSync — thin libSceHttp2 wrapper used by gdrive.c.
//
// Sony's Http2 stack is full-featured but verbose. These helpers
// collapse the common request shapes (GET, POST application/json,
// POST application/x-www-form-urlencoded, resumable upload, DELETE, and
// file-download) into one-call entry points that gdrive.c can use.

#ifndef TOSTONSYNC_HTTP_CLIENT_H
#define TOSTONSYNC_HTTP_CLIENT_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    int    status;
    int    transport_error; // negative SDK or local transport error, if any
    char*  body;        // heap-allocated, NUL-terminated
    size_t body_len;
    char*  headers;     // heap-allocated raw response headers
    size_t headers_len;
    int    ssl_error;     // request-local diagnostic; never borrowed from a peer
    unsigned long ssl_detail;
} http_response_t;

void http_response_free(http_response_t* r);
// Local deferral/cleanup message; NULL means the error is not a local gate.
const char* http_transport_local_detail(int error);

// Result of the connectivity probe. The plain-HTTP leg carries no TLS, so
// comparing the two legs pinpoints whether a failure is DNS/TCP or TLS.
typedef struct {
    bool plain_ok;                // plain-HTTP 204 reached (DNS+TCP work)
    int  plain_status;
    int  plain_transport_error;
    bool tls_ok;                  // HTTPS 204 reached (TLS works end to end)
    int  tls_status;
    int  tls_transport_error;
    int  trust_state;             // see http_tls_trust_state()
} http_probe_t;

// Run the two-leg probe (plain HTTP then HTTPS to Google infra). Returns true
// only when both legs succeed. Safe to call from any worker.
bool http_connectivity_probe(http_probe_t* out);

// Diagnostic override: disable TLS server-certificate verification. Default is
// OFF (secure). Only for confirming that a CA/verification failure is the root
// cause on hardware — never leave enabled for real Drive tokens.
void http_tls_set_insecure(bool insecure);

// Enable/disable loading a custom CA bundle at daemon init. Default OFF: the
// startup path and connectivity checks must NEVER call sceSslLoadRootCACert
// (it destabilised the daemon on hardware). Set from config before first use.
void http_tls_set_custom_ca(bool enabled);

// Resume invalidates Sony network/TLS contexts on some firmware. Preserve
// tokens and credentials; rebuild lazily only after all active leases drain.
// A stale/busy transport returns a temporary error, never waits for that drain.
void http_client_mark_stale(bool drive_was_ready);
void http_client_rebuild_after_cert_repair(void);

// The release embeds the known-good Google WE2 + WR2 bundle. First run installs
// it only when cacert.pem is absent; repair is an explicit overwrite.
bool http_google_cert_ensure(void);
bool http_google_cert_repair(void);
void http_google_cert_status(char* status, size_t status_sz, int* blocks,
                             int64_t* last_verified_unix);

// True once, only after a stale transport completes a real Drive API request.
// OAuth/token success alone does not count as Drive reconnection.
bool http_client_take_drive_reconnected(void);

// EXPERIMENTAL, isolated self-test of custom CA loading. Runs sceSslLoadRootCACert
// on a throwaway SSL context and reports the outcome. Only call from an explicit
// diagnostic action, never at startup. Returns 1 if any cert was accepted.
int  http_ca_selftest(char* out, size_t out_sz);

// EXPERIMENTAL, isolated self-test of the libSceHttp (v1) trust path: own
// contexts, sceHttpsLoadCert + one HTTPS GET to Google, reports rc/status/ssl
// error. Only call from an explicit diagnostic action. Returns 1 on 2xx/204.
int  http_https_selftest(char* out, size_t out_sz);

// EXPERIMENTAL OAuth HTTPS matrix: runs GET/POST probes against gstatic and
// oauth2.googleapis.com over the live libSceHttp transport, logging
// rc/status/sslErr/bodyLen per case to isolate TLS-vs-POST-vs-body issues.
// Only call from an explicit diagnostic action. Returns 0, or a negative local
// transport gate error (waiting for active requests / uncertain cleanup).
int  http_oauth_matrix(char* out, size_t out_sz);

// EXPERIMENTAL Google host TLS matrix: GET each of several Google/CDN hosts to
// isolate which hosts the libSceHttp TLS handshake can and cannot reach. Only
// call from an explicit diagnostic action. Returns 1 when every host returns
// its expected HTTP status over a clean TLS transport; negative means a local
// gate deferred the diagnostic, not a failed certificate/host test.
int  http_google_host_matrix(char* out, size_t out_sz);

// Trust-configuration outcome: 0 not attempted, 1 CA bundle loaded, 2 system
// store only, -1 verification disabled (diagnostic).
int  http_tls_trust_state(void);

// Copy the last CA-load diagnostic (bytes, PEM block count, strategy, rc, first
// failing cert index, total loaded) into out. Returns the trust state.
int  http_ca_diag(char* out, size_t out_sz);

bool http_get_auth(const char* url, const char* bearer,
                   http_response_t* out);

// Public metadata only: HTTPS, no credentials or redirects, bounded body.
// max_bytes must be 1..512 KiB. Never enables insecure TLS verification.
bool http_get_public_limited(const char* url, size_t max_bytes,
                             http_response_t* out);

// Fixed public title catalogue only, up to 4 MiB; optional validated ETag.
// Same TLS/lease/redirect protections, never credentials or arbitrary hosts.
bool http_get_public_catalog(const char* url, const char* etag,
                             size_t max_bytes, http_response_t* out);

// Anonymous GitHub release GETs: fixed repository, isolated embedded roots,
// validated CDN redirects (at most three), no retries or diagnostic TLS bypass.
// Only final HTTP 200 succeeds. Buffered bodies are limited to 1..512 KiB.
bool http_get_release_limited(const char* url, size_t max_bytes,
                              http_response_t* out);
// Stream exactly 1..16 MiB to an empty regular fd positioned at zero. The caller
// owns/closes the fd and discards partial data on failure; no pathname is used.
// No file bytes are written before final 200; body is NULL, body_len is bytes.
bool http_get_release_to_fd(const char* url, int fd, uint64_t expected_bytes,
                            http_response_t* out);

bool http_get_auth_to_file(const char* url, const char* bearer,
                           const char* local_path);

// Stream an authenticated GET directly to disk. If max_bytes is non-zero,
// aborts and removes the partial file once the response exceeds that cap.
bool http_get_auth_to_file_limited(const char* url, const char* bearer,
                                   const char* local_path,
                                   uint64_t max_bytes);

// Resume an authenticated download into <local_path>.part and atomically
// rename it after the expected byte count is present. Existing partial data is
// reused with HTTP Range requests.
bool http_get_auth_to_file_resumable(const char* url, const char* bearer,
                                     const char* local_path,
                                     uint64_t expected_bytes,
                                     uint64_t max_bytes);

bool http_post_form(const char* url, const char* form_body,
                    http_response_t* out);

bool http_post_json_auth(const char* url, const char* bearer,
                         const char* json_body, http_response_t* out);

bool http_patch_json_auth(const char* url, const char* bearer,
                          const char* json_body, http_response_t* out);

bool http_delete_auth(const char* url, const char* bearer,
                      http_response_t* out);

// Google-style resumable upload: create a session, then PUT file chunks. The
// final JSON response is returned in *out.
bool http_post_resumable_file_auth(const char* init_url, const char* bearer,
                                   const char* json_metadata,
                                   const char* content_type,
                                   const char* file_path,
                                   size_t chunk_bytes,
                                   uint64_t max_bytes,
                                   http_response_t* out);

#ifdef __cplusplus
}
#endif
#endif
