// TostónSync — Google Drive backend implementation.
//
// HTTPS is done through libSceHttp (Sony's native client). All API
// calls hit https://oauth2.googleapis.com or https://www.googleapis.com
// and follow the standard Drive v3 + OAuth 2.0 Device Authorization
// Grant (RFC 8628). We never embed our own credentials in the binary —
// the Client ID and Client Secret are read from config.ini, which the
// user fills in from their own Google Cloud Console project.

#include "gdrive.h"
#include "config.h"
#include "log.h"
#include "json.h"
#include "http_client.h"
#include "gdrive_default_creds.h"
#include "dest_dedup.h"
#include "backup_names.h"
#include "sha256.h"

#include <ctype.h>
#include <errno.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#define DEVICE_CODE_URL   "https://oauth2.googleapis.com/device/code"
#define TOKEN_URL         "https://oauth2.googleapis.com/token"
#define DRIVE_API_BASE    "https://www.googleapis.com/drive/v3"
#define DRIVE_UPLOAD_BASE "https://www.googleapis.com/upload/drive/v3"

// Matches the resumable browser-import ceiling. This is a product safety cap,
// not a RAM cap: Drive transfers stream in 8 MiB chunks.
#define GDRIVE_MAX_BYTES (8ULL * 1024ULL * 1024ULL * 1024ULL)
#define GDRIVE_CHUNK_BYTES (8U * 1024U * 1024U)

// Drive needs one of these scopes. "drive.file" is enough — the app
// only sees files it created. Use "drive.appdata" if use_appdata=true.
#define SCOPE_DRIVE_FILE    "https://www.googleapis.com/auth/drive.file"
#define SCOPE_DRIVE_APPDATA "https://www.googleapis.com/auth/drive.appdatafolder"

// --------------------------------------------------------------------
// Internal state.
// --------------------------------------------------------------------

typedef struct {
    char     access_token[2048];
    char     refresh_token[512];
    int64_t  access_expires_unix;
    char     root_folder_id[GDRIVE_FILEID_MAX];   // resolved on first use
} tokens_t;

// Drive owns an immutable copy. The live config is edited in place by the HTTP
// settings endpoint, so retaining its address would make credential/path reads
// race with config_apply_json(). Reconfigure replaces this copy under s_lock.
static config_t           s_cfg_storage;
static const config_t*    s_cfg = &s_cfg_storage;
// _Atomic so the lock-free read in gdrive_get_state() is well-defined C11
// (not just "atomic in practice on this CPU"). All writes are plain stores,
// which the qualifier makes atomic.
static _Atomic gdrive_state_t s_state = GDRIVE_STATE_NOT_CONFIGURED;
static tokens_t           s_tokens  = {0};
static gdrive_account_t   s_account = {0};
static gdrive_device_flow_t s_flow  = {0};
static gdrive_diagnostic_t  s_diag  = {0};
static int64_t            s_flow_next_poll_unix = 0;
static int64_t            s_flow_expires_unix   = 0;
static _Atomic bool       s_recovery_retryable = false;
static _Atomic int64_t    s_recovery_at = 0;
static unsigned           s_recovery_failures = 0;
static uint64_t           s_session_generation = 0; // protected by s_lock
static bool               s_initialization_deferred = false; // protected by s_lock
static bool               s_read_session_loaded = false; // protected by s_lock
static bool               s_read_session_failed = false; // protected by s_lock
static pthread_mutex_t    s_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t    s_diag_lock = PTHREAD_MUTEX_INITIALIZER;
// Dedicated lock for s_account ONLY. Held just long enough to copy the struct
// in or out — never across a network call — so gdrive_get_account() (on the
// /api/status hot path) can read a consistent snapshot without ever blocking
// behind an in-flight Drive HTTPS request that holds s_lock.
static pthread_mutex_t    s_acct_lock = PTHREAD_MUTEX_INITIALIZER;

static void account_email_copy(char* out, size_t out_sz) {
    if (!out || out_sz == 0) return;
    pthread_mutex_lock(&s_acct_lock);
    snprintf(out, out_sz, "%s", s_account.email);
    pthread_mutex_unlock(&s_acct_lock);
}

static void diag_set_locked(const char* code, const char* detail,
                            int http_status, int transport_error) {
    pthread_mutex_lock(&s_diag_lock);
    snprintf(s_diag.code, sizeof(s_diag.code), "%s", code ? code : "");
    snprintf(s_diag.detail, sizeof(s_diag.detail), "%s", detail ? detail : "");
    s_diag.http_status = http_status;
    s_diag.transport_error = transport_error;
    pthread_mutex_unlock(&s_diag_lock);
}

static void response_diag_locked(const char* operation,const http_response_t* r) {
    char error[64]="";
    if(r&&r->body){json_get_string(r->body,"error",error,sizeof(error));if(!error[0])json_get_string(r->body,"reason",error,sizeof(error));}
    const char* known[]={"invalid_grant","invalid_client","unauthorized_client","access_denied","invalid_scope","authorization_pending","slow_down","expired_token","rateLimitExceeded","userRateLimitExceeded","dailyLimitExceeded","storageQuotaExceeded","insufficientPermissions","notFound","forbidden","authError"};
    const char* safe="http_error";for(size_t i=0;i<sizeof(known)/sizeof(known[0]);i++)if(!strcmp(error,known[i]))safe=known[i];
    const char* local=http_transport_local_detail(r?r->transport_error:0);
    const char* code=local?(r->transport_error==-EAGAIN?"transport_rebuilding":"transport_cleanup_failed"):
        r&&r->transport_error?"network_tls_failure":safe;
    if(!strcmp(code,"unauthorized_client"))code="invalid_client_type";
    char detail[GDRIVE_DIAG_DETAIL_MAX];
    if(local)snprintf(detail,sizeof(detail),"%s",local);
    else if(r&&r->transport_error)snprintf(detail,sizeof(detail),"PS5 network/TLS request failed (0x%x)",(unsigned)r->transport_error);
    else snprintf(detail,sizeof(detail),"Google returned HTTP %d (%s)",r?r->status:0,code);
    diag_set_locked(code,detail,r?r->status:0,r?r->transport_error:0);
    log_warn("gdrive: %s failed reason=%s status=%d transport=0x%x",operation,code,r?r->status:0,(unsigned)(r?r->transport_error:0));
}

// After a transport failure, run the two-leg connectivity probe to say exactly
// what broke: DNS/TCP or TLS. Does NOT hold s_lock (the probe makes network
// calls); diag_set_locked uses its own small lock, so this is safe to call
// after unlocking s_lock. Refines the generic "network_tls_failure" set by
// response_diag_locked() into a precise, user-facing reason.
static void refine_transport_diag(int http_status, int transport_error) {
    if (http_transport_local_detail(transport_error)) return;
    http_probe_t p = {0};
    http_connectivity_probe(&p);
    int local_error = http_transport_local_detail(p.plain_transport_error)
                      ? p.plain_transport_error : p.tls_transport_error;
    const char* local = http_transport_local_detail(local_error);
    if (local) {
        diag_set_locked(local_error == -EAGAIN ? "transport_rebuilding"
                                              : "transport_cleanup_failed",
                        local, http_status, local_error);
        log_warn("gdrive: connectivity probe deferred by local transport error=0x%x",
                 (unsigned)local_error);
    } else if (p.plain_ok && !p.tls_ok) {
        char detail[GDRIVE_DIAG_DETAIL_MAX];
        snprintf(detail, sizeof(detail),
                 "DNS OK, TLS failed (0x%x). PS5 reached the internet but could "
                 "not complete TLS to Google. Check the CA bundle "
                 "(/data/tostonsync/cacert.pem) and the PS5 date/time.",
                 (unsigned)p.tls_transport_error);
        diag_set_locked("tls_failed", detail, http_status, transport_error);
        log_warn("gdrive: transport classified reason=tls_failed "
                 "(plain_ok=1 tls_ok=0 trust_state=%d)", p.trust_state);
    } else if (!p.plain_ok) {
        diag_set_locked("dns_or_network_failed",
                        "DNS/network failed. The PS5 could not reach the "
                        "internet (check nanoDNS, router, and internet access).",
                        http_status, transport_error);
        log_warn("gdrive: transport classified reason=dns_or_network_failed "
                 "(plain_ok=0)");
    }
    // If both legs pass now (transient), leave the base diagnosis in place.
}

static void url_encode(const char* in, char* out, size_t out_sz);
static void json_escape(const char* in, char* out, size_t out_sz);
static void drive_query_escape(const char* in, char* out, size_t out_sz);

// --------------------------------------------------------------------
// tokens.json persistence — never leaves the console.
// --------------------------------------------------------------------

static void tokens_path(char* out, size_t out_sz) {
    snprintf(out, out_sz, "%s/tokens.json", s_cfg->paths.state_dir);
}

static bool tokens_load(void) {
    char path[256];
    tokens_path(path, sizeof(path));
    FILE* f = fopen(path, "rb");
    if (!f) return false;
    char buf[4096];
    size_t n = fread(buf, 1, sizeof(buf) - 1, f);
    fclose(f);
    buf[n] = '\0';

    if (!json_get_string(buf, "refresh_token",
                         s_tokens.refresh_token,
                         sizeof(s_tokens.refresh_token))) {
        return false;
    }
    json_get_string(buf, "access_token", s_tokens.access_token,
                    sizeof(s_tokens.access_token));
    json_get_string(buf, "root_folder_id", s_tokens.root_folder_id,
                    sizeof(s_tokens.root_folder_id));
    s_tokens.access_expires_unix =
        (int64_t)json_get_number(buf, "access_expires_unix");
    pthread_mutex_lock(&s_acct_lock);
    json_get_string(buf, "email", s_account.email, sizeof(s_account.email));
    pthread_mutex_unlock(&s_acct_lock);
    return s_tokens.refresh_token[0] != '\0';
}

static void tokens_save(void) {
    char path[256];
    tokens_path(path, sizeof(path));
    FILE* f = fopen(path, "wb");
    if (!f) {
        log_warn("gdrive: cannot write %s", path);
        return;
    }
    char refresh[1024], access[4096], root[GDRIVE_FILEID_MAX * 2], email[256];
    json_escape(s_tokens.refresh_token, refresh, sizeof(refresh));
    json_escape(s_tokens.access_token, access, sizeof(access));
    json_escape(s_tokens.root_folder_id, root, sizeof(root));
    char account_email[sizeof(s_account.email)];
    account_email_copy(account_email, sizeof(account_email));
    json_escape(account_email, email, sizeof(email));
    fprintf(f,
        "{\n"
        "  \"refresh_token\": \"%s\",\n"
        "  \"access_token\":  \"%s\",\n"
        "  \"access_expires_unix\": %lld,\n"
        "  \"root_folder_id\": \"%s\",\n"
        "  \"email\": \"%s\"\n"
        "}\n",
        refresh,
        access,
        (long long)s_tokens.access_expires_unix,
        root,
        email);
    fclose(f);
    chmod(path, 0600);
}

static void tokens_wipe(void) {
    char path[256];
    tokens_path(path, sizeof(path));
    unlink(path);
    memset(&s_tokens, 0, sizeof(s_tokens));
    pthread_mutex_lock(&s_acct_lock);
    memset(&s_account, 0, sizeof(s_account));
    pthread_mutex_unlock(&s_acct_lock);
}

// --------------------------------------------------------------------
// Helpers.
// --------------------------------------------------------------------

static const char* gdrive_scope(void) {
    return s_cfg->gdrive.use_appdata ? SCOPE_DRIVE_APPDATA : SCOPE_DRIVE_FILE;
}

static void url_encode(const char* in, char* out, size_t out_sz) {
    static const char hex[] = "0123456789ABCDEF";
    size_t j = 0;
    for (size_t i = 0; in && in[i] && j + 1 < out_sz; i++) {
        unsigned char c = (unsigned char)in[i];
        bool unreserved = isalnum(c) || c == '-' || c == '_' || c == '.' || c == '~';
        if (unreserved) {
            out[j++] = (char)c;
        } else if (j + 3 < out_sz) {
            out[j++] = '%';
            out[j++] = hex[c >> 4];
            out[j++] = hex[c & 0x0f];
        } else {
            break;
        }
    }
    out[j] = '\0';
}

static void json_escape(const char* in, char* out, size_t out_sz) {
    size_t j = 0;
    for (size_t i = 0; in && in[i] && j + 1 < out_sz; i++) {
        unsigned char c = (unsigned char)in[i];
        if ((c == '"' || c == '\\') && j + 2 < out_sz) {
            out[j++] = '\\'; out[j++] = (char)c;
        } else if (c == '\n' && j + 2 < out_sz) {
            out[j++] = '\\'; out[j++] = 'n';
        } else if (c == '\r' && j + 2 < out_sz) {
            out[j++] = '\\'; out[j++] = 'r';
        } else if (c == '\t' && j + 2 < out_sz) {
            out[j++] = '\\'; out[j++] = 't';
        } else if (c >= 0x20) {
            out[j++] = (char)c;
        }
    }
    out[j] = '\0';
}

static void drive_query_escape(const char* in, char* out, size_t out_sz) {
    size_t j = 0;
    for (size_t i = 0; in && in[i] && j + 1 < out_sz; i++) {
        unsigned char c = (unsigned char)in[i];
        if ((c == '\'' || c == '\\') && j + 2 < out_sz) out[j++] = '\\';
        out[j++] = (char)c;
    }
    out[j] = '\0';
}

// Effective OAuth credentials: a user-supplied value in config.ini always
// wins; otherwise we fall back to the credentials baked into the binary at
// build time (gdrive_default_creds.h). This lets a published build sign in
// with zero per-user setup while still letting power users override.
static const char* eff_client_id(void) {
    return s_cfg->gdrive.client_id[0] ? s_cfg->gdrive.client_id
                                      : GDRIVE_DEFAULT_CLIENT_ID;
}
static const char* eff_client_secret(void) {
    return s_cfg->gdrive.client_secret[0] ? s_cfg->gdrive.client_secret
                                          : GDRIVE_DEFAULT_CLIENT_SECRET;
}

static int64_t now_unix(void) {
    return (int64_t)time(NULL);
}

static bool gdrive_refresh_locked(void);
static bool gdrive_test_ready_locked(gdrive_diagnostic_t* out);

static void recovery_reset_locked(void) {
    s_recovery_retryable = false;
    s_recovery_at = 0;
    s_recovery_failures = 0;
}

static void recovery_failed_locked(void) {
    gdrive_diagnostic_t d = {0};
    gdrive_get_diagnostic(&d);
    bool credentials = !strcmp(d.code, "invalid_grant") ||
        !strcmp(d.code, "invalid_client") || !strcmp(d.code, "invalid_client_type") ||
        !strcmp(d.code, "access_denied") || !strcmp(d.code, "not_configured") ||
        !strcmp(d.code, "not_signed_in");
    bool temporary = !credentials && (d.transport_error || !d.http_status ||
        d.http_status == 408 || d.http_status == 429 ||
        (d.http_status >= 500 && d.http_status <= 599) ||
        (d.http_status == 403 && (!strcmp(d.code, "rateLimitExceeded") ||
                                  !strcmp(d.code, "userRateLimitExceeded"))) ||
        !strcmp(d.code, "invalid_response"));
    s_recovery_retryable = temporary && eff_client_id()[0] &&
                           s_tokens.refresh_token[0];
    if (s_recovery_failures < 16) s_recovery_failures++;
    s_recovery_at = now_unix() + dest_retry_delay_seconds(s_recovery_failures);
    char detail[GDRIVE_DIAG_DETAIL_MAX];
    snprintf(detail, sizeof(detail), "%.140s. %s", d.detail,
        temporary ? "Automatic backups will retry with backoff."
                  : "Check Drive settings or sign in again; pending backups are kept.");
    diag_set_locked(d.code, detail, d.http_status, d.transport_error);
    s_state = GDRIVE_STATE_ERROR;
    log_warn("gdrive: recovery=%s reason=%s status=%d transport=0x%x retry_at=%lld",
        s_recovery_retryable ? "pending" : "needs_attention", d.code,
        d.http_status, (unsigned)d.transport_error, (long long)s_recovery_at);
}

static bool access_token_fresh(void) {
    return s_tokens.access_token[0] &&
           now_unix() + 60 < s_tokens.access_expires_unix;
}

static bool ensure_access_token_locked(void) {
    if (access_token_fresh()) return true;
    return gdrive_refresh_locked();
}

// --------------------------------------------------------------------
// Public API.
// --------------------------------------------------------------------

static gdrive_state_t initialize_saved_session_locked(void) {
    s_initialization_deferred = false;
    // Device flow needs a Client ID; the Client Secret is OPTIONAL (TVs/limited-
    // input clients have none, and it is never sent to /device/code).
    if (!eff_client_id()[0]) {
        s_state = GDRIVE_STATE_NOT_CONFIGURED;
        log_info("gdrive: automatic PS5 Drive is not configured; browser Drive is separate");
        return s_state;
    }

    if (!tokens_load()) {
        s_state = GDRIVE_STATE_NOT_SIGNED_IN;
        return s_state;
    }

    bool api_ready = gdrive_test_ready_locked(NULL);
    if (api_ready) {
        char email[sizeof(s_account.email)];
        account_email_copy(email, sizeof(email));
        log_info("gdrive: signed in as %s", email[0] ? email : "(unknown)");
    }
    return s_state;
}

gdrive_state_t gdrive_init(const config_t* cfg) {
    pthread_mutex_lock(&s_lock);
    if (cfg) s_cfg_storage = *cfg;
    s_session_generation++;
    recovery_reset_locked();
    s_read_session_loaded = false;
    s_read_session_failed = false;
    s_initialization_deferred = cfg && cfg->triggers.modes_count == 1 &&
        strcmp(cfg->triggers.modes[0], "manual") == 0;
    if (s_initialization_deferred) {
        // Local startup must not inspect or refresh an unrelated saved account.
        // Passive status/recovery calls never acquire activation authority.
        memset(&s_tokens, 0, sizeof(s_tokens));
        pthread_mutex_lock(&s_acct_lock);
        memset(&s_account, 0, sizeof(s_account));
        pthread_mutex_unlock(&s_acct_lock);
        s_state = eff_client_id()[0] ? GDRIVE_STATE_NOT_SIGNED_IN
                                    : GDRIVE_STATE_NOT_CONFIGURED;
        diag_set_locked("deferred", "Drive is deferred for manual/local startup; use an explicit Drive action to connect.", 0, 0);
    } else {
        initialize_saved_session_locked();
    }
    gdrive_state_t result = s_state;
    pthread_mutex_unlock(&s_lock);
    return result;
}

gdrive_state_t gdrive_activate(void) {
    pthread_mutex_lock(&s_lock);
    if (s_initialization_deferred) initialize_saved_session_locked();
    gdrive_state_t result = s_state;
    pthread_mutex_unlock(&s_lock);
    return result;
}

gdrive_state_t gdrive_reconfigure(const config_t* cfg) {
    pthread_mutex_lock(&s_lock);
    if (cfg) {
        bool credentials_changed =
            strcmp(s_cfg_storage.gdrive.client_id, cfg->gdrive.client_id) != 0 ||
            strcmp(s_cfg_storage.gdrive.client_secret, cfg->gdrive.client_secret) != 0;
        bool folder_changed =
            strcmp(s_cfg_storage.gdrive.root_folder,
                   cfg->gdrive.root_folder) != 0 ||
            s_cfg_storage.gdrive.use_appdata != cfg->gdrive.use_appdata;
        s_cfg_storage = *cfg;
        if (folder_changed) s_tokens.root_folder_id[0] = '\0';
        if (folder_changed || credentials_changed) {
            s_session_generation++;
            recovery_reset_locked();
        }
        if (credentials_changed && s_state == GDRIVE_STATE_READY)
            s_state = GDRIVE_STATE_ERROR;
    }
    bool have_creds = eff_client_id()[0] != '\0'; // secret optional (device flow)

    // Don't disturb an in-progress device flow or an already-signed-in
    // session — the user is mid-action or already good.
    if (s_state == GDRIVE_STATE_DEVICE_PENDING) {
        pthread_mutex_unlock(&s_lock);
        return s_state;
    }
    if (!have_creds) {
        s_state = GDRIVE_STATE_NOT_CONFIGURED;
        diag_set_locked("not_configured",
                        "Automatic Drive Client ID is missing",
                        0, 0);
        pthread_mutex_unlock(&s_lock);
        return s_state;
    }
    if (s_state == GDRIVE_STATE_READY) {
        pthread_mutex_unlock(&s_lock);
        return s_state;
    }

    // Credentials are now present and we are not signed in. Re-evaluate so a
    // freshly-pasted Client ID/Secret immediately unblocks sign-in — the bug
    // was that state stayed NOT_CONFIGURED until a restart, so
    // /api/oauth/start kept refusing right after the user saved them.
    s_initialization_deferred = false;
    bool have_tokens = tokens_load();
    bool api_ready = have_tokens && gdrive_test_ready_locked(NULL);
    if (api_ready) {
        char email[sizeof(s_account.email)];
        account_email_copy(email, sizeof(email));
        log_info("gdrive: credentials updated — signed in as %s",
                 email[0] ? email : "(unknown)");
    } else {
        s_state = have_tokens ? GDRIVE_STATE_ERROR : GDRIVE_STATE_NOT_SIGNED_IN;
        if (!have_tokens) diag_set_locked("", "", 0, 0);
        if (!have_tokens) log_info("gdrive: credentials set — ready to sign in");
    }
    pthread_mutex_unlock(&s_lock);
    return gdrive_get_state();
}

const gdrive_device_flow_t* gdrive_device_flow_start(void) {
    pthread_mutex_lock(&s_lock);
    if (s_initialization_deferred) initialize_saved_session_locked();
    if (s_state == GDRIVE_STATE_NOT_CONFIGURED) {
        diag_set_locked("not_configured",
                        "Automatic Drive Client ID is missing",
                        0, 0);
        log_warn("gdrive: device flow start failed reason=not_configured");
        pthread_mutex_unlock(&s_lock);
        return NULL;
    }

    // Clock guard: an invalid PS5 date makes the server certificate look
    // "not yet valid"/"expired" and TLS verification fails. 1704067200 =
    // 2024-01-01 UTC; anything earlier is certainly wrong.
    if (time(NULL) < (time_t)1704067200) {
        diag_set_locked("invalid_clock",
                        "PS5 date/time may be invalid; TLS certificate "
                        "validation can fail.", 0, 0);
        log_warn("gdrive: device flow start failed reason=invalid_clock");
        s_state = GDRIVE_STATE_ERROR;
        pthread_mutex_unlock(&s_lock);
        return NULL;
    }

    char cid[256], scope[160];
    url_encode(eff_client_id(), cid, sizeof(cid));
    url_encode(gdrive_scope(), scope, sizeof(scope));
    char body[512];
    snprintf(body, sizeof(body),
             "client_id=%s&scope=%s",
             cid, scope);

    http_response_t r = {0};
    if (!http_post_form(DEVICE_CODE_URL, body, &r) || r.status != 200) {
        int terr = r.transport_error, hstat = r.status;
        response_diag_locked("device flow start", &r);
        http_response_free(&r);
        s_state = GDRIVE_STATE_ERROR;
        pthread_mutex_unlock(&s_lock);
        // Classify DNS-vs-TLS outside the lock (the probe does network I/O).
        if (terr) refine_transport_diag(hstat, terr);
        return NULL;
    }

    diag_set_locked("", "", 0, 0);

    memset(&s_flow, 0, sizeof(s_flow));
    json_get_string(r.body, "user_code",       s_flow.user_code,       sizeof(s_flow.user_code));
    json_get_string(r.body, "device_code",     s_flow.device_code,     sizeof(s_flow.device_code));
    json_get_string(r.body, "verification_url",s_flow.verification_url,sizeof(s_flow.verification_url));
    s_flow.interval_seconds   = (int)json_get_number(r.body, "interval");
    s_flow.expires_in_seconds = (int)json_get_number(r.body, "expires_in");
    if (s_flow.interval_seconds < 1) s_flow.interval_seconds = 5;
    http_response_free(&r);

    // Build the QR-friendly URL with the code pre-filled.
    snprintf(s_flow.verification_url_complete,
             sizeof(s_flow.verification_url_complete),
             "%s?user_code=%s",
             s_flow.verification_url, s_flow.user_code);

    s_flow_next_poll_unix = now_unix() + s_flow.interval_seconds;
    s_flow_expires_unix   = now_unix() + s_flow.expires_in_seconds;
    s_state = GDRIVE_STATE_DEVICE_PENDING;

    log_info("gdrive: device flow started");
    pthread_mutex_unlock(&s_lock);
    return &s_flow;
}

void gdrive_get_diagnostic(gdrive_diagnostic_t* out) {
    if (!out) return;
    pthread_mutex_lock(&s_diag_lock);
    *out = s_diag;
    pthread_mutex_unlock(&s_diag_lock);
}

bool gdrive_test_connectivity(gdrive_diagnostic_t* out) {
    gdrive_diagnostic_t result = {0};
    char scope[160], body[512];
    url_encode(SCOPE_DRIVE_FILE, scope, sizeof(scope));
    snprintf(body, sizeof(body),
             "client_id=tostonsync-connectivity-test.invalid&scope=%s", scope);
    http_response_t r = {0};
    bool sent = http_post_form(DEVICE_CODE_URL, body, &r);
    bool ok = sent && r.status > 0;
    if (ok) {
        snprintf(result.code, sizeof(result.code), "reachable");
        snprintf(result.detail, sizeof(result.detail),
                 "PS5 can reach Google; DNS and HTTPS succeeded (HTTP %d)",
                 r.status);
        result.http_status = r.status;
        log_info("gdrive: connectivity test passed status=%d", r.status);
    } else {
        const char* local = http_transport_local_detail(r.transport_error);
        snprintf(result.code, sizeof(result.code), "%s",
                 local ? (r.transport_error == -EAGAIN ? "transport_rebuilding"
                                                        : "transport_cleanup_failed")
                       : "network_tls_failure");
        if (local) snprintf(result.detail, sizeof(result.detail), "%s", local);
        else snprintf(result.detail, sizeof(result.detail),
                      "PS5 cannot reach Google (DNS, internet, or TLS error 0x%x)",
                      (unsigned)r.transport_error);
        result.transport_error = r.transport_error;
        log_warn("gdrive: connectivity test failed reason=%s transport=0x%x",
                 result.code, (unsigned)r.transport_error);
    }
    http_response_free(&r);
    if (out) *out = result;
    return ok;
}

gdrive_state_t gdrive_device_flow_poll(void) {
    pthread_mutex_lock(&s_lock);
    if (s_state != GDRIVE_STATE_DEVICE_PENDING) {
        pthread_mutex_unlock(&s_lock);
        return s_state;
    }
    if (now_unix() < s_flow_next_poll_unix) {
        pthread_mutex_unlock(&s_lock);
        return s_state;
    }
    if (now_unix() > s_flow_expires_unix) {
        log_warn("gdrive: device code expired");
        s_state = GDRIVE_STATE_DEVICE_DENIED;
        pthread_mutex_unlock(&s_lock);
        return s_state;
    }
    s_flow_next_poll_unix = now_unix() + s_flow.interval_seconds;

    char cid[256], secret[256], dev[256];
    url_encode(eff_client_id(), cid, sizeof(cid));
    url_encode(eff_client_secret(), secret, sizeof(secret));
    url_encode(s_flow.device_code, dev, sizeof(dev));
    // client_secret is OPTIONAL: only send it when configured (TVs/limited-input
    // device-flow clients have none; sending an empty one can be rejected).
    char body[1408];
    if (eff_client_secret()[0])
        snprintf(body, sizeof(body),
                 "client_id=%s&client_secret=%s&device_code=%s"
                 "&grant_type=urn:ietf:params:oauth:grant-type:device_code",
                 cid, secret, dev);
    else
        snprintf(body, sizeof(body),
                 "client_id=%s&device_code=%s"
                 "&grant_type=urn:ietf:params:oauth:grant-type:device_code",
                 cid, dev);

    http_response_t r = {0};
    bool ok = http_post_form(TOKEN_URL, body, &r);
    if (!ok) {
        response_diag_locked("device flow poll", &r);
        http_response_free(&r);
        s_state = GDRIVE_STATE_ERROR;
        pthread_mutex_unlock(&s_lock);
        return s_state;
    }

    if (r.status == 200) {
        s_session_generation++;
        json_get_string(r.body, "access_token",
                        s_tokens.access_token,
                        sizeof(s_tokens.access_token));
        json_get_string(r.body, "refresh_token",
                        s_tokens.refresh_token,
                        sizeof(s_tokens.refresh_token));
        int expires_in = (int)json_get_number(r.body, "expires_in");
        if (expires_in <= 0) expires_in = 3600;
        s_tokens.access_expires_unix = now_unix() + expires_in;
        tokens_save();
        log_info("gdrive: Google authorization complete; verifying Drive API");
        http_response_free(&r);
        pthread_mutex_unlock(&s_lock);
        bool ready = gdrive_refresh_quota();
        pthread_mutex_lock(&s_lock);
        s_state = ready ? GDRIVE_STATE_READY : GDRIVE_STATE_ERROR;
        if (ready) {
            diag_set_locked("", "", 0, 0);
            log_info("gdrive: sign-in complete; Drive API ready");
        } else {
            log_warn("gdrive: Google sign-in completed, but Drive API check failed");
        }
        pthread_mutex_unlock(&s_lock);
        return s_state;
    }

    // Standard RFC 8628 pending / slow-down responses.
    char err[64] = {0};
    json_get_string(r.body, "error", err, sizeof(err));
    if (strcmp(err, "authorization_pending") == 0) {
        // Keep polling.
    } else if (strcmp(err, "slow_down") == 0) {
        s_flow.interval_seconds += 5;
    } else if (strcmp(err, "access_denied") == 0 ||
               strcmp(err, "expired_token") == 0) {
        response_diag_locked("device flow poll", &r);
        s_state = GDRIVE_STATE_DEVICE_DENIED;
    } else if (err[0]) {
        response_diag_locked("device flow poll", &r);
        s_state = GDRIVE_STATE_ERROR;
    }
    http_response_free(&r);
    pthread_mutex_unlock(&s_lock);
    return s_state;
}

void gdrive_device_flow_cancel(void) {
    pthread_mutex_lock(&s_lock);
    if (s_state == GDRIVE_STATE_DEVICE_PENDING) {
        s_state = GDRIVE_STATE_NOT_SIGNED_IN;
        memset(&s_flow, 0, sizeof(s_flow));
    }
    pthread_mutex_unlock(&s_lock);
}

void gdrive_sign_out(void) {
    pthread_mutex_lock(&s_lock);
    s_session_generation++;
    recovery_reset_locked();
    s_initialization_deferred = false;
    tokens_wipe();
    s_state = eff_client_id()[0]
        ? GDRIVE_STATE_NOT_SIGNED_IN : GDRIVE_STATE_NOT_CONFIGURED;
    diag_set_locked("", "", 0, 0);
    log_info("gdrive: signed out");
    pthread_mutex_unlock(&s_lock);
}

gdrive_state_t gdrive_get_state(void) {
    // Well-defined lock-free atomic load (s_state is _Atomic). The /api/status
    // poll hits this every few seconds; it must never wait on s_lock, which a
    // slow Drive upload/quota call holds across the network (that would stall
    // the status endpoint → "Could not reach the TostónSync API").
    return s_state;
}

const char* gdrive_get_session_presence(void) {
    if (gdrive_get_state() == GDRIVE_STATE_READY) return "present";
    config_t cfg;
    if (!config_snapshot(&cfg) || !cfg.paths.state_dir[0] ||
        !memchr(cfg.paths.state_dir, '\0', sizeof(cfg.paths.state_dir)))
        return "unknown";
    char path[CFG_MAX_PATH + sizeof("/tokens.json")];
    int len = snprintf(path, sizeof(path), "%s/tokens.json", cfg.paths.state_dir);
    if (len < 0 || (size_t)len >= sizeof(path)) return "unknown";
    struct stat st;
    if (stat(path, &st) != 0) return errno == ENOENT ? "absent" : "unknown";
    // Presence is not validity; only an explicit Drive action may validate it.
    return S_ISREG(st.st_mode) && st.st_size > 0 ? "present" : "unknown";
}

bool gdrive_get_account(gdrive_account_t* out) {
    if (!out) return false;
    // s_acct_lock is only ever held for a struct copy, never across a network
    // call, so this is both race-free (no torn read) and non-blocking for the
    // status poll.
    pthread_mutex_lock(&s_acct_lock);
    *out = s_account;
    pthread_mutex_unlock(&s_acct_lock);
    return s_state == GDRIVE_STATE_READY;   // atomic load
}

// Token/email responses must be complete, nonempty ASCII strings, not the
// truncated prefixes accepted by the general lightweight JSON reader.
static bool drive_read_ascii_string(const char* json, const char* key,
                                     char* out, size_t out_sz) {
    if (!out || !out_sz) return false;
    out[0] = '\0';
    if (!json || !key || strlen(key) > 32) return false;
    char field[36];
    snprintf(field, sizeof(field), "\"%s\"", key);
    const char* p = strstr(json, field);
    if (!p) return false;
    p += strlen(field);
    while (isspace((unsigned char)*p)) p++;
    if (*p++ != ':') return false;
    while (isspace((unsigned char)*p)) p++;
    if (*p++ != '"') return false;
    const char* start = p;
    while (*p >= '!' && *p <= '~' && *p != '"' && *p != '\\') p++;
    size_t len = (size_t)(p - start);
    if (*p != '"' || !len || len >= out_sz) return false;
    memcpy(out, start, len);
    out[len] = '\0';
    return true;
}

static bool gdrive_refresh_session_locked(bool read_only) {
    if (!s_tokens.refresh_token[0]) return false;

    char cid[256], secret[256], refresh[768];
    url_encode(eff_client_id(), cid, sizeof(cid));
    url_encode(eff_client_secret(), secret, sizeof(secret));
    url_encode(s_tokens.refresh_token, refresh, sizeof(refresh));
    // client_secret optional (see device flow poll).
    char body[1408];
    if (eff_client_secret()[0])
        snprintf(body, sizeof(body),
                 "client_id=%s&client_secret=%s&refresh_token=%s"
                 "&grant_type=refresh_token",
                 cid, secret, refresh);
    else
        snprintf(body, sizeof(body),
                 "client_id=%s&refresh_token=%s&grant_type=refresh_token",
                 cid, refresh);

    http_response_t r = {0};
    if (!http_post_form(TOKEN_URL, body, &r) || r.status != 200) {
        response_diag_locked("token refresh", &r);
        http_response_free(&r);
        if (!read_only) recovery_failed_locked();
        return false;
    }
    if (!drive_read_ascii_string(r.body, "access_token",
                         s_tokens.access_token, sizeof(s_tokens.access_token)) ||
        !s_tokens.access_token[0]) {
        diag_set_locked("invalid_response", "Google returned no access token", r.status, 0);
        http_response_free(&r);
        if (!read_only) recovery_failed_locked();
        return false;
    }
    int expires_in = (int)json_get_number(r.body, "expires_in");
    if (expires_in <= 0) expires_in = 3600;
    s_tokens.access_expires_unix = now_unix() + expires_in;
    // Google may rotate the refresh token; honor it if present.
    char new_rt[512] = {0};
    if (json_get_string(r.body, "refresh_token", new_rt, sizeof(new_rt))
        && new_rt[0]) {
        strncpy(s_tokens.refresh_token, new_rt,
                sizeof(s_tokens.refresh_token) - 1);
    }
    tokens_save();
    http_response_free(&r);
    return true;
}

static bool gdrive_refresh_locked(void) {
    return gdrive_refresh_session_locked(false);
}

static bool ensure_read_access_token_locked(void) {
    if (!eff_client_id()[0]) return false;
    if (s_initialization_deferred && !s_read_session_loaded) {
        s_read_session_loaded = true;
        if (!tokens_load()) {
            s_read_session_failed = true;
            diag_set_locked("not_signed_in", "Google Drive has no saved session for reading backups.", 0, 0);
            return false;
        }
    }
    // Read capability never publishes write readiness or recovery authority.
    if (access_token_fresh()) {
        s_read_session_failed = false;
        return true;
    }
    if (s_read_session_failed) return false;
    if (gdrive_refresh_session_locked(true)) return true;
    s_read_session_failed = true;
    return false;
}

bool gdrive_refresh(void) {
    pthread_mutex_lock(&s_lock);
    bool ok = gdrive_refresh_locked();
    pthread_mutex_unlock(&s_lock);
    return ok;
}

static bool gdrive_refresh_quota_locked(void) {
    if (!ensure_access_token_locked()) {
        return false;
    }
    char url[256];
    snprintf(url, sizeof(url),
             "%s/about?fields=user(emailAddress),storageQuota", DRIVE_API_BASE);
    http_response_t r = {0};
    if (!http_get_auth(url, s_tokens.access_token, &r) || r.status != 200) {
        response_diag_locked("Drive API account check", &r);
        http_response_free(&r);
        recovery_failed_locked();
        return false;
    }
    char email[GDRIVE_EMAIL_MAX] = {0};
    if (!drive_read_ascii_string(r.body, "emailAddress", email, sizeof(email))) {
        diag_set_locked("invalid_response", "Google returned no account identity", r.status, 0);
        http_response_free(&r);
        recovery_failed_locked();
        return false;
    }
    pthread_mutex_lock(&s_acct_lock);
    snprintf(s_account.email, sizeof(s_account.email), "%s", email);
    s_account.quota_total_bytes = (uint64_t)json_get_number(r.body, "limit");
    s_account.quota_used_bytes  = (uint64_t)json_get_number(r.body, "usage");
    pthread_mutex_unlock(&s_acct_lock);
    http_response_free(&r);
    tokens_save();
    return true;
}

bool gdrive_refresh_quota(void) {
    pthread_mutex_lock(&s_lock);
    bool ok = gdrive_refresh_quota_locked();
    pthread_mutex_unlock(&s_lock);
    return ok;
}

bool gdrive_estimate_backup_bytes(uint64_t* out_bytes) {
    size_t files = 0;
    return gdrive_estimate_backup_usage(out_bytes, &files);
}

// --------------------------------------------------------------------
// Folder resolution: <root_folder>/<title_id>.
// --------------------------------------------------------------------

// IDs are opaque ASCII tokens, not general user text. Reject truncated values,
// missing quotes and escapes rather than hashing a plausible-looking prefix.
static bool drive_read_id(const char* json, const char* key,
                           char* out, size_t out_sz) {
    if (!out || !out_sz) return false;
    out[0] = '\0';
    if (!json || !key || strlen(key) > 32) return false;
    char field[36];
    snprintf(field, sizeof(field), "\"%s\"", key);
    const char* p = strstr(json, field);
    if (!p) return false;
    p += strlen(field);
    while (isspace((unsigned char)*p)) p++;
    if (*p++ != ':') return false;
    while (isspace((unsigned char)*p)) p++;
    if (*p++ != '\"') return false;
    const char* start = p;
    while ((*p >= 'a' && *p <= 'z') || (*p >= 'A' && *p <= 'Z') ||
           (*p >= '0' && *p <= '9') || *p == '_' || *p == '-') p++;
    size_t len = (size_t)(p - start);
    if (*p != '\"' || !len || len >= out_sz) return false;
    memcpy(out, start, len);
    out[len] = '\0';
    return true;
}

static bool drive_resolve_folder(const char* name, const char* parent_id,
                                  bool create,
                                  char out_id[GDRIVE_FILEID_MAX]) {
    out_id[0] = '\0';
    if (!ensure_access_token_locked()) return false;

    // Search.
    char name_q[256], parent_q[GDRIVE_FILEID_MAX * 2];
    char name_enc[768], parent_enc[GDRIVE_FILEID_MAX * 3];
    drive_query_escape(name, name_q, sizeof(name_q));
    const char* parent = parent_id && parent_id[0] ? parent_id
        : s_cfg->gdrive.use_appdata ? "appDataFolder" : "root";
    drive_query_escape(parent, parent_q, sizeof(parent_q));
    url_encode(name_q, name_enc, sizeof(name_enc));
    url_encode(parent_q, parent_enc, sizeof(parent_enc));
    char q[1536];
    int q_len = snprintf(q, sizeof(q),
            "%s/files?q=name%%3D%%27%s%%27+and+mimeType%%3D%%27application"
            "%%2Fvnd.google-apps.folder%%27+and+%%27%s%%27+in+parents"
            "+and+trashed%%3Dfalse&spaces=%s&fields=files(id)",
            DRIVE_API_BASE, name_enc, parent_enc,
            s_cfg->gdrive.use_appdata ? "appDataFolder" : "drive");
    if (q_len < 0 || (size_t)q_len >= sizeof(q)) return false;
    http_response_t r = {0};
    if (!http_get_auth(q, s_tokens.access_token, &r) || r.status != 200) {
        response_diag_locked("folder lookup", &r);
        http_response_free(&r);
        recovery_failed_locked();
        return false;
    }
    bool found = drive_read_id(r.body, "id", out_id, GDRIVE_FILEID_MAX);
    bool malformed_id = r.body && strstr(r.body, "\"id\"") && !found;
    http_response_free(&r);
    if (found) return true;
    out_id[0] = '\0';
    if (malformed_id) {
        diag_set_locked("invalid_response", "Google returned an invalid folder ID", 200, 0);
        recovery_failed_locked();
        return false;
    }
    if (!create) return false;

    // Create.
    char body[512];
    char name_json[160], parent_json[GDRIVE_FILEID_MAX * 2];
    json_escape(name, name_json, sizeof(name_json));
    json_escape(parent_id ? parent_id : "", parent_json, sizeof(parent_json));
    if (parent_id && parent_id[0]) {
        snprintf(body, sizeof(body),
            "{\"name\":\"%s\",\"mimeType\":\"application/vnd.google-apps.folder\","
            "\"parents\":[\"%s\"]}",
            name_json, parent_json);
    } else if (s_cfg->gdrive.use_appdata) {
        snprintf(body, sizeof(body),
            "{\"name\":\"%s\",\"mimeType\":\"application/vnd.google-apps.folder\","
            "\"parents\":[\"appDataFolder\"]}",
            name_json);
    } else {
        snprintf(body, sizeof(body),
            "{\"name\":\"%s\",\"mimeType\":\"application/vnd.google-apps.folder\"}",
            name_json);
    }
    char url[256];
    snprintf(url, sizeof(url), "%s/files?fields=id", DRIVE_API_BASE);
    memset(&r, 0, sizeof(r));
    if (!http_post_json_auth(url, s_tokens.access_token, body, &r)
        || (r.status != 200 && r.status != 201)) {
        response_diag_locked("folder create", &r);
        http_response_free(&r);
        recovery_failed_locked();
        return false;
    }
    bool ok = drive_read_id(r.body, "id", out_id, GDRIVE_FILEID_MAX);
    if (!ok) diag_set_locked("invalid_response", "Google returned no folder ID", r.status, 0);
    http_response_free(&r);
    if (!ok) recovery_failed_locked();
    return ok;
}

static bool drive_find_or_create_folder(const char* name,
                                        const char* parent_id,
                                        char out_id[GDRIVE_FILEID_MAX]) {
    return drive_resolve_folder(name, parent_id, true, out_id);
}

// Keep the complete test in one session: sign-out/reconfigure must not
// interleave between refresh, account validation and root folder resolution.
static bool gdrive_test_ready_locked(gdrive_diagnostic_t* out) {
    if (!eff_client_id()[0] || !s_tokens.refresh_token[0]) {
        s_state = eff_client_id()[0] ? GDRIVE_STATE_NOT_SIGNED_IN
                                    : GDRIVE_STATE_NOT_CONFIGURED;
        diag_set_locked(eff_client_id()[0] ? "not_signed_in" : "not_configured",
                        eff_client_id()[0] ? "Google Drive is not signed in."
                                          : "Automatic Drive Client ID is missing", 0, 0);
        recovery_reset_locked();
        if (out) gdrive_get_diagnostic(out);
        return false;
    }
    char root_id[GDRIVE_FILEID_MAX] = {0};
    if (!gdrive_refresh_locked() || !gdrive_refresh_quota_locked() ||
        !drive_find_or_create_folder(s_cfg->gdrive.root_folder, NULL, root_id)) {
        if (out) gdrive_get_diagnostic(out);
        return false;
    }
    snprintf(s_tokens.root_folder_id, sizeof(s_tokens.root_folder_id), "%s", root_id);
    tokens_save();
    recovery_reset_locked();
    diag_set_locked("", "", 0, 0);
    s_state = GDRIVE_STATE_READY;
    if (out) {
        *out = (gdrive_diagnostic_t){0};
        snprintf(out->code, sizeof(out->code), "ready");
        snprintf(out->detail, sizeof(out->detail),
                 "Google Drive is ready for automatic backups.");
    }
    return true;
}

bool gdrive_test_ready(gdrive_diagnostic_t* out) {
    pthread_mutex_lock(&s_lock);
    if (s_initialization_deferred) {
        // The explicit test performs readiness once, not once for activation
        // and again for the test. Existing OAuth validation stays unchanged.
        s_initialization_deferred = false;
        if (eff_client_id()[0]) (void)tokens_load();
    }
    bool ok = gdrive_test_ready_locked(out);
    pthread_mutex_unlock(&s_lock);
    return ok;
}

bool gdrive_recovery_due(void) {
    // Lock-free scheduler/status check; never stall title triggers on HTTPS.
    int64_t now = now_unix(), deadline = s_recovery_at;
    return s_state == GDRIVE_STATE_ERROR && s_recovery_retryable &&
           (now >= deadline || deadline - now > 300); // clock rollback: never strand work
}

bool gdrive_ensure_ready(void) {
    if (s_state == GDRIVE_STATE_READY) return true;
    pthread_mutex_lock(&s_lock);
    bool ok = s_state == GDRIVE_STATE_READY;
    if (!ok && gdrive_recovery_due()) {
        // ponytail: one provider cooldown across all titles, not per-title probes.
        s_recovery_at = now_unix() + dest_retry_delay_seconds(1);
        log_info("gdrive: checking availability for pending backup");
        ok = gdrive_test_ready_locked(NULL);
        if (ok) log_info("gdrive: automatic backups ready after temporary failure");
    }
    pthread_mutex_unlock(&s_lock);
    return ok;
}

static bool drive_catalog_children(const char* parent, bool files,
                                    gdrive_version_t* out, size_t cap,
                                    size_t* count, const char** reason);
static bool drive_catalog_root(char root_id[GDRIVE_FILEID_MAX], bool* absent,
                               const char** reason);
static const char *drive_metadata_ws(const char* p);
static bool
drive_retention_string(const char** cursor, char* out, size_t cap);

// Enumerate one complete parent, then compare codes rather than mutable labels.
// An incomplete listing never authorizes creating a second folder.
static bool drive_code_folders(const char* parent, const char* code, bool title,
                                gdrive_version_t* out, size_t cap, size_t* count) {
    const char* reason = NULL;
    size_t total = 0;
    *count = 0;
    if (!drive_catalog_children(parent, false, out, cap, &total, &reason)) {
        log_warn("gdrive: folder identity listing incomplete (%s)",
                 reason ? reason : "unknown");
        return false;
    }
    char wanted[16];
    if (!backup_folder_code(code, title, wanted, sizeof(wanted))) return false;
    for (size_t i = 0; i < total; i++) {
        char observed[16];
        if (backup_folder_code(out[i].name, title, observed, sizeof(observed)) &&
            !strcmp(observed, wanted)) out[(*count)++] = out[i];
    }
    return true;
}

static bool drive_folder_before(const gdrive_version_t* a,
                                 const gdrive_version_t* b, const char* code) {
    // Entries already matched the canonical code; a bare code has no prefix.
    bool a_bare = strlen(a->name) == strlen(code), b_bare = strlen(b->name) == strlen(code);
    if (a_bare != b_bare) return a_bare;
    int order = strcmp(a->name, b->name);
    return order ? order < 0 : strcmp(a->file_id, b->file_id) < 0;
}

static bool drive_rename_folder(const char* id, const char* readable) {
    char escaped[256], body[288], url[256];
    json_escape(readable, escaped, sizeof(escaped));
    int n = snprintf(body, sizeof(body), "{\"name\":\"%s\"}", escaped);
    if (n < 0 || (size_t)n >= sizeof(body)) return false;
    snprintf(url, sizeof(url), "%s/files/%s?fields=id,name", DRIVE_API_BASE, id);
    http_response_t r = {0};
    bool ok = http_patch_json_auth(url, s_tokens.access_token, body, &r) &&
              r.status == 200 && !r.transport_error && r.body &&
              r.body_len == strlen(r.body);
    if (ok) {
        const char* p = drive_metadata_ws(r.body);
        unsigned fields = 0;
        if (*p++ != '{') ok = false;
        while (ok && *p != '}') {
            char key[16] = {0}, value[128] = {0};
            p = drive_metadata_ws(p);
            ok = drive_retention_string(&p, key, sizeof(key)) && *p++ == ':';
            if (!ok) break;
            unsigned bit = !strcmp(key, "id") ? 1 : !strcmp(key, "name") ? 2 : 0;
            p = drive_metadata_ws(p);
            ok = ok && bit && !(fields & bit) &&
                 drive_retention_string(&p, value, sizeof(value)) &&
                 !strcmp(value, bit == 1 ? id : readable);
            if (!ok) break;
            fields |= bit;
            if (*p == '}') break;
            if (*p++ != ',') { ok = false; break; }
        }
        ok = ok && fields == 3 && *p++ == '}' && !*drive_metadata_ws(p);
    }
    http_response_free(&r);
    if (!ok) log_warn("gdrive: folder rename unconfirmed; existing folder reused, no second folder");
    return ok;
}

static bool drive_resolve_code_folder(const char* parent, const char* code,
                                       const char* readable, bool title,
                                       bool create, bool allow_rename,
                                       char out[GDRIVE_FILEID_MAX]) {
    enum { FOLDER_MAX = 256 };
    char canonical[16];
    out[0] = '\0';
    if (!backup_folder_code(code, title, canonical, sizeof(canonical))) return false;
    code = canonical;
    gdrive_version_t* folders = calloc(FOLDER_MAX, sizeof(*folders));
    size_t count = 0;
    bool ok = folders && drive_code_folders(parent, code, title, folders,
                                            FOLDER_MAX, &count);
    out[0] = '\0';
    if (ok && count) {
        size_t chosen = 0;
        for (size_t i = 1; i < count; i++)
            if (drive_folder_before(&folders[i], &folders[chosen], code)) chosen = i;
        if (count > 1)
            log_warn("gdrive: duplicate folders for code %s; deterministic destination, no merge or deletion", code);
        snprintf(out, GDRIVE_FILEID_MAX, "%s", folders[chosen].file_id);
        if (create && count == 1 && strcmp(folders[chosen].name, readable) &&
            (allow_rename || strlen(folders[chosen].name) == strlen(code)))
            (void)drive_rename_folder(out, readable);
    } else if (ok && create) {
        ok = drive_resolve_folder(readable, parent, true, out);
    } else ok = false;
    free(folders);
    return ok;
}

// Resolve the deterministic write destination without caching mutable labels.
// Drive identity remains account + actual folder ID across a same-parent rename.
static bool resolve_title_folder_mode(const char* user_alias,
                                      const char* title_id, bool create,
                                      char out_id[GDRIVE_FILEID_MAX]) {
    // Never trust a tokens.json root ID for dedupe or an upload: its account
    // or selected folder may have changed since it was persisted.
    char root_id[GDRIVE_FILEID_MAX];
    if (!drive_resolve_folder(s_cfg->gdrive.root_folder, NULL, create, root_id))
        return false;
    snprintf(s_tokens.root_folder_id, sizeof(s_tokens.root_folder_id), "%s", root_id);
    backup_names_t names;
    if (!backup_names_current(user_alias, title_id, NULL, "Manual", time(NULL), &names))
        return false;
    char user_folder_id[GDRIVE_FILEID_MAX];
    if (!drive_resolve_code_folder(root_id, user_alias, names.user_folder, false,
                                    create, true, user_folder_id))
        return false;
    return drive_resolve_code_folder(user_folder_id, title_id, names.title_folder,
                                      true, create, names.title_rename_requested, out_id);
}

static bool resolve_title_folder(const char* user_alias, const char* title_id,
                                 char out_id[GDRIVE_FILEID_MAX]) {
    return resolve_title_folder_mode(user_alias, title_id, true, out_id);
}

static bool drive_folder_identity_locked(const char* folder_id, char out[65]) {
    out[0] = '\0';
    if (!folder_id || !folder_id[0] || !ensure_access_token_locked()) return false;
    http_response_t r = {0};
    char permission_id[64] = {0};
    bool known = http_get_auth(DRIVE_API_BASE "/about?fields=user(permissionId)",
                              s_tokens.access_token, &r) && r.status == 200
        && drive_read_id(r.body, "permissionId", permission_id,
                         sizeof(permission_id));
    if (!known) {
        if (r.status != 200 || r.transport_error)
            response_diag_locked("backup account identity", &r);
        else diag_set_locked("invalid_response", "Google returned no account identity", 200, 0);
        recovery_failed_locked();
    }
    http_response_free(&r);
    if (!known) return false;

    // Google's permissionId identifies the authenticated account independently
    // of mutable email addresses. The actual folder ID distinguishes recreated
    // folders with the same name. No account identifier is persisted in clear.
    const char* fields[] = {"tostonsync-drive-v1", permission_id,
        s_cfg->gdrive.use_appdata ? "appDataFolder" : "drive", folder_id};
    return dest_identity_hash(fields, sizeof(fields) / sizeof(fields[0]), out);
}

// Read paths inspect every matching physical user/title folder. They never
// rename, create, merge, or turn a partial enumeration into authority.
static bool drive_title_folders(const char* user, const char* title,
                                 gdrive_version_t* out, size_t cap,
                                 size_t* count, bool read_only) {
    enum { GROUP_MAX = 256 };
    *count = 0;
    char root[GDRIVE_FILEID_MAX];
    if (read_only) {
        bool absent = false;
        const char* reason = NULL;
        if (!drive_catalog_root(root, &absent, &reason) || absent) return false;
    } else if (!drive_resolve_folder(s_cfg->gdrive.root_folder, NULL, false, root)) return false;
    gdrive_version_t* users = calloc(GROUP_MAX, sizeof(*users));
    gdrive_version_t* titles = calloc(GROUP_MAX, sizeof(*titles));
    size_t un = 0;
    bool ok = users && titles && drive_code_folders(root, user, false, users, GROUP_MAX, &un);
    for (size_t i = 0; ok && i < un; i++) {
        size_t tn = 0;
        ok = drive_code_folders(users[i].file_id, title, true, titles, GROUP_MAX, &tn);
        for (size_t j = 0; ok && j < tn; j++) {
            if (*count == cap) { ok = false; break; }
            out[(*count)++] = titles[j];
        }
    }
    free(users); free(titles);
    if (!ok) *count = 0;
    return ok;
}

static bool resolve_title_folder_scope(const char* user, const char* title,
                                        const char* expected_identity,
                                        char out[GDRIVE_FILEID_MAX]) {
    if (!expected_identity || !expected_identity[0])
        return resolve_title_folder_mode(user, title, false, out);
    enum { GROUP_MAX = 256 };
    gdrive_version_t* folders = calloc(GROUP_MAX, sizeof(*folders));
    size_t count = 0;
    bool ok = folders && drive_title_folders(user, title, folders, GROUP_MAX, &count, false);
    out[0] = '\0';
    for (size_t i = 0; ok && i < count; i++) {
        char identity[65];
        if (!drive_folder_identity_locked(folders[i].file_id, identity)) { ok = false; break; }
        if (!strcmp(identity, expected_identity)) {
            if (out[0]) { ok = false; break; }
            snprintf(out, GDRIVE_FILEID_MAX, "%s", folders[i].file_id);
        }
    }
    free(folders);
    if (!ok) out[0] = '\0';
    return ok && out[0];
}

bool gdrive_backup_identity(const char* user_alias, const char* title_id,
                            char out_identity[65]) {
    if (!out_identity) return false;
    out_identity[0] = '\0';
    pthread_mutex_lock(&s_lock);
    char folder_id[GDRIVE_FILEID_MAX];
    bool known = s_state == GDRIVE_STATE_READY
        && resolve_title_folder_mode(user_alias, title_id, false, folder_id)
        && drive_folder_identity_locked(folder_id, out_identity);
    pthread_mutex_unlock(&s_lock);
    return known;
}

// This endpoint requests only five fields. Parse that narrow shape strictly:
// the general JSON helpers accept truncated strings and numeric prefixes,
// which must never turn an uncertain response into permission to skip a copy.
static const char* drive_metadata_ws(const char* p) {
    while (*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r') p++;
    return p;
}

static bool drive_metadata_matches_named(const char* json, const char* file_id,
                                    const char* folder_id, uint64_t size,
                                    const char* name) {
    if (!json) return false;
    const char* p = drive_metadata_ws(json);
    if (*p++ != '{') return false;
    unsigned seen = 0;
    for (;;) {
        p = drive_metadata_ws(p);
        static const char* keys[] = {"\"id\"", "\"size\"", "\"trashed\"",
                                     "\"parents\"", "\"mimeType\"", "\"name\""};
        unsigned key_count = name ? 6 : 5;
        unsigned key = 0;
        while (key < key_count && strncmp(p, keys[key], strlen(keys[key]))) key++;
        if (key == key_count || (seen & (1U << key))) return false;
        seen |= 1U << key;
        p = drive_metadata_ws(p + strlen(keys[key]));
        if (*p++ != ':') return false;
        p = drive_metadata_ws(p);
        if (key == 0 || key >= 4) {
            const char* value = key == 0 ? file_id : key == 4 ? "application/zip" : name;
            size_t len = strlen(value);
            if (*p++ != '"' || strncmp(p, value, len) || p[len] != '"')
                return false;
            p += len + 1;
        } else if (key == 1) {
            if (*p++ != '"' || *p < '1' || *p > '9') return false;
            uint64_t parsed = 0;
            while (*p >= '0' && *p <= '9') {
                unsigned digit = (unsigned)(*p++ - '0');
                if (parsed > (GDRIVE_MAX_BYTES - digit) / 10) return false;
                parsed = parsed * 10 + digit;
            }
            if (*p++ != '"' || parsed != size) return false;
        } else if (key == 2) {
            if (strncmp(p, "false", 5)) return false;
            p += 5;
        } else {
            if (*p++ != '[') return false;
            bool parent_matches = false;
            for (;;) {
                p = drive_metadata_ws(p);
                if (*p++ != '"') return false;
                const char* start = p;
                while ((*p >= 'a' && *p <= 'z') || (*p >= 'A' && *p <= 'Z') ||
                       (*p >= '0' && *p <= '9') || *p == '_' || *p == '-') p++;
                size_t len = (size_t)(p - start);
                if (*p++ != '"' || !len || len >= GDRIVE_FILEID_MAX) return false;
                if (strlen(folder_id) == len && !memcmp(start, folder_id, len))
                    parent_matches = true;
                p = drive_metadata_ws(p);
                if (*p == ']') { p++; break; }
                if (*p++ != ',') return false;
            }
            if (!parent_matches) return false;
        }
        p = drive_metadata_ws(p);
        if (*p == '}') return seen == (name ? 63U : 31U) && !*drive_metadata_ws(p + 1);
        if (*p++ != ',') return false;
    }
}

static bool drive_metadata_matches(const char* json, const char* file_id,
                                    const char* folder_id, uint64_t size) {
    return drive_metadata_matches_named(json, file_id, folder_id, size, NULL);
}

bool gdrive_backup_exists(const char* user_alias, const char* title_id,
                          const char* file_id, uint64_t expected_size,
                          const char* expected_identity) {
    if (!file_id || !file_id[0] || strlen(file_id) >= GDRIVE_FILEID_MAX ||
        !expected_size || expected_size > GDRIVE_MAX_BYTES ||
        !dest_fingerprint_hex(expected_identity)) return false;
    for (const char* p = file_id; *p; p++)
        if (!((*p >= 'a' && *p <= 'z') || (*p >= 'A' && *p <= 'Z') ||
              (*p >= '0' && *p <= '9') || *p == '_' || *p == '-')) return false;

    // Keep account/folder resolution and file metadata in one locked session.
    // A concurrent reconfigure or sign-out cannot relabel this confirmation.
    pthread_mutex_lock(&s_lock);
    char folder_id[GDRIVE_FILEID_MAX], identity[65];
    bool exists = s_state == GDRIVE_STATE_READY &&
        resolve_title_folder_scope(user_alias, title_id, expected_identity, folder_id) &&
        drive_folder_identity_locked(folder_id, identity) &&
        strcmp(identity, expected_identity) == 0;
    if (exists) {
        char encoded[GDRIVE_FILEID_MAX * 3], url[384];
        url_encode(file_id, encoded, sizeof(encoded));
        snprintf(url, sizeof(url),
                 "%s/files/%s?fields=id,size,trashed,parents,mimeType",
                 DRIVE_API_BASE, encoded);
        http_response_t r = {0};
        exists = http_get_auth(url, s_tokens.access_token, &r) && r.status == 200 &&
            drive_metadata_matches(r.body, file_id, folder_id, expected_size);
        http_response_free(&r);
    }
    pthread_mutex_unlock(&s_lock);
    return exists;
}

// --------------------------------------------------------------------
// Upload (Drive resumable protocol, bounded only by the 8 GiB product cap).
// --------------------------------------------------------------------

static bool drive_individual_folder_page(const char* json, const char* name,
                                         char out[GDRIVE_FILEID_MAX], bool* found) {
    *found = false;
    out[0] = '\0';
    if (!json) return false;
    const char* p = drive_metadata_ws(json);
    if (*p++ != '{') return false;
    p = drive_metadata_ws(p);
    unsigned top = 0;
    while (*p != '}') {
        char key[24];
        if (!drive_retention_string(&p, key, sizeof(key)) || *p++ != ':') return false;
        p = drive_metadata_ws(p);
        if (!strcmp(key, "incompleteSearch") && !(top & 2)) {
            if (strncmp(p, "false", 5)) return false;
            p = drive_metadata_ws(p + 5); top |= 2;
        } else if (!strcmp(key, "nextPageToken") && !(top & 4)) {
            char next[256];
            if (!drive_retention_string(&p, next, sizeof(next)) || next[0]) return false;
            top |= 4;
        } else if (!strcmp(key, "files") && !(top & 1)) {
            top |= 1;
            if (*p++ != '[') return false;
            p = drive_metadata_ws(p);
            if (*p != ']') {
                if (*p++ != '{') return false;
                unsigned fields = 0;
                for (;;) {
                    char field[16], value[128];
                    if (!drive_retention_string(&p, field, sizeof(field)) || *p++ != ':' ||
                        !drive_retention_string(&p, value, sizeof(value))) return false;
                    unsigned bit = !strcmp(field, "id") ? 1 : !strcmp(field, "name") ? 2 :
                                   !strcmp(field, "mimeType") ? 4 : 0;
                    if (!bit || (fields & bit)) return false;
                    fields |= bit;
                    if (bit == 1) {
                        if (!value[0] || strlen(value) >= GDRIVE_FILEID_MAX) return false;
                        for (const char* q = value; *q; q++)
                            if (!((*q >= 'A' && *q <= 'Z') || (*q >= 'a' && *q <= 'z') ||
                                  (*q >= '0' && *q <= '9') || *q == '_' || *q == '-')) return false;
                        snprintf(out, GDRIVE_FILEID_MAX, "%s", value);
                    } else if (bit == 2 ? strcmp(value, name) :
                               strcmp(value, "application/vnd.google-apps.folder")) return false;
                    if (*p == '}') { p = drive_metadata_ws(p + 1); break; }
                    if (*p++ != ',') return false;
                }
                if (fields != 7) return false;
                *found = true;
            }
            // More than one exact-name entry is ambiguous, never a merge target.
            if (*p++ != ']') return false;
            p = drive_metadata_ws(p);
        } else return false;
        if (*p == '}') break;
        if (*p++ != ',') return false;
        p = drive_metadata_ws(p);
        if (*p == '}') return false;
    }
    return (top & 1) && !*drive_metadata_ws(p + 1);
}

static bool drive_individual_folder(const char* parent, const char* name,
                                     char out[GDRIVE_FILEID_MAX]) {
    char name_q[256], name_enc[768], url[1536];
    drive_query_escape(name, name_q, sizeof(name_q));
    url_encode(name_q, name_enc, sizeof(name_enc));
    int n = snprintf(url, sizeof(url), "%s/files?q=name%%3D%%27%s%%27+and+"
        "%%27%s%%27+in+parents+and+trashed%%3Dfalse&spaces=%s&pageSize=2"
        "&fields=nextPageToken,incompleteSearch,files(id,name,mimeType)",
        DRIVE_API_BASE, name_enc, parent,
        s_cfg->gdrive.use_appdata ? "appDataFolder" : "drive");
    if (n <= 0 || (size_t)n >= sizeof(url)) return false;
    http_response_t r = {0};
    bool found = false;
    bool ok = http_get_auth(url, s_tokens.access_token, &r) && r.status == 200 &&
        !r.transport_error && r.body && r.body_len == strlen(r.body) &&
        drive_individual_folder_page(r.body, name, out, &found);
    http_response_free(&r);
    if (!ok || found) return ok;
    char escaped[160], body[512];
    json_escape(name, escaped, sizeof(escaped));
    n = snprintf(body, sizeof(body), "{\"name\":\"%s\","
        "\"mimeType\":\"application/vnd.google-apps.folder\",\"parents\":[\"%s\"]}",
        escaped, parent);
    if (n <= 0 || (size_t)n >= sizeof(body)) return false;
    snprintf(url, sizeof(url), "%s/files?fields=id", DRIVE_API_BASE);
    ok = http_post_json_auth(url, s_tokens.access_token, body, &r) &&
        (r.status == 200 || r.status == 201) && !r.transport_error && r.body &&
        r.body_len == strlen(r.body) && drive_read_id(r.body, "id", out, GDRIVE_FILEID_MAX);
    http_response_free(&r);
    return ok;
}

static bool gdrive_upload_in_folder(const char* user_alias,
                   const char* title_id,
                   const char* filename,
                   const char* local_zip_path,
                   char        out_file_id[GDRIVE_FILEID_MAX],
                   char        out_identity[65], const char* subfolder) {
    if (out_identity) out_identity[0] = '\0';
    if (!out_file_id) return false;
    out_file_id[0] = '\0';
    struct stat st;
    if (!local_zip_path || stat(local_zip_path, &st) != 0 ||
        st.st_size <= 0 || (uint64_t)st.st_size > GDRIVE_MAX_BYTES) {
        log_warn("gdrive: upload rejected (missing, empty, or larger than 8 GiB)");
        return false;
    }
    pthread_mutex_lock(&s_lock);
    if (!ensure_access_token_locked()) {
        pthread_mutex_unlock(&s_lock);
        return false;
    }
    char title_folder_id[GDRIVE_FILEID_MAX];
    if (!resolve_title_folder(user_alias, title_id, title_folder_id)) {
        pthread_mutex_unlock(&s_lock);
        return false;
    }
    if (subfolder) {
        char child[GDRIVE_FILEID_MAX];
        if (!drive_individual_folder(title_folder_id, subfolder, child)) {
            pthread_mutex_unlock(&s_lock);
            return false;
        }
        memcpy(title_folder_id, child, sizeof(child));
    }
    char identity[65] = {0};
    if (out_identity) drive_folder_identity_locked(title_folder_id, identity);
    char token[sizeof(s_tokens.access_token)];
    snprintf(token, sizeof(token), "%s", s_tokens.access_token);
    uint64_t generation = s_session_generation;
    pthread_mutex_unlock(&s_lock);

    // Folder resolution needs the Drive state lock; the long byte transfer
    // does not. Upload from a token snapshot so status/list requests remain
    // responsive while a multi-gigabyte save is moving.
    char metadata[512];
    char filename_json[160], parent_json[GDRIVE_FILEID_MAX * 2];
    json_escape(filename, filename_json, sizeof(filename_json));
    json_escape(title_folder_id, parent_json, sizeof(parent_json));
    snprintf(metadata, sizeof(metadata),
             "{\"name\":\"%s\",\"parents\":[\"%s\"]}",
             filename_json, parent_json);
    char url[256];
    snprintf(url, sizeof(url),
             "%s/files?uploadType=resumable&fields=id", DRIVE_UPLOAD_BASE);

    http_response_t r = {0};
    if (!http_post_resumable_file_auth(url, token, metadata,
                                       "application/zip", local_zip_path,
                                       GDRIVE_CHUNK_BYTES, GDRIVE_MAX_BYTES, &r)
        || (r.status != 200 && r.status != 201)) {
        pthread_mutex_lock(&s_lock);
        // A late failure from account A must not poison a newly signed-in B.
        if (generation == s_session_generation &&
            s_state != GDRIVE_STATE_DEVICE_PENDING && s_tokens.refresh_token[0]) {
            response_diag_locked("backup upload", &r);
            recovery_failed_locked();
        }
        pthread_mutex_unlock(&s_lock);
        log_warn("gdrive: upload failed (status=%d)", r.status);
        http_response_free(&r);
        return false;
    }

    bool ok = drive_read_id(r.body, "id", out_file_id, GDRIVE_FILEID_MAX);
    http_response_free(&r);
    if (!ok || !out_file_id[0]) {
        log_warn("gdrive: upload succeeded but no file id returned");
        return false;
    }
    log_debug("gdrive: uploaded %s/%s/%s",
             (user_alias && user_alias[0]) ? user_alias : "default",
             title_id, filename);
    if (out_identity) snprintf(out_identity, 65, "%s", identity);
    return true;
}

bool gdrive_upload_identified(const char* user_alias, const char* title_id,
                              const char* filename, const char* local_zip_path,
                              char out_file_id[GDRIVE_FILEID_MAX], char out_identity[65]) {
    return gdrive_upload_in_folder(user_alias, title_id, filename, local_zip_path,
                                   out_file_id, out_identity, NULL);
}

bool gdrive_upload_individual_identified(const char* user_alias, const char* title_id,
                              const char* filename, const char* local_zip_path,
                              char out_file_id[GDRIVE_FILEID_MAX], char out_identity[65]) {
    return gdrive_upload_in_folder(user_alias, title_id, filename, local_zip_path,
                                   out_file_id, out_identity, "Individual saves");
}

bool gdrive_upload(const char* user_alias, const char* title_id,
                   const char* filename, const char* local_zip_path,
                   char out_file_id[GDRIVE_FILEID_MAX]) {
    return gdrive_upload_identified(user_alias, title_id, filename,
                                    local_zip_path, out_file_id, NULL);
}

// --------------------------------------------------------------------
// Listing & retention.
// --------------------------------------------------------------------

size_t gdrive_list_versions(const char* user_alias, const char* title_id,
                            gdrive_version_t* out, size_t max_out) {
    if (!out || max_out == 0) return 0;
    pthread_mutex_lock(&s_lock);
    if (!ensure_read_access_token_locked()) {
        pthread_mutex_unlock(&s_lock);
        return 0;
    }
    enum { GROUP_MAX = 256 };
    gdrive_version_t* folders = calloc(GROUP_MAX, sizeof(*folders));
    gdrive_version_t* files = calloc(max_out, sizeof(*files));
    size_t count = 0, n = 0;
    bool ok = folders && files && drive_title_folders(user_alias, title_id,
                                                      folders, GROUP_MAX, &count, true);
    for (size_t i = 0; ok && i < count; i++) {
        size_t fn = 0;
        const char* reason = NULL;
        ok = drive_catalog_children(folders[i].file_id, true, files, max_out,
                                      &fn, &reason);
        for (size_t j = 0; ok && j < fn; j++) {
            size_t len = strlen(files[j].name);
            if (len <= 4 || strcmp(files[j].name + len - 4, ".zip")) continue;
            if (n == max_out) { ok = false; break; }
            out[n++] = files[j];
        }
    }
    free(folders); free(files);
    if (!ok) n = 0;
    for (size_t i = 1; i < n; i++) {
        gdrive_version_t key = out[i];
        size_t j = i;
        while (j && (key.created_unix > out[j - 1].created_unix ||
                     (key.created_unix == out[j - 1].created_unix &&
                      strcmp(key.name, out[j - 1].name) > 0))) {
            out[j] = out[j - 1]; j--;
        }
        out[j] = key;
    }
    pthread_mutex_unlock(&s_lock);
    return n;
}

// Narrow destructive-list parser, not the permissive UI JSON reader. Refuse
// partial pages, truncated/escaped strings, duplicate fields/IDs and bad sizes.
// ponytail: one bounded complete page; defer cleanup rather than paginate under
// a changing target. Add pagination only if >512 archives per title is needed.
static bool drive_retention_string(const char** cursor, char* out, size_t cap) {
    const char* p = drive_metadata_ws(*cursor);
    if (*p++ != '"') return false;
    size_t n = 0;
    while (*p && *p != '"') {
        if (*p == '\\' || (unsigned char)*p < 32 || n + 1 >= cap) return false;
        out[n++] = *p++;
    }
    if (*p != '"' || !n) return false;
    out[n] = '\0';
    *cursor = drive_metadata_ws(p + 1);
    return true;
}

static bool drive_retention_versions(const char* json, gdrive_version_t* out,
                                      size_t cap, size_t* count) {
    *count = 0;
    if (!json) return false;
    const char* p = drive_metadata_ws(json);
    if (*p++ != '{') return false;
    p = drive_metadata_ws(p);
    unsigned top = 0;
    while (*p != '}') {
        char key[24];
        if (!drive_retention_string(&p, key, sizeof(key)) || *p++ != ':') return false;
        p = drive_metadata_ws(p);
        if (!strcmp(key, "incompleteSearch") && !(top & 2)) {
            if (strncmp(p, "false", 5)) return false;
            p = drive_metadata_ws(p + 5); top |= 2;
        } else if (!strcmp(key, "files") && !(top & 1)) {
            top |= 1;
            if (*p++ != '[') return false;
            p = drive_metadata_ws(p);
            while (*p != ']') {
                if (*count >= cap || *p++ != '{') return false;
                gdrive_version_t v = {0};
                unsigned seen = 0;
                for (;;) {
                    char field[16], value[128];
                    if (!drive_retention_string(&p, field, sizeof(field)) || *p++ != ':' ||
                        !drive_retention_string(&p, value, sizeof(value))) return false;
                    unsigned bit = !strcmp(field, "id") ? 1 :
                                   !strcmp(field, "name") ? 2 :
                                   !strcmp(field, "size") ? 4 : 0;
                    if (!bit || (seen & bit)) return false;
                    seen |= bit;
                    if (bit == 1) {
                        if (strlen(value) >= sizeof(v.file_id)) return false;
                        for (const char* q = value; *q; q++)
                            if (!((*q >= 'A' && *q <= 'Z') || (*q >= 'a' && *q <= 'z') ||
                                  (*q >= '0' && *q <= '9') || *q == '_' || *q == '-')) return false;
                        snprintf(v.file_id, sizeof(v.file_id), "%s", value);
                    } else if (bit == 2) snprintf(v.name, sizeof(v.name), "%s", value);
                    else {
                        if (*value < '1' || *value > '9') return false;
                        for (const char* q = value; *q; q++) {
                            if (*q < '0' || *q > '9' ||
                                v.size_bytes > (GDRIVE_MAX_BYTES - (unsigned)(*q - '0')) / 10)
                                return false;
                            v.size_bytes = v.size_bytes * 10 + (unsigned)(*q - '0');
                        }
                    }
                    if (*p == '}') { p = drive_metadata_ws(p + 1); break; }
                    if (*p++ != ',') return false;
                }
                if (seen != 7) return false;
                for (size_t i = 0; i < *count; i++)
                    if (!strcmp(out[i].file_id, v.file_id)) return false;
                out[(*count)++] = v;
                if (*p == ']') break;
                if (*p++ != ',') return false;
                p = drive_metadata_ws(p);
                if (*p == ']') return false;
            }
            p = drive_metadata_ws(p + 1);
        } else return false; // nextPageToken (even empty) is not a complete list.
        if (*p == '}') break;
        if (*p++ != ',') return false;
        p = drive_metadata_ws(p);
        if (*p == '}') return false;
    }
    return (top & 1) && !*drive_metadata_ws(p + 1);
}

bool gdrive_retention_list(const char* user_uid, const char* title_id,
                           const char* expected_identity,
                           gdrive_version_t* out, size_t max_out,
                           size_t* out_count, gdrive_retention_scope_t* scope) {
    if (out_count) *out_count = 0;
    if (scope) memset(scope, 0, sizeof(*scope));
    if (!out || !out_count || !scope || !max_out || max_out > 1000 ||
        (expected_identity && !dest_fingerprint_hex(expected_identity))) return false;
    pthread_mutex_lock(&s_lock);
    char folder[GDRIVE_FILEID_MAX], identity[65];
    bool ok = s_state == GDRIVE_STATE_READY &&
        resolve_title_folder_scope(user_uid, title_id, expected_identity, folder) &&
        drive_folder_identity_locked(folder, identity) &&
        (!expected_identity || !strcmp(identity, expected_identity));
    if (ok) {
        char url[768];
        snprintf(url, sizeof(url),
            "%s/files?q=%%27%s%%27+in+parents+and+trashed%%3Dfalse"
            "+and+mimeType%%3D%%27application%%2Fzip%%27"
            "&orderBy=createdTime+desc&pageSize=%zu"
            "&fields=nextPageToken,incompleteSearch,files(id,name,size)%s",
            DRIVE_API_BASE, folder, max_out,
            s_cfg->gdrive.use_appdata ? "&spaces=appDataFolder" : "");
        http_response_t r = {0};
        ok = http_get_auth(url, s_tokens.access_token, &r) && r.status == 200 &&
            drive_retention_versions(r.body, out, max_out, out_count);
        http_response_free(&r);
    }
    if (ok) {
        snprintf(scope->identity, sizeof(scope->identity), "%s", identity);
        scope->generation = s_session_generation;
    } else *out_count = 0;
    pthread_mutex_unlock(&s_lock);
    return ok;
}

static bool drive_delete_scoped(const char* user_uid, const char* title_id,
                             const gdrive_version_t* version,
                             const gdrive_version_t* keep_version,
                             const gdrive_retention_scope_t* scope, bool match_name) {
    if (!version || !scope || !dest_fingerprint_hex(scope->identity)) return false;
    const gdrive_version_t* checks[] = {keep_version, version};
    for (size_t i = 0; i < 2; i++) {
        const gdrive_version_t* v = checks[i];
        if (!v) continue;
        if (!memchr(v->file_id, '\0', sizeof(v->file_id)) ||
            !v->file_id[0] || !v->size_bytes || v->size_bytes > GDRIVE_MAX_BYTES)
            return false;
        for (const char* p = v->file_id; *p; p++)
            if (!((*p >= 'A' && *p <= 'Z') || (*p >= 'a' && *p <= 'z') ||
                  (*p >= '0' && *p <= '9') || *p == '_' || *p == '-')) return false;
    }
    if (keep_version && !strcmp(version->file_id, keep_version->file_id)) return false;
    pthread_mutex_lock(&s_lock);
    char folder[GDRIVE_FILEID_MAX], identity[65];
    bool ok = scope->generation == s_session_generation && s_state == GDRIVE_STATE_READY &&
        resolve_title_folder_scope(user_uid, title_id, scope->identity, folder) &&
        drive_folder_identity_locked(folder, identity) &&
        !strcmp(identity, scope->identity);
    if (ok) {
        char url[384];
        http_response_t r = {0};
        // Do not prune older copies if the accepted archive disappeared or
        // moved since listing. Both proofs and DELETE share one local session.
        for (size_t i = 0; i < 2 && ok; i++) {
            const gdrive_version_t* v = checks[i];
            if (!v) continue;
            snprintf(url, sizeof(url), "%s/files/%s?fields=id,size,trashed,parents,mimeType%s",
                     DRIVE_API_BASE, v->file_id, match_name ? ",name" : "");
            ok = http_get_auth(url, s_tokens.access_token, &r) && r.status == 200 &&
                drive_metadata_matches_named(r.body, v->file_id, folder, v->size_bytes,
                                               match_name ? v->name : NULL);
            http_response_free(&r);
        }
        if (ok) {
            snprintf(url, sizeof(url), "%s/files/%s", DRIVE_API_BASE, version->file_id);
            ok = http_delete_auth(url, s_tokens.access_token, &r) &&
                (r.status == 204 || r.status == 200);
            http_response_free(&r);
        }
    }
    pthread_mutex_unlock(&s_lock);
    return ok;
}

bool gdrive_retention_delete(const char* user_uid, const char* title_id,
                             const gdrive_version_t* version,
                             const gdrive_version_t* keep_version,
                             const gdrive_retention_scope_t* scope) {
    return drive_delete_scoped(user_uid, title_id, version, keep_version, scope, false);
}

bool gdrive_delete_version_identified(const char* user_uid, const char* title_id,
                                      const gdrive_version_t* version,
                                      const gdrive_retention_scope_t* scope) {
    if (!version || !memchr(version->name, '\0', sizeof(version->name)) ||
        !version->name[0]) return false;
    return drive_delete_scoped(user_uid, title_id, version, NULL, scope, true);
}

// Whole-catalog pages request a narrow shape and validate the entire response.
// Reuse the retention string reader: unsupported escapes/oversized fields fail
// closed rather than silently truncating an identity, group or cleanup order.
static bool drive_catalog_time(const char* ts, int64_t* unix_time) {
    size_t len = strlen(ts);
    if (len < 20 || len > 30 || ts[4] != '-' || ts[7] != '-' ||
        ts[10] != 'T' || ts[13] != ':' || ts[16] != ':' || ts[len - 1] != 'Z')
        return false;
    for (size_t i = 0; i < 19; i++)
        if (i != 4 && i != 7 && i != 10 && i != 13 && i != 16 &&
            (ts[i] < '0' || ts[i] > '9')) return false;
    if (len != 20) {
        if (len < 22 || ts[19] != '.') return false;
        for (size_t i = 20; i + 1 < len; i++)
            if (ts[i] < '0' || ts[i] > '9') return false;
    }
    int Y, M, D, h, m, s;
    if (sscanf(ts, "%4d-%2d-%2dT%2d:%2d:%2d", &Y, &M, &D, &h, &m, &s) != 6 ||
        Y < 1970 || M < 1 || M > 12 || D < 1 || h > 23 || m > 59 || s > 59)
        return false;
    static const int mday[] = {31,28,31,30,31,30,31,31,30,31,30,31};
    bool leap = (Y % 4 == 0 && Y % 100 != 0) || Y % 400 == 0;
    if (D > mday[M - 1] + (M == 2 && leap)) return false;
    int64_t days = 0;
    for (int y = 1970; y < Y; y++)
        days += ((y % 4 == 0 && y % 100 != 0) || y % 400 == 0) ? 366 : 365;
    for (int mi = 0; mi < M - 1; mi++) days += mday[mi];
    if (M > 2 && leap) days++;
    *unix_time = (days + D - 1) * 86400 + h * 3600 + m * 60 + s;
    return true;
}

static bool drive_catalog_page(const char* json, gdrive_version_t* out,
                               size_t cap, bool files, size_t* count,
                               char next[256], const char** reason) {
    *count = 0; next[0] = '\0'; *reason = "invalid_page";
    if (!json) return false;
    const char* p = drive_metadata_ws(json);
    if (*p++ != '{') return false;
    p = drive_metadata_ws(p);
    unsigned top = 0;
    while (*p != '}') {
        char key[24];
        if (!drive_retention_string(&p, key, sizeof(key)) || *p++ != ':') return false;
        p = drive_metadata_ws(p);
        if (!strcmp(key, "incompleteSearch") && !(top & 2)) {
            if (strncmp(p, "false", 5)) { *reason = "incomplete_search"; return false; }
            p = drive_metadata_ws(p + 5); top |= 2;
        } else if (!strcmp(key, "nextPageToken") && !(top & 4)) {
            if (!drive_retention_string(&p, next, 256)) return false;
            top |= 4;
        } else if (!strcmp(key, "files") && !(top & 1)) {
            top |= 1;
            if (*p++ != '[') return false;
            p = drive_metadata_ws(p);
            while (*p != ']') {
                if (*count >= cap) { *reason = "catalog_limit"; return false; }
                if (*p++ != '{') return false;
                gdrive_version_t v = {0};
                unsigned seen = 0;
                for (;;) {
                    char field[16], value[128];
                    if (!drive_retention_string(&p, field, sizeof(field)) || *p++ != ':' ||
                        !drive_retention_string(&p, value, sizeof(value))) return false;
                    unsigned bit = !strcmp(field, "id") ? 1 : !strcmp(field, "name") ? 2 :
                        files && !strcmp(field, "size") ? 4 :
                        files && !strcmp(field, "createdTime") ? 8 : 0;
                    if (!bit || (seen & bit)) return false;
                    seen |= bit;
                    if (bit == 1) {
                        if (strlen(value) >= sizeof(v.file_id)) return false;
                        for (const char* q = value; *q; q++)
                            if (!((*q >= 'A' && *q <= 'Z') || (*q >= 'a' && *q <= 'z') ||
                                  (*q >= '0' && *q <= '9') || *q == '_' || *q == '-')) return false;
                        snprintf(v.file_id, sizeof(v.file_id), "%s", value);
                    } else if (bit == 2) snprintf(v.name, sizeof(v.name), "%s", value);
                    else if (bit == 4) {
                        if (*value < '1' || *value > '9') return false;
                        for (const char* q = value; *q; q++) {
                            if (*q < '0' || *q > '9' ||
                                v.size_bytes > (GDRIVE_MAX_BYTES - (unsigned)(*q - '0')) / 10)
                                return false;
                            v.size_bytes = v.size_bytes * 10 + (unsigned)(*q - '0');
                        }
                    } else if (!drive_catalog_time(value, &v.created_unix)) return false;
                    if (*p == '}') { p = drive_metadata_ws(p + 1); break; }
                    if (*p++ != ',') return false;
                }
                if (seen != (files ? 15U : 3U)) return false;
                for (size_t i = 0; i < *count; i++)
                    if (!strcmp(out[i].file_id, v.file_id)) return false;
                out[(*count)++] = v;
                if (*p == ']') break;
                if (*p++ != ',') return false;
                p = drive_metadata_ws(p);
                if (*p == ']') return false;
            }
            p = drive_metadata_ws(p + 1);
        } else return false;
        if (*p == '}') break;
        if (*p++ != ',') return false;
        p = drive_metadata_ws(p);
        if (*p == '}') return false;
    }
    return (top & 1) && !*drive_metadata_ws(p + 1);
}

static bool drive_catalog_list_budget(const char* token, const char* query,
                               bool files, gdrive_version_t* out, size_t cap,
                               size_t* count, const char** reason, size_t* budget) {
    *count = 0;
    // ponytail: bounded on-demand pagination; larger catalogs defer cleanup.
    // Increase this limit only with the Library memory/display ceiling.
    enum { PAGE_MAX = 128 };
    char seen[PAGE_MAX][256], next[256] = {0};
    for (size_t page = 0; page < PAGE_MAX; page++) {
        if (budget) {
            if (!*budget) { *reason = "listing_budget"; return false; }
            (*budget)--;
        }
        if (*count == cap) { *reason = "catalog_limit"; return false; }
        char url[2048], encoded[768];
        url_encode(next, encoded, sizeof(encoded));
        size_t page_size = cap - *count;
        if (page_size > 1000) page_size = 1000;
        int len = snprintf(url, sizeof(url), "%s&pageSize=%zu&fields=nextPageToken,"
            "incompleteSearch,files(id,name%s)%s%s", query, page_size,
            files ? ",size,createdTime" : "", next[0] ? "&pageToken=" : "", encoded);
        if (len < 0 || (size_t)len >= sizeof(url)) { *reason = "query_limit"; return false; }
        http_response_t r = {0};
        bool ok = http_get_auth(url, token, &r) && r.status == 200 && !r.transport_error;
        size_t parsed = 0;
        if (ok && (!r.body || r.body_len != strlen(r.body))) {
            ok = false; *reason = "invalid_page";
        } else if (ok) ok = drive_catalog_page(r.body, out + *count,
                                                cap - *count, files, &parsed, next, reason);
        else *reason = "listing_failed";
        http_response_free(&r);
        if (!ok) return false; // retain only fully validated earlier pages
        for (size_t i = 0; i < parsed; i++)
            for (size_t j = 0; j < *count; j++)
                if (!strcmp(out[*count + i].file_id, out[j].file_id)) {
                    *reason = "duplicate_id"; return false;
                }
        *count += parsed;
        if (!next[0]) return true; // exact capacity is complete with no next page
        for (size_t i = 0; i < page; i++)
            if (!strcmp(seen[i], next)) { *reason = "pagination_loop"; return false; }
        snprintf(seen[page], sizeof(seen[page]), "%s", next);
    }
    *reason = "catalog_limit";
    return false;
}

static bool drive_catalog_list(const char* token, const char* query,
                               bool files, gdrive_version_t* out, size_t cap,
                               size_t* count, const char** reason) {
    return drive_catalog_list_budget(token, query, files, out, cap, count, reason, NULL);
}

static bool drive_catalog_children(const char* parent, bool files,
                                    gdrive_version_t* out, size_t cap,
                                    size_t* count, const char** reason) {
    char query[768];
    snprintf(query, sizeof(query), "%s/files?q=%%27%s%%27+in+parents+and+"
        "trashed%%3Dfalse+and+mimeType%s%%27application%%2Fvnd.google-apps.folder%%27"
        "&orderBy=%s&spaces=%s", DRIVE_API_BASE, parent,
        files ? "%21%3D" : "%3D", files ? "createdTime+desc" : "name",
        s_cfg->gdrive.use_appdata ? "appDataFolder" : "drive");
    return drive_catalog_list(s_tokens.access_token, query, files, out, cap, count, reason);
}

static bool drive_catalog_root_budget(char root_id[GDRIVE_FILEID_MAX], bool* absent,
                               const char** reason, size_t* budget) {
    if (!memchr(s_cfg->gdrive.root_folder, '\0', sizeof(s_cfg->gdrive.root_folder)) ||
        !s_cfg->gdrive.root_folder[0]) { *reason = "invalid_root"; return false; }
    char name_q[160], name_enc[480], query[1024];
    drive_query_escape(s_cfg->gdrive.root_folder, name_q, sizeof(name_q));
    url_encode(name_q, name_enc, sizeof(name_enc));
    snprintf(query, sizeof(query), "%s/files?q=name%%3D%%27%s%%27+and+"
        "mimeType%%3D%%27application%%2Fvnd.google-apps.folder%%27+and+"
        "%%27%s%%27+in+parents+and+trashed%%3Dfalse&spaces=%s",
        DRIVE_API_BASE, name_enc, s_cfg->gdrive.use_appdata ? "appDataFolder" : "root",
        s_cfg->gdrive.use_appdata ? "appDataFolder" : "drive");
    gdrive_version_t root;
    size_t count = 0;
    if (!drive_catalog_list_budget(s_tokens.access_token, query, false, &root, 1, &count, reason, budget))
        return false;
    *absent = count == 0;
    if (count && strcmp(root.name, s_cfg->gdrive.root_folder)) {
        *reason = "invalid_root"; return false;
    }
    if (count) snprintf(root_id, GDRIVE_FILEID_MAX, "%s", root.file_id);
    return true;
}

static bool drive_catalog_root(char root_id[GDRIVE_FILEID_MAX], bool* absent,
                               const char** reason) {
    return drive_catalog_root_budget(root_id, absent, reason, NULL);
}

// Usage is not retention authority: incomplete metadata or pagination remains
// unknown, preserving the pre-existing fail-open upload policy.
typedef struct {
    char id[GDRIVE_FILEID_MAX];
    char name[128];
    uint64_t bytes;
    bool sized;
    bool folder;
    bool trashed;
} drive_usage_file_t;

static bool drive_usage_size(const char** cursor, uint64_t* value) {
    const char* p = drive_metadata_ws(*cursor);
    bool quoted = *p == '"';
    if (quoted) p++;
    const char* start = p;
    *value = 0;
    while (*p >= '0' && *p <= '9') {
        unsigned digit = (unsigned)(*p++ - '0');
        if (*value > (UINT64_MAX - digit) / 10) return false;
        *value = *value * 10 + digit;
    }
    if (p == start || (p - start > 1 && *start == '0')) return false;
    if (quoted && *p++ != '"') return false;
    *cursor = drive_metadata_ws(p);
    return true;
}

static bool drive_usage_page(const char* json, drive_usage_file_t* out,
                             size_t cap, size_t* count, char next[256]) {
    *count = 0; next[0] = '\0';
    if (!json) return false;
    const char* p = drive_metadata_ws(json);
    if (*p++ != '{') return false;
    p = drive_metadata_ws(p);
    unsigned top = 0;
    while (*p != '}') {
        char key[24];
        if (!drive_retention_string(&p, key, sizeof(key)) || *p++ != ':') return false;
        p = drive_metadata_ws(p);
        if (!strcmp(key, "incompleteSearch") && !(top & 2)) {
            if (strncmp(p, "false", 5)) return false;
            p = drive_metadata_ws(p + 5); top |= 2;
        } else if (!strcmp(key, "nextPageToken") && !(top & 4)) {
            if (!drive_retention_string(&p, next, 256)) return false;
            top |= 4;
        } else if (!strcmp(key, "files") && !(top & 1)) {
            top |= 1;
            if (*p++ != '[') return false;
            p = drive_metadata_ws(p);
            while (*p != ']') {
                if (*count >= cap || *p++ != '{') return false;
                drive_usage_file_t f = {0};
                unsigned seen = 0;
                for (;;) {
                    char field[16], value[128];
                    if (!drive_retention_string(&p, field, sizeof(field)) || *p++ != ':') return false;
                    p = drive_metadata_ws(p);
                    unsigned bit = !strcmp(field, "id") ? 1 : !strcmp(field, "name") ? 2 :
                        !strcmp(field, "size") ? 4 : !strcmp(field, "mimeType") ? 8 :
                        !strcmp(field, "trashed") ? 16 : 0;
                    if (!bit || (seen & bit)) return false;
                    seen |= bit;
                    if (bit == 4) {
                        if (!drive_usage_size(&p, &f.bytes)) return false;
                        f.sized = true;
                    } else if (bit == 16) {
                        if (!strncmp(p, "false", 5)) p = drive_metadata_ws(p + 5);
                        else if (!strncmp(p, "true", 4)) {
                            f.trashed = true; p = drive_metadata_ws(p + 4);
                        } else return false;
                    } else {
                        if (!drive_retention_string(&p, value, sizeof(value))) return false;
                        if (bit == 1) {
                            if (strlen(value) >= sizeof(f.id)) return false;
                            for (const char* q = value; *q; q++)
                                if (!((*q >= 'A' && *q <= 'Z') || (*q >= 'a' && *q <= 'z') ||
                                      (*q >= '0' && *q <= '9') || *q == '_' || *q == '-')) return false;
                            snprintf(f.id, sizeof(f.id), "%s", value);
                        } else if (bit == 2) snprintf(f.name, sizeof(f.name), "%s", value);
                        else f.folder = !strcmp(value, "application/vnd.google-apps.folder");
                    }
                    if (*p == '}') { p = drive_metadata_ws(p + 1); break; }
                    if (*p++ != ',') return false;
                }
                if ((seen & 27) != 27) return false;
                for (size_t i = 0; i < *count; i++) if (!strcmp(out[i].id, f.id)) return false;
                out[(*count)++] = f;
                if (*p == ']') break;
                if (*p++ != ',') return false;
                p = drive_metadata_ws(p);
                if (*p == ']') return false;
            }
            p = drive_metadata_ws(p + 1);
        } else return false;
        if (*p == '}') break;
        if (*p++ != ',') return false;
        p = drive_metadata_ws(p);
        if (*p == '}') return false;
    }
    return (top & 1) && !*drive_metadata_ws(p + 1);
}

static bool drive_usage_folder_children(const char* parent, gdrive_version_t* out,
                         size_t cap, size_t* count, const char** reason, size_t* budget) {
    char query[768];
    snprintf(query, sizeof(query), "%s/files?q=%%27%s%%27+in+parents+and+"
        "trashed%%3Dfalse+and+mimeType%%3D%%27application%%2Fvnd.google-apps.folder%%27"
        "&orderBy=name&spaces=%s", DRIVE_API_BASE, parent,
        s_cfg->gdrive.use_appdata ? "appDataFolder" : "drive");
    return drive_catalog_list_budget(s_tokens.access_token, query, false, out, cap,
                                     count, reason, budget);
}

static bool s_usage_diagnostic_done;
static void drive_usage_diagnostic(const char (*ids)[GDRIVE_FILEID_MAX], size_t count,
                                   bool complete, drive_usage_file_t* page) {
    if (s_usage_diagnostic_done) return;
    s_usage_diagnostic_done = true; // one sampled listing, never pagination or a decision
    char url[768];
    snprintf(url, sizeof(url), "%s/files?q=trashed%%3Dfalse+and+mimeType%%21%%3D"
        "%%27application%%2Fvnd.google-apps.folder%%27&spaces=%s&pageSize=1000"
        "&fields=nextPageToken,incompleteSearch,files(id,name,size,mimeType,trashed)",
        DRIVE_API_BASE, s_cfg->gdrive.use_appdata ? "appDataFolder" : "drive");
    http_response_t r = {0};
    size_t n = 0, outside_files = 0;
    uint64_t outside_bytes = 0;
    char next[256];
    bool ok = complete && page && http_get_auth(url, s_tokens.access_token, &r) &&
        r.status == 200 && !r.transport_error && r.body && r.body_len == strlen(r.body) &&
        drive_usage_page(r.body, page, 1000, &n, next);
    for (size_t i = 0; ok && i < n; i++) {
        if (page[i].folder || page[i].trashed) continue;
        bool inside = false;
        for (size_t j = 0; j < count; j++) if (!strcmp(page[i].id, ids[j])) inside = true;
        if (inside) continue;
        if (!page[i].sized || outside_bytes > UINT64_MAX - page[i].bytes) { ok = false; break; }
        outside_bytes += page[i].bytes; outside_files++;
    }
    log_info("gdrive: outside_backup_scope diagnostic count=%s sampled_files=%zu outside_files=%zu outside_bytes=%llu sample=true more_pages=%s",
        ok ? "known" : "unknown", ok ? n : 0, ok ? outside_files : 0,
        (unsigned long long)(ok ? outside_bytes : 0), ok ? (next[0] ? "yes" : "no") : "unknown");
    http_response_free(&r);
}

bool gdrive_estimate_backup_usage(uint64_t* out_bytes, size_t* out_files) {
    if (!out_bytes || !out_files) return false;
    *out_bytes = 0; *out_files = 0;
    pthread_mutex_lock(&s_lock);
    if (s_state != GDRIVE_STATE_READY || !ensure_access_token_locked()) {
        pthread_mutex_unlock(&s_lock); return false;
    }
    enum { USER_MAX = 128, TITLE_MAX = 256, FILE_MAX = 4096, PAGE_MAX = 128 };
    gdrive_version_t* users = calloc(USER_MAX, sizeof(*users));
    gdrive_version_t* titles = calloc(TITLE_MAX, sizeof(*titles));
    drive_usage_file_t* page = calloc(1000, sizeof(*page));
    char (*ids)[GDRIVE_FILEID_MAX] = calloc(FILE_MAX, sizeof(*ids));
    bool ok = users && titles && page && ids;
    uint64_t bytes = 0;
    size_t count = 0, budget = PAGE_MAX, un = 0;
    char root[GDRIVE_FILEID_MAX] = {0};
    bool absent = false;
    const char* reason = "memory_unavailable";
    if (ok) ok = drive_catalog_root_budget(root, &absent, &reason, &budget);
    if (ok && !absent) ok = drive_usage_folder_children(root, users, USER_MAX, &un, &reason, &budget);
    for (size_t ui = 0; ok && ui < un; ui++) {
        size_t tn = 0;
        ok = drive_usage_folder_children(users[ui].file_id, titles, TITLE_MAX, &tn, &reason, &budget);
        for (size_t ti = 0; ok && ti < tn; ti++) {
            char next[256] = {0}, seen[PAGE_MAX][256];
            size_t pages = 0;
            do {
                if (!budget || pages == PAGE_MAX) { ok = false; reason = "listing_budget"; break; }
                budget--;
                char encoded[768], url[1536];
                url_encode(next, encoded, sizeof(encoded));
                int len = snprintf(url, sizeof(url), "%s/files?q=%%27%s%%27+in+parents+and+"
                    "trashed%%3Dfalse+and+mimeType%%21%%3D%%27application%%2Fvnd.google-apps.folder%%27"
                    "&spaces=%s&pageSize=1000&fields=nextPageToken,incompleteSearch,files(id,name,size,mimeType,trashed)%s%s",
                    DRIVE_API_BASE, titles[ti].file_id, s_cfg->gdrive.use_appdata ? "appDataFolder" : "drive",
                    next[0] ? "&pageToken=" : "", encoded);
                http_response_t r = {0};
                size_t pn = 0;
                ok = len > 0 && (size_t)len < sizeof(url) && http_get_auth(url, s_tokens.access_token, &r) &&
                    r.status == 200 && !r.transport_error && r.body && r.body_len == strlen(r.body) &&
                    drive_usage_page(r.body, page, 1000, &pn, next);
                http_response_free(&r);
                if (!ok) { reason = "listing_unavailable_or_incomplete"; break; }
                for (size_t i = 0; ok && i < pn; i++) {
                    drive_usage_file_t* f = &page[i];
                    size_t n = strlen(f->name);
                    if (f->folder || f->trashed || n <= 4 || strcmp(f->name + n - 4, ".zip")) continue;
                    if (!f->sized || count == FILE_MAX || bytes > UINT64_MAX - f->bytes) { ok = false; reason = "size_or_count_limit"; break; }
                    for (size_t j = 0; j < count; j++) if (!strcmp(ids[j], f->id)) { ok = false; reason = "duplicate_file"; break; }
                    if (ok) { snprintf(ids[count++], GDRIVE_FILEID_MAX, "%s", f->id); bytes += f->bytes; }
                }
                if (ok && next[0]) {
                    for (size_t j = 0; j < pages; j++) if (!strcmp(seen[j], next)) { ok = false; reason = "pagination_loop"; break; }
                    snprintf(seen[pages], sizeof(seen[pages]), "%s", next);
                }
                pages++;
            } while (ok && next[0]);
        }
    }
    if (ok) { *out_bytes = bytes; *out_files = count; }
    else log_warn("gdrive: backup tree byte count unknown (%s)", reason);
    drive_usage_diagnostic(ids, count, ok, page);
    free(users); free(titles); free(page); free(ids);
    pthread_mutex_unlock(&s_lock);
    return ok;
}

static bool drive_catalog_account(char permission_id[64]) {
    http_response_t r = {0};
    bool ok = http_get_auth(DRIVE_API_BASE "/about?fields=user(permissionId)",
                            s_tokens.access_token, &r) && r.status == 200 &&
                            !r.transport_error && r.body && r.body_len == strlen(r.body);
    if (ok) {
        const char* p = drive_metadata_ws(r.body);
        char key[24];
        ok = *p++ == '{' && drive_retention_string(&p, key, sizeof(key)) &&
            !strcmp(key, "user") && *p++ == ':';
        if (ok) {
            p = drive_metadata_ws(p);
            ok = *p++ == '{' && drive_retention_string(&p, key, sizeof(key)) &&
                !strcmp(key, "permissionId") && *p++ == ':' &&
                drive_retention_string(&p, permission_id, 64);
        }
        if (ok) {
            for (const char* q = permission_id; *q; q++)
                if (!((*q >= 'A' && *q <= 'Z') || (*q >= 'a' && *q <= 'z') ||
                      (*q >= '0' && *q <= '9') || *q == '_' || *q == '-')) ok = false;
            ok = ok && *p++ == '}' && *(p = drive_metadata_ws(p)) == '}';
            if (ok) ok = !*drive_metadata_ws(p + 1);
        }
    }
    http_response_free(&r);
    return ok;
}

static bool drive_backup_newer(const gdrive_backup_t* a,
                               const gdrive_backup_t* b) {
    if (a->created_unix != b->created_unix)
        return a->created_unix > b->created_unix;
    return strcmp(a->name, b->name) > 0;
}

size_t gdrive_catalog_scan(gdrive_backup_t* out, size_t max_out, catalog_scan_t* scan) {
    catalog_scan_t result = {CATALOG_UNAVAILABLE, "not_configured", false};
    size_t n = 0;
    pthread_mutex_lock(&s_lock);
    result.configured = s_state != GDRIVE_STATE_NOT_CONFIGURED;
    if (!result.configured) goto done;
    result.reason = "not_ready";
    if ((s_state != GDRIVE_STATE_READY && !s_initialization_deferred) ||
        !s_session_generation || !ensure_read_access_token_locked()) goto done;
    result.reason = "catalog_limit";
    if (!out || !max_out) goto done;
    char permission_id[64];
    result.reason = "identity_unavailable";
    if (!drive_catalog_account(permission_id)) goto done;
    char root_id[GDRIVE_FILEID_MAX] = {0};
    bool absent = false;
    if (!drive_catalog_root(root_id, &absent, &result.reason)) goto done;
    if (absent) { result.state = CATALOG_EMPTY; result.reason = "root_absent"; goto done; }
    result.state = CATALOG_PARTIAL; // target reached, but its hierarchy is not yet complete
    // ponytail: one lock for this on-demand catalog; scans can delay settings
    // until HTTP timeouts. Snapshot sessions if that latency becomes a problem.
    // No cached root from a different destination may label listing evidence.
    enum { USER_MAX = 128, TITLE_MAX = 256 };
    gdrive_version_t* users = calloc(USER_MAX, sizeof(*users));
    gdrive_version_t* titles = calloc(TITLE_MAX, sizeof(*titles));
    gdrive_version_t* files = calloc(max_out, sizeof(*files));
    bool complete = users && titles && files;
    const char* failure_reason = NULL;
    if (!users || !titles || !files) {
        result.reason = "memory_unavailable";
        goto scanned;
    }
    size_t un = 0;
    complete = drive_catalog_children(root_id, false, users, USER_MAX, &un, &result.reason);
    if (!complete) failure_reason = result.reason;
    for (size_t ui = 0; ui < un; ui++) {
        char user_code[32];
        if (!backup_folder_code(users[ui].name, false, user_code, sizeof(user_code))) {
            complete = false; result.reason = "invalid_user_code"; break;
        }
        size_t tn = 0;
        bool title_complete = drive_catalog_children(users[ui].file_id, false,
                                                      titles, TITLE_MAX, &tn, &result.reason);
        if (!title_complete && !failure_reason) failure_reason = result.reason;
        complete = complete && title_complete;
        for (size_t ti = 0; ti < tn; ti++) {
            char title_code[16];
            if (!backup_folder_code(titles[ti].name, true, title_code, sizeof(title_code))) {
                complete = false; result.reason = "invalid_title_code"; break;
            }
            char identity[65] = {0};
            const char* fields[] = {"tostonsync-drive-v1", permission_id,
                s_cfg->gdrive.use_appdata ? "appDataFolder" : "drive", titles[ti].file_id};
            bool identified = dest_identity_hash(fields, sizeof(fields) / sizeof(fields[0]), identity);
            if (!identified) { complete = false; result.reason = "identity_unavailable"; break; }
            size_t fn = 0;
            bool file_complete = drive_catalog_children(titles[ti].file_id, true,
                                                          files, max_out - n, &fn, &result.reason);
            if (!file_complete && !failure_reason) failure_reason = result.reason;
            complete = complete && file_complete;
            for (size_t fi = 0; fi < fn; fi++) {
                size_t L = strlen(files[fi].name);
                if (L <= 4 || strcmp(files[fi].name + L - 4, ".zip") != 0)
                    continue;
                bool duplicate = false;
                for (size_t i = 0; i < n; i++)
                    if (!strcmp(out[i].file_id, files[fi].file_id)) duplicate = true;
                if (duplicate) { complete = false; result.reason = "duplicate_id"; break; }
                gdrive_backup_t* b = &out[n];
                memset(b, 0, sizeof(*b));
                snprintf(b->user, sizeof(b->user), "%s", user_code);
                snprintf(b->title_id, sizeof(b->title_id), "%s", title_code);
                snprintf(b->file_id, sizeof(b->file_id), "%s", files[fi].file_id);
                snprintf(b->name, sizeof(b->name), "%s", files[fi].name);
                b->size_bytes = files[fi].size_bytes;
                b->created_unix = files[fi].created_unix;
                snprintf(b->destination_identity, sizeof(b->destination_identity), "%s", identity);
                b->generation = s_session_generation;
                snprintf(b->observed_root,sizeof(b->observed_root),"%s",root_id);
                snprintf(b->destination_label, sizeof(b->destination_label),
                         "Drive %s/%s/%s · folder=%s · destination=%.12s",
                         s_cfg->gdrive.root_folder, users[ui].name, titles[ti].name, titles[ti].file_id,
                         identity[0] ? identity : "unknown");
                n++;
            }
            if (!file_complete) break;
        }
        if (!complete) break;
    }
scanned:
    for (size_t i = 1; i < n; i++) {
        gdrive_backup_t key = out[i];
        size_t j = i;
        while (j > 0 && drive_backup_newer(&key, &out[j - 1])) {
            out[j] = out[j - 1];
            j--;
        }
        out[j] = key;
    }
    free(users);
    free(titles);
    free(files);
    result.state = complete ? (n ? CATALOG_COMPLETE : CATALOG_EMPTY) : CATALOG_PARTIAL;
    if (complete) result.reason = "complete";
    else if (failure_reason) result.reason = failure_reason;
done:
    if (scan) *scan = result;
    pthread_mutex_unlock(&s_lock);
    return n;
}

size_t gdrive_list_all_versions(gdrive_backup_t* out, size_t max_out) {
    return gdrive_catalog_scan(out, max_out, NULL);
}

bool gdrive_delete_version(const char* file_id) {
    pthread_mutex_lock(&s_lock);
    if (!ensure_access_token_locked()) {
        pthread_mutex_unlock(&s_lock);
        return false;
    }
    char fid[160];
    url_encode(file_id, fid, sizeof(fid));
    char url[256];
    snprintf(url, sizeof(url), "%s/files/%s", DRIVE_API_BASE, fid);
    http_response_t r = {0};
    bool ok = http_delete_auth(url, s_tokens.access_token, &r);
    int status = r.status;
    http_response_free(&r);
    if (!ok || (status != 204 && status != 200)) {
        log_warn("gdrive: delete %s failed (status=%d)", file_id, status);
        pthread_mutex_unlock(&s_lock);
        return false;
    }
    pthread_mutex_unlock(&s_lock);
    return true;
}

bool gdrive_download(const char* file_id, const char* local_path) {
    char token[sizeof(s_tokens.access_token)] = {0};
    pthread_mutex_lock(&s_lock);
    if ((s_state != GDRIVE_STATE_READY && !s_initialization_deferred) ||
        !ensure_read_access_token_locked()) {
        pthread_mutex_unlock(&s_lock);
        return false;
    }
    snprintf(token, sizeof(token), "%s", s_tokens.access_token);
    pthread_mutex_unlock(&s_lock);

    char fid[160];
    url_encode(file_id, fid, sizeof(fid));
    char meta_url[256];
    snprintf(meta_url, sizeof(meta_url), "%s/files/%s?fields=size",
             DRIVE_API_BASE, fid);
    http_response_t meta = {0};
    if (!http_get_auth(meta_url, token, &meta) || meta.status != 200) {
        log_warn("gdrive: could not read download size (status=%d)", meta.status);
        http_response_free(&meta);
        return false;
    }
    uint64_t expected = (uint64_t)json_get_number(meta.body, "size");
    http_response_free(&meta);
    if (!expected || expected > GDRIVE_MAX_BYTES) {
        log_warn("gdrive: download rejected (missing size or larger than 8 GiB)");
        return false;
    }
    // A fixed restore staging name may be reused for another Drive version.
    // Bind its resumable .part file to this exact file id so equal-sized
    // backups can never be spliced together.
    char part[512], marker[544], saved_id[GDRIVE_FILEID_MAX] = {0};
    snprintf(part, sizeof(part), "%s.part", local_path);
    snprintf(marker, sizeof(marker), "%s.id", part);
    FILE* mf = fopen(marker, "rb");
    if (mf) {
        size_t n = fread(saved_id, 1, sizeof(saved_id) - 1, mf);
        saved_id[n] = '\0';
        fclose(mf);
    }
    if (!saved_id[0] || strcmp(saved_id, file_id) != 0) {
        unlink(part);
        mf = fopen(marker, "wb");
        bool marker_ok = false;
        if (mf) {
            marker_ok = fwrite(file_id, 1, strlen(file_id), mf) == strlen(file_id);
            if (fclose(mf) != 0) marker_ok = false;
            mf = NULL;
        }
        if (!marker_ok) {
            unlink(marker);
            return false;
        }
    }
    char url[256];
    snprintf(url, sizeof(url),
             "%s/files/%s?alt=media", DRIVE_API_BASE, fid);
    bool ok = http_get_auth_to_file_resumable(url, token, local_path,
                                              expected, GDRIVE_MAX_BYTES);
    if (!ok) log_warn("gdrive: resumable download incomplete");
    else unlink(marker);
    return ok;
}

// Individual Library is a separate read-only scope, never Full cleanup authority.
#ifndef INDIVIDUAL_VERIFY_BASE
#define INDIVIDUAL_VERIFY_BASE "/data/tostonsync"
#endif
static bool drive_individual_scope_locked(const char* user, const char* title,
                                          char parent[GDRIVE_FILEID_MAX], char identity[65],
                                          bool* absent, const char** reason) {
    char account[64], current[GDRIVE_FILEID_MAX]; *absent = false;
    if (!drive_catalog_account(account) || !drive_catalog_root(current, absent, reason)) {
        if (!*reason) *reason = "identity_unavailable"; return false;
    }
    if (*absent) return true;
    gdrive_version_t* folders = calloc(512, sizeof(*folders));
    if (!folders) { *reason = "memory_unavailable"; return false; }
    bool ok = true;
    for (unsigned level = 0; ok && level < 3; level++) {
        size_t n = 0, matched = 0; char next[GDRIVE_FILEID_MAX] = {0};
        ok = drive_catalog_children(current, false, folders, 512, &n, reason);
        for (size_t i = 0; ok && i < n; i++) {
            char code[32]; bool match = level == 2 ? !strcmp(folders[i].name, "Individual saves") :
                backup_folder_code(folders[i].name, level == 1, code, sizeof(code)) && !strcmp(code, level ? title : user);
            if (match) { matched++; snprintf(next, sizeof(next), "%s", folders[i].file_id); }
        }
        if (!ok) break;
        if (matched > 1) { *reason = "ambiguous_folder"; ok = false; break; }
        if (!matched) { *absent = true; break; }
        snprintf(current, sizeof(current), "%s", next);
    }
    free(folders);
    if (ok && !*absent) {
        snprintf(parent, GDRIVE_FILEID_MAX, "%s", current);
        const char* parts[] = {"drive-individual-v1", account,
            s_cfg->gdrive.use_appdata ? "appDataFolder" : "drive", current};
        ok = dest_identity_hash(parts, 4, identity);
        if (!ok) *reason = "identity_unavailable";
    }
    return ok;
}

static bool drive_individual_metadata_page(const char* json, const char* file_id,
                                           const char* parent, const char* name,
                                           const char* user, const char* title,
                                           individual_backup_t* out) {
    if (!json || !individual_catalog_label(user, title, "drive", name, out)) return false;
    const char* p = drive_metadata_ws(json); if (*p++ != '{') return false;
    unsigned seen = 0; char modified[32] = {0}; uint64_t size = 0;
    for (;;) {
        char key[24], value[384];
        if (!drive_retention_string(&p, key, sizeof(key)) || *p++ != ':') return false;
        p = drive_metadata_ws(p);
        static const char* keys[] = {"id","name","size","trashed","parents","mimeType","modifiedTime","sha256Checksum"};
        unsigned index = 0; while (index < 8 && strcmp(key, keys[index])) index++;
        if (index == 8 || (seen & (1U << index))) return false; seen |= 1U << index;
        if (index == 2) {
            if (!drive_usage_size(&p, &size) || size < 22 || size > INDIVIDUAL_MAX_BYTES) return false;
        } else if (index == 3) {
            if (strncmp(p, "false", 5)) return false; p = drive_metadata_ws(p + 5);
        } else if (index == 4) {
            if (*p++ != '[' || !drive_retention_string(&p, value, sizeof(value)) || strcmp(value, parent) || *p++ != ']') return false;
            p = drive_metadata_ws(p);
        } else {
            if (!drive_retention_string(&p, value, sizeof(value))) return false;
            if (index == 0 ? strcmp(value, file_id) : index == 1 ? strcmp(value, name) :
                index == 5 ? strcmp(value, "application/zip") : false) return false;
            if (index == 6) {
                int64_t parsed; if (!drive_catalog_time(value, &parsed) || strlen(value) >= sizeof(modified)) return false;
                snprintf(modified, sizeof(modified), "%s", value);
            } else if (index == 7) {
                if (!dest_fingerprint_hex(value)) return false;
                snprintf(out->checksum, sizeof(out->checksum), "%s", value);
            }
        }
        p = drive_metadata_ws(p);
        if (*p == '}') { if ((seen & 127U) != 127U || *drive_metadata_ws(p + 1)) return false; break; }
        if (*p++ != ',') return false;
    }
    out->size_bytes = size; char amount[32]; snprintf(amount, sizeof(amount), "%llu", (unsigned long long)size);
    const char* parts[] = {"drive-individual-file-v1", file_id, parent, name, amount, modified, out->checksum};
    if (!dest_identity_hash(parts, 7, out->file_stamp)) return false;
    snprintf(out->ref, sizeof(out->ref), "drive:%s", file_id);
    snprintf(out->parent_ref, sizeof(out->parent_ref), "%s", parent);
    out->generation = s_session_generation; return true;
}

static bool drive_individual_metadata_locked(const char* file_id, const char* parent,
                                             const char* name, const char* user,
                                             const char* title, individual_backup_t* out) {
    if (!file_id || !file_id[0] || strlen(file_id) >= GDRIVE_FILEID_MAX ||
        strspn(file_id, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-") != strlen(file_id)) return false;
    char url[512];
    snprintf(url, sizeof(url), "%s/files/%s?fields=id,name,size,trashed,parents,mimeType,modifiedTime,sha256Checksum", DRIVE_API_BASE, file_id);
    http_response_t r = {0};
    bool ok = http_get_auth(url, s_tokens.access_token, &r) && r.status == 200 && !r.transport_error &&
        r.body && r.body_len == strlen(r.body) &&
        drive_individual_metadata_page(r.body, file_id, parent, name, user, title, out);
    http_response_free(&r); return ok;
}

typedef struct {
    char id[GDRIVE_FILEID_MAX], name[384];
} drive_individual_file_t;

static bool drive_individual_files_page(const char* json, drive_individual_file_t* out,
                                        size_t cap, size_t* count, char next[256]) {
    *count = 0; next[0] = 0; if (!json) return false;
    const char* p = drive_metadata_ws(json); if (*p++ != '{') return false;
    unsigned top = 0;
    for (;;) {
        char key[24];
        if (!drive_retention_string(&p, key, sizeof(key)) || *p++ != ':') return false;
        p = drive_metadata_ws(p);
        if (!strcmp(key, "nextPageToken") && !(top & 2)) {
            if (!drive_retention_string(&p, next, 256)) return false; top |= 2;
        } else if (!strcmp(key, "incompleteSearch") && !(top & 4)) {
            if (strncmp(p, "false", 5)) return false; p = drive_metadata_ws(p + 5); top |= 4;
        } else if (!strcmp(key, "files") && !(top & 1)) {
            top |= 1; if (*p++ != '[') return false; p = drive_metadata_ws(p);
            while (*p != ']') {
                if (*count == cap || *p++ != '{') return false;
                drive_individual_file_t row = {0}; unsigned seen = 0;
                for (;;) {
                    char field[16], value[384];
                    if (!drive_retention_string(&p, field, sizeof(field)) || *p++ != ':' ||
                        !drive_retention_string(&p, value, sizeof(value))) return false;
                    unsigned bit = !strcmp(field, "id") ? 1 : !strcmp(field, "name") ? 2 : 0;
                    if (!bit || (seen & bit)) return false; seen |= bit;
                    if (bit == 1) {
                        size_t length = strlen(value);
                        if (!length || length >= sizeof(row.id) ||
                            strspn(value, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-") != length) return false;
                        snprintf(row.id, sizeof(row.id), "%s", value);
                    } else {
                        if (!individual_catalog_name_safe(value)) return false;
                        snprintf(row.name, sizeof(row.name), "%s", value);
                    }
                    if (*p == '}') { p = drive_metadata_ws(p + 1); break; }
                    if (*p++ != ',') return false;
                }
                if (seen != 3) return false;
                out[(*count)++] = row;
                if (*p == ']') break;
                if (*p++ != ',') return false; p = drive_metadata_ws(p);
                if (*p == ']') return false;
            }
            p = drive_metadata_ws(p + 1);
        } else return false;
        if (*p == '}') return (top & 1) && !*drive_metadata_ws(p + 1);
        if (*p++ != ',') return false;
    }
}

static bool drive_individual_files_locked(const char* parent, drive_individual_file_t* out,
                                          size_t cap, size_t* count, const char** reason) {
    *count = 0; char next[256] = {0};
    for (unsigned page = 0; page < 128; page++) {
        char encoded[768], url[1536]; url_encode(next, encoded, sizeof(encoded));
        snprintf(url, sizeof(url), "%s/files?q=%%27%s%%27+in+parents+and+trashed%%3Dfalse+and+"
            "mimeType%%21%%3D%%27application%%2Fvnd.google-apps.folder%%27&spaces=%s&"
            "fields=nextPageToken,incompleteSearch,files(id,name)&pageSize=512%s%s", DRIVE_API_BASE,
            parent, s_cfg->gdrive.use_appdata ? "appDataFolder" : "drive",
            next[0] ? "&pageToken=" : "", next[0] ? encoded : "");
        http_response_t r = {0}; size_t n = 0; char following[256];
        bool ok = http_get_auth(url, s_tokens.access_token, &r) && r.status == 200 && !r.transport_error &&
            r.body && r.body_len == strlen(r.body) &&
            drive_individual_files_page(r.body, out + *count, cap - *count, &n, following);
        http_response_free(&r);
        if (!ok) { *reason = "listing_incomplete"; return false; }
        for (size_t i = *count; i < *count + n; i++) for (size_t j = 0; j < i; j++)
            if (!strcmp(out[i].id, out[j].id)) { *reason = "ambiguous_entry"; return false; }
        *count += n;
        if (!following[0]) return true;
        if (*count == cap || !strcmp(next, following)) { *reason = "catalog_limit"; return false; }
        snprintf(next, sizeof(next), "%s", following);
    }
    *reason = "catalog_limit"; return false;
}

size_t gdrive_individual_scan(const char* user, const char* title, individual_backup_t* out,
                              size_t cap, catalog_scan_t* scan) {
    catalog_scan_t result = {CATALOG_UNAVAILABLE, "not_ready", false}; size_t n = 0;
    char uid[32], tid[16];
    if (!out || !cap || cap > INDIVIDUAL_CATALOG_MAX ||
        !backup_folder_code(user, false, uid, sizeof(uid)) || !backup_folder_code(title, true, tid, sizeof(tid))) {
        if (scan) *scan = result; return 0;
    }
    pthread_mutex_lock(&s_lock);
    result.configured = s_state != GDRIVE_STATE_NOT_CONFIGURED;
    if ((s_state != GDRIVE_STATE_READY && !s_initialization_deferred) ||
        !s_session_generation || !ensure_read_access_token_locked()) goto done;
    result.state = CATALOG_PARTIAL; result.reason = NULL;
    char parent[GDRIVE_FILEID_MAX], identity[65]; bool absent = false;
    if (!drive_individual_scope_locked(uid, tid, parent, identity, &absent, &result.reason)) goto done;
    if (absent) { result.state = CATALOG_EMPTY; result.reason = NULL; goto done; }
    drive_individual_file_t* files = calloc(cap, sizeof(*files));
    if (!files) { result.reason = "memory_unavailable"; goto done; }
    size_t count = 0;
    bool complete = drive_individual_files_locked(parent, files, cap, &count, &result.reason);
    for (size_t i = 0; i < count; i++) {
        size_t length = strlen(files[i].name);
        if (length < 4 || strcmp(files[i].name + length - 4, ".zip")) continue;
        individual_backup_t row;
        if (!drive_individual_metadata_locked(files[i].id, parent, files[i].name, uid, tid, &row)) {
            complete = false; if (!result.reason) result.reason = "invalid_individual_archive"; continue;
        }
        snprintf(row.destination_identity, sizeof(row.destination_identity), "%s", identity); out[n++] = row;
    }
    free(files);
    result.state = complete ? (n ? CATALOG_COMPLETE : CATALOG_EMPTY) : CATALOG_PARTIAL;
done:
    pthread_mutex_unlock(&s_lock); if (scan) *scan = result; return n;
}

static bool drive_individual_current_locked(const individual_backup_t* item, individual_backup_t* current) {
    if (!individual_catalog_item_valid(item, "drive") || strncmp(item->ref, "drive:", 6) ||
        item->generation != s_session_generation ||
        (s_state != GDRIVE_STATE_READY && !s_initialization_deferred) || !ensure_read_access_token_locked()) return false;
    const char* reason = NULL; char parent[GDRIVE_FILEID_MAX], identity[65]; bool absent = false;
    return drive_individual_scope_locked(item->user, item->title_id, parent, identity, &absent, &reason) && !absent &&
        !strcmp(parent, item->parent_ref) && !strcmp(identity, item->destination_identity) &&
        drive_individual_metadata_locked(item->ref + 6, parent, item->name, item->user, item->title_id, current) &&
        (snprintf(current->destination_identity, sizeof(current->destination_identity), "%s", identity), true) &&
        individual_catalog_same(item, current) &&
        (!current->checksum[0] || !item->checksum[0] || !strcmp(current->checksum, item->checksum));
}

static bool drive_individual_read_locked(const individual_backup_t* item, const char* local_path) {
    extern char* mkdtemp(char*); // Darwin's strict POSIX headers hide this libc declaration.
    // The HTTP writer accepts a path, so isolate it in a new private directory.
    // link() publishes exclusively: an existing caller file is never overwritten.
    char dir[1024], path[1100], url[512];
    int length = snprintf(dir, sizeof(dir), "%s.individual.XXXXXX", local_path ? local_path : INDIVIDUAL_VERIFY_BASE "/verify");
    if (length < 0 || (size_t)length >= sizeof(dir) || !mkdtemp(dir)) return false;
    snprintf(path, sizeof(path), "%s/copy.zip", dir);
    snprintf(url, sizeof(url), "%s/files/%s?alt=media", DRIVE_API_BASE, item->ref + 6);
    bool ok = http_get_auth_to_file_limited(url, s_tokens.access_token, path, item->size_bytes);
    struct stat st; char checksum[65]; individual_backup_t after;
    ok = ok && !lstat(path, &st) && S_ISREG(st.st_mode) && st.st_size >= 22 &&
        (uint64_t)st.st_size == item->size_bytes && !chmod(path, 0600) && sha256_file_hex(path, checksum) &&
        (!item->checksum[0] || !strcmp(item->checksum, checksum)) && drive_individual_current_locked(item, &after);
    if (ok && local_path) {
        FILE* f = fopen(path, "rb");
        ok = f && !fsync(fileno(f)); if (f && fclose(f)) ok = false;
        if (ok) ok = !link(path, local_path);
    }
    unlink(path); rmdir(dir); return ok;
}

bool gdrive_individual_revalidate(const individual_backup_t* item) {
    pthread_mutex_lock(&s_lock); individual_backup_t current;
    bool ok = drive_individual_current_locked(item, &current);
    // No reliable provider checksum? Fresh bounded bytes prove canonical equality.
    if (ok && item->checksum[0] && !current.checksum[0]) ok = drive_individual_read_locked(item, NULL);
    pthread_mutex_unlock(&s_lock); return ok;
}

bool gdrive_individual_download_bounded(const individual_backup_t* item, const char* local_path,
                                       char* err, size_t err_sz) {
    pthread_mutex_lock(&s_lock); individual_backup_t current;
    bool ok = local_path && local_path[0] && drive_individual_current_locked(item, &current) &&
        drive_individual_read_locked(item, local_path);
    pthread_mutex_unlock(&s_lock);
    if (!ok && err && err_sz) snprintf(err, err_sz, "Individual source changed or bounded copy failed.");
    return ok;
}
