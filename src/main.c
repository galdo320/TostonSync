// TostónSync — Automatic PS5 Save Backup Daemon. Entry point.
//
// Normal startup sequence:
//   1. Acquire the canonical cooperative file lock before operational initialization.
//   2. Migrate state, load config and initialize logging/destinations.
//   3. Preserve existing recovery barriers and informational pidfile behavior.
//   4. Bring up the internal HTTP server (Settings UI on :1993).
//   5. Escape the payload sandbox, then start watcher/workers.
//   6. Drop a notification "TostónSync ready @ <ip>:<port>" and idle
//      until SIGTERM.
//
// On SIGTERM we flush the queue (on_shutdown trigger if enabled) and
// exit through the existing cooperative closure. Remote lifecycle is optional.

#include "config.h"
#include "version.h"
#include "log.h"
#include "fs.h"
#include "gdrive.h"
#include "usb.h"
#include "history.h"
#include "httpd.h"
#include "http_client.h"
#include "watcher.h"
#include "resume_recovery.h"
#include "lifecycle.h"
#include "instance_lock.h"
#include "import_session.h"
#include "update.h"
#include "github_update.h"

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <signal.h>
#include <stdatomic.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <pthread.h>
#include <unistd.h>
#include <time.h>

#define DEFAULT_INI       "/data/tostonsync/config.ini"
#define LEGACY_STATE_DIR  "/data/savesync"
#define DEFAULT_STATE_DIR "/data/tostonsync"
#define TOSTONSYNC_PROC_NAME "tostonsync.elf"

// Open the PS5's own web browser to a URL (same call Payload Manager and
// the menu App use). Lets you configure TostónSync from the console itself.
int sceSystemServiceLaunchWebBrowser(const char* url, void* unk);
int sceUserServiceInitialize(void* params);
int sceUserServiceTerminate(void);

// First-boot rename migration. Move /data/savesync -> /data/tostonsync
// when the legacy dir exists and the new one does not. Failure is non-
// fatal: the daemon will simply start with defaults in the new dir.
static void maybe_migrate_state_dir(void) {
    struct stat sb_old, sb_new;
    if (stat(LEGACY_STATE_DIR, &sb_old) != 0) return;
    if (stat(DEFAULT_STATE_DIR, &sb_new) == 0) return;
    if (rename(LEGACY_STATE_DIR, DEFAULT_STATE_DIR) == 0) {
        log_info("migrated state dir %s -> %s",
                 LEGACY_STATE_DIR, DEFAULT_STATE_DIR);
    } else {
        log_warn("could not migrate %s -> %s (will use defaults)",
                 LEGACY_STATE_DIR, DEFAULT_STATE_DIR);
    }
}

static volatile sig_atomic_t s_stop = 0;
static volatile sig_atomic_t s_resume = 0;
static void on_sigterm(int sig) { (void)sig; s_stop = 1; }
static void on_sigcont(int sig) { (void)sig; s_resume = 1; }

static void announce_web_ui(const config_t* cfg) {
    const char* ip = httpd_get_lan_ip();
    bool es = strcmp(cfg->general.language, "es") == 0;
    char msg[160];
    log_info("console[name=%s type=%s role=%s ip=%s]",
             cfg->console.name, cfg->console.type, cfg->console.role,
             ip[0] ? ip : "unknown");
    if (ip[0]) {
        snprintf(msg, sizeof(msg), "Web UI ready: http://%s:%d/",
                 ip, cfg->general.http_port);
        // The startup address is important even when routine backup toasts
        // are hidden. The master toggle and duplicate throttle still apply.
        log_notify(msg);
    } else {
        log_info("Web UI ready on loopback only: http://127.0.0.1:%d/; LAN unavailable",
                 cfg->general.http_port);
        log_notify(es ? "TostónSync está corriendo local\nEsperando LAN…"
                      : "TostónSync is running locally\nWaiting for LAN…");
    }
}

static void open_ps5_browser(const config_t* cfg) {
    char url[64];
    snprintf(url, sizeof(url), "http://127.0.0.1:%d/", cfg->general.http_port);
    // The SDK browser sample initializes UserService before launching. Only
    // terminate an initialization owned by this helper; an unknown failure is
    // not evidence that another owner's service is safe to use or terminate.
    int rc = sceUserServiceInitialize(NULL);
    if (rc == 0) {
        rc = sceSystemServiceLaunchWebBrowser(url, NULL);
        int term_rc = sceUserServiceTerminate();
        if (term_rc != 0)
            log_warn("PS5 browser UserService cleanup failed rc=0x%x; Web UI remains running",
                     (unsigned)term_rc);
        if (rc != 0)
            log_warn("PS5 browser launch failed rc=0x%x; Web UI remains running",
                     (unsigned)rc);
    } else {
        log_warn("PS5 browser UserService initialization failed rc=0x%x; Web UI remains running",
                 (unsigned)rc);
    }
    if (rc != 0) {
        const char* ip = httpd_get_lan_ip();
        bool es = strcmp(cfg->general.language, "es") == 0;
        char msg[192];
        if (ip[0])
            snprintf(msg, sizeof(msg), es
                     ? "No se pudo abrir el navegador PS5\nWeb UI: http://%s:%d/"
                     : "PS5 browser could not open\nWeb UI: http://%s:%d/",
                     ip, cfg->general.http_port);
        else
            snprintf(msg, sizeof(msg), "%s", es
                     ? "No se pudo abrir el navegador PS5\nTostónSync está corriendo local. Esperando LAN…"
                     : "PS5 browser could not open\nTostónSync is running locally. Waiting for LAN…");
        log_notify(msg);
    }
}

static dev_t s_pidfile_dev;
static ino_t s_pidfile_ino;

static bool status_identifies_tostonsync(int port, long pid, bool* port_open) {
    if (port_open) *port_open = false;
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return false;
    struct timeval tv = {2, 0};
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons((uint16_t)port);
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (connect(fd, (struct sockaddr*)&addr, sizeof(addr)) != 0) {
        close(fd);
        return false;
    }
    if (port_open) *port_open = true;
    static const char req[] =
        "GET /api/status HTTP/1.0\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n";
    size_t sent = 0;
    while (sent < sizeof(req) - 1) {
        ssize_t n = send(fd, req + sent, sizeof(req) - 1 - sent, 0);
        if (n <= 0) { close(fd); return false; }
        sent += (size_t)n;
    }
    char resp[8192];
    size_t used = 0;
    while (used + 1 < sizeof(resp)) {
        ssize_t n = recv(fd, resp + used, sizeof(resp) - used - 1, 0);
        if (n <= 0) break;
        used += (size_t)n;
    }
    close(fd);
    resp[used] = '\0';

    char pid_field[48];
    // Include the following comma so pid 24 cannot accidentally match 247.
    snprintf(pid_field, sizeof(pid_field), "\"pid\":%ld,", pid);
    return strstr(resp, " 200 ") != NULL &&
           strstr(resp, "\"app\":\"TostónSync\"") != NULL &&
           strstr(resp, pid_field) != NULL &&
           strstr(resp, "\"version\":\"") != NULL;
}

// Recovery markers remain independent of instance discovery/exclusivity.
static void prepare_instance_state(const char* state_dir) {
    char busy[300];
    snprintf(busy, sizeof(busy), "%s/restore.busy", state_dir);
    if (access(busy, F_OK) == 0) {
        char interrupted[512];
        snprintf(interrupted, sizeof(interrupted), "%s/restore.interrupted", state_dir);
        if (access(interrupted, F_OK) == 0 || rename(busy, interrupted) != 0)
            log_error("restore: recovery markers need review; existing files preserved");
        sync();
        log_warn("Previous restore was interrupted. Keep the game closed and use Restore previous save");
    }

    // Informational only: never authority for admission, identity or stop.
    char path[300];
    snprintf(path, sizeof(path), "%s/tostonsync.pid", state_dir);
    int fd = open(path, O_WRONLY | O_CREAT | O_NOFOLLOW | O_NONBLOCK, 0644);
    if (fd < 0) {
        log_warn("pidfile: cannot open %s; cooperative instance lock remains held", path);
        return;
    }
    struct stat st;
    if (fstat(fd, &st) || !S_ISREG(st.st_mode) || st.st_nlink != 1 || st.st_uid != geteuid() ||
        ftruncate(fd, 0)) {
        log_warn("pidfile: cannot safely record our pid; reservation remains held");
        close(fd);
        return;
    }
    s_pidfile_dev = st.st_dev;
    s_pidfile_ino = st.st_ino;
    char buf[32];
    int n = snprintf(buf, sizeof(buf), "%d\n", (int)getpid());
    if (n > 0 && write(fd, buf, (size_t)n) != n)
        log_warn("pidfile: could not record our pid");
    close(fd);
}

static const char* reservation_errno_name(int error) {
#define ERRNO_NAME(name) if (error == name) return #name
    ERRNO_NAME(EPERM); ERRNO_NAME(EACCES); ERRNO_NAME(EINVAL);
    ERRNO_NAME(ENOMEM); ERRNO_NAME(ENOENT); ERRNO_NAME(EEXIST);
    ERRNO_NAME(EADDRINUSE); ERRNO_NAME(ENOTDIR); ERRNO_NAME(ENOTSUP);
    ERRNO_NAME(EIO); ERRNO_NAME(EBUSY); ERRNO_NAME(EMFILE);
    ERRNO_NAME(ENFILE); ERRNO_NAME(ENAMETOOLONG); ERRNO_NAME(ENOSPC);
    ERRNO_NAME(EWOULDBLOCK); ERRNO_NAME(EAGAIN); ERRNO_NAME(ENOSYS);
#undef ERRNO_NAME
    return NULL;
}

static void report_instance_lock(const instance_lock_diagnostic_t* d,bool acquired) {
    fprintf(stderr,"{\"diagnostic\":\"startup_instance_lock\",\"version\":\"%s\","
        "\"outcome\":\"%s\",\"mechanism\":\"cooperative_flock\",\"path\":\"%s\","
        "\"stage\":\"%s\",\"operation\":\"%s\",\"reason\":\"%s\",\"result\":",
        TOSTONSYNC_VERSION,acquired?"ACQUIRED":"BLOCKED",INSTANCE_LOCK_PATH,
        d->stage,d->operation,d->reason);
    if(d->result_known) fprintf(stderr,"%d",d->result); else fputs("null",stderr);
    fputs(",\"errno\":",stderr);
    if(d->error_known) fprintf(stderr,"%d",d->error); else fputs("null",stderr);
    const char* name=d->error_known?reservation_errno_name(d->error):NULL;
    fputs(",\"errno_name\":",stderr);
    if(name) fprintf(stderr,"\"%s\"",name); else fputs("null",stderr);
    fprintf(stderr,",\"lock_acquired\":%s,\"startup_allowed\":%s,"
        "\"identity_proven\":false,\"lifecycle_ipc_started\":false}\n",
        acquired?"true":"false",acquired?"true":"false");
    fflush(stderr);
}

static void write_one_port_marker(const char* dir, int port) {
    if (!dir || !dir[0]) return;
    fs_mkdir_p(dir);
    char path[300];
    snprintf(path, sizeof(path), "%s/.port", dir);
    FILE* f = fopen(path, "w");
    if (!f) {
        log_warn("could not write dashboard port marker %s", path);
        return;
    }
    fprintf(f, "%d\n", port);
    fclose(f);
}

static void write_port_marker(const char* state_dir, int port) {
    const char* configured = (state_dir && state_dir[0])
        ? state_dir : DEFAULT_STATE_DIR;
    write_one_port_marker(configured, port);
    // The dashboard launcher has no config parser. Keep this canonical marker
    // in sync even when an advanced user moves state_dir elsewhere.
    if (strcmp(configured, DEFAULT_STATE_DIR) != 0)
        write_one_port_marker(DEFAULT_STATE_DIR, port);
}

static void remove_pidfile(const char* state_dir) {
    char path[300];
    snprintf(path, sizeof(path), "%s/tostonsync.pid",
             (state_dir && state_dir[0]) ? state_dir : DEFAULT_STATE_DIR);
    struct stat st;
    if (s_pidfile_ino && !lstat(path, &st) && S_ISREG(st.st_mode) &&
        st.st_uid == geteuid() && st.st_dev == s_pidfile_dev && st.st_ino == s_pidfile_ino)
        unlink(path);
    s_pidfile_ino = 0;
}

// "Forgot my access code" escape hatches, checked once at boot:
//   1. the ui_auth_reset_on_boot option (clears every boot);
//   2. an empty file named "reset_auth" in the state dir (drop it via FTP);
//   3. the same marker in the root of a plugged-in USB drive.
// (Editing config.ini directly is the fourth, always-available route.)
static void maybe_reset_ui_auth(const config_t* cfg) {
    bool do_reset = config_ui_reset_on_boot();

    char marker[300];
    snprintf(marker, sizeof(marker), "%s/reset_auth", cfg->paths.state_dir);
    if (access(marker, F_OK) == 0) { do_reset = true; unlink(marker); }

    char mount[80];
    if (usb_detect(mount, sizeof(mount))) {
        char um[160];
        snprintf(um, sizeof(um), "%s/reset_auth", mount);
        if (access(um, F_OK) == 0) { do_reset = true; unlink(um); }
    }

    if (do_reset && (cfg->general.ui_auth_enabled || config_ui_password()[0])) {
        config_reset_ui_auth();
        log_warn("UI access code was reset (reset_auth marker / boot option)");
        log_notify("TostónSync: UI access code has been reset");
    }
}

static void observation_json_string(const char* value) {
    putchar('"');
    for (const unsigned char* p = (const unsigned char*)value; p && *p; p++) {
        if (*p == '"' || *p == '\\') { putchar('\\'); putchar(*p); }
        else if (*p < 32) printf("\\u%04x", *p);
        else putchar(*p);
    }
    putchar('"');
}

static void report_import_observation(void) {
    import_session_observation_t observed;
    bool have = import_session_observe_snapshot(&observed);
    bool valid = have && observed.checkpoint_valid;
    printf("{\"diagnostic\":\"startup_import_observation\",\"version\":\"%s\","
           "\"result\":\"%s\",\"checkpoint_present\":", TOSTONSYNC_VERSION,
           valid ? "OBSERVED" : "UNKNOWN");
    if (have && observed.checkpoint_present) printf("true");
    else if (valid) printf("false");
    else printf("null");
    printf(",\"import_id\":");
    if (valid && observed.checkpoint_present) observation_json_string(observed.info.id);
    else printf("null");
    printf(",\"state\":");
    if (valid && observed.checkpoint_present)
        observation_json_string(import_state_name(observed.info.state));
    else printf("null");
    printf(",\"title_hint\":");
    if (valid && observed.checkpoint_present) observation_json_string(observed.info.title_hint);
    else printf("null");
    printf(",\"detail\":");
    observation_json_string(have ? observed.detail : "Observation unavailable");
    printf(",\"historical_receipt_present\":%s,\"receipt_domain\":\"HISTORICAL_NON_AUTHORIZING\","
           "\"operational_authority\":false,\"sources_integrity\":\"NOT_CHECKED\","
           "\"checkpoint_mutated\":false}\n",
           have && observed.historical_receipt_present ? "true" : "false");
    fflush(stdout);
}

static atomic_bool s_stop_web_teardown_done;
static atomic_bool s_stop_web_teardown_clear;

static void stop_web_freeze(const char* reason) {
    if (!strcmp(reason, "teardown_deadline_exceeded"))
        log_warn("stop[web] STOP TIMEOUT; instance lock retained; closure UNKNOWN");
    else log_warn("stop[web] closure UNKNOWN reason=%s; %s", reason,
                  !strcmp(reason, "instance_lock_release_unknown") ?
                  "instance lock ownership UNKNOWN" : "instance lock retained");
    // Terminal admission stays closed. Never return, release the lock or force a thread.
    for (;;) sleep(1);
}

static bool stop_web_monotonic_ns(int64_t* out) {
    struct timespec now;
    if (!out || clock_gettime(CLOCK_MONOTONIC, &now) || now.tv_sec < 0 ||
        now.tv_sec > (INT64_MAX - 999999999) / 1000000000 ||
        now.tv_nsec < 0 || now.tv_nsec >= 1000000000) return false;
    *out = (int64_t)now.tv_sec * 1000000000 + now.tv_nsec;
    return true;
}

static void* stop_web_teardown(void* unused) {
    (void)unused;
    // The accepted HTTP handler must release both of its own admissions first.
    while (lifecycle_operations()) usleep(100 * 1000);
    lifecycle_server_stop();
    bool clear = watcher_stop_checked();
    if (clear) clear = httpd_stop_cooperatively();
    clear = clear && !lifecycle_operations() && !httpd_active_connections();
    atomic_store(&s_stop_web_teardown_clear, clear);
    atomic_store(&s_stop_web_teardown_done, true);
    return NULL;
}

static int stop_web_cooperatively(const config_t* cfg) {
    log_info("stop[web] begin");
    int64_t started;
    if (!stop_web_monotonic_ns(&started)) stop_web_freeze("monotonic_clock_unknown");
    atomic_store(&s_stop_web_teardown_done, false);
    atomic_store(&s_stop_web_teardown_clear, false);
    pthread_t teardown;
    if (pthread_create(&teardown, NULL, stop_web_teardown, NULL))
        stop_web_freeze("teardown_thread_unavailable");
    for (;;) {
        int64_t now;
        if (!stop_web_monotonic_ns(&now) || now < started)
            stop_web_freeze("monotonic_clock_unknown");
        if (now - started >= (int64_t)30 * 1000000000)
            stop_web_freeze("teardown_deadline_exceeded");
        if (atomic_load(&s_stop_web_teardown_done)) break;
        usleep(100 * 1000);
    }
    if (pthread_join(teardown, NULL)) stop_web_freeze("teardown_join_unknown");
    if (!atomic_load(&s_stop_web_teardown_clear) || lifecycle_operations() ||
        httpd_active_connections()) stop_web_freeze("teardown_incomplete");
    remove_pidfile(cfg->paths.state_dir);
    if (!instance_lock_release()) stop_web_freeze("instance_lock_release_unknown");
    log_info("stop[web] complete");
    log_info("TostónSync stopped");
    return 0;
}

int main(int argc, char** argv) {
    (void)argc; (void)argv;

    // Auxiliary process label only; never admission, identity or stop authority.
    syscall(SYS_thr_set_name, -1, TOSTONSYNC_PROC_NAME);

    // Keep config.ini, tokens.json, logs and temporary plain-PFS staging
    // private by default. USB/exFAT ignores POSIX modes, but /data honors
    // them and may be reachable over FTP on jailbroken consoles.
    umask(0077);

    // Install signal handlers first so a SIGTERM during startup still
    // results in a clean shutdown rather than an abrupt default exit.
    signal(SIGTERM, on_sigterm);
    signal(SIGINT,  on_sigterm);
    signal(SIGPIPE, SIG_IGN);
    signal(SIGHUP,  SIG_IGN);
    signal(SIGCONT, on_sigcont);

    // Cooperative exclusion precedes migration, config, logs, certificates and work.
    instance_lock_diagnostic_t reservation;
    bool acquired = instance_lock_acquire(&reservation);
    report_instance_lock(&reservation,acquired);
    if(!acquired) return 1;

#if TOSTONSYNC_STARTUP_VALIDATION_ONLY
    // Temporary .217 delivery: no new mode/state; operational startup below
    // remains intact for a separately authorized later delivery.
    config_t observed_cfg;
    if (!config_load_observational(&observed_cfg, DEFAULT_INI)) {
        fprintf(stderr, "startup validation BLOCKED: stable existing manual-only INI required\n");
        if (!instance_lock_release()) fprintf(stderr, "instance lock release UNKNOWN\n");
        return 1;
    }
    import_session_observe_init(&observed_cfg);
    report_import_observation();
    if (!httpd_start(&observed_cfg)) {
        fprintf(stderr, "startup validation BLOCKED: HTTP unavailable\n");
        if (!instance_lock_release()) fprintf(stderr, "instance lock release UNKNOWN\n");
        return 1;
    }
    bool escaped = fs_escape_sandbox();
    const char* validation_ip = httpd_get_lan_ip();
    printf("{\"diagnostic\":\"startup_validation_ready\",\"version\":\"%s\","
           "\"validation_only\":true,\"manual_only\":true,\"browser_opened\":false,"
           "\"watcher_started\":false,\"sandbox_escape_reported\":%s,\"address\":",
           TOSTONSYNC_VERSION, escaped ? "true" : "false");
    observation_json_string(validation_ip);
    printf(",\"http_port\":%d}\n", observed_cfg.general.http_port);
    fflush(stdout);
    // No watchdog/status polling, retry evaluation or automatic transition.
    while (!s_stop) sleep(1);
    httpd_stop();
    if (!instance_lock_release()) fprintf(stderr, "instance lock release UNKNOWN\n");
    return 0;
#endif

    // Retain post-admission migration behavior. An absent canonical base is
    // blocked by the lock guard, never created here to bypass legacy-only state.
    maybe_migrate_state_dir();

    // Keep the existing sandbox/HTTP/watcher ordering after exclusive admission.

    // 1. Config. Creates /data/tostonsync + a default config.ini on first
    //    run (/data is writable from the sandbox, no escape needed).
    config_t cfg;
    if (!config_load(&cfg, DEFAULT_INI)) {
        fprintf(stderr, "fatal: cannot load %s\n", DEFAULT_INI);
        if (!instance_lock_release())
            fprintf(stderr, "instance lock retained; release UNKNOWN\n");
        return 1;
    }

    // 2. Logging. Proof-of-life goes to the log only — the single
    //    user-facing toast is the "ready" one below, emitted after the port
    //    is bound. That way a normal boot shows exactly ONE notification
    //    instead of three or four ("starting" + "ready" + "no kernel" ...).
    log_init(&cfg);
    char run_id[48];
    snprintf(run_id, sizeof(run_id), "%ld-%lld", (long)getpid(),
             (long long)time(NULL));
    log_info("daemon[run=%s pid=%ld]: TostónSync v%s starting",
             run_id, (long)getpid(), TOSTONSYNC_VERSION);
    log_debug("build %s", TOSTONSYNC_BUILD);

    // 3. Backup destinations + the "forgot my UI code" reset. None of
    //    these need kernel access.
    // Custom CA loading is OFF unless explicitly enabled in config. It stays
    // off by default because sceSslLoadRootCACert destabilised the daemon on
    // hardware; a present/missing cacert.pem must never be able to kill us.
    if (!http_google_cert_ensure())
        log_warn("automatic Google certificate setup failed; use Repair Google certificates in Advanced diagnostics");
    http_tls_set_custom_ca(cfg.gdrive.custom_ca);
    gdrive_init(&cfg); // Manual/local startup only configures; Drive actions activate.
    usb_init(&cfg);
    history_init(&cfg);
    maybe_reset_ui_auth(&cfg);

    // 4. Recovery barriers are retained. HTTP is not instance authority.
    prepare_instance_state(cfg.paths.state_dir);
    github_update_init(&cfg);
    bool ui_ok = httpd_start(&cfg);
    if (!ui_ok) {
        // Bind failure does not establish who owns the port, or even a peer.
        log_warn("HTTP startup failed on port %d; stopping admitted startup",
                 cfg.general.http_port);
        log_notify("TostónSync could not start the Web UI");
        remove_pidfile(cfg.paths.state_dir);
        if (!instance_lock_release())
            log_warn("instance lock retained; release UNKNOWN");
        return 1;
    }
    write_port_marker(cfg.paths.state_dir, cfg.general.http_port);
    announce_web_ui(&cfg);

    // Pop open the PS5's browser on the Settings UI so you can configure
    // everything from the console itself (disable with [general]
    // open_browser = false).
    if (ui_ok && cfg.general.open_browser) {
        open_ps5_browser(&cfg);
    }

    // 5. Kernel-dependent part: escape the sandbox so /user/home (the
    //    saves) is reachable, then start watching. Non-fatal — if kstuff
    //    isn't active the UI stays up and we tell you what's wrong.
    if (!fs_escape_sandbox()) {
        log_warn("sandbox escape failed — is kstuff loaded BEFORE TostónSync?");
        log_notify("TostónSync: no kernel access — load kstuff first "
                   "(UI works, save backup is paused)");
    }
    if (!watcher_start(&cfg)) {
        log_warn("automatic backup watcher could not start");
        log_notify("TostónSync UI is ready, but automatic backups could not "
                   "start — open Status for details");
    }
    // Keep operation/gate/recovery guards, without requiring unsupported IPC.
    log_info("cooperative instance lock held; lifecycle IPC not started, remote STOP/VERIFY unsupported");

    char known_ip[64];
    snprintf(known_ip, sizeof(known_ip), "%s", httpd_get_lan_ip());
    bool network_available = known_ip[0] != '\0';
    time_t next_network_check = time(NULL) + 5;
    time_t last_lan_notice = 0;
    time_t last_local_notice = 0;
    time_t last_drive_notice = 0;
    while (!s_stop) {
        if (lifecycle_local_stop_pending()) break;
        sleep(1);
        if (lifecycle_local_stop_pending()) break;
        if (s_stop) break;
        if (!lifecycle_operation_begin()) continue;
        import_session_maintenance();
        httpd_maintenance();
        watcher_maintenance();
        github_update_tick();
        bool resumed = s_resume != 0;
        time_t now = time(NULL);
        if (http_client_take_drive_reconnected()) {
            if (last_drive_notice == 0 || now - last_drive_notice >= 90) {
                config_t notice_cfg;
                bool es = config_snapshot(&notice_cfg) &&
                          strcmp(notice_cfg.general.language, "es") == 0;
                log_notify_level(NOTIFY_BALANCED, es
                    ? "Google Drive listo\nBackups automáticos activos"
                    : "Google Drive is ready\nAutomatic backups enabled");
                last_drive_notice = now;
            } else {
                log_info("gdrive-http: reconnection notification throttled");
            }
        }
        if (!resumed && now < next_network_check) {
            lifecycle_operation_end();
            continue;
        }
        if (resumed) {
            s_resume = 0;
            log_info("daemon[run=%s]: SIGCONT received", run_id);
            log_info("daemon[run=%s]: PS5 resume detected; recovery starting",
                     run_id);
        }
        next_network_check = now + 5;

        char current_ip[64] = "";
        (void)httpd_detect_lan_ip(current_ip, sizeof(current_ip));
        bool had_network = network_available;
        network_available = current_ip[0] != '\0';
        bool port_open = false;
        bool healthy = status_identifies_tostonsync(
            cfg.general.http_port, (long)getpid(), &port_open);
        if (s_stop) { lifecycle_operation_end(); break; }
        bool restart_http = resume_http_restart_needed(
            resumed, healthy, had_network ? known_ip : "", current_ip);
        bool network_changed = current_ip[0] &&
            (!had_network || strcmp(known_ip, current_ip) != 0);
        bool restart_watcher = resumed || network_changed;

        // Joining the old generation first guarantees one watcher and no
        // in-flight backup while network/TLS contexts are replaced.
        if (restart_watcher && watcher_active_jobs() > 0)
            log_warn("Backup is still in progress; it may resume after Rest Mode");
        if (restart_watcher) watcher_stop();
        if (resumed) {
            char usb_mount[64];
            log_info("daemon[run=%s]: USB rediscovery after resume: %s",
                     run_id, usb_detect(usb_mount, sizeof(usb_mount))
                         ? usb_mount : "not present");
        }

        if (restart_http) {
            log_info("daemon[run=%s]: network refresh old_ip=%s new_ip=%s healthy=%s",
                     run_id, had_network && known_ip[0] ? known_ip : "unknown",
                     current_ip[0] ? current_ip : "unknown",
                     healthy ? "yes" : "no");
            log_info("daemon[run=%s]: restarting web server after %s",
                     run_id, resumed ? "resume" : "network refresh");
            httpd_stop();
            if (restart_watcher)
                http_client_mark_stale(
                    gdrive_get_state() == GDRIVE_STATE_READY);
            usleep(800 * 1000);
            if (s_stop) { lifecycle_operation_end(); break; }
            if (httpd_start(&cfg)) {
                write_port_marker(cfg.paths.state_dir, cfg.general.http_port);
                const char* restored_ip = httpd_get_lan_ip();
                snprintf(current_ip, sizeof(current_ip), "%s", restored_ip);
                network_available = current_ip[0] != '\0';
                if (!restored_ip[0]) {
                    log_info("daemon[run=%s]: web server restored on loopback "
                             "only; LAN unavailable", run_id);
                    if (resume_local_notice_needed(
                            false, (long long)now,
                            (long long)last_local_notice, 90)) {
                        config_t notice_cfg;
                        bool es = config_snapshot(&notice_cfg) &&
                                  strcmp(notice_cfg.general.language, "es") == 0;
                        log_notify(es
                            ? "TostónSync está corriendo local\nEsperando LAN…"
                            : "TostónSync is running locally\nWaiting for LAN…");
                        last_local_notice = now;
                    }
                } else {
                    log_info("daemon[run=%s]: web server restored on %s:%d",
                             run_id, restored_ip, cfg.general.http_port);
                }
                if (restored_ip[0] && resume_lan_notice_needed(
                               had_network, true, (long long)now,
                               (long long)last_lan_notice, 90)) {
                    config_t notice_cfg;
                    bool es = config_snapshot(&notice_cfg) &&
                              strcmp(notice_cfg.general.language, "es") == 0;
                    char notice[192];
                    snprintf(notice, sizeof(notice),
                             es ? "TostónSync volvió en línea\nWeb UI: %s:%d"
                                : "TostónSync is back online\nWeb UI: %s:%d",
                             restored_ip, cfg.general.http_port);
                    log_notify(notice);
                    last_lan_notice = now;
                }
            } else {
                log_warn("daemon[run=%s]: web server restart failed; watchdog will retry",
                         run_id);
            }
        }

        if (current_ip[0])
            snprintf(known_ip, sizeof(known_ip), "%s", current_ip);
        if (restart_watcher) {
            if (s_stop) { lifecycle_operation_end(); break; }
            if (watcher_start(&cfg))
                log_info("daemon[run=%s]: watcher restarted after %s", run_id,
                         resumed ? "resume" : "network refresh");
            else
                log_warn("daemon[run=%s]: watcher recovery failed", run_id);
        }
        lifecycle_operation_end();
    }

    if (lifecycle_local_stop_pending()) {
        int stopped = stop_web_cooperatively(&cfg);
        (void)update_restart_after_stop();
        return stopped;
    }

    log_info("TostónSync stopping");
    lifecycle_server_stop();
    watcher_on_shutdown();
    watcher_stop();
    httpd_stop();
    remove_pidfile(cfg.paths.state_dir);
    log_info("TostónSync stopped");
    // Detached operations can outlive HTTP teardown. Never release their
    // exclusivity. The persistent regular lockfile is never unlinked.
    if (!instance_lock_release())
        fprintf(stderr, "instance lock retained; shutdown incomplete or release UNKNOWN\n");
    return 0;
}
