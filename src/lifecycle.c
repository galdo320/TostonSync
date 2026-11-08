// Local lifecycle admission. This unit has no system calls that signal a process.
#include "lifecycle.h"
#include <errno.h>
#include <limits.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <strings.h>

static pthread_mutex_t s_mutex = PTHREAD_MUTEX_INITIALIZER;
static life_identity_t s_identity;
static unsigned s_operations;
static life_state_t s_state = LIFE_RUNNING;
static _Thread_local unsigned s_depth;
static _Thread_local bool s_http_handler;
static bool s_local_stop_pending;
static uint64_t s_update_ticket, s_update_ticket_next;
static _Thread_local bool s_update_worker, s_update_install;

static bool text_valid(const char* text, size_t capacity) {
    return text && text[0] && memchr(text, '\0', capacity) && strcasecmp(text, "UNKNOWN");
}

static bool version_valid(const char* version, size_t capacity) {
    if (!text_valid(version, capacity)) return false;
    unsigned parts = 0;
    for (const char* p = version; *p;) {
        if (*p < '0' || *p > '9') return false;
        while (*p >= '0' && *p <= '9') p++;
        if (++parts == 3) return *p == '\0';
        if (*p++ != '.') return false;
    }
    return false;
}

bool lifecycle_identity_valid(const life_identity_t* id) {
    if (!id || !id->kernel_identity_known || !id->module_known || id->pid <= 1 ||
        id->pid > INT_MAX || id->start_sec <= 0 || id->start_usec < 0 ||
        id->start_usec >= 1000000 || !id->module_base ||
        !text_valid(id->module, sizeof(id->module)) ||
        !version_valid(id->version, sizeof(id->version)) ||
        !text_valid(id->build, sizeof(id->build)) || id->nonce[64] != '\0' ||
        id->process_model < LIFE_PROCESS_UNKNOWN || id->process_model > LIFE_PROCESS_CARRIER)
        return false;
    for (unsigned i = 0; i < 64; ++i)
        if (!((id->nonce[i] >= '0' && id->nonce[i] <= '9') ||
              (id->nonce[i] >= 'a' && id->nonce[i] <= 'f'))) return false;
    return true;
}

bool lifecycle_identity_equal(const life_identity_t* a, const life_identity_t* b) {
    return lifecycle_identity_valid(a) && lifecycle_identity_valid(b) &&
        a->pid == b->pid && a->start_sec == b->start_sec && a->start_usec == b->start_usec &&
        a->module_base == b->module_base && a->process_model == b->process_model &&
        !strcmp(a->nonce, b->nonce) && !strcmp(a->module, b->module) &&
        !strcmp(a->version, b->version) && !strcmp(a->build, b->build);
}

void lifecycle_init(const life_identity_t* identity) {
    pthread_mutex_lock(&s_mutex);
    // Initialization is one process startup action, never a thaw operation.
    if (s_state == LIFE_RUNNING) {
        memset(&s_identity, 0, sizeof(s_identity));
        if (identity) s_identity = *identity;
    }
    pthread_mutex_unlock(&s_mutex);
}

bool lifecycle_operation_begin(void) {
    if (s_depth) {
        if (s_depth == UINT_MAX) return false;
        ++s_depth;
        return true;
    }
    bool accepted = lifecycle_activity_begin();
    if (accepted) s_depth = 1;
    return accepted;
}

void lifecycle_operation_end(void) {
    if (!s_depth || --s_depth) return;
    lifecycle_activity_end();
}

bool lifecycle_http_operation_begin(void) {
    if (s_depth || s_http_handler || !lifecycle_operation_begin()) return false;
    s_http_handler = true;
    return true;
}

void lifecycle_http_operation_end(void) {
    if (!s_http_handler) return;
    s_http_handler = false;
    lifecycle_operation_end();
    lifecycle_activity_end();
}

bool lifecycle_activity_begin(void) {
    pthread_mutex_lock(&s_mutex);
    bool accepted = (s_state == LIFE_RUNNING || (s_state == LIFE_RESERVING && s_update_install)) && s_operations < UINT_MAX;
    if (accepted) ++s_operations;
    pthread_mutex_unlock(&s_mutex);
    return accepted;
}

void lifecycle_activity_end(void) {
    pthread_mutex_lock(&s_mutex);
    if (s_operations) --s_operations;
    pthread_mutex_unlock(&s_mutex);
}

unsigned lifecycle_operations(void) {
    pthread_mutex_lock(&s_mutex);
    unsigned count = s_operations;
    pthread_mutex_unlock(&s_mutex);
    return count;
}

life_state_t lifecycle_state(void) {
    pthread_mutex_lock(&s_mutex);
    life_state_t state = s_state;
    pthread_mutex_unlock(&s_mutex);
    return state;
}

bool lifecycle_stopping(void) { return lifecycle_state() != LIFE_RUNNING; }

void lifecycle_identity(life_identity_t* out) {
    if (!out) return;
    pthread_mutex_lock(&s_mutex);
    *out = s_identity;
    pthread_mutex_unlock(&s_mutex);
}

static void unknown_snapshot(life_snapshot_t* out, const char* reason) {
    memset(out, 0, sizeof(*out));
    out->import_work = out->recovery = out->mounts = out->gate = out->checkpoint = LIFE_UNKNOWN;
    snprintf(out->reason, sizeof(out->reason), "%s", reason);
}

bool lifecycle_inspect(life_snapshot_fn snapshot, life_identity_t* identity, life_snapshot_t* out) {
    if (!out) return false;
    if (identity) lifecycle_identity(identity);
    unknown_snapshot(out, "snapshot_unavailable");
    bool ok = snapshot && snapshot(out);
    unsigned count = lifecycle_operations();
    out->operations = count > INT_MAX ? INT_MAX : (int)count;
    out->reason[sizeof(out->reason) - 1] = '\0';
    return ok;
}

static bool snapshot_clear(const life_snapshot_t* s) {
    return s->jobs == 0 && s->queued == 0 && s->operations == 0 &&
        s->import_work == LIFE_CLEAR && s->recovery == LIFE_CLEAR &&
        s->mounts == LIFE_CLEAR && s->gate == LIFE_CLEAR && s->checkpoint == LIFE_CLEAR;
}

static const char* cooperative_blocker(const life_snapshot_t* s) {
    if (s->jobs != 0) return "jobs_busy_or_unknown";
    if (s->queued != 0) return "queue_busy_or_unknown";
    if (s->operations != 0) return "operations_busy_or_unknown";
    if (s->import_work != LIFE_CLEAR) return "import_busy_or_unknown";
    if (s->mounts != LIFE_CLEAR) return "mounts_busy_or_unknown";
    if (s->gate != LIFE_CLEAR) return "gate_busy_or_unknown";
    if (s->recovery != LIFE_CLEAR) return "recovery_busy_or_unknown";
    if (s->checkpoint != LIFE_CLEAR) return "checkpoint_busy_or_unknown";
    return NULL;
}

bool lifecycle_update_worker_reserve(uint64_t* ticket) {
    if (!ticket) return false;
    *ticket = 0;
    pthread_mutex_lock(&s_mutex);
    bool accepted = s_state == LIFE_RUNNING && !s_update_ticket &&
        s_operations < UINT_MAX && s_update_ticket_next != UINT64_MAX;
    if (accepted) { *ticket = s_update_ticket = ++s_update_ticket_next; ++s_operations; }
    pthread_mutex_unlock(&s_mutex);
    return accepted;
}

bool lifecycle_update_worker_enter(uint64_t ticket) {
    pthread_mutex_lock(&s_mutex);
    bool accepted = ticket && ticket == s_update_ticket && !s_depth && !s_http_handler && !s_update_worker;
    if (accepted) { s_update_ticket = 0; s_depth = 1; s_update_worker = true; }
    pthread_mutex_unlock(&s_mutex);
    return accepted;
}

void lifecycle_update_worker_cancel(uint64_t ticket) {
    pthread_mutex_lock(&s_mutex);
    if (ticket && ticket == s_update_ticket) { s_update_ticket = 0; if (s_operations) --s_operations; }
    pthread_mutex_unlock(&s_mutex);
}

bool lifecycle_update_install_begin(life_snapshot_fn snapshot, life_snapshot_t* out) {
    if (!out) return false;
    unknown_snapshot(out, "update_worker_context_invalid");
    pthread_mutex_lock(&s_mutex);
    bool allowed = s_update_worker && s_depth == 1 && !s_http_handler &&
        !s_update_install && s_operations >= 1 && s_state == LIFE_RUNNING && snapshot;
    if (!allowed) { pthread_mutex_unlock(&s_mutex); return false; }
    s_state = LIFE_RESERVING;
    pthread_mutex_unlock(&s_mutex);
    bool observed = snapshot(out);
    pthread_mutex_lock(&s_mutex);
    out->operations = s_operations >= 1 && s_operations - 1 <= INT_MAX ? (int)(s_operations - 1) : -1;
    const char* blocker = cooperative_blocker(out);
    bool accepted = observed && !blocker && snapshot_clear(out);
    if (accepted) s_update_install = true;
    else s_state = LIFE_RUNNING;
    snprintf(out->reason, sizeof(out->reason), "%s", accepted ? "update_install_reserved" : blocker ? blocker : "snapshot_unavailable");
    pthread_mutex_unlock(&s_mutex);
    return accepted;
}

void lifecycle_update_install_end(void) {
    pthread_mutex_lock(&s_mutex);
    if (s_update_worker && s_update_install && s_state == LIFE_RESERVING) {
        s_update_install = false; s_state = LIFE_RUNNING;
    }
    pthread_mutex_unlock(&s_mutex);
}

void lifecycle_update_worker_leave(void) {
    if (!s_update_worker || s_depth != 1) return;
    lifecycle_update_install_end();
    s_update_worker = false;
    lifecycle_operation_end();
}

bool lifecycle_request_cooperative_stop(life_snapshot_fn snapshot, life_snapshot_t* out) {
    if (!out) return false;
    unknown_snapshot(out, "stop_denied");
    pthread_mutex_lock(&s_mutex);
    const char* denied = !s_http_handler || s_depth != 1 || s_operations < 2 ?
        "http_stop_context_invalid" : s_state != LIFE_RUNNING ? "already_stopping" :
        !snapshot ? "snapshot_unavailable" : NULL;
    if (denied) {
        snprintf(out->reason, sizeof(out->reason), "%s", denied);
        pthread_mutex_unlock(&s_mutex);
        return false;
    }
    s_state = LIFE_RESERVING;
    pthread_mutex_unlock(&s_mutex);
    bool observed = snapshot(out);
    pthread_mutex_lock(&s_mutex);
    // These two leases remain owned by this handler throughout the snapshot.
    // Any other handler, producer or detached worker is still counted.
    out->operations = s_operations >= 2 && s_operations - 2 <= INT_MAX ?
        (int)(s_operations - 2) : -1;
    const char* blocker = cooperative_blocker(out);
    bool accepted = observed && !blocker && snapshot_clear(out);
    s_state = accepted ? LIFE_STOP_ACCEPTED : LIFE_RUNNING;
    snprintf(out->reason, sizeof(out->reason), "%s", accepted ? "stop_accepted" :
             blocker ? blocker : "snapshot_unavailable");
    pthread_mutex_unlock(&s_mutex);
    return accepted;
}

void lifecycle_cooperative_response_sent(void) {
    pthread_mutex_lock(&s_mutex);
    if (s_http_handler && s_depth == 1 && s_state == LIFE_STOP_ACCEPTED)
        s_local_stop_pending = true;
    pthread_mutex_unlock(&s_mutex);
}

bool lifecycle_local_stop_pending(void) {
    pthread_mutex_lock(&s_mutex);
    bool pending = s_local_stop_pending;
    pthread_mutex_unlock(&s_mutex);
    return pending;
}

bool lifecycle_request_stop(const life_identity_t* expected, bool authorized,
                            life_snapshot_fn snapshot, life_signal_fn signal_fn,
                            life_snapshot_t* out, int* signal_error) {
    life_snapshot_t local;
    if (!out) out = &local;
    unknown_snapshot(out, "stop_denied");
    if (signal_error) *signal_error = 0;
    pthread_mutex_lock(&s_mutex);
    const char* denied = !authorized ? "local_authorization_required" :
        !lifecycle_identity_equal(expected, &s_identity) ? "identity_mismatch_or_unknown" :
        s_identity.process_model != LIFE_PROCESS_DEDICATED ? "dedicated_process_not_proven" :
        s_state != LIFE_RUNNING ? "already_stopping" :
        s_operations ? "operations_busy" : !snapshot || !signal_fn ? "adapter_unavailable" : NULL;
    if (denied) {
        snprintf(out->reason, sizeof(out->reason), "%s", denied);
        out->operations = s_operations > INT_MAX ? INT_MAX : (int)s_operations;
        pthread_mutex_unlock(&s_mutex);
        return false;
    }
    s_state = LIFE_RESERVING;
    int64_t pid = s_identity.pid;
    pthread_mutex_unlock(&s_mutex);

    // The callback is read-only. The reserved state prevents every new outer
    // admission without holding the core mutex across subsystem locks.
    bool clear = snapshot(out);
    out->reason[sizeof(out->reason) - 1] = '\0';
    clear = clear && snapshot_clear(out);
    pthread_mutex_lock(&s_mutex);
    if (!clear) {
        s_state = LIFE_RUNNING;
        if (!out->reason[0]) snprintf(out->reason, sizeof(out->reason), "not_quiescent");
        pthread_mutex_unlock(&s_mutex);
        return false;
    }
    s_state = LIFE_STOP_ACCEPTED;
    pthread_mutex_unlock(&s_mutex);
    errno = 0;
    int rc = signal_fn(pid, SIGTERM);
    int error = rc ? (errno ? errno : EIO) : 0;
    pthread_mutex_lock(&s_mutex);
    s_state = rc ? LIFE_SIGNAL_ERROR : LIFE_SIGNAL_SENT;
    pthread_mutex_unlock(&s_mutex);
    if (signal_error) *signal_error = error;
    snprintf(out->reason, sizeof(out->reason), "%s", rc ? "signal_error_frozen" : "signal_sent");
    return rc == 0;
}

life_exit_t lifecycle_verify(const life_identity_t* original, bool query_ok, bool present,
                            const life_identity_t* now) {
    if (!lifecycle_identity_valid(original) || !query_ok ||
        original->process_model != LIFE_PROCESS_DEDICATED) return LIFE_EXIT_UNKNOWN;
    if (!present) return LIFE_EXITED;
    if (!now || !now->kernel_identity_known || now->pid != original->pid ||
        now->start_sec <= 0 || now->start_usec < 0 || now->start_usec >= 1000000)
        return LIFE_EXIT_UNKNOWN;
    return now->start_sec == original->start_sec && now->start_usec == original->start_usec ?
        LIFE_STILL_RUNNING : LIFE_PID_REUSED;
}

const char* lifecycle_exit_name(life_exit_t result) {
    switch (result) {
    case LIFE_EXITED: return "INSTANCE EXITED";
    case LIFE_PID_REUSED: return "PID REUSED";
    case LIFE_STILL_RUNNING: return "PROCESS STILL RUNNING";
    default: return "UNKNOWN";
    }
}
