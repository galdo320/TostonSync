#!/usr/bin/env python3
"""OFFLINE ONLY lifecycle authority tests. No PS5, sockets, process queries or signals."""
import hashlib
import copy
import importlib.util
import json
import os
from pathlib import Path
import re
import shlex
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
PROOF = ROOT / "build/test/lifecycle-proof.json"
SCENARIOS = ("identities", "blockers", "admission", "signal-error", "races", "verify", "snapshots", "wait",
             "watcher", "helper", "native-denials", "native-unknown", "native-busy", "native-stop", "native-error", "native-disappeared")
TESTED_SOURCES = ("src/lifecycle.c", "src/lifecycle.h", "src/lifecycle_ipc.h", "src/lifecycle_native.c",
                  "src/import_session.c", "src/import_session.h", "src/savemount.c", "src/watcher.c",
                  "src/httpd.c", "src/main.c", "src/version.h", "tools/lifecycle_helper.c",
                  "tools/lifecycle_identity.py", "tests/check_lifecycle.py", "tests/lifecycle_harness.c")


def source_hashes():
    return {name: hashlib.sha256((ROOT / name).read_bytes()).hexdigest() for name in TESTED_SOURCES}


def function(source, name):
    """Copy a production function verbatim; skip prototypes and lexical braces."""
    pattern = re.compile(r"^(?:static\s+)?(?:inline\s+)?(?:const\s+)?[A-Za-z_]\w*(?:\s*\*)?\s+" +
                         re.escape(name) + r"\s*\(", re.M)
    for match in pattern.finditer(source):
        start = match.start()
        opening = source.find("{", match.end())
        if opening < 0 or ";" in source[match.end():opening]:
            continue
        depth, quote, comment, escaped = 0, None, None, False
        i = opening
        while i < len(source):
            char, following = source[i], source[i:i + 2]
            if comment == "line":
                if char == "\n":
                    comment = None
            elif comment == "block":
                if following == "*/":
                    comment = None
                    i += 1
            elif quote:
                if escaped:
                    escaped = False
                elif char == "\\":
                    escaped = True
                elif char == quote:
                    quote = None
            elif following in ("//", "/*"):
                comment = "line" if following == "//" else "block"
                i += 1
            elif char in ("'", '"'):
                quote = char
            elif char == "{":
                depth += 1
            elif char == "}":
                depth -= 1
                if not depth:
                    return source[start:i + 1]
            i += 1
    raise AssertionError(f"production function missing: {name}")


def observation_header():
    imports = (ROOT / "src/import_session.c").read_text()
    mounts = (ROOT / "src/savemount.c").read_text()
    imported = function(imports, "import_session_lifecycle_snapshot")
    mounted = function(mounts, "savemount_lifecycle_snapshot")
    for body in (imported, mounted):
        for forbidden in ("expire_abandoned", "persist_session", "clear_session", "unlink(",
                          "rename(", "fopen(", "open(", "write(", "cleanup", "current("):
            assert forbidden not in body, ("snapshot mutates", forbidden)
    return r'''
#include "import_session.h"
#include <stdatomic.h>
static pthread_mutex_t s_lock = PTHREAD_MUTEX_INITIALIZER;
static import_session_info_t s_session;
static char s_state_path[512];
static bool s_checkpoint_uncertain, s_preserved_uncertain;
static atomic_uint s_lifecycle_mounts;
static atomic_bool s_lifecycle_mount_uncertain;
static pthread_mutex_t s_mount_lock = PTHREAD_MUTEX_INITIALIZER;
''' + imported + "\n" + mounted + r'''
static void production_observation_checks(void) {
    memset(&s_session, 0, sizeof(s_session));
    memset(s_state_path, 0, sizeof(s_state_path));
    assert(import_session_lifecycle_snapshot() == LIFE_UNKNOWN);
    snprintf(s_state_path, sizeof(s_state_path), "/synthetic/import.session");
    snprintf(s_session.id, sizeof(s_session.id), "expired-but-retained");
    snprintf(s_session.path, sizeof(s_session.path), "/synthetic/RAW.zip");
    snprintf(s_session.portable_path, sizeof(s_session.portable_path), "/synthetic/portable.zip");
    s_session.updated_unix = 1; // Snapshot must not trigger ordinary expiry.
    for (int state = IMPORT_IDLE; state <= IMPORT_RECOVERING; state++) {
        s_session.state = (import_state_t)state;
        import_session_info_t before = s_session;
        life_check_t expected = state == IMPORT_IDLE || state == IMPORT_READY ? LIFE_CLEAR :
            state == IMPORT_FAILED ? LIFE_UNKNOWN : LIFE_BUSY;
        assert(import_session_lifecycle_snapshot() == expected);
        assert(!memcmp(&before, &s_session, sizeof(before)));
    }
    s_session.state = (import_state_t)999;
    assert(import_session_lifecycle_snapshot() == LIFE_UNKNOWN);
    s_session.state = IMPORT_READY;
    s_checkpoint_uncertain = true;
    assert(import_session_lifecycle_snapshot() == LIFE_UNKNOWN);
    s_checkpoint_uncertain = false; s_preserved_uncertain = true;
    assert(import_session_lifecycle_snapshot() == LIFE_UNKNOWN);
    s_preserved_uncertain = false;
    pthread_mutex_lock(&s_lock);
    assert(import_session_lifecycle_snapshot() == LIFE_BUSY);
    pthread_mutex_unlock(&s_lock);
    assert(import_session_lifecycle_snapshot() == LIFE_CLEAR);
    atomic_store(&s_lifecycle_mounts, 0);
    atomic_store(&s_lifecycle_mount_uncertain, false);
    assert(savemount_lifecycle_snapshot() == LIFE_CLEAR);
    atomic_store(&s_lifecycle_mounts, 2);
    assert(savemount_lifecycle_snapshot() == LIFE_BUSY);
    atomic_store(&s_lifecycle_mount_uncertain, true);
    assert(savemount_lifecycle_snapshot() == LIFE_UNKNOWN);
    atomic_store(&s_lifecycle_mounts, 0);
    assert(savemount_lifecycle_snapshot() == LIFE_UNKNOWN);
    atomic_store(&s_lifecycle_mount_uncertain, false);
    pthread_mutex_lock(&s_mount_lock);
    assert(savemount_lifecycle_snapshot() == LIFE_BUSY);
    pthread_mutex_unlock(&s_mount_lock);
}
'''


def protected_fixture(directory):
    # Synthetic files only; no real import, configuration or savedata is opened.
    paths = ("imports/RAW.zip", "imports/portable.zip", "imports/import.session",
             "preserved/historical.record", "jobs/retry.synthetic", "jobs/backup.state",
             "config.json", "savedata/image.sdimg", "savedata/sealed.key")
    for index, name in enumerate(paths):
        path = directory / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(bytes((index, 0, 255, 17)) * (113 + index))
        path.chmod(0o400)


def fingerprints(directory):
    result = {}
    for path in sorted(directory.rglob("*")):
        if path.is_file():
            metadata = path.stat()
            result[str(path.relative_to(directory))] = {
                "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
                "size_bytes": metadata.st_size, "mode": oct(metadata.st_mode),
                "inode": metadata.st_ino, "mtime_ns": metadata.st_mtime_ns,
                "ctime_ns": metadata.st_ctime_ns,
            }
    return result


def native_header():
    native = (ROOT / "src/lifecycle_native.c").read_text()
    functions = "\n".join(function(native, name) for name in
                            ("self_sigterm", "request_only", "handle_client"))
    return r'''
static life_snapshot_fn s_snapshot = snapshot;
static life_frame_t native_sent[4];
static unsigned native_sends, native_mutation;
static int64_t native_peer = 99;
static bool native_query_ok = true, native_present = true;
static pid_t native_getpid(void) { return (pid_t)own.pid; }
static bool native_timeout(int fd) { assert(fd == 7); return true; }
static bool native_random(void* bytes, size_t size) { memset(bytes, 0x55, size); return true; }
static bool native_query(int64_t pid, bool* present, life_identity_t* out) {
    *out = own; out->pid = pid; *present = pid == own.pid ? native_present : true;
    return pid == own.pid ? native_query_ok : true;
}
static bool native_send(int fd, const life_frame_t* frame) {
    assert(fd == 7 && native_sends < 4);
    native_sent[native_sends++] = *frame;
    return true;
}
static bool native_receive(int fd, life_frame_t* frame, int64_t* peer) {
    assert(fd == 7 && native_sends == 1);
    life_frame_init(frame, native_mutation == 20 ? LIFE_IPC_INSPECT : LIFE_IPC_STOP);
    life_wire_pack(&frame->identity, &own);
    memcpy(frame->challenge, native_sent[0].challenge, sizeof(frame->challenge));
    *peer = native_peer;
    switch (native_mutation) {
    case 1: frame->challenge[0]++; break;
    case 2: frame->identity.nonce[0] = 'b'; break; // restarted launch nonce
    case 3: frame->identity.start_usec++; break; // PID reused before request
    case 4: frame->identity.version[0] = 'x'; break;
    case 5: frame->identity.module_known = 0; break;
    case 6: frame->accepted = 1; break;
    case 7: frame->jobs = 1; break;
    case 8: frame->identity.reserved = 1; break;
    case 9: frame->command = LIFE_IPC_VERIFY; break;
    case 10: frame->reason[0] = 'x'; break;
    default: break;
    }
    return true;
}
static int native_signal(pid_t pid, int number) {
    assert(pid == own.pid && number == SIGTERM && lifecycle_state() == LIFE_STOP_ACCEPTED);
    assert(native_sends == 1); // result is reported only after signal return
    assert(!lifecycle_operation_begin() && ++signals == 1);
    if (signal_result) errno = signal_result;
    return signal_result ? -1 : 0;
}
#define getpid native_getpid
#define lifecycle_native_query native_query
#define life_ipc_timeout native_timeout
#define random_bytes native_random
#define life_ipc_send native_send
#define life_ipc_receive native_receive
#define kill native_signal
''' + functions + r'''
#undef getpid
#undef lifecycle_native_query
#undef life_ipc_timeout
#undef random_bytes
#undef life_ipc_send
#undef life_ipc_receive
#undef kill
static void native_reset(void) {
    native_sends = native_mutation = 0; native_peer = 99;
    native_query_ok = native_present = true;
    memset(native_sent, 0, sizeof(native_sent));
}
static void production_native_checks(const char* mode) {
    reset(); native_reset();
    if (!strcmp(mode, "native-denials")) {
        for (unsigned mutation = 1; mutation <= 10; mutation++) {
            native_reset(); native_mutation = mutation;
            handle_client(7);
            assert(native_sends == 1 && signals == 0 && lifecycle_state() == LIFE_RUNNING);
        }
        native_reset(); native_peer = own.pid; handle_client(7);
        assert(native_sends == 1 && signals == 0);
        native_reset(); native_mutation = 20; handle_client(7); // inspect, never signal
        assert(native_sends == 2 && native_sent[1].accepted && signals == 0);
    } else if (!strcmp(mode, "native-unknown")) {
        own.process_model = LIFE_PROCESS_UNKNOWN; lifecycle_init(&own);
        handle_client(7);
        assert(native_sends == 2 && !native_sent[1].accepted && signals == 0);
        assert(lifecycle_state() == LIFE_RUNNING);
    } else if (!strcmp(mode, "native-busy")) {
        observed.queued = 1; handle_client(7);
        assert(native_sends == 2 && !native_sent[1].accepted && signals == 0);
        assert(lifecycle_state() == LIFE_RUNNING);
    } else if (!strcmp(mode, "native-disappeared")) {
        native_present = false; handle_client(7);
        assert(native_sends == 2 && !native_sent[1].accepted && signals == 0);
        assert(lifecycle_state() == LIFE_SIGNAL_ERROR); // no target, frozen, no retry
    } else {
        if (!strcmp(mode, "native-error")) signal_result = EPERM;
        else assert(!strcmp(mode, "native-stop"));
        handle_client(7);
        assert(signals == 1);
        if (signal_result) {
            assert(native_sends == 2 && !native_sent[1].accepted && native_sent[1].signal_error == EPERM);
            assert(lifecycle_state() == LIFE_SIGNAL_ERROR);
        } else {
            assert(native_sends == 2 && native_sent[1].accepted && native_sent[1].state == LIFE_SIGNAL_SENT);
            assert(lifecycle_state() == LIFE_SIGNAL_SENT);
        }
        assert(!lifecycle_operation_begin());
        native_sends = 0; handle_client(7); // an identical request cannot signal twice
        assert(signals == 1 && native_sends == 2 && !native_sent[1].accepted);
    }
}
'''


def claim_header():
    source = (ROOT / "src/import_session.c").read_text()
    wrappers = "\n".join(function(source, name) for name in
                           ("import_session_claim", "import_session_claim_restore_scope"))
    return r'''
// Only downstream effects are harmless hooks. The admission branches below
// are copied verbatim from the real claim APIs, not reproduced in this test.
static int claim_lock(pthread_mutex_t* mutex) { assert(mutex == &s_lock); claim_hooks++; return 0; }
static int claim_unlock(pthread_mutex_t* mutex) { assert(mutex == &s_lock); claim_hooks++; return 0; }
static bool claim_id(const char* id) { assert(id); claim_hooks++; return true; }
static bool claim_preserved_path(const char* path) { assert(path); claim_hooks++; return false; }
static const char* claim_selected_path(const import_session_info_t* info) {
    assert(info); claim_hooks++; return info->portable_path[0] ? info->portable_path : info->path;
}
static bool claim_validate_source(const import_session_info_t* info) { assert(info); claim_hooks++; return true; }
static bool claim_persist(void) { claim_hooks++; return true; }
static bool claim_scope_matches(const restore_scope_t* scope) { assert(scope); claim_hooks++; return true; }
static bool claim_scope_equal(const restore_scope_t* a, const restore_scope_t* b) {
    assert(a && b); claim_hooks++; return true;
}
#define pthread_mutex_lock claim_lock
#define pthread_mutex_unlock claim_unlock
#define id_ok claim_id
#define preserved_path_blocked_locked claim_preserved_path
#define import_session_selected_path claim_selected_path
#define import_session_validate_selected claim_validate_source
#define persist_session_locked claim_persist
#define scope_matches_session claim_scope_matches
#define restore_scope_equal claim_scope_equal
''' + wrappers + r'''
#undef pthread_mutex_lock
#undef pthread_mutex_unlock
#undef id_ok
#undef preserved_path_blocked_locked
#undef import_session_selected_path
#undef import_session_validate_selected
#undef persist_session_locked
#undef scope_matches_session
#undef restore_scope_equal
static void production_claim_checks(life_state_t expected_state) {
    assert(lifecycle_state() == expected_state && lifecycle_operations() == 0);
    memset(&s_session, 0, sizeof(s_session));
    s_session.state = IMPORT_READY;
    s_session.updated_unix = 1; // even an old READY checkpoint must remain untouched
    snprintf(s_session.id, sizeof(s_session.id), "synthetic-ready");
    snprintf(s_session.path, sizeof(s_session.path), "/synthetic/RAW.zip");
    snprintf(s_session.portable_path, sizeof(s_session.portable_path), "/synthetic/portable.zip");
    import_session_info_t before = s_session, out, untouched;
    memset(&out, 0x5a, sizeof(out)); untouched = out;
    assert(!import_session_claim("synthetic-ready", &out));
    assert(!memcmp(&before, &s_session, sizeof(before)) && !memcmp(&untouched, &out, sizeof(out)));
    assert(s_session.state == IMPORT_READY && claim_hooks == 0); claim_rejections++;
    s_session.restore_selection_required = true;
    snprintf(s_session.restore_scope.import_id, sizeof(s_session.restore_scope.import_id), "%s", s_session.id);
    restore_scope_t reviewed = s_session.restore_scope;
    before = s_session;
    assert(!import_session_claim_restore_scope(&reviewed, &out));
    assert(!memcmp(&before, &s_session, sizeof(before)) && !memcmp(&untouched, &out, sizeof(out)));
    assert(s_session.state == IMPORT_READY && claim_hooks == 0); claim_rejections++;
    assert(lifecycle_state() == expected_state && lifecycle_operations() == 0);
}
'''


def watcher_header():
    source = (ROOT / "src/watcher.c").read_text()
    title = '#include "session_saves.h"\n' + source[source.index("typedef struct {"):source.index("} title_t;") + len("} title_t;")]
    bodies = "\n".join(function(source, name) for name in
                        ("lifecycle_observe_marker", "watcher_lifecycle_snapshot"))
    for forbidden in ("config_snapshot(", "import_session_current(", "expire_", "persist_",
                      "backup_retry_load(", "backup_retry_read(", "unlink(", "rename(", "cleanup_"):
        assert forbidden not in bodies, ("watcher snapshot has effects", forbidden)
    return "#define MAX_TITLES 128\n" + title + r'''
static title_t s_titles[MAX_TITLES];
static size_t s_title_count;
static pthread_mutex_t s_q_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t s_titles_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t s_save_io_lock = PTHREAD_MUTEX_INITIALIZER;
static atomic_int s_jobs_active, s_q_depth;
static bool raw_commit_busy;
static bool raw_selected_commit_active(void) { return raw_commit_busy; }
static char s_lifecycle_state_dir[CFG_MAX_PATH], s_lifecycle_staging_dir[CFG_MAX_PATH];
static unsigned s_save_io_readers, s_save_io_writers_waiting, s_scratch_users;
static bool s_save_io_writer, s_scratch_cleaning;
static unsigned marker_calls, marker_at;
static int marker_error;
static int watcher_fake_lstat(const char* path, struct stat* st) {
    assert(path && st);
    assert(strstr(path, "restore") || strstr(path, "raw-recovery"));
    if (++marker_calls == marker_at) {
        if (marker_error) { errno = marker_error; return -1; }
        memset(st, 0, sizeof(*st)); st->st_mode = S_IFREG | 0400; return 0;
    }
    errno = ENOENT; return -1;
}
#define lstat watcher_fake_lstat
''' + bodies + r'''
#undef lstat
static void watcher_setup(void) {
    s_session.state = IMPORT_READY;
    snprintf(s_state_path, sizeof(s_state_path), "/synthetic/import.session");
    s_checkpoint_uncertain = s_preserved_uncertain = false;
    atomic_store(&s_lifecycle_mounts, 0); atomic_store(&s_lifecycle_mount_uncertain, false);
    atomic_store(&s_jobs_active, 0); atomic_store(&s_q_depth, 0);
    raw_commit_busy = false;
    s_save_io_readers = s_save_io_writers_waiting = s_scratch_users = 0;
    s_save_io_writer = s_scratch_cleaning = false;
    s_title_count = 1;
    memset(s_titles, 0, sizeof(s_titles));
    snprintf(s_titles[0].user_uid, sizeof(s_titles[0].user_uid), "12345678");
    snprintf(s_titles[0].title_id, sizeof(s_titles[0].title_id), "PPSA00001");
    s_titles[0].backup_retry_at = 99999999;
    s_titles[0].backup_retry_journal = true; // dormant durable intent is not work
    s_titles[0].backup_retry_mask = 7;
    snprintf(s_lifecycle_state_dir, sizeof(s_lifecycle_state_dir), "/synthetic/state");
    snprintf(s_lifecycle_staging_dir, sizeof(s_lifecycle_staging_dir), "/synthetic/staging");
    marker_calls = marker_at = 0; marker_error = 0;
}
static void production_watcher_checks(void) {
    reset(); watcher_setup();
    life_snapshot_t result;
    title_t before = s_titles[0];
    assert(!watcher_lifecycle_snapshot(NULL));
    assert(watcher_lifecycle_snapshot(&result));
    assert(result.jobs == 0 && result.queued == 0 && result.import_work == LIFE_CLEAR);
    assert(result.gate == LIFE_CLEAR && result.recovery == LIFE_CLEAR && result.mounts == LIFE_CLEAR);
    assert(result.checkpoint == LIFE_CLEAR && marker_calls == 13);
    assert(!memcmp(&before, &s_titles[0], sizeof(before))); // no retry scheduling
    atomic_store(&s_jobs_active, 2);
    assert(watcher_lifecycle_snapshot(&result) && result.jobs == 2);
    raw_commit_busy = true;
    assert(watcher_lifecycle_snapshot(&result) && result.jobs == 3);
    atomic_store(&s_jobs_active, 0);
    assert(watcher_lifecycle_snapshot(&result) && result.jobs == 1);
    pthread_mutex_lock(&s_q_lock);
    assert(watcher_lifecycle_snapshot(&result) && result.jobs == 1);
    assert(!strcmp(result.reason, "queue_lock_busy"));
    pthread_mutex_unlock(&s_q_lock);
    raw_commit_busy = false;
    atomic_store(&s_jobs_active, 0); atomic_store(&s_q_depth, 3);
    assert(watcher_lifecycle_snapshot(&result) && result.queued == 3);
    unsigned* counts[] = {&s_save_io_readers, &s_save_io_writers_waiting, &s_scratch_users};
    for (size_t i = 0; i < sizeof(counts)/sizeof(*counts); i++) {
        watcher_setup(); *counts[i] = 1;
        assert(watcher_lifecycle_snapshot(&result) && result.gate == LIFE_BUSY);
    }
    watcher_setup(); s_save_io_writer = true;
    assert(watcher_lifecycle_snapshot(&result) && result.gate == LIFE_BUSY);
    watcher_setup(); s_scratch_cleaning = true;
    assert(watcher_lifecycle_snapshot(&result) && result.gate == LIFE_BUSY);
    pthread_mutex_t* locks[] = {&s_q_lock, &s_titles_lock, &s_save_io_lock};
    for (size_t i = 0; i < sizeof(locks)/sizeof(*locks); i++) {
        watcher_setup(); pthread_mutex_lock(locks[i]);
        assert(watcher_lifecycle_snapshot(&result));
        assert(result.recovery == LIFE_UNKNOWN && result.import_work == LIFE_UNKNOWN);
        pthread_mutex_unlock(locks[i]);
    }
    watcher_setup(); s_title_count = MAX_TITLES + 1;
    assert(watcher_lifecycle_snapshot(&result) && result.recovery == LIFE_UNKNOWN);
    assert(!strcmp(result.reason, "title_count_unknown"));
    for (unsigned at = 1; at <= 13; at++) {
        watcher_setup(); marker_at = at;
        assert(watcher_lifecycle_snapshot(&result) && result.recovery == LIFE_BUSY);
        assert(strstr(result.reason, "recovery_marker_present"));
        watcher_setup(); marker_at = at; marker_error = EACCES;
        assert(watcher_lifecycle_snapshot(&result) && result.recovery == LIFE_UNKNOWN);
        watcher_setup(); marker_at = at; marker_error = ENOTDIR;
        assert(watcher_lifecycle_snapshot(&result) && result.recovery == LIFE_UNKNOWN);
    }
    watcher_setup(); s_lifecycle_state_dir[0] = 0;
    assert(watcher_lifecycle_snapshot(&result) && result.recovery == LIFE_UNKNOWN);
    watcher_setup(); s_session.state = IMPORT_COMMITTED;
    assert(watcher_lifecycle_snapshot(&result) && result.import_work == LIFE_BUSY && result.checkpoint == LIFE_BUSY);
    watcher_setup(); s_checkpoint_uncertain = true;
    assert(watcher_lifecycle_snapshot(&result) && result.checkpoint == LIFE_UNKNOWN);
    watcher_setup(); atomic_store(&s_lifecycle_mount_uncertain, true);
    assert(watcher_lifecycle_snapshot(&result) && result.mounts == LIFE_UNKNOWN);
}
'''


def helper_header():
    source = (ROOT / "tools/lifecycle_helper.c").read_text()
    controller = function(source, "main").replace("int main(void)", "static int helper_run(void)", 1)
    return r'''
#include <stdarg.h>
static unsigned helper_mode, helper_event, helper_sends, helper_receives, helper_queries, helper_connects;
static int64_t helper_ms;
static life_identity_t helper_approved;
static char helper_reason[192], helper_output[4096];
static bool helper_input(unsigned mode, life_identity_t* out) {
    assert(mode == helper_mode); *out = helper_approved; return helper_event != 1;
}
static int helper_connect(void) { helper_connects++; return helper_event == 2 ? -1 : 7; }
static int helper_close(int fd) { assert(fd == 7); return 0; }
static bool helper_clock(int64_t* out) { *out = helper_ms; helper_ms += 100; return true; }
static bool helper_pause(void) { return true; }
static bool helper_query(int64_t pid, bool* present, life_identity_t* out) {
    assert(pid == own.pid); *out = own; *present = true;
    helper_queries++;
    if (helper_event == 3 || (helper_receives > 1 && helper_event == 11)) *present = false;
    if (helper_event == 4) return false;
    if (helper_receives > 1 && helper_event == 12) out->start_usec++;
    if (helper_mode == LIFE_IPC_VERIFY && helper_event == 11) *present = false;
    if (helper_mode == LIFE_IPC_VERIFY && helper_event == 12) out->start_usec++;
    return true;
}
static bool helper_send(int fd, const life_frame_t* frame) {
    assert(fd == 7 && helper_receives == 1 && frame->command == helper_mode);
    life_identity_t sent; assert(life_wire_unpack(&sent, &frame->identity));
    assert(lifecycle_identity_equal(&sent, &own));
    helper_sends++; return helper_event != 8;
}
static bool helper_receive(int fd, life_frame_t* frame, int64_t* peer) {
    assert(fd == 7); helper_receives++;
    if (helper_event == 13 && helper_receives > 1) return false; // reply disappeared
    life_frame_init(frame, helper_receives == 1 ? LIFE_IPC_HELLO : LIFE_IPC_RESULT);
    life_identity_t transmitted = own;
    if (helper_event == 5) transmitted.nonce[0] = 'b';
    if (helper_event == 6) transmitted.start_usec++;
    if (helper_event == 7) transmitted.module_known = false;
    if (helper_receives > 1 && helper_event == 9) transmitted.nonce[0] = 'b';
    life_wire_pack(&frame->identity, &transmitted); *peer = own.pid;
    memset(frame->challenge, 0x55, sizeof(frame->challenge));
    frame->accepted = 1; frame->state = helper_mode == LIFE_IPC_INSPECT ? LIFE_RUNNING : LIFE_SIGNAL_SENT;
    if (helper_receives > 1 && helper_event == 10) {
        frame->accepted = 0; frame->state = LIFE_SIGNAL_ERROR;
        frame->signal_error = EPERM; snprintf(frame->reason, sizeof(frame->reason), "signal_error_frozen");
    }
    return true;
}
static int helper_blocked(const char* reason) {
    snprintf(helper_reason, sizeof(helper_reason), "%s", reason); return 1;
}
static int helper_printf(const char* format, ...) {
    size_t used = strlen(helper_output);
    va_list arguments; va_start(arguments, format);
    int written = vsnprintf(helper_output + used, sizeof(helper_output) - used, format, arguments);
    va_end(arguments); assert(written >= 0 && (size_t)written < sizeof(helper_output) - used); return written;
}
static void helper_identity_json(const life_identity_t* value) { assert(lifecycle_identity_valid(value)); }
static void helper_json_string(const char* value) { helper_printf("\"%s\"", value); }
static int helper_flush(FILE* stream) { (void)stream; return 0; }
// The detailed INSPECT production path is executed separately by
// check_lifecycle_inspect.py. Here a distinctive sentinel verifies main's
// dispatch, without pretending the sentinel is an authenticated success.
static int helper_inspect_dispatch(void) { assert(helper_mode == LIFE_IPC_INSPECT); return 77; }
#undef LIFE_HELPER_MODE
#define LIFE_HELPER_MODE helper_mode
#define identity_input helper_input
#define connect_local helper_connect
#define close helper_close
#define lifecycle_native_query helper_query
#define monotonic_ms helper_clock
#define pause_tick helper_pause
#define life_ipc_send helper_send
#define life_ipc_receive helper_receive
#define blocked helper_blocked
#define printf helper_printf
#define identity_json helper_identity_json
#define json_string helper_json_string
#define fflush helper_flush
#define inspect_instance helper_inspect_dispatch
''' + function(source, "uncertain") + "\n" + function(source, "wait_outcome") + "\n" + controller + r'''
#undef LIFE_HELPER_MODE
#undef identity_input
#undef connect_local
#undef close
#undef lifecycle_native_query
#undef monotonic_ms
#undef pause_tick
#undef life_ipc_send
#undef life_ipc_receive
#undef blocked
#undef printf
#undef identity_json
#undef json_string
#undef fflush
#undef inspect_instance
static void helper_reset(unsigned mode, unsigned event) {
    helper_mode = mode; helper_event = event; helper_approved = own;
    helper_sends = helper_receives = helper_queries = helper_connects = 0;
    helper_ms = 0; helper_reason[0] = helper_output[0] = 0;
}
static void production_helper_checks(void) {
    reset();
    // Full production controller; only stdin, transport, kernel and time are fake.
    const char* reasons[] = {"", "explicit_original_identity_input_required",
        "local_socket_unavailable_or_unsafe", "daemon_kernel_identity_unverified",
        "daemon_kernel_identity_unverified", "approved_identity_does_not_match_this_instance",
        "daemon_kernel_identity_unverified", "daemon_kernel_identity_unverified",
        "", "", ""};
    for (unsigned event = 1; event <= 10; event++) {
        helper_reset(LIFE_IPC_STOP, event);
        assert(helper_run() == 1 && !strcmp(helper_reason, reasons[event]));
        assert(helper_sends == (event >= 8 ? 1U : 0U));
        if (event == 8 || event == 9) {
            assert(strstr(helper_output, "UNKNOWN") && strstr(helper_output, "no_resend"));
            assert(helper_queries == 1);
        }
        if (event == 10) {
            assert(strstr(helper_output, "BLOCKED") && strstr(helper_output, "signal_error_frozen"));
            assert(strstr(helper_output, "\"signal_error\":1"));
            assert(helper_queries == 1); // no verify/retry after signal error
        }
    }
    helper_reset(LIFE_IPC_STOP, 11);
    assert(helper_run() == 0 && helper_sends == 1);
    assert(strstr(helper_output, "INSTANCE EXITED"));
    helper_reset(LIFE_IPC_STOP, 12);
    assert(helper_run() == 0 && helper_sends == 1 && strstr(helper_output, "PID REUSED"));
    helper_reset(LIFE_IPC_STOP, 0);
    assert(helper_run() == 1 && helper_sends == 1 && strstr(helper_output, "TIMEOUT"));
    assert(strstr(helper_output, "\"verification\":\"PROCESS STILL RUNNING\""));
    assert(strstr(helper_output, "\"outcome\":\"STOP TIMEOUT\""));
    assert(helper_ms == 30100 && helper_queries == 301); // pre-check + 30s original tuple polling
    helper_reset(LIFE_IPC_INSPECT, 0);
    assert(helper_run() == 77 && helper_sends == 0 && helper_queries == 0 && helper_connects == 0);
    helper_reset(LIFE_IPC_VERIFY, 11);
    assert(helper_run() == 0 && helper_sends == 0 && helper_connects == 0);
    helper_reset(LIFE_IPC_VERIFY, 12);
    assert(helper_run() == 0 && helper_sends == 0 && helper_connects == 0);
    helper_reset(LIFE_IPC_VERIFY, 0);
    assert(helper_run() == 1 && helper_sends == 0 && strstr(helper_output, "TIMEOUT"));
    assert(strstr(helper_output, "\"verification\":\"PROCESS STILL RUNNING\""));
    assert(strstr(helper_output, "\"outcome\":\"STOP TIMEOUT\""));
    assert(helper_ms == 30100 && helper_queries == 300 && signals == 0);
    helper_reset(LIFE_IPC_STOP, 13);
    assert(helper_run() == 1 && helper_sends == 1 && strstr(helper_output, "UNKNOWN"));
    assert(strstr(helper_output, "no_resend") && helper_queries == 1);
    for (unsigned model = LIFE_PROCESS_UNKNOWN; model <= LIFE_PROCESS_CARRIER; model += 2) {
        own.process_model = (life_process_t)model;
        helper_reset(LIFE_IPC_INSPECT, 0);
        assert(helper_run() == 77 && helper_sends == 0 && helper_queries == 0);
        helper_reset(LIFE_IPC_VERIFY, 11);
        assert(helper_run() == 1 && helper_sends == 0 && strstr(helper_output, "UNKNOWN"));
        assert(helper_queries == 1);
    }
}
'''


def admission_contracts():
    watcher = (ROOT / "src/watcher.c").read_text()
    http = (ROOT / "src/httpd.c").read_text()
    main = (ROOT / "src/main.c").read_text()
    imports = (ROOT / "src/import_session.c").read_text()
    for name in ("import_session_claim", "import_session_claim_restore_scope", "import_session_unclaim_internal",
                 "import_session_bind_restore_scope", "import_session_invalidate_restore_scope"):
        body = function(imports, name)
        assert body.index("lifecycle_operation_begin()") < body.index("pthread_mutex_lock(")
        assert body.index("lifecycle_operation_end()") > body.index("pthread_mutex_unlock(")
    assert 'return import_session_unclaim_internal(id, NULL);' in function(imports, 'import_session_unclaim')
    enqueue = function(watcher, "enqueue")
    assert enqueue.index("lifecycle_operation_begin()") < enqueue.index("enqueue_inner(")
    dequeue = function(watcher, "dequeue_blocking")
    assert dequeue.index("lifecycle_operation_begin()") < dequeue.index("s_q_head = j->next")
    assert dequeue.index("if (j)") < dequeue.index("atomic_fetch_add(&s_jobs_active")
    worker = function(watcher, "worker_main")
    assert worker.index("lifecycle_operation_end()") > max(worker.index("do_upload_job("), worker.index("do_restore_job("))
    for name in ("save_io_begin_read", "save_io_try_begin_read", "save_io_begin_write",
                 "save_io_try_begin_inspection", "scratch_begin_cleanup"):
        body = function(watcher, name)
        assert body.index("lifecycle_operation_begin()") < body.index("pthread_mutex_lock(")
    for name in ("watch_main", "trigger_main", "proc_main"):
        body = function(watcher, name)
        assert "lifecycle_operation_begin()" in body and "lifecycle_operation_end()" in body
        assert "if (!s_running) break;" in body or "if (!s_running || lifecycle_terminal()) break;" in body
    shutdown = function(watcher, "watcher_on_shutdown")
    assert shutdown.index("lifecycle_terminal()") < shutdown.index("lifecycle_operation_begin()")
    connection = function(http, "conn_thread")
    assert connection.index("lifecycle_http_operation_begin()") < connection.index("recv_request(") < connection.index("route(")
    assert "lifecycle_activity_end()" in connection and "lifecycle_http_operation_end()" in connection
    background = function(http, "restore_all_catalog_async")
    assert background.index("lifecycle_activity_begin()") < background.index("calloc(") < background.index("pthread_create(")
    accepting = function(http, "accept_loop")
    assert accepting.index("lifecycle_activity_begin()") < accepting.index("pthread_create(")
    operational = main[main.index("#endif", main.index("#if TOSTONSYNC_STARTUP_VALIDATION_ONLY")):] if "#if TOSTONSYNC_STARTUP_VALIDATION_ONLY" in main else main
    watchdog = operational[operational.index("while (!s_stop)"):operational.index("lifecycle_server_stop();")]
    assert watchdog.index("lifecycle_operation_begin()") < watchdog.index("http_client_take_drive_reconnected()")
    assert watchdog.index("lifecycle_operation_begin()") < watchdog.index("httpd_start(")
    assert "lifecycle_operation_end()" in watchdog
    route = function(http, "route")
    assert "lifecycle_request_stop" not in route and '"/api/lifecycle' not in route, "lifecycle must not be remotely exposed"
    native = (ROOT / "src/lifecycle_native.c").read_text()
    helper = (ROOT / "tools/lifecycle_helper.c").read_text()
    for forbidden in ("SIGKILL", "process_vm_", "ptrace(", "kread(", "kwrite(", "sceKernelSendNotificationRequest("):
        assert forbidden not in native + helper, forbidden
    assert "out->process_model=LIFE_PROCESS_UNKNOWN" in native
    assert "SOCK_STREAM" in native and "AF_UNIX" in native
    assert "SCM_CREDS" in (ROOT / "src/lifecycle_ipc.h").read_text()
    print("Lifecycle production admission/source contracts PASS: queue/journal, full-job scope, HTTP/claims, background leases, watchdog, no remote stop, carrier UNKNOWN")


def serializer_checks(executable, fixture):
    module_path = ROOT / "tools/lifecycle_identity.py"
    spec = importlib.util.spec_from_file_location("lifecycle_identity_offline", module_path)
    serializer = importlib.util.module_from_spec(spec)
    # execute_module may create bytecode; loading source explicitly keeps the test
    # restricted to its disposable fixture and never alters shipped tools.
    exec(compile(module_path.read_bytes(), str(module_path), "exec"), serializer.__dict__)
    version = re.search(r'#define TOSTONSYNC_VERSION "([^"]+)"',
                        (ROOT / "src/version.h").read_text()).group(1)
    report = {
        "ok": True, "state": 0, "jobs": 0, "queued": 0, "operations": 0,
        "import_work": 0, "recovery": 0, "mounts": 0, "gate": 0, "checkpoint": 0,
        "reason": "offline-synthetic",
        "identity": {"pid": 4242, "start_sec": 100, "start_usec": 12345,
                     "module_base": 0x400000, "nonce": "a" * 64,
                     "version": version, "build": "offline-synthetic-build",
                     "module": "/data/tostonsync/tostonsync.elf",
                     "kernel_identity_known": True, "module_known": True,
                     "process_model": 1}}
    comparisons = []
    for command in ("stop", "verify"):
        for model in (0, 1, 2):
            candidate = copy.deepcopy(report)
            candidate["identity"]["process_model"] = model
            # UNKNOWN observation is not approval and is never serialized as it.
            candidate["checkpoint"] = -1
            frame = serializer.serialize_inspect(candidate, command)
            native = subprocess.run([str(executable), "wire-" + command, str(model)],
                                    cwd=fixture, check=True, capture_output=True, timeout=15).stdout
            assert len(frame) == 760 and frame == native, (command, model)
            comparisons.append({"command": command, "process_model": model, "bytes": len(frame),
                                "sha256": hashlib.sha256(frame).hexdigest(), "matches_production_C_frame": True})
            values = serializer.FRAME.unpack(frame)
            assert values[3] == (2 if command == "stop" else 3)
            assert all(value == 0 for value in values[4:8])
            assert values[8] == bytes(32)
            assert values[15] == model and values[16] == 0
            assert all(value == 0 for value in values[21:29]) and values[29] == bytes(192)

    invalid = []
    for key in report:
        candidate = copy.deepcopy(report); del candidate[key]; invalid.append(candidate)
    for key in report["identity"]:
        candidate = copy.deepcopy(report); del candidate["identity"][key]; invalid.append(candidate)
    invalid += [[], None, {**report, "extra": 1}, {**report, "ok": False}, {**report, "ok": 1}]
    for field, values in {
        "state": [-1, 5, True], "jobs": [-1, 2**31, True], "queued": [-1],
        "operations": [-1], "import_work": [-2, 2, False], "recovery": [2],
        "mounts": [2], "gate": [2], "checkpoint": [2],
        "reason": ["x" * 192, "bad\0reason", 1],
    }.items():
        for value in values:
            candidate = copy.deepcopy(report); candidate[field] = value; invalid.append(candidate)
    for field, values in {
        "pid": [1, 2**31, True], "start_sec": [0, 2**63, True],
        "start_usec": [-1, 1000000, False], "module_base": [0, 2**64, True],
        "process_model": [-1, 3, True], "nonce": ["a" * 63, "G" * 64, "a" * 65],
        "version": ["", "x" * 32, "bad\0version", "UNKNOWN", "unknown", "UnKnOwN",
                    "1", "1.2", "1.2.", "1..3", ".1.2", "1.2.3.4", "1.2.3-beta",
                    "v1.2.3", "1.2.-3", "1.2.3 "],
        "build": ["", "x" * 64, "UNKNOWN", "unknown", "UnKnOwN"],
        "module": ["", "x" * 256, "é" * 128, "\ud800", "UNKNOWN", "unknown", "UnKnOwN"],
        "kernel_identity_known": [False, 1, "true"], "module_known": [False, 1],
    }.items():
        for value in values:
            candidate = copy.deepcopy(report); candidate["identity"][field] = value; invalid.append(candidate)
    for candidate in invalid:
        try:
            serializer.serialize_inspect(candidate, "stop")
        except (ValueError, UnicodeError):
            pass
        else:
            raise AssertionError(f"unsafe serializer input accepted: {candidate!r}")
    environment = {**os.environ, "PYTHONDONTWRITEBYTECODE": "1"}
    valid_json = json.dumps(report).encode()
    for data in (b'{"ok":true,"ok":false}', b"null", b"NaN", b"[", b" " * 8193,
                 valid_json[:-1] + b',"ok":true}'):
        rejected = subprocess.run(["python3", str(module_path), "stop"], input=data,
                                  capture_output=True, cwd=fixture, env=environment, timeout=15)
        assert rejected.returncode != 0 and rejected.stdout == b"", "partial unsafe frame emitted"
    valid_cli = subprocess.run(["python3", str(module_path), "stop"], input=valid_json,
                               capture_output=True, check=True, cwd=fixture, env=environment, timeout=15)
    assert valid_cli.stdout == serializer.serialize_inspect(report, "stop")
    print(f"Lifecycle offline serializer PASS: six complete C-frame byte comparisons; {len(invalid)} invalid reports + duplicate/NaN/truncation/oversize rejected without output")
    return {"frame_matches": comparisons, "invalid_reports_rejected": len(invalid),
            "invalid_CLI_inputs_rejected_without_output": 6, "valid_CLI_frame_matches": True}


def persist_proof(before, after, scenarios, serializer, sources, compiler, flags):
    assert len(scenarios) == 16
    assert sum(case["production_claim_rejections"] for case in scenarios) == 6
    assert sum(case["production_claim_hook_calls"] for case in scenarios) == 0
    label = "asan-ubsan" if os.environ.get("TOSTON_SANITIZERS") == "1" else "plain"
    runs = {}
    if PROOF.is_file():
        previous = json.loads(PROOF.read_text())
        if previous.get("source_sha256") == sources:
            runs = previous.get("validation_runs", {})
    runs[label] = {"status": "PASS", "scenario_count": len(scenarios),
                   "wire_frame_matches": len(serializer["frame_matches"]),
                   "compiler": compiler, "extra_compiler_flags": flags}
    proof = {
        "schema": 1, "status": "PASS", "offline_only": True,
        "scope": "Synthetic disposable fixture; production lifecycle authority with mocked native effects. No physical PS5 or game-acceptance proof.",
        "source_sha256": sources, "validation_runs": runs, "fixture_observations_run": label,
        "scenario_count": len(scenarios), "scenarios": scenarios,
        "protected_fixture": {"file_count": len(before), "before": before, "after": after,
                              "all_hashes_sizes_modes_inodes_and_times_unchanged": before == after},
        "serializer": serializer,
        "prohibited_effect_counts": {
            "real_signal_syscalls": 0, "real_native_process_queries": 0, "real_socket_opens": 0,
            "real_native_savedata_mounts": 0, "protected_fixture_mutations": 0,
            "harness_guard_violations": sum(case["guard_violations"] for case in scenarios),
        },
        "fake_SIGTERM_callbacks_total": sum(case["fake_sigterm_callbacks"] for case in scenarios),
        "production_import_claim_checks": {
            "rejected_actual_claim_API_calls": sum(case["production_claim_rejections"] for case in scenarios),
            "lock_validation_hash_persistence_hook_calls": sum(case["production_claim_hook_calls"] for case in scenarios),
            "states_checked": ["RESERVING", "SIGNAL_SENT", "SIGNAL_ERROR"],
            "READY_session_and_output_remain_byte_identical": True,
            "hook_types": ["mutex_lock", "mutex_unlock", "id_validation", "preserved_path",
                           "selected_path", "selected_source_hash_validation", "scope_match",
                           "scope_equality", "persist_checkpoint"],
        },
        "source_admission_contracts": "PASS: import claims before lock/checkpoint, enqueue before journal, dequeue before job promotion, full-job lease, HTTP before handlers, background lease, watchdog guards",
    }
    assert source_hashes() == sources, "production/test sources changed during validation"
    PROOF.parent.mkdir(parents=True, exist_ok=True)
    PROOF.write_text(json.dumps(proof, indent=2, ensure_ascii=True) + "\n")
    print(f"Lifecycle durable offline proof: {PROOF}")


def main():
    sources = source_hashes()
    admission_contracts()
    compiler = shlex.split(os.environ.get("HOST_CC", os.environ.get("CC", "cc")))
    flags = shlex.split(os.environ.get("HOST_TEST_FLAGS", ""))
    if os.environ.get("TOSTON_SANITIZERS") == "1":
        flags += ["-fsanitize=address,undefined", "-fno-omit-frame-pointer", "-g"]
    with tempfile.TemporaryDirectory(prefix="tostonsync-lifecycle-offline-") as temporary:
        temporary = Path(temporary)
        fixture = temporary / "protected"
        protected_fixture(fixture)
        before = fingerprints(fixture)
        (temporary / "lifecycle_observation.h").write_text(observation_header())
        (temporary / "lifecycle_claim_test.h").write_text(claim_header())
        (temporary / "lifecycle_native_test.h").write_text(native_header())
        (temporary / "lifecycle_watcher_test.h").write_text(watcher_header())
        (temporary / "lifecycle_helper_test.h").write_text(helper_header())
        executable = temporary / "lifecycle"
        subprocess.run([*compiler, "-std=c11", "-D_DEFAULT_SOURCE", "-Wall", "-Wextra", "-Werror",
                        "-pthread", "-DLIFE_HELPER_TEST", "-I", str(ROOT / "src"), "-include", str(ROOT / "src/jobs.h"), "-I", str(temporary), *flags,
                        str(ROOT / "src/lifecycle.c"), str(ROOT / "tests/lifecycle_harness.c"),
                        str(ROOT / "tools/lifecycle_helper.c"),
                        "-o", str(executable)], check=True, cwd=ROOT)
        scenarios = []
        for case in SCENARIOS:
            completed = subprocess.run([str(executable), case], check=True, cwd=fixture, timeout=15,
                                       text=True, capture_output=True)
            print(completed.stdout, end="")
            counts = re.search(r"guard_violations=(\d+), fake_sigterm_callbacks=(\d+), "
                               r"production_claim_rejections=(\d+), production_claim_hook_calls=(\d+)", completed.stdout)
            assert counts and int(counts[1]) == int(counts[4]) == 0 and not completed.stderr, (case, completed)
            scenarios.append({"name": case, "status": "PASS", "guard_violations": int(counts[1]),
                              "fake_sigterm_callbacks": int(counts[2]), "protected_fixture_unchanged": True,
                              "production_claim_rejections": int(counts[3]), "production_claim_hook_calls": int(counts[4])})
            assert fingerprints(fixture) == before, f"protected fixture changed in {case}"
        serializer = serializer_checks(executable, fixture)
        after = fingerprints(fixture)
        assert after == before, "protected fixture changed in wire/serializer checks"
        persist_proof(before, after, scenarios, serializer, sources, compiler, flags)
    print("Lifecycle OFFLINE ONLY: production core + pure import/mount snapshots PASS; protected RAW/portable/checkpoint/history/retry/config/savedata hashes and metadata unchanged")


if __name__ == "__main__":
    main()
