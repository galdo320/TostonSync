// Single-instance, local-only lifecycle. No savedata or import authority.
#ifndef TOSTONSYNC_LIFECYCLE_H
#define TOSTONSYNC_LIFECYCLE_H
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#define LIFECYCLE_PROTOCOL 1
#define LIFECYCLE_TIMEOUT_SECONDS 30
#define LIFECYCLE_SOCKET "/data/tostonsync/lifecycle/control.sock"
typedef enum { LIFE_UNKNOWN = -1, LIFE_CLEAR = 0, LIFE_BUSY = 1 } life_check_t;
typedef enum { LIFE_PROCESS_UNKNOWN, LIFE_PROCESS_DEDICATED, LIFE_PROCESS_CARRIER } life_process_t;
typedef struct {
    int64_t pid, start_sec, start_usec;
    uint64_t module_base;
    char nonce[65], version[32], build[64], module[256];
    bool kernel_identity_known, module_known;
    life_process_t process_model;
} life_identity_t;
typedef struct {
    int jobs, queued, operations;
    life_check_t import_work, recovery, mounts, gate, checkpoint;
    char reason[192];
} life_snapshot_t;
typedef enum { LIFE_RUNNING, LIFE_RESERVING, LIFE_STOP_ACCEPTED, LIFE_SIGNAL_SENT, LIFE_SIGNAL_ERROR } life_state_t;
typedef enum { LIFE_EXITED, LIFE_PID_REUSED, LIFE_STILL_RUNNING, LIFE_EXIT_UNKNOWN } life_exit_t;
typedef bool (*life_snapshot_fn)(life_snapshot_t* out);
typedef int (*life_signal_fn)(int64_t pid, int signal_number);
void lifecycle_init(const life_identity_t* identity);
// Transferable admission for a thread that has not started yet.
// One transferable lease for the signed-update worker; never a stop capability.
bool lifecycle_update_worker_reserve(uint64_t* ticket);
bool lifecycle_update_worker_enter(uint64_t ticket);
void lifecycle_update_worker_cancel(uint64_t ticket);
void lifecycle_update_worker_leave(void);
bool lifecycle_update_install_begin(life_snapshot_fn snapshot, life_snapshot_t* out);
void lifecycle_update_install_end(void);
bool lifecycle_activity_begin(void);
void lifecycle_activity_end(void);
bool lifecycle_operation_begin(void);
void lifecycle_operation_end(void);
// HTTP accept transfers one activity lease; these own exactly that lease plus
// the handler's outer operation. Only this context can discount its own work.
bool lifecycle_http_operation_begin(void);
void lifecycle_http_operation_end(void);
bool lifecycle_request_cooperative_stop(life_snapshot_fn snapshot, life_snapshot_t* out);
// Called only after the full accepted response was sent. No process signal.
void lifecycle_cooperative_response_sent(void);
bool lifecycle_local_stop_pending(void);
unsigned lifecycle_operations(void);
bool lifecycle_stopping(void);
life_state_t lifecycle_state(void);
void lifecycle_identity(life_identity_t* out);
bool lifecycle_identity_valid(const life_identity_t* identity);
bool lifecycle_identity_equal(const life_identity_t* a, const life_identity_t* b);
bool lifecycle_inspect(life_snapshot_fn snapshot, life_identity_t* identity, life_snapshot_t* out);
// Reservation precedes snapshot and excludes all operation admissions. No
// signal is sent until every necessary check is CLEAR and identity matches.
bool lifecycle_request_stop(const life_identity_t* expected, bool authorized,
                            life_snapshot_fn snapshot, life_signal_fn signal_fn,
                            life_snapshot_t* out, int* signal_error);
life_exit_t lifecycle_verify(const life_identity_t* original,
                            bool query_ok, bool present,
                            const life_identity_t* kernel_now);
const char* lifecycle_exit_name(life_exit_t result);

// PS5 adapter: bounded kernel queries, own-module observation and AF_UNIX IPC.
// It must never use takeover, OAuth, HTTP or inspect process memory.
typedef struct {
    bool socket_called;
    int socket_result, socket_error;
    bool socket_error_known;
    bool provider_called, provider_known;
    int provider_result;
    char provider_module[256];
    bool filesystem_called, filesystem_known, filesystem_device_known;
    int filesystem_result;
    bool filesystem_version_known, filesystem_abi_match;
    uint32_t filesystem_version, filesystem_expected_version;
    uint64_t filesystem_type, filesystem_flags, filesystem_device;
    char filesystem_name[64];
    bool sockaddr_known;
    unsigned sockaddr_family, sockaddr_supplied_length;
    size_t pathname_length;
    bool bind_called, bind_error_known;
    int bind_result, bind_error;
} life_bind_observation_t;
typedef struct {
    char stage[64], operation[32], reason[64];
    char path[256];
    int error;
    bool error_known;
    bool path_present, path_present_known;
    // Path presence cannot establish an existing instance's identity.
    bool ownership_known;
    life_bind_observation_t bind_observation;
} life_reservation_diagnostic_t;
// Preserved historical socket reservation; normal startup uses instance_lock.h.
// The canonical state parent must already exist; acquisition never migrates it.
bool lifecycle_reservation_acquire(life_reservation_diagnostic_t* out);
// Only after operational shutdown and server_stop. Never removes a replacement.
bool lifecycle_reservation_release(void);
bool lifecycle_native_identity(life_identity_t* out, const void* module_symbol);
bool lifecycle_server_start(life_snapshot_fn snapshot, const void* module_symbol);
// Quiesce authenticated IPC; retain reservation until explicit late release.
void lifecycle_server_stop(void);
bool lifecycle_native_query(int64_t pid, bool* present, life_identity_t* out);
#endif
