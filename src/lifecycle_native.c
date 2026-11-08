// Native adapter. Compile-only offline validation must never start this server.
#include "lifecycle.h"
#include "lifecycle_ipc.h"
#include "version.h"
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>
#if defined(__FreeBSD__)
#include <sys/sysctl.h>
#include <sys/user.h>
#endif

static pthread_mutex_t s_server_mutex=PTHREAD_MUTEX_INITIALIZER;
static pthread_t s_server_thread;
static bool s_running, s_joinable;
static int s_listener=-1, s_client=-1;
static life_snapshot_fn s_snapshot;

static bool random_bytes(void* bytes,size_t length) {
    int fd=open("/dev/urandom",O_RDONLY|O_NOFOLLOW);
    if(fd<0) return false;
    size_t done=0;
    while(done<length) {
        ssize_t n=read(fd,(unsigned char*)bytes+done,length-done);
        if(n<0 && errno==EINTR) continue;
        if(n<=0) break;
        done+=(size_t)n;
    }
    bool ok=done==length;
    if(close(fd)) ok=false;
    return ok;
}

bool lifecycle_native_query(int64_t pid,bool* present,life_identity_t* out) {
    if(present) *present=false;
    if(out) memset(out,0,sizeof(*out));
    if(!present || !out || pid<=1 || pid>INT_MAX) return false;
#if defined(__FreeBSD__)
    int mib[4]={CTL_KERN,KERN_PROC,KERN_PROC_PID,(int)pid};
    struct kinfo_proc info; memset(&info,0,sizeof(info));
    size_t bytes=sizeof(info);
    if(sysctl(mib,4,&info,&bytes,NULL,0)) {
        // Only ESRCH denotes an absent PID. Permission/ABI failures are UNKNOWN.
        return errno==ESRCH;
    }
    if(!bytes) return true;
    if(bytes!=sizeof(info) || info.ki_structsize!=(int)sizeof(info) ||
       info.ki_pid!=pid || info.ki_start.tv_sec<=0 || info.ki_start.tv_usec<0 ||
       info.ki_start.tv_usec>=1000000) return false;
    *present=true; out->pid=info.ki_pid;
    out->start_sec=info.ki_start.tv_sec; out->start_usec=info.ki_start.tv_usec;
    out->kernel_identity_known=true;
    return true;
#else
    errno=ENOTSUP; return false;
#endif
}

bool lifecycle_native_identity(life_identity_t* out,const void* module_symbol) {
    if(!out) return false;
    bool present=false;
    bool kernel_ok=lifecycle_native_query(getpid(),&present,out);
    out->pid=getpid(); out->kernel_identity_known=kernel_ok&&present;
    snprintf(out->version,sizeof(out->version),"%s",TOSTONSYNC_VERSION);
    snprintf(out->build,sizeof(out->build),"%s",TOSTONSYNC_BUILD);
    Dl_info module; memset(&module,0,sizeof(module));
    if(module_symbol && dladdr(module_symbol,&module) && module.dli_fbase &&
       module.dli_fname && module.dli_fname[0] && strlen(module.dli_fname)<sizeof(out->module)) {
        out->module_base=(uint64_t)(uintptr_t)module.dli_fbase;
        snprintf(out->module,sizeof(out->module),"%s",module.dli_fname);
        out->module_known=true;
    }
    unsigned char nonce[32];
    if(random_bytes(nonce,sizeof(nonce)))
        for(size_t i=0;i<sizeof(nonce);++i) snprintf(out->nonce+2*i,3,"%02x",nonce[i]);
    // The pinned SDK payload.h documents payload_exit returning to a hijacked
    // carrier, but exposes no dedicated-process proof. Its private CRT stack
    // backup is not a supported ABI. Own dladdr identity or a process/thread
    // name alone cannot prove ownership of the whole process. Stop stays blocked.
    out->process_model=LIFE_PROCESS_UNKNOWN;
    return lifecycle_identity_valid(out);
}

// BEGIN lifecycle reservation: independent of kernel/process identity and IPC.
static int s_reservation_fd=-1;
static bool s_reservation_owned, s_reservation_close_uncertain;
static dev_t s_socket_dev;
static ino_t s_socket_ino;

static void reservation_diagnostic(life_reservation_diagnostic_t* out,
        const char* stage,const char* operation,const char* reason,
        bool error_known,int error) {
    if(!out) return;
    snprintf(out->stage,sizeof(out->stage),"%s",stage);
    snprintf(out->operation,sizeof(out->operation),"%s",operation);
    snprintf(out->reason,sizeof(out->reason),"%s",reason);
    out->error_known=error_known; out->error=error_known?error:0;
}

static bool reservation_directory(const char* path,bool create,
        life_reservation_diagnostic_t* out) {
    if(out) snprintf(out->path,sizeof(out->path),"%s",path);
    if(create && mkdir(path,0700)) {
        int error=errno;
        if(error!=EEXIST) {
            reservation_diagnostic(out,"RESERVATION_PARENT_CREATE","mkdir",
                    "reservation_parent_unavailable",true,error);
            return false;
        }
    }
    struct stat st;
    if(lstat(path,&st)) {
        int error=errno;
        reservation_diagnostic(out,"RESERVATION_PARENT_LSTAT","lstat",
                error==ENOENT?"reservation_parent_missing":"reservation_parent_unknown",true,error);
        return false;
    }
    // Platform /data is not private. Cooperative modern instances do not rename
    // or replace this namespace; hostile equivalent-privilege payloads are out
    // of scope. All owned descendants retain their strict permission checks.
    bool platform_parent=!strcmp(path,"/data");
    if(!S_ISDIR(st.st_mode) || st.st_uid!=geteuid() || (!platform_parent && (st.st_mode&022)) ||
       (create && (st.st_mode&077))) {
        reservation_diagnostic(out,"RESERVATION_PARENT_SECURITY","lstat",
                "reservation_parent_unsafe",false,0);
        return false;
    }
    char canonical[1024];
    if(!realpath(path,canonical)) {
        int error=errno;
        reservation_diagnostic(out,"RESERVATION_PARENT_CANONICAL","realpath",
                "reservation_parent_unknown",true,error);
        return false;
    }
    if(strcmp(path,canonical)) {
        reservation_diagnostic(out,"RESERVATION_PARENT_CANONICAL","realpath",
                "reservation_parent_unsafe",false,0);
        return false;
    }
    if(out && !strcmp(path,LIFE_IPC_DIRECTORY)) {
        out->bind_observation.filesystem_device_known=true;
        out->bind_observation.filesystem_device=(uint64_t)st.st_dev;
    }
    return true;
}

static void observe_bind_context(life_reservation_diagnostic_t* out) {
    if(!out) return;
    life_bind_observation_t* observation=&out->bind_observation;
    Dl_info provider; memset(&provider,0,sizeof(provider));
    observation->provider_called=true;
    observation->provider_result=dladdr((const void*)(uintptr_t)&bind,&provider);
    if(observation->provider_result && provider.dli_fname && provider.dli_fname[0]) {
        size_t length=strnlen(provider.dli_fname,sizeof(observation->provider_module));
        if(length<sizeof(observation->provider_module)) {
            const char* module=strrchr(provider.dli_fname,'/');
            module=module?module+1:provider.dli_fname;
            if(module[0]) {
                memcpy(observation->provider_module,module,strlen(module)+1);
                observation->provider_known=true;
            }
        }
    }
    struct statfs filesystem; memset(&filesystem,0,sizeof(filesystem));
    observation->filesystem_called=true;
    observation->filesystem_result=statfs(LIFE_IPC_DIRECTORY,&filesystem);
    // SDK v0.43 statfs is a raw syscall wrapper: it does not set errno.
    // Never attribute a residual errno to it or parse unsuccessful output.
    if(observation->filesystem_result!=0) return;
#if defined(__FreeBSD__)
    observation->filesystem_version_known=true;
    observation->filesystem_version=filesystem.f_version;
    observation->filesystem_expected_version=STATFS_VERSION;
    observation->filesystem_abi_match=filesystem.f_version==STATFS_VERSION;
    if(filesystem.f_version!=STATFS_VERSION) return;
#endif
    size_t length=strnlen(filesystem.f_fstypename,sizeof(filesystem.f_fstypename));
    if(!length || length==sizeof(filesystem.f_fstypename) ||
       length>=sizeof(observation->filesystem_name)) return;
    memcpy(observation->filesystem_name,filesystem.f_fstypename,length+1);
    observation->filesystem_type=(uint64_t)filesystem.f_type;
    observation->filesystem_flags=(uint64_t)filesystem.f_flags;
    observation->filesystem_known=true;
}

static bool own_socket(void) {
    struct stat st;
    return s_reservation_owned && !lstat(LIFE_IPC_SOCKET,&st) && S_ISSOCK(st.st_mode) &&
        st.st_uid==geteuid() && st.st_dev==s_socket_dev && st.st_ino==s_socket_ino;
}

static bool reservation_release_locked(void) {
    // An active IPC thread still depends on this descriptor. No early release.
    if(s_joinable || lifecycle_operations()!=0) { errno=EBUSY; return false; }
    if(s_reservation_close_uncertain) { errno=EIO; return false; }
    bool ok=true;
    if(s_reservation_fd>=0 && close(s_reservation_fd)) {
        // Descriptor state after a close error is not demonstrable. Keep the
        // pathname barrier; never retry close or unlink on this uncertainty.
        s_reservation_fd=-1; s_reservation_close_uncertain=true; return false;
    }
    s_reservation_fd=-1;
    if(s_reservation_owned) {
        // Do not unlink a stale/replaced/missing object, even on shutdown.
        if(!own_socket() || unlink(LIFE_IPC_SOCKET)) ok=false;
    }
    s_reservation_owned=false; s_socket_dev=0; s_socket_ino=0;
    return ok;
}

bool lifecycle_reservation_acquire(life_reservation_diagnostic_t* out) {
    if(out) {
        memset(out,0,sizeof(*out));
        snprintf(out->path,sizeof(out->path),"%s",LIFE_IPC_SOCKET);
    }
    pthread_mutex_lock(&s_server_mutex);
    if(s_reservation_fd>=0 || s_reservation_owned || s_reservation_close_uncertain || s_joinable) {
        reservation_diagnostic(out,"RESERVATION_LOCAL_STATE","reserve",
                "reservation_already_held",false,0);
        pthread_mutex_unlock(&s_server_mutex); return false;
    }
    // Never create the canonical state parent: doing so could bypass an existing
    // /data/savesync migration. Missing/ambiguous parents require separate setup.
    if(!reservation_directory("/data",false,out) ||
       !reservation_directory("/data/tostonsync",false,out) ||
       !reservation_directory(LIFE_IPC_DIRECTORY,true,out)) {
        pthread_mutex_unlock(&s_server_mutex); return false;
    }
    if(out) snprintf(out->path,sizeof(out->path),"%s",LIFE_IPC_SOCKET);
    struct stat existing;
    if(!lstat(LIFE_IPC_SOCKET,&existing)) {
        if(out) { out->path_present=true; out->path_present_known=true; }
        reservation_diagnostic(out,"RESERVATION_SOCKET_LSTAT","lstat",
                "reservation_path_present",false,0);
        // Presence is not a live peer, generation or ownership proof.
        pthread_mutex_unlock(&s_server_mutex); return false;
    }
    int error=errno;
    if(error!=ENOENT) {
        reservation_diagnostic(out,"RESERVATION_SOCKET_LSTAT","lstat",
                "reservation_path_unknown",true,error);
        pthread_mutex_unlock(&s_server_mutex); return false;
    }
    if(out) { out->path_present=false; out->path_present_known=true; }
    int fd=socket(AF_UNIX,SOCK_STREAM,0);
    error=fd<0?errno:0;
    if(out) {
        out->bind_observation.socket_called=true;
        out->bind_observation.socket_result=fd;
        out->bind_observation.socket_error_known=fd<0;
        out->bind_observation.socket_error=error;
    }
    if(fd<0) {
        reservation_diagnostic(out,"RESERVATION_SOCKET_CREATE","socket",
                "reservation_unavailable",true,error);
        pthread_mutex_unlock(&s_server_mutex); return false;
    }
    if(fd>=FD_SETSIZE) {
        close(fd);
        reservation_diagnostic(out,"RESERVATION_SOCKET_DESCRIPTOR","descriptor_limit",
                "reservation_descriptor_limit",false,0);
        pthread_mutex_unlock(&s_server_mutex); return false;
    }
    int flags=fcntl(fd,F_GETFL);
    if(flags<0 || fcntl(fd,F_SETFL,flags|O_NONBLOCK)) {
        error=errno; close(fd);
        reservation_diagnostic(out,"RESERVATION_SOCKET_FLAGS",
                flags<0?"fcntl_getfl":"fcntl_setfl","reservation_unavailable",true,error);
        pthread_mutex_unlock(&s_server_mutex); return false;
    }
    struct sockaddr_un address; memset(&address,0,sizeof(address));
    address.sun_family=AF_UNIX;
#if defined(__FreeBSD__)
    address.sun_len=sizeof(address);
#endif
    if(strlen(LIFE_IPC_SOCKET)>=sizeof(address.sun_path)) {
        close(fd);
        reservation_diagnostic(out,"RESERVATION_SOCKET_PATH","socket_path",
                "reservation_path_unknown",false,0);
        pthread_mutex_unlock(&s_server_mutex); return false;
    }
    snprintf(address.sun_path,sizeof(address.sun_path),"%s",LIFE_IPC_SOCKET);
    if(out) {
        out->bind_observation.sockaddr_known=true;
        out->bind_observation.sockaddr_family=address.sun_family;
        out->bind_observation.sockaddr_supplied_length=sizeof(address);
        out->bind_observation.pathname_length=strlen(address.sun_path);
    }
    observe_bind_context(out);
    // Atomic bind, not the preceding lstat, establishes exclusive admission.
    // No SO_REUSE* and no unlink of a pathname owned by another generation.
    int bind_result=bind(fd,(struct sockaddr*)&address,sizeof(address));
    error=bind_result?errno:0;
    if(out) {
        out->bind_observation.bind_called=true;
        out->bind_observation.bind_result=bind_result;
        out->bind_observation.bind_error_known=bind_result!=0;
        out->bind_observation.bind_error=error;
    }
    if(bind_result) {
        close(fd);
        if(out && error==EADDRINUSE) { out->path_present=true; out->path_present_known=true; }
        reservation_diagnostic(out,"RESERVATION_SOCKET_BIND","bind",
                error==EADDRINUSE?"reservation_path_present":"reservation_bind_failed",true,error);
        pthread_mutex_unlock(&s_server_mutex); return false;
    }
    s_reservation_fd=fd;
    struct stat st;
    if(lstat(LIFE_IPC_SOCKET,&st)) {
        error=errno; close(fd); s_reservation_fd=-1;
        reservation_diagnostic(out,"RESERVATION_BOUND_LSTAT","lstat",
                "reservation_ownership_unknown",true,error);
        pthread_mutex_unlock(&s_server_mutex); return false;
    }
    if(!S_ISSOCK(st.st_mode) || st.st_uid!=geteuid()) {
        close(fd); s_reservation_fd=-1;
        reservation_diagnostic(out,"RESERVATION_BOUND_SECURITY","lstat",
                "reservation_ownership_unknown",false,0);
        pthread_mutex_unlock(&s_server_mutex); return false;
    }
    s_socket_dev=st.st_dev; s_socket_ino=st.st_ino; s_reservation_owned=true;
    if(chmod(LIFE_IPC_SOCKET,0600)) {
        error=errno; reservation_release_locked();
        reservation_diagnostic(out,"RESERVATION_SOCKET_MODE","chmod",
                "reservation_mode_failed",true,error);
        pthread_mutex_unlock(&s_server_mutex); return false;
    }
    if(!own_socket()) {
        reservation_release_locked();
        reservation_diagnostic(out,"RESERVATION_BOUND_RECHECK","lstat",
                "reservation_ownership_unknown",false,0);
        pthread_mutex_unlock(&s_server_mutex); return false;
    }
    if(out) { out->path_present=true; out->path_present_known=true; out->ownership_known=true; }
    reservation_diagnostic(out,"RESERVATION_ACQUIRED","bind",
            "reservation_acquired",false,0);
    pthread_mutex_unlock(&s_server_mutex); return true;
}

bool lifecycle_reservation_release(void) {
    pthread_mutex_lock(&s_server_mutex);
    bool ok=reservation_release_locked();
    pthread_mutex_unlock(&s_server_mutex); return ok;
}
// END lifecycle reservation

static int self_sigterm(int64_t pid,int signal_number) {
    life_identity_t original,now; bool present=false;
    lifecycle_identity(&original);
    if(pid!=getpid() || signal_number!=SIGTERM || !lifecycle_native_query(pid,&present,&now) ||
       lifecycle_verify(&original,true,present,&now)!=LIFE_STILL_RUNNING) {
        errno=EPERM; return -1;
    }
    return kill(getpid(),SIGTERM);
}

static bool request_only(const life_frame_t* r) {
    if(r->accepted || r->state || r->signal_error || r->jobs || r->queued || r->operations ||
       r->import_work || r->recovery || r->mounts || r->gate || r->checkpoint) return false;
    for(size_t i=0;i<sizeof(r->reason);++i) if(r->reason[i]) return false;
    return r->command==LIFE_IPC_INSPECT || r->command==LIFE_IPC_STOP;
}

static void handle_client(int fd) {
    if(!life_ipc_timeout(fd)) return;
    life_frame_t hello,request,result;
    life_identity_t identity,expected;
    life_snapshot_t snapshot;
    life_frame_init(&hello,LIFE_IPC_HELLO);
    lifecycle_inspect(s_snapshot,&identity,&snapshot);
    life_wire_pack(&hello.identity,&identity); life_frame_snapshot(&hello,&snapshot);
    hello.state=lifecycle_state();
    if(!random_bytes(hello.challenge,sizeof(hello.challenge)) || !life_ipc_send(fd,&hello)) return;
    int64_t peer=-1;
    if(!life_ipc_receive(fd,&request,&peer) || !request_only(&request) ||
       memcmp(request.challenge,hello.challenge,sizeof(hello.challenge)) ||
       !life_wire_unpack(&expected,&request.identity) ||
       !lifecycle_identity_equal(&identity,&expected)) return;
    life_identity_t peer_now; bool peer_present=false;
    if(peer==getpid() || !lifecycle_native_query(peer,&peer_present,&peer_now) || !peer_present) return;
    // This challenge is local to this socket connection, consumed exactly once.
    memset(hello.challenge,0,sizeof(hello.challenge));
    life_frame_init(&result,LIFE_IPC_RESULT); life_wire_pack(&result.identity,&identity);
    if(request.command==LIFE_IPC_INSPECT) {
        result.accepted=lifecycle_inspect(s_snapshot,NULL,&snapshot);
        life_frame_snapshot(&result,&snapshot); result.state=lifecycle_state();
        life_ipc_send(fd,&result); return;
    }
    int error=0;
    bool stopped=lifecycle_request_stop(&expected,true,s_snapshot,self_sigterm,&snapshot,&error);
    life_frame_snapshot(&result,&snapshot); result.accepted=stopped;
    result.state=lifecycle_state(); result.signal_error=error;
    // The daemon's SIGTERM handler returns to this thread. Main teardown joins
    // it before closing an approved connection, so no early acceptance can
    // conceal a failed signal. The result remains separate from kernel exit proof.
    life_ipc_send(fd,&result);
}

static void* serve(void* unused) {
    (void)unused;
    for(;;) {
        pthread_mutex_lock(&s_server_mutex);
        int fd=s_listener; bool running=s_running;
        pthread_mutex_unlock(&s_server_mutex);
        if(!running || fd<0) break;
        fd_set set; FD_ZERO(&set); FD_SET(fd,&set); struct timeval timeout={1,0};
        int ready=select(fd+1,&set,NULL,NULL,&timeout);
        if(ready<0) { if(errno==EINTR) continue; break; }
        if(!ready) continue;
        int client=accept(fd,NULL,NULL);
        if(client<0) {
            if(errno==EINTR || errno==EAGAIN || errno==EWOULDBLOCK) continue;
            break;
        }
        // BSD accept flag inheritance must not change the existing blocking,
        // timeout-bounded lifecycle frame protocol on the accepted connection.
        int flags=fcntl(client,F_GETFL);
        if(flags<0 || fcntl(client,F_SETFL,flags&~O_NONBLOCK)) { close(client); continue; }
        pthread_mutex_lock(&s_server_mutex);
        if(!s_running) { pthread_mutex_unlock(&s_server_mutex); close(client); break; }
        s_client=client; pthread_mutex_unlock(&s_server_mutex);
        handle_client(client);
        pthread_mutex_lock(&s_server_mutex);
        s_client=-1; pthread_mutex_unlock(&s_server_mutex); close(client);
    }
    return NULL;
}

bool lifecycle_server_start(life_snapshot_fn snapshot,const void* module_symbol) {
#if !defined(__FreeBSD__) || !defined(SCM_CREDS)
    (void)snapshot;(void)module_symbol; errno=ENOTSUP; return false;
#else
    pthread_mutex_lock(&s_server_mutex);
    if(s_joinable || !snapshot || s_reservation_fd<0 || !own_socket()) {
        pthread_mutex_unlock(&s_server_mutex); return false;
    }
    life_identity_t identity;
    if(!lifecycle_native_identity(&identity,module_symbol)) {
        pthread_mutex_unlock(&s_server_mutex); return false;
    }
    int fd=s_reservation_fd;
    if(listen(fd,4)) { pthread_mutex_unlock(&s_server_mutex); return false; }
    lifecycle_init(&identity); s_snapshot=snapshot; s_listener=fd; s_running=true;
    if(pthread_create(&s_server_thread,NULL,serve,NULL)) {
        s_listener=-1; s_running=false;
        pthread_mutex_unlock(&s_server_mutex); return false;
    }
    s_joinable=true; pthread_mutex_unlock(&s_server_mutex); return true;
#endif
}

void lifecycle_server_stop(void) {
    pthread_mutex_lock(&s_server_mutex);
    if(!s_joinable) { pthread_mutex_unlock(&s_server_mutex); return; }
    s_running=false;
    // The accept loop checks s_running at most one second later. Do not close
    // or shutdown the reserved listener while operational teardown still runs.
    life_state_t state=lifecycle_state();
    if(s_client>=0 && state!=LIFE_STOP_ACCEPTED && state!=LIFE_SIGNAL_SENT && state!=LIFE_SIGNAL_ERROR)
        shutdown(s_client,SHUT_RDWR);
    pthread_t thread=s_server_thread;
    pthread_mutex_unlock(&s_server_mutex);
    if(pthread_equal(thread,pthread_self())) return;
    int error=pthread_join(thread,NULL);
    if(error) { errno=error; return; }
    pthread_mutex_lock(&s_server_mutex);
    s_listener=-1; s_joinable=false;
    pthread_mutex_unlock(&s_server_mutex);
}
