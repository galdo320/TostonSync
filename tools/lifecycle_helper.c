// Build three separate payloads with LIFE_HELPER_MODE=1,2,3. No default stop.
// Explicit stop/verify identity input is one bounded life_frame_t on stdin.
// The pinned SDK hello_stdio sample and prospero-deploy -i support stdin.
#include "lifecycle_ipc.h"
#include "version.h"
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/select.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <time.h>
#include <unistd.h>
#ifndef LIFE_HELPER_MODE
#define LIFE_HELPER_MODE LIFE_IPC_INSPECT
#endif

life_exit_t lifecycle_wait_exit(const life_identity_t* original, life_wait_query_fn query,
                               life_wait_clock_fn clock_now, life_wait_pause_fn pause_tick) {
    int64_t start,now,previous;
    if(!query || !clock_now || !pause_tick || !lifecycle_identity_valid(original) ||
       !clock_now(&start) || start<0) return LIFE_EXIT_UNKNOWN;
    previous=start;
    for(;;) {
        life_identity_t current; bool present=false;
        bool ok=query(original->pid,&present,&current);
        life_exit_t result=lifecycle_verify(original,ok,present,&current);
        if(result!=LIFE_STILL_RUNNING) return result;
        if(!clock_now(&now) || now<previous || now-start<0) return LIFE_EXIT_UNKNOWN;
        if(now-start>=(int64_t)LIFECYCLE_TIMEOUT_SECONDS*1000) return LIFE_STILL_RUNNING;
        previous=now;
        if(!pause_tick()) return LIFE_EXIT_UNKNOWN;
    }
}

#ifndef LIFE_HELPER_TEST
static bool monotonic_ms(int64_t* out) {
    struct timespec ts;
    if(clock_gettime(CLOCK_MONOTONIC,&ts) || ts.tv_sec<0 || ts.tv_sec>INT64_MAX/1000 ||
       ts.tv_nsec<0 || ts.tv_nsec>=1000000000) return false;
    *out=(int64_t)ts.tv_sec*1000+ts.tv_nsec/1000000;
    return true;
}
static bool pause_tick(void) {
    struct timespec delay={0,100000000};
    while(nanosleep(&delay,&delay)) if(errno!=EINTR) return false;
    return true;
}
static void json_string(const char* s) {
    putchar('"');
    for(const unsigned char* p=(const unsigned char*)s;*p;++p) {
        if(*p=='"' || *p=='\\') { putchar('\\'); putchar(*p); }
        else if(*p<32) printf("\\u%04x",*p);
        else putchar(*p);
    }
    putchar('"');
}
static void identity_json(const life_identity_t* i) {
    printf("\"identity\":{\"pid\":%lld,\"start_sec\":%lld,\"start_usec\":%lld,\"module_base\":%llu,",
           (long long)i->pid,(long long)i->start_sec,(long long)i->start_usec,(unsigned long long)i->module_base);
    printf("\"nonce\":"); json_string(i->nonce);
    printf(",\"version\":"); json_string(i->version);
    printf(",\"build\":"); json_string(i->build);
    printf(",\"module\":"); json_string(i->module);
    printf(",\"kernel_identity_known\":%s,\"module_known\":%s,\"process_model\":%u}",
           i->kernel_identity_known?"true":"false",i->module_known?"true":"false",(unsigned)i->process_model);
}
static int blocked(const char* reason) {
    printf("{\"ok\":false,\"outcome\":\"BLOCKED\",\"reason\":"); json_string(reason); printf("}\n"); fflush(stdout); return 1;
}
static int uncertain(const char* reason, const life_identity_t* original) {
    printf("{\"ok\":false,\"outcome\":\"UNKNOWN\",\"reason\":");
    json_string(reason); printf(","); identity_json(original);
    printf("}\n"); fflush(stdout); return 1;
}
static const char* wait_outcome(life_exit_t result) {
    return result==LIFE_STILL_RUNNING?"STOP TIMEOUT":lifecycle_exit_name(result);
}

static bool identity_input(unsigned mode,life_identity_t* identity) {
    life_frame_t input; memset(&input,0,sizeof(input));
    int64_t deadline,now;
    if(!monotonic_ms(&deadline)) return false;
    deadline+=3000; size_t bytes=0;
    while(bytes<sizeof(input)) {
        if(!monotonic_ms(&now) || now>=deadline) return false;
        struct timeval remaining={(deadline-now)/1000,((deadline-now)%1000)*1000};
        fd_set set; FD_ZERO(&set); FD_SET(STDIN_FILENO,&set);
        int ready=select(STDIN_FILENO+1,&set,NULL,NULL,&remaining);
        if(ready<0 && errno==EINTR) continue;
        if(ready<=0) return false;
        ssize_t n=read(STDIN_FILENO,(unsigned char*)&input+bytes,sizeof(input)-bytes);
        if(n<0 && errno==EINTR) continue;
        if(n<=0) return false;
        bytes+=(size_t)n;
    }
    if(!life_frame_valid(&input) || input.command!=mode || input.accepted || input.state ||
       input.signal_error || input.jobs || input.queued || input.operations || input.import_work ||
       input.recovery || input.mounts || input.gate || input.checkpoint) return false;
    for(size_t i=0;i<sizeof(input.challenge);++i) if(input.challenge[i]) return false;
    for(size_t i=0;i<sizeof(input.reason);++i) if(input.reason[i]) return false;
    // Bounded input must contain exactly one frame, never an appended command.
    unsigned char extra;
    fd_set set; FD_ZERO(&set); FD_SET(STDIN_FILENO,&set); struct timeval zero={0,0};
    int ready=select(STDIN_FILENO+1,&set,NULL,NULL,&zero);
    if(ready<0 || (ready>0 && read(STDIN_FILENO,&extra,1)>0)) return false;
    return life_wire_unpack(identity,&input.identity) && lifecycle_identity_valid(identity);
}

static bool protected_socket(void) {
    struct stat st;
    char path[1024];
    return realpath(LIFE_IPC_DIRECTORY,path) && !strcmp(path,LIFE_IPC_DIRECTORY) &&
        !lstat(LIFE_IPC_DIRECTORY,&st) && S_ISDIR(st.st_mode) && st.st_uid==geteuid() && !(st.st_mode&077) &&
        !lstat(LIFE_IPC_SOCKET,&st) && S_ISSOCK(st.st_mode) && st.st_uid==geteuid() && (st.st_mode&0777)==0600;
}

static int connect_local(void) {
    if(!protected_socket()) return -1;
    int fd=socket(AF_UNIX,SOCK_STREAM,0);
    if(fd<0) return -1;
    struct sockaddr_un address; memset(&address,0,sizeof(address));
    address.sun_family=AF_UNIX;
#if defined(__FreeBSD__) || defined(__APPLE__)
    address.sun_len=sizeof(address);
#endif
    snprintf(address.sun_path,sizeof(address.sun_path),"%s",LIFE_IPC_SOCKET);
    if(!life_ipc_timeout(fd) || connect(fd,(struct sockaddr*)&address,sizeof(address))) {
        close(fd); return -1;
    }
    return fd;
}

// INSPECT reporting only. This carries no authority and never repairs a path,
// adopts an identity for STOP, reads import content or changes saved state.
typedef struct {
    const char* category;
    const char* stage;
    const char* path;
    char detail[64], expected_text[96], observed_text[1024];
    bool result_known, error_known, values_numeric, stat_known;
    int64_t result, expected, observed;
    int error;
    struct stat metadata;
} life_inspect_diagnostic_t;

static const char* inspect_errno_name(int error) {
    switch(error) {
    case EPERM: return "EPERM";
    case ENOENT: return "ENOENT";
    case EINTR: return "EINTR";
    case EIO: return "EIO";
    case EBADF: return "EBADF";
    case EAGAIN: return "EAGAIN";
    case ENOMEM: return "ENOMEM";
    case EACCES: return "EACCES";
    case EFAULT: return "EFAULT";
    case ENOTDIR: return "ENOTDIR";
    case EINVAL: return "EINVAL";
    case ENFILE: return "ENFILE";
    case EMFILE: return "EMFILE";
    case EPIPE: return "EPIPE";
    case ELOOP: return "ELOOP";
    case ENAMETOOLONG: return "ENAMETOOLONG";
    case ENOSYS: return "ENOSYS";
    case ENOTSOCK: return "ENOTSOCK";
    case ENOPROTOOPT: return "ENOPROTOOPT";
    case EPROTONOSUPPORT: return "EPROTONOSUPPORT";
    case EAFNOSUPPORT: return "EAFNOSUPPORT";
    case EADDRINUSE: return "EADDRINUSE";
    case EADDRNOTAVAIL: return "EADDRNOTAVAIL";
    case ENETUNREACH: return "ENETUNREACH";
    case ECONNRESET: return "ECONNRESET";
    case ENOBUFS: return "ENOBUFS";
    case ETIMEDOUT: return "ETIMEDOUT";
    case ECONNREFUSED: return "ECONNREFUSED";
    case EHOSTUNREACH: return "EHOSTUNREACH";
    case ENOTSUP: return "ENOTSUP";
    default: return NULL; // Never guess a symbolic name for an unmapped value.
    }
}

static const char* inspect_file_type(mode_t mode) {
    if(S_ISLNK(mode)) return "symlink";
    if(S_ISDIR(mode)) return "directory";
    if(S_ISSOCK(mode)) return "socket";
    if(S_ISREG(mode)) return "regular";
    if(S_ISFIFO(mode)) return "fifo";
    if(S_ISCHR(mode)) return "character_device";
    if(S_ISBLK(mode)) return "block_device";
    return "other";
}

static bool inspect_failure(life_inspect_diagnostic_t* d,const char* category,
    const char* stage,const char* detail,const char* expected,const char* observed) {
    d->category=category; d->stage=stage;
    snprintf(d->detail,sizeof(d->detail),"%s",detail);
    snprintf(d->expected_text,sizeof(d->expected_text),"%s",expected?expected:"");
    snprintf(d->observed_text,sizeof(d->observed_text),"%s",observed?observed:"");
    d->result_known=d->error_known=d->values_numeric=false;
    return false;
}
static bool inspect_numeric_failure(life_inspect_diagnostic_t* d,const char* category,
    const char* stage,const char* detail,int64_t expected,int64_t observed) {
    inspect_failure(d,category,stage,detail,NULL,NULL);
    d->values_numeric=true; d->expected=expected; d->observed=observed;
    return false;
}
static bool inspect_syscall_failure(life_inspect_diagnostic_t* d,const char* category,
    const char* stage,const char* detail,int64_t result,int error) {
    inspect_failure(d,category,stage,detail,"system_call_success","system_call_failed");
    d->result_known=d->error_known=true; d->result=result; d->error=error;
    return false;
}
static int inspect_blocked(const life_inspect_diagnostic_t* d) {
    printf("{\"ok\":false,\"outcome\":\"BLOCKED\",\"diagnostic_schema\":1,\"helper_version\":");
    json_string(TOSTONSYNC_VERSION);
    printf(",\"reason\":"); json_string(d->category);
    printf(",\"category\":"); json_string(d->category);
    printf(",\"stage\":"); json_string(d->stage);
    printf(",\"operation\":"); json_string(d->detail);
    printf(",\"result\":"); if(d->result_known) printf("%lld",(long long)d->result); else printf("null");
    printf(",\"errno\":"); if(d->error_known) printf("%d",d->error); else printf("null");
    printf(",\"errno_name\":");
    const char* name=d->error_known?inspect_errno_name(d->error):NULL;
    if(name) json_string(name); else printf("null");
    printf(",\"expected\":");
    if(d->values_numeric) printf("%lld",(long long)d->expected);
    else if(d->expected_text[0]) json_string(d->expected_text); else printf("null");
    printf(",\"observed\":");
    if(d->values_numeric) printf("%lld",(long long)d->observed);
    else if(d->observed_text[0]) json_string(d->observed_text); else printf("null");
    if(d->path) { printf(",\"path\":"); json_string(d->path); }
    if(d->stat_known) {
        printf(",\"type\":"); json_string(inspect_file_type(d->metadata.st_mode));
        printf(",\"mode\":\"%04o\",\"uid\":%llu,\"gid\":%llu",
               (unsigned)(d->metadata.st_mode&07777),(unsigned long long)d->metadata.st_uid,
               (unsigned long long)d->metadata.st_gid);
    }
    printf("}\n"); fflush(stdout); return 1;
}

static bool inspect_path_check(const char* path,bool parent,life_inspect_diagnostic_t* d) {
    memset(d,0,sizeof(*d)); d->path=path;
    struct stat st;
    int rc=lstat(path,&st); int error=errno;
    if(rc) {
        bool absent=error==ENOENT || error==ENOTDIR;
        return inspect_syscall_failure(d,absent?"ipc_absent":"ipc_metadata_unverified",
            parent?"IPC_PARENT_LSTAT":absent?"IPC_SOCKET_EXISTS":"IPC_SOCKET_LSTAT",
            parent?"parent_lstat":"socket_lstat",rc,error);
    }
    d->metadata=st; d->stat_known=true;
    // Literal lstat and type rejection precede realpath. A symlink cannot pass
    // by first following it and examining the destination's attributes.
    if(parent?!S_ISDIR(st.st_mode):!S_ISSOCK(st.st_mode))
        return inspect_failure(d,"ipc_present_but_unsafe",parent?"IPC_PARENT_TYPE":"IPC_SOCKET_TYPE",
            parent?"parent_type":"socket_type",parent?"directory":"socket",inspect_file_type(st.st_mode));
    uid_t own=geteuid();
    if(st.st_uid!=own)
        return inspect_numeric_failure(d,"ipc_present_but_unsafe",parent?"IPC_PARENT_OWNER":"IPC_SOCKET_OWNER",
            parent?"parent_owner":"socket_owner",own,st.st_uid);
    if(parent?(st.st_mode&077)!=0:(st.st_mode&0777)!=0600)
        return inspect_numeric_failure(d,"ipc_present_but_unsafe",parent?"IPC_PARENT_MODE":"IPC_SOCKET_MODE",
            parent?"parent_mode":"socket_mode",parent?0:0600,parent?(st.st_mode&077):(st.st_mode&0777));
    if(parent) {
        char canonical[1024];
        char* resolved=realpath(path,canonical); error=errno;
        if(!resolved) return inspect_syscall_failure(d,error==ENOENT || error==ENOTDIR?
            "ipc_absent":"ipc_metadata_unverified","IPC_PATH_RESOLVE","parent_realpath",0,error);
        if(strcmp(path,canonical)) return inspect_failure(d,"ipc_present_but_unsafe","IPC_PATH_RESOLVE",
                                                        "parent_canonical",path,canonical);
    }
    return true;
}

static bool inspect_receive(int fd,life_frame_t* frame,int64_t* peer,
    const char* phase,life_inspect_diagnostic_t* d) {
    life_ipc_receive_diagnostic_t received;
    if(life_ipc_receive_detailed(fd,frame,peer,&received)) return true;
    char detail[64];
    snprintf(detail,sizeof(detail),"%s_%s",phase,life_ipc_receive_stage_name(received.stage));
    inspect_failure(d,received.credentials_failure?"ipc_credentials_unverified":"ipc_handshake_failed",
        received.credentials_failure?"IPC_PEER_CREDENTIALS":"IPC_PROTOCOL_HANDSHAKE",detail,NULL,NULL);
    d->result_known=received.result_known; d->result=received.result;
    d->error_known=received.error_known; d->error=received.error;
    d->values_numeric=received.values_known; d->expected=received.expected; d->observed=received.observed;
    return false;
}

static int inspect_instance(void) {
    life_inspect_diagnostic_t d;
    if(!inspect_path_check(LIFE_IPC_DIRECTORY,true,&d) || !inspect_path_check(LIFE_IPC_SOCKET,false,&d))
        return inspect_blocked(&d);
    int fd=socket(AF_UNIX,SOCK_STREAM,0); int error=errno;
    if(fd<0) {
        inspect_syscall_failure(&d,"ipc_connect_failed","IPC_SOCKET_CREATE","socket",fd,error);
        return inspect_blocked(&d);
    }
    struct timeval timeout={3,0};
    int rc=setsockopt(fd,SOL_SOCKET,SO_RCVTIMEO,&timeout,sizeof(timeout)); error=errno;
    if(rc) { inspect_syscall_failure(&d,"ipc_connect_failed","IPC_SOCKET_TIMEOUT","setsockopt_receive",rc,error); goto failed; }
    rc=setsockopt(fd,SOL_SOCKET,SO_SNDTIMEO,&timeout,sizeof(timeout)); error=errno;
    if(rc) { inspect_syscall_failure(&d,"ipc_connect_failed","IPC_SOCKET_TIMEOUT","setsockopt_send",rc,error); goto failed; }
    struct sockaddr_un address; memset(&address,0,sizeof(address)); address.sun_family=AF_UNIX;
#if defined(__FreeBSD__) || defined(__APPLE__)
    address.sun_len=sizeof(address);
#endif
    snprintf(address.sun_path,sizeof(address.sun_path),"%s",LIFE_IPC_SOCKET);
    rc=connect(fd,(struct sockaddr*)&address,sizeof(address)); error=errno;
    if(rc) { inspect_syscall_failure(&d,"ipc_connect_failed","IPC_CONNECT","connect",rc,error); goto failed; }
    life_frame_t hello,request,result;
    life_identity_t daemon,kernel; bool present=false; int64_t peer=-1;
    if(!inspect_receive(fd,&hello,&peer,"hello",&d)) goto failed;
    if(hello.command!=LIFE_IPC_HELLO) {
        inspect_numeric_failure(&d,"ipc_handshake_failed","IPC_PROTOCOL_HANDSHAKE","hello_command",LIFE_IPC_HELLO,hello.command); goto failed;
    }
    if(!life_wire_unpack(&daemon,&hello.identity)) {
        inspect_failure(&d,"ipc_identity_unverified","IPC_INSTANCE_IDENTITY","hello_identity_decode","bounded_identity","invalid_identity_encoding"); goto failed;
    }
    if(!lifecycle_identity_valid(&daemon)) {
        inspect_failure(&d,"ipc_identity_unverified","IPC_INSTANCE_IDENTITY","hello_identity_valid","complete_instance_identity","incomplete_or_invalid_identity"); goto failed;
    }
    if(peer!=daemon.pid) {
        inspect_numeric_failure(&d,"ipc_identity_unverified","IPC_INSTANCE_IDENTITY","hello_peer_pid",daemon.pid,peer); goto failed;
    }
    bool queried=lifecycle_native_query(peer,&present,&kernel);
    if(!queried) {
        inspect_failure(&d,"ipc_identity_unverified","IPC_INSTANCE_IDENTITY","hello_kernel_query","kernel_query_success","kernel_query_unverified");
        // The adapter also fails on semantic ABI checks; its bool API does
        // not guarantee an errno provenance. Report the result, not stale errno.
        d.result_known=true; d.result=0; goto failed;
    }
    if(!present || !kernel.kernel_identity_known) {
        inspect_numeric_failure(&d,"ipc_identity_unverified","IPC_INSTANCE_IDENTITY",!present?"hello_kernel_present":"hello_kernel_identity",1,0); goto failed;
    }
    if(kernel.pid!=daemon.pid) {
        inspect_numeric_failure(&d,"ipc_identity_unverified","IPC_INSTANCE_IDENTITY","hello_kernel_pid",daemon.pid,kernel.pid); goto failed;
    }
    if(kernel.start_sec!=daemon.start_sec) {
        inspect_numeric_failure(&d,"ipc_identity_unverified","IPC_INSTANCE_IDENTITY","hello_kernel_start_sec",daemon.start_sec,kernel.start_sec); goto failed;
    }
    if(kernel.start_usec!=daemon.start_usec) {
        inspect_numeric_failure(&d,"ipc_identity_unverified","IPC_INSTANCE_IDENTITY","hello_kernel_start_usec",daemon.start_usec,kernel.start_usec); goto failed;
    }
    life_frame_init(&request,LIFE_IPC_INSPECT); life_wire_pack(&request.identity,&daemon);
    memcpy(request.challenge,hello.challenge,sizeof(request.challenge));
    bool sent=life_ipc_send(fd,&request);
    if(!sent) {
        inspect_failure(&d,"ipc_handshake_failed","IPC_PROTOCOL_HANDSHAKE","request_send","full_inspect_frame_sent","send_failed_or_short");
        // The boolean wrapper does not distinguish a short write from a
        // failing syscall. Its result is known, errno provenance is not.
        d.result_known=true; d.result=0; goto failed;
    }
    if(!inspect_receive(fd,&result,&peer,"result",&d)) goto failed;
    if(result.command!=LIFE_IPC_RESULT) {
        inspect_numeric_failure(&d,"ipc_handshake_failed","IPC_PROTOCOL_HANDSHAKE","result_command",LIFE_IPC_RESULT,result.command); goto failed;
    }
    if(peer!=daemon.pid) {
        inspect_numeric_failure(&d,"ipc_identity_unverified","IPC_INSTANCE_IDENTITY","result_peer_pid",daemon.pid,peer); goto failed;
    }
    if(!life_wire_unpack(&kernel,&result.identity)) {
        inspect_failure(&d,"ipc_identity_unverified","IPC_INSTANCE_IDENTITY","result_identity_decode","bounded_identity","invalid_identity_encoding"); goto failed;
    }
    if(!lifecycle_identity_equal(&daemon,&kernel)) {
        inspect_failure(&d,"ipc_identity_unverified","IPC_INSTANCE_IDENTITY","result_identity_match","exact_original_identity","identity_mismatch"); goto failed;
    }
    if(!result.accepted) {
        inspect_numeric_failure(&d,"ipc_handshake_failed","IPC_PROTOCOL_HANDSHAKE","snapshot_accepted",1,0);
        goto failed;
    }
    close(fd);
    // Preserve the successful protocol-1 INSPECT response exactly; it remains
    // consumable by the strict explicit-identity serializer.
    printf("{\"ok\":true,"); identity_json(&daemon);
    printf(",\"state\":%u,\"jobs\":%d,\"queued\":%d,\"operations\":%d,\"import_work\":%d,"
           "\"recovery\":%d,\"mounts\":%d,\"gate\":%d,\"checkpoint\":%d,\"reason\":",
           result.state,result.jobs,result.queued,result.operations,result.import_work,result.recovery,
           result.mounts,result.gate,result.checkpoint); json_string(result.reason); printf("}\n"); fflush(stdout);
    return 0;
failed:
    close(fd); return inspect_blocked(&d);
}

int main(void) {
    const unsigned mode=LIFE_HELPER_MODE;
    if(mode!=LIFE_IPC_INSPECT && mode!=LIFE_IPC_STOP && mode!=LIFE_IPC_VERIFY)
        return blocked("unsupported_helper_mode");
    if(mode==LIFE_IPC_INSPECT) return inspect_instance();
    life_identity_t approved;
    memset(&approved,0,sizeof(approved));
    if(mode!=LIFE_IPC_INSPECT && !identity_input(mode,&approved))
        return blocked("explicit_original_identity_input_required");
    if(mode==LIFE_IPC_VERIFY) {
        life_exit_t result=lifecycle_wait_exit(&approved,lifecycle_native_query,monotonic_ms,pause_tick);
        printf("{\"ok\":%s,\"verification\":\"%s\",\"outcome\":\"%s\",",result==LIFE_EXITED || result==LIFE_PID_REUSED?"true":"false",
               lifecycle_exit_name(result),wait_outcome(result)); identity_json(&approved); printf("}\n"); fflush(stdout);
        return result==LIFE_EXITED || result==LIFE_PID_REUSED?0:1;
    }
    int fd=connect_local();
    if(fd<0) return blocked("local_socket_unavailable_or_unsafe");
    life_frame_t hello,request,result;
    life_identity_t daemon,kernel; bool present=false; int64_t peer=-1;
    if(!life_ipc_receive(fd,&hello,&peer) || hello.command!=LIFE_IPC_HELLO ||
       !life_wire_unpack(&daemon,&hello.identity) || !lifecycle_identity_valid(&daemon) ||
       peer!=daemon.pid || !lifecycle_native_query(peer,&present,&kernel) || !present ||
       !kernel.kernel_identity_known || kernel.pid!=daemon.pid ||
       kernel.start_sec!=daemon.start_sec || kernel.start_usec!=daemon.start_usec) {
        close(fd); return blocked("daemon_kernel_identity_unverified");
    }
    if(mode==LIFE_IPC_STOP && !lifecycle_identity_equal(&approved,&daemon)) {
        close(fd); return blocked("approved_identity_does_not_match_this_instance");
    }
    life_frame_init(&request,mode); life_wire_pack(&request.identity,&daemon);
    memcpy(request.challenge,hello.challenge,sizeof(request.challenge));
    if(!life_ipc_send(fd,&request) || !life_ipc_receive(fd,&result,&peer) ||
       result.command!=LIFE_IPC_RESULT || peer!=daemon.pid ||
       !life_wire_unpack(&kernel,&result.identity) || !lifecycle_identity_equal(&daemon,&kernel)) {
        close(fd);
        // A partial send or lost reply may already have requested self-SIGTERM.
        // Never label it a proven rejection and never resend.
        if(mode==LIFE_IPC_STOP) return uncertain("stop_response_lost_or_unverified_no_resend", &approved);
        return blocked("local_protocol_rejected");
    }
    close(fd);
    if(mode==LIFE_IPC_INSPECT) {
        printf("{\"ok\":%s,",result.accepted?"true":"false"); identity_json(&daemon);
        printf(",\"state\":%u,\"jobs\":%d,\"queued\":%d,\"operations\":%d,\"import_work\":%d,"
               "\"recovery\":%d,\"mounts\":%d,\"gate\":%d,\"checkpoint\":%d,\"reason\":",
               result.state,result.jobs,result.queued,result.operations,result.import_work,result.recovery,
               result.mounts,result.gate,result.checkpoint); json_string(result.reason); printf("}\n"); fflush(stdout);
        return result.accepted?0:1;
    }
    if(!result.accepted || result.state!=LIFE_SIGNAL_SENT) {
        printf("{\"ok\":false,\"outcome\":\"BLOCKED\",\"signal_error\":%u,\"state\":%u,\"reason\":",
               result.signal_error,result.state);
        json_string(result.reason); printf(","); identity_json(&approved);
        printf("}\n"); fflush(stdout); return 1;
    }
    life_exit_t exit=lifecycle_wait_exit(&approved,lifecycle_native_query,monotonic_ms,pause_tick);
    printf("{\"ok\":%s,\"stop_accepted\":true,\"verification\":\"%s\",\"outcome\":\"%s\",",
           exit==LIFE_EXITED || exit==LIFE_PID_REUSED?"true":"false",lifecycle_exit_name(exit),wait_outcome(exit));
    identity_json(&approved); printf("}\n"); fflush(stdout);
    return exit==LIFE_EXITED || exit==LIFE_PID_REUSED?0:1;
}
#endif
