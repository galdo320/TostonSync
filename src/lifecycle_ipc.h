// Fixed, same-device protocol. No strings are interpreted as paths or commands.
#ifndef TOSTONSYNC_LIFECYCLE_IPC_H
#define TOSTONSYNC_LIFECYCLE_IPC_H
#include "lifecycle.h"
#include <errno.h>
#include <limits.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>
#define LIFE_IPC_MAGIC 0x544c4946u
#define LIFE_IPC_INSPECT 1u
#define LIFE_IPC_STOP 2u
#define LIFE_IPC_VERIFY 3u
#define LIFE_IPC_HELLO 4u
#define LIFE_IPC_RESULT 5u
#define LIFE_IPC_DIRECTORY "/data/tostonsync/lifecycle"
#define LIFE_IPC_SOCKET LIFECYCLE_SOCKET
// Entire frame zero-initialized, fixed integers, no bool or compiler enum ABI.
typedef struct {
    int64_t pid, start_sec, start_usec;
    uint64_t module_base;
    uint32_t kernel_known, module_known, process_model, reserved;
    char nonce[65], version[32], build[64], module[256];
    unsigned char padding[7];
} life_wire_identity_t;
typedef struct {
    uint32_t magic, protocol, bytes, command;
    uint32_t accepted, state, signal_error, reserved;
    unsigned char challenge[32];
    life_wire_identity_t identity;
    int32_t jobs, queued, operations, import_work, recovery, mounts, gate, checkpoint;
    char reason[192];
} life_frame_t;
_Static_assert(sizeof(life_wire_identity_t)==472,"identity wire ABI changed");
_Static_assert(sizeof(life_frame_t)==760,"frame wire ABI changed");

static inline void life_frame_init(life_frame_t* f, unsigned command) {
    memset(f, 0, sizeof(*f));
    f->magic = LIFE_IPC_MAGIC; f->protocol = LIFECYCLE_PROTOCOL;
    f->bytes = sizeof(*f); f->command = command;
}
static inline void life_wire_pack(life_wire_identity_t* w, const life_identity_t* i) {
    memset(w, 0, sizeof(*w));
    w->pid=i->pid; w->start_sec=i->start_sec; w->start_usec=i->start_usec;
    w->module_base=i->module_base; w->kernel_known=i->kernel_identity_known;
    w->module_known=i->module_known; w->process_model=i->process_model;
    memcpy(w->nonce,i->nonce,sizeof(w->nonce)); memcpy(w->version,i->version,sizeof(w->version));
    memcpy(w->build,i->build,sizeof(w->build)); memcpy(w->module,i->module,sizeof(w->module));
}
static inline bool life_wire_unpack(life_identity_t* i, const life_wire_identity_t* w) {
    memset(i, 0, sizeof(*i));
    if (w->kernel_known > 1 || w->module_known > 1 || w->process_model > LIFE_PROCESS_CARRIER ||
        w->reserved) return false;
    for (size_t k=0;k<sizeof(w->padding);++k) if(w->padding[k]) return false;
    i->pid=w->pid; i->start_sec=w->start_sec; i->start_usec=w->start_usec;
    i->module_base=w->module_base; i->kernel_identity_known=w->kernel_known;
    i->module_known=w->module_known; i->process_model=(life_process_t)w->process_model;
    memcpy(i->nonce,w->nonce,sizeof(i->nonce)); memcpy(i->version,w->version,sizeof(i->version));
    memcpy(i->build,w->build,sizeof(i->build)); memcpy(i->module,w->module,sizeof(i->module));
    return memchr(i->nonce,'\0',sizeof(i->nonce)) && memchr(i->version,'\0',sizeof(i->version)) &&
        memchr(i->build,'\0',sizeof(i->build)) && memchr(i->module,'\0',sizeof(i->module));
}
static inline bool life_frame_valid(const life_frame_t* f) {
    return f->magic==LIFE_IPC_MAGIC && f->protocol==LIFECYCLE_PROTOCOL &&
        f->bytes==sizeof(*f) && !f->reserved && f->accepted<=1 &&
        f->state<=LIFE_SIGNAL_ERROR && f->signal_error<=INT_MAX &&
        f->command>=LIFE_IPC_INSPECT && f->command<=LIFE_IPC_RESULT &&
        f->jobs>=0 && f->queued>=0 && f->operations>=0 &&
        f->import_work>=LIFE_UNKNOWN && f->import_work<=LIFE_BUSY &&
        f->recovery>=LIFE_UNKNOWN && f->recovery<=LIFE_BUSY &&
        f->mounts>=LIFE_UNKNOWN && f->mounts<=LIFE_BUSY &&
        f->gate>=LIFE_UNKNOWN && f->gate<=LIFE_BUSY &&
        f->checkpoint>=LIFE_UNKNOWN && f->checkpoint<=LIFE_BUSY &&
        memchr(f->reason,'\0',sizeof(f->reason));
}
static inline void life_frame_snapshot(life_frame_t* f, const life_snapshot_t* s) {
    f->jobs=s->jobs; f->queued=s->queued; f->operations=s->operations;
    f->import_work=s->import_work; f->recovery=s->recovery; f->mounts=s->mounts;
    f->gate=s->gate; f->checkpoint=s->checkpoint;
    memcpy(f->reason,s->reason,sizeof(f->reason)); f->reason[sizeof(f->reason)-1]='\0';
}
static inline bool life_ipc_timeout(int fd) {
    struct timeval timeout={3,0};
    return setsockopt(fd,SOL_SOCKET,SO_RCVTIMEO,&timeout,sizeof(timeout))==0 &&
           setsockopt(fd,SOL_SOCKET,SO_SNDTIMEO,&timeout,sizeof(timeout))==0;
}
static inline bool life_ipc_send(int fd, const life_frame_t* f) {
#if defined(__FreeBSD__) && defined(SCM_CREDS)
    union { struct cmsghdr align; unsigned char bytes[CMSG_SPACE(sizeof(struct cmsgcred))]; } control;
    memset(&control,0,sizeof(control));
    struct iovec iov={(void*)f,sizeof(*f)};
    struct msghdr msg; memset(&msg,0,sizeof(msg));
    msg.msg_iov=&iov; msg.msg_iovlen=1; msg.msg_control=control.bytes; msg.msg_controllen=sizeof(control);
    struct cmsghdr* c=CMSG_FIRSTHDR(&msg);
    c->cmsg_level=SOL_SOCKET; c->cmsg_type=SCM_CREDS; c->cmsg_len=CMSG_LEN(sizeof(struct cmsgcred));
    ssize_t n=sendmsg(fd,&msg,MSG_NOSIGNAL);
    return n==(ssize_t)sizeof(*f);
#else
    (void)fd;(void)f; errno=ENOTSUP; return false;
#endif
}
typedef enum {
    LIFE_IPC_RECV_COMPLETE, LIFE_IPC_RECV_SYSCALL, LIFE_IPC_RECV_SIZE,
    LIFE_IPC_RECV_FLAGS, LIFE_IPC_RECV_CREDENTIALS_MISSING,
    LIFE_IPC_RECV_CREDENTIALS_LEVEL, LIFE_IPC_RECV_CREDENTIALS_TYPE,
    LIFE_IPC_RECV_CREDENTIALS_LENGTH, LIFE_IPC_RECV_CREDENTIALS_EXTRA,
    LIFE_IPC_RECV_CREDENTIALS_PID, LIFE_IPC_RECV_CREDENTIALS_EUID,
    LIFE_IPC_RECV_CREDENTIALS_GROUPS, LIFE_IPC_RECV_FRAME,
    LIFE_IPC_RECV_UNSUPPORTED
} life_ipc_receive_stage_t;
typedef struct {
    life_ipc_receive_stage_t stage;
    ssize_t result;
    int error;
    bool result_known, error_known, values_known, credentials_failure;
    int64_t expected, observed;
} life_ipc_receive_diagnostic_t;
static inline void life_ipc_receive_failure(life_ipc_receive_diagnostic_t* d,
    life_ipc_receive_stage_t stage, bool credentials, int64_t expected, int64_t observed) {
    if(!d) return;
    d->stage=stage; d->credentials_failure=credentials;
    d->values_known=true; d->expected=expected; d->observed=observed;
}
static inline const char* life_ipc_receive_stage_name(life_ipc_receive_stage_t stage) {
    switch(stage) {
    case LIFE_IPC_RECV_COMPLETE: return "complete";
    case LIFE_IPC_RECV_SYSCALL: return "recvmsg";
    case LIFE_IPC_RECV_SIZE: return "frame_size";
    case LIFE_IPC_RECV_FLAGS: return "message_flags";
    case LIFE_IPC_RECV_CREDENTIALS_MISSING: return "credentials_missing";
    case LIFE_IPC_RECV_CREDENTIALS_LEVEL: return "credentials_level";
    case LIFE_IPC_RECV_CREDENTIALS_TYPE: return "credentials_type";
    case LIFE_IPC_RECV_CREDENTIALS_LENGTH: return "credentials_length";
    case LIFE_IPC_RECV_CREDENTIALS_EXTRA: return "credentials_extra";
    case LIFE_IPC_RECV_CREDENTIALS_PID: return "credentials_pid";
    case LIFE_IPC_RECV_CREDENTIALS_EUID: return "credentials_euid";
    case LIFE_IPC_RECV_CREDENTIALS_GROUPS: return "credentials_groups";
    case LIFE_IPC_RECV_FRAME: return "frame_validate";
    default: return "credentials_unsupported";
    }
}
// Optional reporting only. The wrapper below retains every old rejection and
// the same peer_pid/errno semantics; details never make a failed frame usable.
static inline bool life_ipc_receive_detailed(int fd, life_frame_t* f, int64_t* peer_pid,
                                            life_ipc_receive_diagnostic_t* detail) {
    if(detail) memset(detail,0,sizeof(*detail));
#if defined(__FreeBSD__) && defined(SCM_CREDS)
    union { struct cmsghdr align; unsigned char bytes[CMSG_SPACE(sizeof(struct cmsgcred))]; } control;
    memset(&control,0,sizeof(control)); memset(f,0,sizeof(*f));
    struct iovec iov={f,sizeof(*f)};
    struct msghdr msg; memset(&msg,0,sizeof(msg));
    msg.msg_iov=&iov; msg.msg_iovlen=1; msg.msg_control=control.bytes; msg.msg_controllen=sizeof(control);
    ssize_t n=recvmsg(fd,&msg,MSG_WAITALL);
    if(detail) {
        detail->result=n; detail->result_known=true;
        if(n<0) { detail->error=errno; detail->error_known=true; }
    }
    if(n!=(ssize_t)sizeof(*f)) {
        life_ipc_receive_failure(detail,n<0?LIFE_IPC_RECV_SYSCALL:LIFE_IPC_RECV_SIZE,
                                 false,sizeof(*f),n); return false;
    }
    if(msg.msg_flags&(MSG_TRUNC|MSG_CTRUNC)) {
        life_ipc_receive_failure(detail,LIFE_IPC_RECV_FLAGS,(msg.msg_flags&MSG_CTRUNC)!=0,
                                 0,msg.msg_flags&(MSG_TRUNC|MSG_CTRUNC)); return false;
    }
    struct cmsghdr* c=CMSG_FIRSTHDR(&msg);
    if(!c) { life_ipc_receive_failure(detail,LIFE_IPC_RECV_CREDENTIALS_MISSING,true,1,0); return false; }
    if(c->cmsg_level!=SOL_SOCKET) {
        life_ipc_receive_failure(detail,LIFE_IPC_RECV_CREDENTIALS_LEVEL,true,SOL_SOCKET,c->cmsg_level); return false;
    }
    if(c->cmsg_type!=SCM_CREDS) {
        life_ipc_receive_failure(detail,LIFE_IPC_RECV_CREDENTIALS_TYPE,true,SCM_CREDS,c->cmsg_type); return false;
    }
    if(c->cmsg_len!=CMSG_LEN(sizeof(struct cmsgcred))) {
        life_ipc_receive_failure(detail,LIFE_IPC_RECV_CREDENTIALS_LENGTH,true,
                                 CMSG_LEN(sizeof(struct cmsgcred)),c->cmsg_len); return false;
    }
    if(CMSG_NXTHDR(&msg,c)) {
        life_ipc_receive_failure(detail,LIFE_IPC_RECV_CREDENTIALS_EXTRA,true,1,2); return false;
    }
    struct cmsgcred cred; memcpy(&cred,CMSG_DATA(c),sizeof(cred));
    if(cred.cmcred_pid<=1) {
        life_ipc_receive_failure(detail,LIFE_IPC_RECV_CREDENTIALS_PID,true,2,cred.cmcred_pid); return false;
    }
    uid_t own_uid=geteuid();
    if(cred.cmcred_euid!=own_uid) {
        life_ipc_receive_failure(detail,LIFE_IPC_RECV_CREDENTIALS_EUID,true,own_uid,cred.cmcred_euid); return false;
    }
    if(cred.cmcred_ngroups<0 || cred.cmcred_ngroups>CMGROUP_MAX) {
        life_ipc_receive_failure(detail,LIFE_IPC_RECV_CREDENTIALS_GROUPS,true,CMGROUP_MAX,cred.cmcred_ngroups); return false;
    }
    if(peer_pid) *peer_pid=cred.cmcred_pid;
    if(!life_frame_valid(f)) {
        life_ipc_receive_failure(detail,LIFE_IPC_RECV_FRAME,false,1,0); return false;
    }
    return true;
#else
    (void)fd;(void)f;(void)peer_pid;
    life_ipc_receive_failure(detail,LIFE_IPC_RECV_UNSUPPORTED,true,1,0);
    errno=ENOTSUP; return false;
#endif
}
static inline bool life_ipc_receive(int fd, life_frame_t* f, int64_t* peer_pid) {
    return life_ipc_receive_detailed(fd,f,peer_pid,NULL);
}

typedef bool (*life_wait_query_fn)(int64_t, bool*, life_identity_t*);
typedef bool (*life_wait_clock_fn)(int64_t* milliseconds);
typedef bool (*life_wait_pause_fn)(void);
life_exit_t lifecycle_wait_exit(const life_identity_t* original, life_wait_query_fn query,
                               life_wait_clock_fn clock_now, life_wait_pause_fn pause_tick);
#endif
