#include "github_update.h"
#include "release_verify.h"
#include "http_client.h"
#include "update.h"
#include "watcher.h"
#include "import_session.h"
#include "lifecycle.h"
#include "log.h"
#include "version.h"
#include "at_io.h"
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#define CHECK_INTERVAL 86400
static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
static github_update_status_t state = {.state="idle"};
static release_manifest_t candidate;
static char candidate_tag[40], state_path[CFG_MAX_PATH], notified[32];
static bool initialized, busy, auto_blocked;
static int64_t last_monotonic;
static unsigned temp_sequence;

typedef struct { uint64_t ticket; bool install; release_manifest_t manifest; char tag[40]; } request_t;
static int64_t monotonic_now(void) {
    struct timespec now;
    return clock_gettime(CLOCK_MONOTONIC,&now)==0 && now.tv_sec>=0 ? (int64_t)now.tv_sec : -1;
}
static bool stat_fd(int fd, struct stat* out) {
    toston_stat_guard_t guard=TOSTON_STAT_GUARD_INIT;
    bool ok=toston_fstat(fd,&guard.value)==0 && toston_stat_guard_valid(&guard);
    if(ok)*out=guard.value;
    return ok;
}
static bool stat_name(int dir, const char* name, struct stat* out) {
    toston_stat_guard_t guard=TOSTON_STAT_GUARD_INIT;
    bool ok=toston_fstatat(dir,name,&guard.value,AT_SYMLINK_NOFOLLOW)==0 && toston_stat_guard_valid(&guard);
    if(ok)*out=guard.value;
    return ok;
}
static bool owned(int dir,const char* name,int fd) {
    struct stat held,named;
    return stat_fd(fd,&held) && stat_name(dir,name,&named) && S_ISREG(held.st_mode) &&
        S_ISREG(named.st_mode) && held.st_nlink==1 && named.st_nlink==1 &&
        held.st_dev==named.st_dev && held.st_ino==named.st_ino;
}
static void cleanup_owned(int dir,const char* name,int fd) {
    if(fd>=0) { if(owned(dir,name,fd)) (void)unlinkat(dir,name,0); close(fd); }
}
static int open_state_dir(void) {
    if(state_path[0]!='/')return -1;
    char path[CFG_MAX_PATH]; snprintf(path,sizeof(path),"%s",state_path);
    int dir=open("/",O_RDONLY|O_DIRECTORY|O_NOFOLLOW);
    char* save=NULL;
    for(char* part=strtok_r(path,"/",&save); dir>=0 && part; part=strtok_r(NULL,"/",&save)) {
        if(!strcmp(part,".")||!strcmp(part,"..")) {close(dir);return -1;}
        int next=toston_openat(dir,part,O_RDONLY|O_DIRECTORY|O_NOFOLLOW,0); close(dir);dir=next;
    }
    return dir;
}
static bool directory_current(int held) {
    int current=open_state_dir();struct stat a,b;
    bool ok=current>=0&&stat_fd(held,&a)&&stat_fd(current,&b)&&a.st_dev==b.st_dev&&a.st_ino==b.st_ino;
    if(current>=0)close(current);
    return ok;
}
static int new_temp(int dir,const char* prefix,char name[128]) {
    const char* boot=update_boot_id();
    if(!boot[0]||temp_sequence==~0u)return -1;
    snprintf(name,128,".%s-%.32s-%u.tmp",prefix,boot,++temp_sequence);
    return toston_openat(dir,name,O_RDWR|O_CREAT|O_EXCL|O_NOFOLLOW,0600);
}
// Caller holds lock. Intent is durable before the first request or notification.
static bool persist(void) {
    int dir=open_state_dir(); if(dir<0)return false;
    char name[128],text[256];
    int fd=new_temp(dir,"github-state",name);
    int length=snprintf(text,sizeof(text),"v1\nlast_attempt=%lld\nnotified=%s\nauto_blocked=%d\n",
        (long long)state.last_attempt_unix,notified,auto_blocked?1:0);
    bool ok=fd>=0 && length>0 && (size_t)length<sizeof(text);
    size_t used=0;
    while(ok && used<(size_t)length) {
        ssize_t n=write(fd,text+used,(size_t)length-used);
        if(n<0&&errno==EINTR)continue;
        if(n<=0)ok=false;else used+=(size_t)n;
    }
    if(ok)ok=fsync(fd)==0 && owned(dir,name,fd);
    if(ok) {
        struct stat current;errno=0;
        bool exists=stat_name(dir,"github-update.state",&current);
        ok=exists?(S_ISREG(current.st_mode)&&current.st_nlink==1):errno==ENOENT;
    }
    if(ok)ok=directory_current(dir)&&renameat(dir,name,dir,"github-update.state")==0;
    if(ok)ok=fsync(dir)==0&&directory_current(dir);
    cleanup_owned(dir,name,fd);close(dir);return ok;
}
static void fail(const char* error,const char* detail,bool uncertain) {
    pthread_mutex_lock(&lock);
    snprintf(state.state,sizeof(state.state),"%s",uncertain?"unknown":"error");
    snprintf(state.error,sizeof(state.error),"%s",error&&error[0]?error:"update_failed");
    snprintf(state.detail,sizeof(state.detail),"%s",detail?detail:"");
    if(uncertain||!strcmp(state.error,"update_state_write_failed"))auto_blocked=true;
    if(!persist())auto_blocked=true;
    pthread_mutex_unlock(&lock);
}
void github_update_init(const config_t* cfg) {
    if(!cfg)return;
    pthread_mutex_lock(&lock);
    if(initialized) {pthread_mutex_unlock(&lock);return;}
    snprintf(state_path,sizeof(state_path),"%s",cfg->paths.state_dir);
    state.auto_check=cfg->general.update_auto_check;
    initialized=true;
    int dir=open_state_dir();
    if(dir<0)auto_blocked=true;
    else {
        int fd=toston_openat(dir,"github-update.state",O_RDONLY|O_NOFOLLOW|O_NONBLOCK,0);
        if(fd<0)auto_blocked=errno!=ENOENT;
        else {
            struct stat st;char text[256]={0};ssize_t count=read(fd,text,sizeof(text)-1);
            long long attempt=0;int blocked=0,used=0;char notice[32]={0};
            bool valid=stat_fd(fd,&st)&&S_ISREG(st.st_mode)&&st.st_nlink==1&&count>0&&count<(ssize_t)sizeof(text)-1&&st.st_size==count&&
                !memchr(text,0,(size_t)count)&&owned(dir,"github-update.state",fd)&&directory_current(dir);
            if(valid) {
                char* n=strstr(text,"\nnotified=");char* e=n?strchr(n+10,'\n'):NULL;
                valid=n&&e&&(size_t)(e-(n+10))<sizeof(notice);
                if(valid) {memcpy(notice,n+10,(size_t)(e-(n+10)));memmove(n+10,e,strlen(e)+1);}
                valid=valid&&sscanf(text,"v1\nlast_attempt=%lld\nnotified=\nauto_blocked=%d\n%n",&attempt,&blocked,&used)==2 &&
                    used>0&&text[used]=='\0'&&attempt>=0&&(blocked==0||blocked==1)&&
                    (!notice[0]||release_version_compare(notice,notice)==0);
            }
            if(valid) {state.last_attempt_unix=attempt;auto_blocked=blocked!=0;snprintf(notified,sizeof(notified),"%s",notice);}
            else auto_blocked=true;
            close(fd);
        }
        close(dir);
    }
    if(auto_blocked) {snprintf(state.state,sizeof(state.state),"error");snprintf(state.error,sizeof(state.error),"automatic_check_paused");}
    pthread_mutex_unlock(&lock);
}
void github_update_status(github_update_status_t* out) {
    if(!out)return;
    int previous_errno=errno;
    pthread_mutex_lock(&lock);*out=state;
    out->automatic_paused=auto_blocked;
    out->next_check_unix=!auto_blocked&&state.last_attempt_unix>0&&state.last_attempt_unix<=INT64_MAX-CHECK_INTERVAL?
        state.last_attempt_unix+CHECK_INTERVAL:0;
    pthread_mutex_unlock(&lock);
    config_t cfg;if(config_snapshot(&cfg))out->auto_check=cfg.general.update_auto_check;
    errno=previous_errno;
}
static bool fetch(const char* url,size_t max,http_response_t* response) {
    bool received=http_get_release_limited(url,max,response);
    if(response->status>0&&response->status!=200) {
        const char* error=response->status==404?"github_not_found":response->status==429?"github_rate_limited":response->status==401||response->status==403?"github_access_denied":"github_http_error";
        char detail[128];snprintf(detail,sizeof(detail),"GitHub returned HTTP %d.",response->status);
        fail(error,detail,false);return false;
    }
    if(!received||response->status!=200) {fail("github_transport_error","The release request failed; the next automatic check remains scheduled.",false);return false;}
    return true;
}
static bool install_snapshot(life_snapshot_t* out) {
    if(!watcher_lifecycle_snapshot(out))return false;
    import_jobs_snapshot_t imported;
    if(import_session_jobs_snapshot(&imported)!=IMPORT_JOBS_OBSERVED||imported.uncertain||imported.observation_only)
        out->import_work=out->checkpoint=LIFE_UNKNOWN;
    else if(imported.current_present)out->import_work=out->checkpoint=LIFE_BUSY;
    return true;
}
static void check_release(void) {
    http_response_t listing_response={0},manifest_response={0},signature_response={0};
    release_listing_t listing;release_manifest_t found;char error[128]={0},url[RELEASE_URL_MAX];
    if(!fetch(RELEASE_API_URL,RELEASE_LISTING_MAX,&listing_response))goto done;
    if(!release_parse_listing(listing_response.body,listing_response.body_len,&listing,error,sizeof(error))) {fail(error,"Release metadata was rejected.",false);goto done;}
    int compare=release_version_compare(listing.version,TOSTONSYNC_VERSION);
    if(compare==0||compare==-1) {
        pthread_mutex_lock(&lock);snprintf(state.state,sizeof(state.state),"current");state.error[0]=state.detail[0]=0;
        state.candidate_id[0]=0;memset(&candidate,0,sizeof(candidate));state.last_success_unix=time(NULL);auto_blocked=false;
        bool saved=persist();pthread_mutex_unlock(&lock);
        if(!saved)fail("update_state_write_failed","The check result could not be saved.",false);
        goto done;
    }
    if(!release_asset_url(listing.tag,listing.manifest_name,url,sizeof(url))) {fail("update_asset_invalid","Invalid manifest URL.",false);goto done;}
    if(!fetch(url,RELEASE_MANIFEST_MAX,&manifest_response))goto done;
    if(!release_asset_url(listing.tag,listing.signature_name,url,sizeof(url))) {fail("update_asset_invalid","Invalid signature URL.",false);goto done;}
    if(!fetch(url,64,&signature_response))goto done;
    if(!release_verify_manifest(manifest_response.body,manifest_response.body_len,signature_response.body,signature_response.body_len,
        TOSTONSYNC_VERSION,&listing,&found,error,sizeof(error))) {fail(error,"Signed release verification failed.",false);goto done;}
    config_t cfg;bool configured=config_snapshot(&cfg);bool notify=false;
    pthread_mutex_lock(&lock);
    candidate=found;snprintf(candidate_tag,sizeof(candidate_tag),"%s",listing.tag);
    snprintf(state.version,sizeof(state.version),"%s",found.version);snprintf(state.build,sizeof(state.build),"%s",found.build);
    state.notes_verified=found.notes_verified;
    snprintf(state.notes,sizeof(state.notes),"%s",found.notes_verified?listing.notes:"");
    for(size_t i=0;state.notes[i];i++)if((unsigned char)state.notes[i]<32&&state.notes[i]!='\n'&&state.notes[i]!='\t')state.notes[i]=' ';snprintf(state.candidate_id,sizeof(state.candidate_id),"%s",found.candidate_id);
    snprintf(state.state,sizeof(state.state),"available");state.error[0]=state.detail[0]=0;state.last_success_unix=time(NULL);auto_blocked=false;
    if(configured&&cfg.general.notifications&&(!notified[0]||release_version_compare(found.version,notified)==1)) {
        snprintf(notified,sizeof(notified),"%s",found.version);notify=true;
    }
    bool saved=persist();pthread_mutex_unlock(&lock);
    if(!saved) {fail("update_state_write_failed","The release observation could not be saved.",false);goto done;}
    if(notify) {
        char notice[192];snprintf(notice,sizeof(notice),!strcmp(cfg.general.language,"es")?
            "TostónSync v%s disponible. Abre Ajustes para revisar la actualización.":
            "TostónSync v%s is available. Open Settings to review the update.",found.version);
        log_notify_level(NOTIFY_IMPORTANT,notice);
    }
done:
    http_response_free(&listing_response);http_response_free(&manifest_response);http_response_free(&signature_response);
}
static void install_release(const request_t* request) {
    int dir=open_state_dir(),fd=-1;char temp[128]={0},url[RELEASE_URL_MAX],error[128]={0};
    void* bytes=NULL;size_t length=0;http_response_t response={0};bool reserved=false;update_result_t result={0};char session[65]={0};
    if(dir<0||(fd=new_temp(dir,"github-release",temp))<0) {fail("update_download_stage_failed","Could not create the private download.",false);goto done;}
    if(!release_asset_url(request->tag,request->manifest.asset,url,sizeof(url))) {fail("update_asset_invalid","The signed asset URL is invalid.",false);goto done;}
    if(!http_get_release_to_fd(url,fd,request->manifest.asset_size,&response)||response.status!=200) {fail("update_download_failed","The release download failed; retry manually.",false);goto done;}
    if(!owned(dir,temp,fd)||!release_extract_elf(fd,&request->manifest,&bytes,&length,error,sizeof(error))) {fail(error[0]?error:"update_download_changed","Downloaded release verification failed.",false);goto done;}
    update_file_info_t info;
    if(!update_inspect_bytes(bytes,length,&info)||strcmp(info.version,request->manifest.version)||strcmp(info.build,request->manifest.build)||
        strcmp(info.sha256,request->manifest.sha256)||info.bytes!=request->manifest.size) {fail("update_marker_mismatch","The ELF identity does not match the signed manifest.",false);goto done;}
    life_snapshot_t snapshot;
    if(!lifecycle_update_install_begin(install_snapshot,&snapshot)) {fail("update_install_busy",snapshot.reason,false);goto done;}
    reserved=true;
    update_status_t existing;
    if(!update_get_status(&existing)||existing.publication_unknown) {fail("update_publication_unknown","Existing update publication is unknown.",true);goto done;}
    if(existing.saved.valid&&!strcmp(existing.saved.sha256,info.sha256)) {
        pthread_mutex_lock(&lock);snprintf(state.state,sizeof(state.state),"saved");state.error[0]=state.detail[0]=0;
        snprintf(state.saved_version,sizeof(state.saved_version),"%s",info.version);snprintf(state.saved_sha256,sizeof(state.saved_sha256),"%s",info.sha256);
        state.candidate_id[0]=0;memset(&candidate,0,sizeof(candidate));pthread_mutex_unlock(&lock);goto done;
    }
    if(!update_start(request->manifest.candidate_id,"tostonsync.elf",length,info.sha256,true,false,&result))goto native_failed;
    snprintf(session,sizeof(session),"%s",result.session_id);
    for(size_t offset=0;offset<length;) {
        size_t count=length-offset>UPDATE_CHUNK_BYTES?UPDATE_CHUNK_BYTES:length-offset;
        if(!update_chunk(request->manifest.candidate_id,session,offset,(char*)bytes+offset,count,true,&result))goto native_failed;
        offset+=count;
    }
    if(!update_finish_quiet(request->manifest.candidate_id,session,true,&result)||!result.published)goto native_failed;
    pthread_mutex_lock(&lock);snprintf(state.state,sizeof(state.state),"saved");state.error[0]=state.detail[0]=0;
    snprintf(state.saved_version,sizeof(state.saved_version),"%s",result.version);snprintf(state.saved_sha256,sizeof(state.saved_sha256),"%s",result.sha256);
    state.candidate_id[0]=0;memset(&candidate,0,sizeof(candidate));pthread_mutex_unlock(&lock);goto done;
native_failed:
    fail(result.error,result.detail,result.code==UPDATE_UNKNOWN);
done:
    if(session[0]) (void)update_abort(request->manifest.candidate_id,session);
    if(reserved)lifecycle_update_install_end();
    free(bytes);http_response_free(&response);
    if(dir>=0) {cleanup_owned(dir,temp,fd);close(dir);}
}
static void* worker(void* opaque) {
    request_t* request=opaque;
    if(!lifecycle_update_worker_enter(request->ticket)) {lifecycle_update_worker_cancel(request->ticket);fail("update_worker_unavailable","Worker admission failed.",false);goto done;}
    if(request->install)install_release(request);
    else {
        pthread_mutex_lock(&lock);
        int64_t now=(int64_t)time(NULL);last_monotonic=monotonic_now();state.last_attempt_unix=now;auto_blocked=false;
        bool recorded=now>0&&last_monotonic>=0&&persist();
        pthread_mutex_unlock(&lock);
        if(recorded)check_release();else fail("update_state_write_failed","The check attempt could not be saved; no request was sent.",false);
    }
    lifecycle_update_worker_leave();
done:
    pthread_mutex_lock(&lock);busy=false;pthread_mutex_unlock(&lock);free(request);return NULL;
}
static bool dispatch(bool install,const char* id,bool automatic) {
    config_t cfg;if(!config_snapshot(&cfg))return false;
    pthread_mutex_lock(&lock);
    int64_t now=(int64_t)time(NULL),mono=monotonic_now();
    bool due=now>0&&mono>=0&&(!state.last_attempt_unix||(now>=state.last_attempt_unix&&now-state.last_attempt_unix>=CHECK_INTERVAL))&&
        (!last_monotonic||(mono>=last_monotonic&&mono-last_monotonic>=CHECK_INTERVAL));
    bool allowed=initialized&&!busy&&(!automatic||(cfg.general.update_auto_check&&!auto_blocked&&due))&&
        (!install||(id&&candidate.candidate_id[0]&&!strcmp(id,candidate.candidate_id)&&strcmp(state.state,"saved")&&strcmp(state.state,"unknown")));
    if(!allowed) {pthread_mutex_unlock(&lock);return false;}
    request_t* request=calloc(1,sizeof(*request));
    if(!request||!lifecycle_update_worker_reserve(&request->ticket)) {free(request);pthread_mutex_unlock(&lock);return false;}
    request->install=install;request->manifest=candidate;snprintf(request->tag,sizeof(request->tag),"%s",candidate_tag);
    busy=true;snprintf(state.state,sizeof(state.state),"%s",install?"installing":"checking");state.error[0]=state.detail[0]=0;
    pthread_t thread;pthread_attr_t attr;bool attr_ready=pthread_attr_init(&attr)==0;
    bool started=attr_ready&&pthread_attr_setdetachstate(&attr,PTHREAD_CREATE_DETACHED)==0&&pthread_create(&thread,&attr,worker,request)==0;
    if(attr_ready)pthread_attr_destroy(&attr);
    if(!started) {lifecycle_update_worker_cancel(request->ticket);free(request);busy=false;snprintf(state.state,sizeof(state.state),"error");snprintf(state.error,sizeof(state.error),"update_worker_unavailable");}
    pthread_mutex_unlock(&lock);return started;
}
bool github_update_check(void) {return dispatch(false,NULL,false);}
bool github_update_install(const char* id) {return dispatch(true,id,false);}
void github_update_tick(void) {(void)dispatch(false,NULL,true);}
