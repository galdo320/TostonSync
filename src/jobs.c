#include "backup_control.h"
#include "jobs.h"
#include <errno.h>
#include <limits.h>
#include <pthread.h>
#include <stdatomic.h>
#include <string.h>
#include <time.h>

typedef struct { jobs_record_t record; char native_id[65]; } jobs_slot_t;
typedef struct { jobs_ref_t ref; char native_id[65]; bool terminal; } jobs_native_t;
static pthread_mutex_t s_jobs_lock = PTHREAD_MUTEX_INITIALIZER;
static jobs_slot_t s_live[JOBS_LIVE_MAX], s_recent[JOBS_RECENT_MAX];
static jobs_native_t s_native[2];
static size_t s_recent_next;
static jobs_ref_t s_watch_highwater;
static atomic_uint_fast64_t s_next = ATOMIC_VAR_INIT(1);
static atomic_uint_fast64_t s_dropped = ATOMIC_VAR_INIT(0);
static _Thread_local jobs_ref_t s_bound;

static void dropped(void) { atomic_fetch_add_explicit(&s_dropped, 1, memory_order_relaxed); }
static bool locked(void) {
    if (pthread_mutex_trylock(&s_jobs_lock) == 0) return true;
    dropped(); return false;
}
static int64_t observed_now(void) { time_t now = time(NULL); return now < 0 ? 0 : (int64_t)now; }
static jobs_slot_t* find_slot(jobs_ref_t ref) {
    for (size_t i=0;i<JOBS_LIVE_MAX;i++) if (s_live[i].record.id==ref) return &s_live[i];
    for (size_t i=0;i<JOBS_RECENT_MAX;i++) if (s_recent[i].record.id==ref) return &s_recent[i];
    return NULL;
}
static bool kind_valid(jobs_kind_t kind) { return kind>=JOB_FULL_BACKUP && kind<=JOB_USB_TEST; }
static int native_index(jobs_kind_t kind) { return kind==JOB_IMPORT ? 0 : kind==JOB_UPDATE ? 1 : -1; }
static bool retired_native(jobs_ref_t ref) {
    for (size_t i=0;i<2;i++) if (s_native[i].ref==ref && s_native[i].terminal) return true;
    return false;
}
static jobs_ref_t next_ref(void) {
    uint64_t value=atomic_load_explicit(&s_next,memory_order_relaxed);
    while (value && value<=UINT64_MAX-2) {
        if (atomic_compare_exchange_weak_explicit(&s_next,&value,value+2,memory_order_relaxed,memory_order_relaxed)) return value;
    }
    dropped(); return 0;
}
static jobs_slot_t* create_slot(jobs_ref_t ref,jobs_kind_t kind) {
    if (retired_native(ref)) return NULL;
    for (size_t i=0;i<JOBS_LIVE_MAX;i++) if (!s_live[i].record.id) {
        jobs_slot_t* slot=&s_live[i]; memset(slot,0,sizeof(*slot));
        slot->record.id=ref; slot->record.kind=kind; slot->record.state=JOB_QUEUED;
        slot->record.updated_unix=observed_now();
        return slot;
    }
    dropped(); return NULL;
}
static bool copy_field(char* out,size_t cap,const char* text,bool code) {
    if (!text) text="";
    size_t length=strnlen(text,cap);
    if (length>=cap) { dropped(); return false; }
    for (size_t i=0;i<length;i++) {
        unsigned char c=(unsigned char)text[i];
        if (c<32 || c==127 || (code && !((c>='a'&&c<='z')||(c>='A'&&c<='Z')||(c>='0'&&c<='9')||c=='_'||c=='-'))) {
            dropped(); return false;
        }
    }
    if (!strcmp(out,text)) return false;
    memcpy(out,text,length+1); return true;
}

jobs_ref_t jobs_watch_id(unsigned long native_id) {
    int saved=errno; jobs_ref_t ref=0;
    if (native_id && (uint64_t)native_id<=UINT64_MAX/2) ref=(uint64_t)native_id<<1;
    else dropped();
    errno=saved; return ref;
}
void jobs_incomplete(void) { int saved=errno; dropped(); errno=saved; }
static void metadata_locked(jobs_slot_t* slot,const char* uid,const char* title,const char* container,const char* destination) {
    if (!slot || slot->record.terminal) return;
    jobs_record_t* r=&slot->record;
    copy_field(r->user_uid,sizeof(r->user_uid),uid,true);
    copy_field(r->title_id,sizeof(r->title_id),title,true);
    copy_field(r->container,sizeof(r->container),container,false);
    copy_field(r->destination,sizeof(r->destination),destination,true);
}
jobs_ref_t jobs_watch_queued(unsigned long native_id,jobs_kind_t kind,const char* uid,const char* title,const char* container,const char* destination) {
    int saved=errno; jobs_ref_t ref=jobs_watch_id(native_id);
    if (ref && kind_valid(kind) && locked()) {
        jobs_slot_t* slot=find_slot(ref);
        if (!slot) {
            if (ref<=s_watch_highwater) dropped();
            else { s_watch_highwater=ref;slot=create_slot(ref,kind); }
        }
        if (slot && slot->record.kind==kind) metadata_locked(slot,uid,title,container,destination);
        else if (slot) dropped();
        pthread_mutex_unlock(&s_jobs_lock);
    }
    errno=saved;return ref;
}
void jobs_queued(jobs_ref_t ref,jobs_kind_t kind,const char* uid,const char* title,const char* container,const char* destination) {
    int saved=errno;
    if (!ref || !kind_valid(kind)) { dropped(); errno=saved; return; }
    if (locked()) {
        jobs_slot_t* slot=find_slot(ref);
        if (!slot && !retired_native(ref)) dropped();
        if (slot && slot->record.kind!=kind) { dropped(); slot=NULL; }
        metadata_locked(slot,uid,title,container,destination);
        pthread_mutex_unlock(&s_jobs_lock);
    }
    errno=saved;
}
jobs_ref_t jobs_begin(jobs_kind_t kind,const char* uid,const char* title,const char* container,const char* destination) {
    int saved=errno; jobs_ref_t ref=next_ref();
    if (!kind_valid(kind)) { dropped();ref=0; }
    if (ref && locked()) {
        metadata_locked(create_slot(ref,kind),uid,title,container,destination);
        pthread_mutex_unlock(&s_jobs_lock);
    }
    errno=saved; return ref;
}
static jobs_ref_t native_lookup_locked(jobs_kind_t kind,const char* native_id,int index) {
    jobs_ref_t ref=0;
    if (!strcmp(s_native[index].native_id,native_id)) ref=s_native[index].ref;
    for (size_t i=0;!ref && i<JOBS_LIVE_MAX;i++)
        if (s_live[i].record.id && s_live[i].record.kind==kind && !strcmp(s_live[i].native_id,native_id)) ref=s_live[i].record.id;
    for (size_t i=0;!ref && i<JOBS_RECENT_MAX;i++)
        if (s_recent[i].record.id && s_recent[i].record.kind==kind && !strcmp(s_recent[i].native_id,native_id)) ref=s_recent[i].record.id;
    return ref;
}
static jobs_ref_t native_locked(jobs_kind_t kind,const char* native_id,size_t length,int index) {
    jobs_ref_t ref=native_lookup_locked(kind,native_id,index);
    if (!ref) {
        ref=next_ref();
        jobs_slot_t* slot=ref ? create_slot(ref,kind) : NULL;
        if (slot) memcpy(slot->native_id,native_id,length+1);
        // Only the current native session remains correlated beyond recent-20.
        jobs_native_t* binding=&s_native[index];
        binding->ref=ref; memcpy(binding->native_id,native_id,length+1); binding->terminal=false;
    }
    return ref;
}
jobs_ref_t jobs_native_lookup(jobs_kind_t kind,const char* native_id) {
    int saved=errno; jobs_ref_t ref=0; int index=native_index(kind);
    size_t length=native_id ? strnlen(native_id,65) : 0;
    if (index>=0 && length && length<65 && pthread_mutex_trylock(&s_jobs_lock)==0) {
        ref=native_lookup_locked(kind,native_id,index);
        pthread_mutex_unlock(&s_jobs_lock);
    }
    errno=saved; return ref;
}
jobs_ref_t jobs_native(jobs_kind_t kind,const char* native_id) {
    int saved=errno; jobs_ref_t ref=0; int index=native_index(kind);
    size_t length=native_id ? strnlen(native_id,65) : 0;
    if (index<0 || !length || length>=65) { dropped(); errno=saved; return 0; }
    if (locked()) { ref=native_locked(kind,native_id,length,index); pthread_mutex_unlock(&s_jobs_lock); }
    errno=saved; return ref;
}
jobs_ref_t jobs_native_observe(jobs_kind_t kind,const char* native_id,jobs_ref_t expected_ref) {
    int saved=errno; jobs_ref_t ref=0; int index=native_index(kind);
    size_t length=native_id ? strnlen(native_id,65) : 0;
    if (index<0 || !length || length>=65) { dropped(); errno=saved; return 0; }
    if (locked()) {
        if (s_native[index].ref==expected_ref) ref=native_locked(kind,native_id,length,index);
        else dropped();
        pthread_mutex_unlock(&s_jobs_lock);
    }
    errno=saved; return ref;
}
bool jobs_tracked(jobs_ref_t ref) {
    int saved=errno; bool found=false;
    if (ref && pthread_mutex_trylock(&s_jobs_lock)==0) { found=find_slot(ref)!=NULL; pthread_mutex_unlock(&s_jobs_lock); }
    errno=saved; return found;
}
jobs_ref_t jobs_native_begin(jobs_kind_t kind,const char* native_id) {
    int saved=errno; jobs_ref_t ref=jobs_native(kind,native_id); int index=native_index(kind);
    if (ref && index>=0 && locked()) {
        jobs_native_t* binding=&s_native[index];
        jobs_slot_t* old=find_slot(ref);
        if ((old && old->record.terminal) || (binding->ref==ref && binding->terminal)) {
            jobs_ref_t next=next_ref(); jobs_slot_t* slot=next?create_slot(next,kind):NULL;
            if (slot) memcpy(slot->native_id,native_id,strlen(native_id)+1);
            binding->ref=next; memcpy(binding->native_id,native_id,strlen(native_id)+1); binding->terminal=false;
            ref=next;
        }
        pthread_mutex_unlock(&s_jobs_lock);
    } else ref=0;
    errno=saved; return ref;
}
jobs_ref_t jobs_native_current(jobs_kind_t kind) {
    int saved=errno; int index=native_index(kind); jobs_ref_t ref=0;
    if (index>=0 && pthread_mutex_trylock(&s_jobs_lock)==0) {
        ref=s_native[index].ref;
        pthread_mutex_unlock(&s_jobs_lock);
    }
    errno=saved; return ref;
}
void jobs_native_absent(jobs_kind_t kind,jobs_ref_t expected_ref) {
    int saved=errno; int index=native_index(kind); jobs_ref_t ref=0;
    if (expected_ref && index>=0 && locked()) {
        if (!s_native[index].terminal && s_native[index].ref==expected_ref) ref=expected_ref;
        pthread_mutex_unlock(&s_jobs_lock);
    }
    if (ref) jobs_finish(ref,JOB_UNKNOWN,"session_disappeared");
    errno=saved;
}
jobs_ref_t jobs_bind(jobs_ref_t ref) { jobs_ref_t old=s_bound; s_bound=ref; return old; }
jobs_ref_t jobs_bound(void) { return s_bound; }
void jobs_phase(jobs_ref_t ref,const char* destination,const char* phase,uint64_t total,bool total_known) {
    int saved=errno;
    if (ref && locked()) {
        jobs_slot_t* slot=find_slot(ref);
        if (!slot && !retired_native(ref)) dropped();
        if (slot && !slot->record.terminal) {
            jobs_record_t* r=&slot->record;
            bool changed=copy_field(r->destination,sizeof(r->destination),destination,true);
            changed=copy_field(r->phase,sizeof(r->phase),phase,true)||changed;
            if (changed) { r->phase_epoch++; r->bytes_done=0; r->bytes_known=false; r->bytes_total=total_known?total:0; r->total_known=total_known; }
            else if (r->total_known!=total_known || (total_known&&r->bytes_total!=total)) {
                r->bytes_total=total_known?total:0; r->total_known=total_known; changed=true;
            }
            if (r->state==JOB_QUEUED) { r->state=JOB_RUNNING; r->started_unix=observed_now(); changed=true; }
            if (changed) r->updated_unix=observed_now();
        }
        pthread_mutex_unlock(&s_jobs_lock);
    }
    errno=saved;
}
static void progress_locked(jobs_record_t* r,uint64_t done,uint64_t total,bool total_known) {
    if (r->terminal) return;
    if (total_known && done>total) { dropped(); return; }
    bool changed=!r->bytes_known || r->bytes_done!=done || r->total_known!=total_known || (total_known&&r->bytes_total!=total);
    if (r->bytes_known && done<r->bytes_done) r->phase_epoch++;
    r->bytes_done=done; r->bytes_known=true; r->bytes_total=total_known?total:0; r->total_known=total_known;
    if (changed) r->updated_unix=observed_now();
}
void jobs_progress(uint64_t done,uint64_t total,bool total_known) {
    int saved=errno;
    if (s_bound && locked()) {
        jobs_slot_t* slot=find_slot(s_bound);
        if (slot) progress_locked(&slot->record,done,total,total_known);
        else if (!retired_native(s_bound)) dropped();
        pthread_mutex_unlock(&s_jobs_lock);
    }
    errno=saved;
}
void jobs_progress_add(uint64_t bytes) {
    int saved=errno;
    if (s_bound && locked()) {
        jobs_slot_t* slot=find_slot(s_bound);
        if (!slot && !retired_native(s_bound)) dropped();
        if (slot && !slot->record.terminal) {
            jobs_record_t* r=&slot->record;
            if (bytes>UINT64_MAX-r->bytes_done) dropped();
            else progress_locked(r,r->bytes_done+bytes,r->bytes_total,r->total_known);
        }
        pthread_mutex_unlock(&s_jobs_lock);
    }
    errno=saved;
}
void jobs_note_saved(unsigned mask) {
    int saved=errno;
    if(s_bound && locked()){
        jobs_slot_t* slot=find_slot(s_bound);
        if(slot && !slot->record.terminal)slot->record.saved_destinations|=mask&7U;
        pthread_mutex_unlock(&s_jobs_lock);
    }
    errno=saved;
}
static bool detail_literal(const char** p,const char* literal) {
    size_t n=strlen(literal);
    if (strncmp(*p,literal,n)) return false;
    *p+=n; return true;
}
static bool detail_size(const char** p) {
    const char* start=*p; size_t digits=0;
    while (**p>='0' && **p<='9' && digits<20) { (*p)++; digits++; }
    if (!digits) return false;
    if (**p=='.') {
        (*p)++;
        if ((*p)[0]<'0'||(*p)[0]>'9'||(*p)[1]<'0'||(*p)[1]>'9') { *p=start; return false; }
        *p+=2;
    }
    if (detail_literal(p," GB") || detail_literal(p," MB") || detail_literal(p," bytes")) return true;
    *p=start; return false;
}
static bool detail_integer(const char** p) {
    size_t digits=0;
    while (**p>='0' && **p<='9' && digits<20) { (*p)++; digits++; }
    return digits && !(**p>='0' && **p<='9');
}
static bool detail_part(const char** p) {
    const char* probe = *p;
    if (detail_literal(p,"USB write test completed") ||
        detail_literal(p,"USB write test partial: phase deadline reached") ||
        detail_literal(p,"USB write test canceled") || detail_literal(p,"USB write test failed; inspect logs")) {
        if (detail_literal(p,"; 64 KiB: ") && detail_integer(p) && detail_literal(p," B, write ") &&
            detail_integer(p) && detail_literal(p," ms, fsync ") && detail_integer(p) &&
            detail_literal(p," ms; 1 MiB: ") && detail_integer(p) && detail_literal(p," B, write ") &&
            detail_integer(p) && detail_literal(p," ms, fsync ") && detail_integer(p) && detail_literal(p," ms")) return true;
        *p = probe;return false;
    }
    *p = probe;
    static const char* fixed[]={
        "USB: copy failed; no automatic retry",
        "USB: choose the drive or start a manual backup to identify it",
        "USB: drive is read-only; no automatic retry",
        "USB: drive cannot be used; unlock it if protected",
        "USB: unsupported format; use exFAT",
        "USB: this backup will not fit",
        "USB: backup exceeds the file size limit; use exFAT",
        "USB: drive changed or disconnected; no automatic retry",
        "USB: read failed; no automatic retry",
        "USB: write failed; no automatic retry",
        "USB: backup could not be confirmed; no automatic retry",
        "USB: disabled","USB: not connected","USB: copy failed",
        "FTP: disabled","FTP: host not configured","FTP: upload failed",
        "Google Drive: not signed in","Google Drive: client not configured",
        "Google Drive: connection not ready","Google Drive: upload failed",
        "USB: complete · Google Drive: complete","USB: complete · Google Drive: failed",
        "No backup destinations are enabled. Enable USB, FTP, or Google Drive in Settings.",
        "No backup destinations are enabled. Enable USB or Google Drive in Settings.",
        "Backup canceled by user; no automatic retry",
        "Backup copied but confirmation could not be saved",
        "Cancel request could not be saved; recovery after restart is uncertain",
        "Backup already in flight","Destinations already have this fingerprint",
        "Restore is settling","Excluded by backup settings","Save is no longer registered"
    };
    for (size_t i=0;i<sizeof(fixed)/sizeof(fixed[0]);i++) if (detail_literal(p,fixed[i])) return true;
    if (detail_literal(p,"Saved to ")) {
        for (size_t count=0;count<3;count++) {
            if (!detail_literal(p,"drive")&&!detail_literal(p,"usb")&&!detail_literal(p,"ftp")) return false;
            if (**p!=',') return true;
            (*p)++;
        }
        return false;
    }
    const char* start=*p;
    if (detail_literal(p,"Google Drive: global backup size limit reached (") &&
        detail_size(p) && detail_literal(p," of ") && detail_size(p) &&
        detail_literal(p," used; this backup is ") && detail_size(p) &&
        detail_literal(p,"). Raise the limit in Settings or delete old backups.")) return true;
    *p=start;
    if (detail_literal(p,"Google Drive: global backup size limit reached (") &&
        detail_integer(p) && detail_literal(p," of ") && detail_integer(p) &&
        detail_literal(p," bytes used; this backup is ") && detail_integer(p) &&
        detail_literal(p," bytes). Raise the limit in Settings or delete old backups.")) return true;
    *p=start;
    if (detail_literal(p,"Google Drive: per-title backup size limit reached (this backup is ") &&
        detail_size(p) && detail_literal(p,"; limit is ") && detail_size(p) &&
        detail_literal(p,"). Raise the limit in Settings or delete old backups.")) return true;
    *p=start; return false;
}
void jobs_backup_detail(jobs_ref_t ref,const char* detail) {
    int saved=errno;
    if (!ref || !detail || !detail[0] || strnlen(detail,768)>=768) { errno=saved; return; }
    const char* p=detail; bool valid=false;
    for (size_t parts=0;parts<5;parts++) {
        if (!detail_part(&p)) break;
        if (!*p) { valid=true; break; }
        if (!detail_literal(&p,"; ")) break;
    }
    if (valid && locked()) {
        jobs_slot_t* slot=find_slot(ref);
        if (slot && !slot->record.terminal && (slot->record.kind==JOB_FULL_BACKUP || slot->record.kind==JOB_USB_TEST))
            memcpy(slot->record.backup_detail,detail,strlen(detail)+1);
        pthread_mutex_unlock(&s_jobs_lock);
    }
    errno=saved;
}
void jobs_finish(jobs_ref_t ref,jobs_state_t state,const char* error) {
    int saved=errno;
    if (state!=JOB_DONE && state!=JOB_FAILED && state!=JOB_UNKNOWN) { dropped(); errno=saved; return; }
    if (ref && locked()) {
        jobs_slot_t* slot=find_slot(ref);
        if (!slot && !retired_native(ref)) dropped();
        if (slot && !slot->record.terminal) {
            jobs_record_t* r=&slot->record;
            backup_control_t* control=backup_control_bound();
            if(control && control->id==ref)r->saved_destinations|=backup_control_saved();
            r->state=state; r->terminal=true; r->finished_unix=r->updated_unix=observed_now();
            copy_field(r->error,sizeof(r->error),error,true);
            for (size_t i=0;i<2;i++) if (s_native[i].ref==ref) s_native[i].terminal=true;
            s_recent[s_recent_next]=*slot; s_recent_next=(s_recent_next+1)%JOBS_RECENT_MAX;
            memset(slot,0,sizeof(*slot));
        }
        pthread_mutex_unlock(&s_jobs_lock);
    }
    errno=saved;
}
bool jobs_snapshot(jobs_snapshot_t* out) {
    int saved=errno; bool ok=false;
    if (!out) { errno=saved; return false; }
    memset(out,0,sizeof(*out));
    if (pthread_mutex_trylock(&s_jobs_lock)==0) {
        for (size_t i=0;i<JOBS_LIVE_MAX;i++) if (s_live[i].record.id) out->items[out->count++]=s_live[i].record;
        for (size_t i=0;i<JOBS_RECENT_MAX;i++) {
            jobs_slot_t* slot=&s_recent[(s_recent_next+i)%JOBS_RECENT_MAX];
            if (slot->record.id) out->items[out->count++]=slot->record;
        }
        pthread_mutex_unlock(&s_jobs_lock); ok=true;
    }
    out->dropped_observations=atomic_load_explicit(&s_dropped,memory_order_relaxed);
    out->complete=ok && !out->dropped_observations;
    errno=saved; return ok;
}
const char* jobs_kind_name(jobs_kind_t kind) {
    static const char* names[]={"full_backup","individual_backup","restore","import","update","usb_test"};
    return kind_valid(kind)?names[kind]:"unknown";
}
const char* jobs_state_name(jobs_state_t state) {
    static const char* names[]={"queued","running","done","failed","unknown"};
    return state>=JOB_QUEUED && state<=JOB_UNKNOWN?names[state]:"unknown";
}
#ifdef JOBS_TEST
void jobs_test_reset(void) {
    pthread_mutex_lock(&s_jobs_lock); memset(s_live,0,sizeof(s_live)); memset(s_recent,0,sizeof(s_recent)); memset(s_native,0,sizeof(s_native));
    s_recent_next=0; s_watch_highwater=0; atomic_store(&s_next,1); atomic_store(&s_dropped,0); s_bound=0; pthread_mutex_unlock(&s_jobs_lock);
}
void jobs_test_lock(bool lock) { if (lock) pthread_mutex_lock(&s_jobs_lock); else pthread_mutex_unlock(&s_jobs_lock); }
#endif


// Command state is owned by the live worker, never created by GET or job history.
static pthread_mutex_t s_backup_control_lock = PTHREAD_MUTEX_INITIALIZER;
static backup_control_t* s_backup_controls;
static _Thread_local backup_control_t* s_backup_bound;
bool backup_control_begin(backup_control_t* c, uint64_t id) {
    if (!c) return false;
    if (!id) {c->id=0;c->cancel_result=0;atomic_init(&c->published,0);atomic_init(&c->state,0);c->next=NULL;return true;}
    pthread_mutex_lock(&s_backup_control_lock);
    for (backup_control_t* p=s_backup_controls;p;p=p->next) if (p->id==id) {
        pthread_mutex_unlock(&s_backup_control_lock); return false;
    }
    c->id=id; c->cancel_result=0; atomic_init(&c->published,0); atomic_init(&c->state,0); c->next=s_backup_controls; s_backup_controls=c;
    pthread_mutex_unlock(&s_backup_control_lock); return true;
}
void backup_control_end(backup_control_t* c) {
    pthread_mutex_lock(&s_backup_control_lock);
    backup_control_t** p=&s_backup_controls;
    while (*p && *p!=c) p=&(*p)->next;
    if (*p) *p=c->next;
    pthread_mutex_unlock(&s_backup_control_lock);
}
backup_control_t* backup_control_bind(backup_control_t* c) {
    backup_control_t* previous=s_backup_bound; s_backup_bound=c; return previous;
}
backup_control_t* backup_control_bound(void) { return s_backup_bound; }
bool backup_control_request(uint64_t id) {
    bool accepted=false;
    // Never wait behind filesystem I/O: this lock protects only stack ownership.
    if (pthread_mutex_trylock(&s_backup_control_lock)) return false;
    for (backup_control_t* p=s_backup_controls;p;p=p->next) if (p->id==id) {
        int running=0;
        accepted=atomic_compare_exchange_strong(&p->state,&running,1) || running==1;
        break;
    }
    pthread_mutex_unlock(&s_backup_control_lock); return accepted;
}
bool backup_control_observe(uint64_t id, backup_control_status_t* out) {
    int saved=errno;
    if (!out) return false;
    memset(out,0,sizeof(*out));
    // This list lock covers memory only; no filesystem or provider call holds it.
    if (pthread_mutex_lock(&s_backup_control_lock)) { errno=saved;return false; }
    for (backup_control_t* p=s_backup_controls;p;p=p->next) if (p->id==id) {
        int state=atomic_load(&p->state);
        out->active=true;out->requested=state==1;out->publishing=state>=2;
        out->saved=atomic_load(&p->published);break;
    }
    pthread_mutex_unlock(&s_backup_control_lock);errno=saved;return true;
}
bool backup_control_cancelled(void) { return s_backup_bound && atomic_load(&s_backup_bound->state)==1; }
bool backup_control_finish_begin(void) {
    if(!s_backup_bound)return false;
    int state=atomic_load(&s_backup_bound->state);
    while(state==0||state==3){
        if(atomic_compare_exchange_weak(&s_backup_bound->state,&state,4))return false;
    }
    return state==1;
}
bool backup_control_publish_begin(void) {
    if (!s_backup_bound) return true;
    int running=atomic_load(&s_backup_bound->state);
    return (running==0 || running==3) && atomic_compare_exchange_strong(&s_backup_bound->state,&running,2);
}
unsigned backup_control_saved(void) {return s_backup_bound?atomic_load(&s_backup_bound->published):0;}
void backup_control_publish_end(bool published, unsigned destination_mask) {
    if (s_backup_bound) {
        if (published) {atomic_fetch_or(&s_backup_bound->published,destination_mask&7U);jobs_note_saved(destination_mask);}
        atomic_store(&s_backup_bound->state,0);
    }
}
