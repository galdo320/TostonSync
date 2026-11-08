#include "instance_lock.h"
#include "lifecycle.h"

#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static pthread_mutex_t s_lock_mutex=PTHREAD_MUTEX_INITIALIZER;
static int s_lock_fd=-1;
static bool s_close_uncertain;

static bool lock_failure(instance_lock_diagnostic_t* out,const char* stage,
        const char* operation,const char* reason,int result,bool error_known,int error) {
    if(out) *out=(instance_lock_diagnostic_t){stage,operation,reason,result,error,true,error_known};
    return false;
}

static bool lock_file_valid(const struct stat* st) {
    return S_ISREG(st->st_mode) && st->st_nlink==1 && st->st_uid==geteuid() && !(st->st_mode&077);
}

bool instance_lock_acquire(instance_lock_diagnostic_t* out) {
    if(out) memset(out,0,sizeof(*out));
    pthread_mutex_lock(&s_lock_mutex);
    if(s_lock_fd>=0 || s_close_uncertain) {
        lock_failure(out,"INSTANCE_LOCK_HELD","reservation","instance_lock_already_held",0,false,0);
        pthread_mutex_unlock(&s_lock_mutex); return false;
    }
    struct stat parent;
    int result=lstat(INSTANCE_LOCK_DIRECTORY,&parent);
    int error=result==-1?errno:0;
    if(result!=0) {
        lock_failure(out,"INSTANCE_LOCK_PARENT","lstat","instance_lock_parent_unavailable",result,result==-1,error);
        pthread_mutex_unlock(&s_lock_mutex); return false;
    }
    if(!S_ISDIR(parent.st_mode) || parent.st_uid!=geteuid() || (parent.st_mode&022)) {
        lock_failure(out,"INSTANCE_LOCK_PARENT","lstat","instance_lock_parent_unsafe",0,false,0);
        pthread_mutex_unlock(&s_lock_mutex); return false;
    }
    char canonical[1024];
    if(!realpath(INSTANCE_LOCK_DIRECTORY,canonical)) {
        error=errno;
        lock_failure(out,"INSTANCE_LOCK_PARENT","realpath","instance_lock_parent_unknown",-1,true,error);
        pthread_mutex_unlock(&s_lock_mutex); return false;
    }
    if(strcmp(canonical,INSTANCE_LOCK_DIRECTORY)) {
        lock_failure(out,"INSTANCE_LOCK_PARENT","realpath","instance_lock_parent_unsafe",0,false,0);
        pthread_mutex_unlock(&s_lock_mutex); return false;
    }
    int fd=open(INSTANCE_LOCK_PATH,O_RDWR|O_CREAT|O_NOFOLLOW|O_NONBLOCK,0600);
    error=fd==-1?errno:0;
    if(fd<0) {
        lock_failure(out,"INSTANCE_LOCK_OPEN","open","instance_lock_unavailable",fd,fd==-1,error);
        pthread_mutex_unlock(&s_lock_mutex); return false;
    }
    struct stat st;
    result=fstat(fd,&st); error=result==-1?errno:0;
    if(result!=0 || !lock_file_valid(&st)) {
        lock_failure(out,"INSTANCE_LOCK_FILE","fstat","instance_lock_file_unsafe",result,result==-1,error);
        close(fd); pthread_mutex_unlock(&s_lock_mutex); return false;
    }
    int flags=fcntl(fd,F_GETFD);
    error=flags==-1?errno:0;
    if(flags<0) {
        lock_failure(out,"INSTANCE_LOCK_FLAGS","fcntl_getfd","instance_lock_unavailable",flags,flags==-1,error);
        close(fd); pthread_mutex_unlock(&s_lock_mutex); return false;
    }
    result=fcntl(fd,F_SETFD,flags|FD_CLOEXEC); error=result==-1?errno:0;
    if(result!=0) {
        lock_failure(out,"INSTANCE_LOCK_FLAGS","fcntl_setfd","instance_lock_unavailable",result,result==-1,error);
        close(fd); pthread_mutex_unlock(&s_lock_mutex); return false;
    }
    result=flock(fd,LOCK_EX|LOCK_NB); error=result==-1?errno:0;
    if(result!=0) {
        lock_failure(out,"INSTANCE_LOCK_FLOCK","flock",
            result==-1 && (error==EWOULDBLOCK || error==EAGAIN)?"instance_lock_busy":"instance_lock_unknown",
            result,result==-1,error);
        close(fd); pthread_mutex_unlock(&s_lock_mutex); return false;
    }
    struct stat current;
    result=lstat(INSTANCE_LOCK_PATH,&current); error=result==-1?errno:0;
    if(result!=0 || !lock_file_valid(&current) || current.st_dev!=st.st_dev || current.st_ino!=st.st_ino) {
        lock_failure(out,"INSTANCE_LOCK_RECHECK","lstat","instance_lock_path_changed",result,result==-1,error);
        close(fd); pthread_mutex_unlock(&s_lock_mutex); return false;
    }
    s_lock_fd=fd;
    if(out) *out=(instance_lock_diagnostic_t){"INSTANCE_LOCK_ACQUIRED","flock","cooperative_lock_acquired",0,0,true,false};
    pthread_mutex_unlock(&s_lock_mutex); return true;
}

bool instance_lock_release(void) {
    pthread_mutex_lock(&s_lock_mutex);
    if(s_close_uncertain || lifecycle_operations()!=0) {
        errno=s_close_uncertain?EIO:EBUSY;
        pthread_mutex_unlock(&s_lock_mutex); return false;
    }
    if(s_lock_fd>=0) {
        int result=close(s_lock_fd),error=result==-1?errno:0;
        s_lock_fd=-1;
        if(result!=0) {
            s_close_uncertain=true;
            if(result==-1) errno=error;
            pthread_mutex_unlock(&s_lock_mutex); return false;
        }
    }
    pthread_mutex_unlock(&s_lock_mutex); return true;
}
