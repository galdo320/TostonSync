// Private restore evidence: rename only; no old snapshot is disposable scratch.
#pragma once
#include "at_io.h"
#include <ctype.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <dirent.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <time.h>
#include <unistd.h>

static inline bool rollback_archive_existing(const char* path, char* err, size_t n) {
    struct stat st;
    if (lstat(path,&st)) {
        if (errno==ENOENT) return true;
        goto failed;
    }
    if (!S_ISDIR(st.st_mode)&&!S_ISREG(st.st_mode)) goto failed;
    char date[32],archive[1024],snapshot[1100];struct tm when;
    if (!gmtime_r(&st.st_mtime,&when) ||
        !strftime(date,sizeof(date),"%Y-%m-%d_%H-%M-%SZ",&when)) goto failed;
    int len=snprintf(archive,sizeof(archive),"%s.saved-%s-XXXXXX",path,date);
    if (len<0||(size_t)len>=sizeof(archive)||!mkdtemp(archive)) goto failed;
    snprintf(snapshot,sizeof(snapshot),"%s/snapshot",archive);
    if (rename(path,snapshot)) {int e=errno;rmdir(archive);errno=e;goto failed;}
    // The archive is a sibling, outside every recovery-pending namespace.
    sync();return true;
failed:
    if (err&&n) snprintf(err,n,"Could not archive previous restore evidence (errno=%d); nothing may be overwritten",errno);
    return false;
}

// Read-only and fail closed on symlinks, unknown types, overflow or unreadable entries.
static inline bool rollback_tree_observe(const char* path,uint64_t* bytes,size_t* images,unsigned depth) {
    struct stat st;if(depth>32||lstat(path,&st))return false;
    if(S_ISREG(st.st_mode)) {
        if(st.st_size<0||UINT64_MAX-*bytes<(uint64_t)st.st_size)return false;
        *bytes+=(uint64_t)st.st_size;
        const char* leaf=strrchr(path,'/');leaf=leaf?leaf+1:path;
        if(images&&(!strncmp(leaf,"sdimg_",6)||!strcmp(leaf,"savedata0.bin"))) (*images)++;
        return true;
    }
    if(!S_ISDIR(st.st_mode))return false;
    int fd=open(path,O_RDONLY|O_DIRECTORY|O_NOFOLLOW);if(fd<0)return false;
    DIR* d=fdopendir(fd);if(!d){close(fd);return false;}
    bool ok=true;struct dirent* e;
    for(;;){errno=0;e=readdir(d);if(!e){if(errno)ok=false;break;}
        if(!strcmp(e->d_name,".")||!strcmp(e->d_name,".."))continue;
        char child[1024];int len=snprintf(child,sizeof(child),"%s/%s",path,e->d_name);
        if(len<0||(size_t)len>=sizeof(child)||!rollback_tree_observe(child,bytes,images,depth+1)){ok=false;break;}
    }
    if(closedir(d))ok=false;return ok;
}
static inline bool rollback_tree_size(const char* path,uint64_t* bytes,unsigned depth) {
    return rollback_tree_observe(path,bytes,NULL,depth);
}
static inline bool rollback_snapshot_space(const char* source,const char* destination,
                                           char* err,size_t n) {
    uint64_t need=0;char parent[1024];struct statvfs space;
    int len=snprintf(parent,sizeof(parent),"%s",destination);
    if(len<0||(size_t)len>=sizeof(parent))goto unknown;
    char* slash=strrchr(parent,'/');if(slash){if(slash==parent)slash[1]=0;else *slash=0;}else strcpy(parent,".");
    if(!rollback_tree_size(source,&need,0)||statvfs(parent,&space)||!space.f_frsize||
        (uint64_t)space.f_bavail>UINT64_MAX/(uint64_t)space.f_frsize||need>UINT64_MAX-1048576)goto unknown;
    need+=1048576; // Snapshot bytes plus directory/journal margin, never reclaim old evidence.
    uint64_t available=(uint64_t)space.f_bavail*(uint64_t)space.f_frsize;
    if(available>=need)return true;
    if(err&&n)snprintf(err,n,"Not enough space for rollback snapshot: missing %llu bytes; no saves changed",(unsigned long long)(need-available));
    return false;
unknown:
    if(err&&n)snprintf(err,n,"Rollback snapshot space could not be verified (errno=%d); no saves changed",errno);
    return false;
}

// Only the exact archive shape produced above is deletable. All traversal and
// unlink operations remain relative to held no-follow descriptors.
static inline bool rollback_archive_shape(int fd) {
    int copy=toston_openat(fd,".",O_RDONLY|O_DIRECTORY|O_NOFOLLOW,0);if(copy<0)return false;DIR* d=fdopendir(copy);
    if(!d){close(copy);return false;}bool found=false,ok=true;
    for(;;){errno=0;struct dirent* e=readdir(d);if(!e){if(errno)ok=false;break;}
        if(!strcmp(e->d_name,".")||!strcmp(e->d_name,".."))continue;
        if(strcmp(e->d_name,"snapshot")||found){ok=false;break;}
        struct stat st;if(toston_fstatat(fd,"snapshot",&st,AT_SYMLINK_NOFOLLOW)||
            (!S_ISREG(st.st_mode)&&!S_ISDIR(st.st_mode))){ok=false;break;}found=true;
    }
    if(closedir(d))ok=false;return ok&&found;
}
static inline bool rollback_delete_entries(int fd,unsigned depth) {
    if(depth>32)return false;int copy=toston_openat(fd,".",O_RDONLY|O_DIRECTORY|O_NOFOLLOW,0);if(copy<0)return false;
    DIR* d=fdopendir(copy);if(!d){close(copy);return false;}bool ok=true;
    for(;;){errno=0;struct dirent* e=readdir(d);if(!e){if(errno)ok=false;break;}
        if(!strcmp(e->d_name,".")||!strcmp(e->d_name,".."))continue;
        struct stat before,after;
        if(toston_fstatat(fd,e->d_name,&before,AT_SYMLINK_NOFOLLOW)){ok=false;break;}
        if(S_ISDIR(before.st_mode)){
            int child=toston_openat(fd,e->d_name,O_RDONLY|O_DIRECTORY|O_NOFOLLOW,0);
            struct stat held;
            if(child<0){ok=false;break;}
            ok=!fstat(child,&held)&&held.st_dev==before.st_dev&&held.st_ino==before.st_ino&&rollback_delete_entries(child,depth+1);
            if(close(child))ok=false;
        }else if(!S_ISREG(before.st_mode))ok=false;
        if(!ok||toston_fstatat(fd,e->d_name,&after,AT_SYMLINK_NOFOLLOW)||
            after.st_dev!=before.st_dev||after.st_ino!=before.st_ino||
            unlinkat(fd,e->d_name,S_ISDIR(before.st_mode)?AT_REMOVEDIR:0)){ok=false;break;}
    }
    if(closedir(d))ok=false;return ok;
}
static inline bool rollback_delete_archive(const char* parent,const char* name) {
    int root=open(parent,O_RDONLY|O_DIRECTORY|O_NOFOLLOW);if(root<0)return false;
    int archive=toston_openat(root,name,O_RDONLY|O_DIRECTORY|O_NOFOLLOW,0);
    struct stat held,named;bool ok=archive>=0&&!fstat(archive,&held)&&rollback_archive_shape(archive);
    // No deletion starts unless the pathname still names the inspected archive.
    ok=ok&&!toston_fstatat(root,name,&named,AT_SYMLINK_NOFOLLOW)&&held.st_dev==named.st_dev&&held.st_ino==named.st_ino;
    if(ok)ok=rollback_delete_entries(archive,0);
    ok=ok&&!toston_fstatat(root,name,&named,AT_SYMLINK_NOFOLLOW)&&held.st_dev==named.st_dev&&held.st_ino==named.st_ino;
    if(ok)ok=!unlinkat(root,name,AT_REMOVEDIR)&&!fsync(root);
    if(archive>=0&&close(archive))ok=false;if(close(root))ok=false;return ok;
}
