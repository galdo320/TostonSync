// TostónSync — USB / external-drive backup backend. See usb.h.

#include "usb.h"
#include "jobs.h"
#include "backup_control.h"
#include <time.h>
#include "protect.h"
#include "config.h"
#include "log.h"
#include "fs.h"
#include "json.h"
#include "dest_dedup.h"
#include "at_io.h"
#include "backup_names.h"
#include "sha256.h"
#include "retention.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdatomic.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <sys/types.h>
#include <unistd.h>

#if (defined(__APPLE__) || defined(__FreeBSD__)) && \
    !defined(USB_NO_BSD_STATFS)
#include <sys/mount.h>
#define USB_HAVE_BSD_STATFS 1
#endif

static const config_t* s_cfg = NULL;
static _Atomic uint64_t s_largest_backup;
static pthread_mutex_t s_selection_lock = PTHREAD_MUTEX_INITIALIZER;
static usb_mount_t s_last_selected;

// Per-operation config snapshot, thread-local so two backup workers never
// collide. Refreshed at each public entry point; CFG reads it (falling back to
// the live pointer). Closes the window where config_apply_json mutates the
// live config in place while a backup reads usb.folder/mount_path/retention
// (audit #4) — including reads inside helpers like usb_folder().
// Thread-local STORAGE (not a pointer to a stack local) so it can never
// dangle when usb_detect()/usb_folder() are reused as helpers within a larger
// op. CFG reads the snapshot once one has been taken on this thread.
static _Thread_local config_t s_cfg_store;
static _Thread_local bool     s_cfg_have = false;
#define CFG (s_cfg_have ? &s_cfg_store : s_cfg)
#define USB_CFG_BEGIN() do { s_cfg_have = config_snapshot(&s_cfg_store); } while (0)

static const char* usb_folder(void);

// PS5 mounts USB mass storage as /mnt/usb0 .. /mnt/usb7. Overridable at
// build time (e.g. -DUSB_MOUNT_BASE="\"/mnt/ext\"") for unusual setups
// and for host tests.
#ifndef USB_MOUNT_BASE
#define USB_MOUNT_BASE "/mnt/usb"
#endif

// Mounted-filesystem metadata distinguishes real mounts from empty slots;
// capacity and a model name never identify an encrypted helper partition.
#if defined(__FreeBSD__) && defined(USB_HAVE_BSD_STATFS)
_Static_assert(sizeof(struct statfs) == 472, "SDK v0.43 statfs size");
_Static_assert(offsetof(struct statfs, f_flags) == 8, "statfs flags");
_Static_assert(offsetof(struct statfs, f_blocks) == 32, "statfs blocks");
_Static_assert(offsetof(struct statfs, f_bavail) == 48, "statfs available");
_Static_assert(offsetof(struct statfs, f_fsid) == 192, "statfs identity");
_Static_assert(offsetof(struct statfs, f_fstypename) == 280, "statfs type");
_Static_assert(offsetof(struct statfs, f_mntfromname) == 296, "statfs device");
_Static_assert(offsetof(struct statfs, f_mntonname) == 384, "statfs mount");
#endif

#define USB_WRITE_RESERVE (UINT64_C(1024) * 1024)
static _Thread_local const char* s_copy_failure = "";
static bool usb_volume_identity(int dirfd, const char* mount, char out[65]);
static bool usb_marker(int dirfd, const char* name, bool create, char out[65]);
static void usb_observe_identity(usb_mount_t* mount);
static bool usb_mount_same(int,const usb_mount_t*,uint64_t,bool);
static _Thread_local int s_write_mountfd=-1;
static _Thread_local usb_mount_t s_write_mount;
static bool usb_write_revalidate(int,const char*);
static bool usb_mkdir_relative(int,const char*);
static size_t usb_observe_snapshot_current(usb_mount_t*,usb_mount_t*,size_t);
static int usb_write_root(int);
void usb_note_backup_size(uint64_t bytes) {
    uint64_t largest=atomic_load(&s_largest_backup);
    while (largest < bytes && !atomic_compare_exchange_weak(&s_largest_backup,&largest,bytes)) {}
}
const char* usb_last_copy_failure(void) { return s_copy_failure; }
const char* usb_state_name(usb_state_t state) {
    static const char* names[] = {"ready", "low_space", "full", "read_only", "locked",
        "not_usable", "unsupported_format", "not_connected"};
    return (unsigned)state < sizeof(names)/sizeof(names[0]) ? names[state] : "not_usable";
}

void usb_classify_mount(usb_mount_t* m, uint64_t incoming, bool known) {
    if (!m) return;
    if (!m->path[0]) { m->state = USB_NOT_CONNECTED; strcpy(m->reason, "not_connected"); return; }
    if (!strcmp(m->reason, "auxiliary_partition")) { m->state = USB_NOT_USABLE; return; }
    if (!m->space_known || !m->total_bytes) {
        m->state = USB_NOT_USABLE; strcpy(m->reason, "observation_incomplete"); return;
    }
    if (!strcmp(m->fs_type,"ntfs") || !strcmp(m->fs_type,"apfs") ||
        !strcmp(m->fs_type,"hfs") || !strcmp(m->fs_type,"ext4")) {
        m->state = USB_UNSUPPORTED_FORMAT; strcpy(m->reason, "unsupported_format"); return;
    }
    bool exfat = !strcmp(m->fs_type,"exfat") || !strcmp(m->fs_type,"exfatfs");
    bool fat = !strcmp(m->fs_type,"msdosfs") || !strcmp(m->fs_type,"fat32") || !strcmp(m->fs_type,"vfat");
    if (!exfat && !fat) { m->state = USB_NOT_USABLE; strcpy(m->reason,"filesystem_not_identified"); return; }
    m->max_file_bytes = fat ? UINT32_MAX : UINT64_MAX;
    if (!m->writable || (m->mount_flags & 1U)) {
        m->state = USB_READ_ONLY; strcpy(m->reason, "read_only"); return;
    }
    if ((known && incoming > m->max_file_bytes) || m->free_bytes <= USB_WRITE_RESERVE ||
        (known && incoming > m->free_bytes - USB_WRITE_RESERVE)) {
        m->state = USB_FULL; strcpy(m->reason, known && incoming > m->max_file_bytes ? "file_too_large" : "full"); return;
    }
    // Budget plus 10%, at least the write reserve; capacity percentage is irrelevant.
    uint64_t budget=CFG?retention_parse_size(CFG->retention.max_total_size_global_str):0;
    if (!budget) budget = known && incoming ? incoming : atomic_load(&s_largest_backup);
    uint64_t margin=budget/10>USB_WRITE_RESERVE?budget/10:USB_WRITE_RESERVE;
    uint64_t warning=budget>UINT64_MAX-margin?UINT64_MAX:budget+margin;
    m->state = budget && m->free_bytes < warning ? USB_LOW_SPACE : USB_READY;
    strcpy(m->reason, m->state == USB_LOW_SPACE ? "low_space" : budget ? "ready" : "estimate_unknown");
}

static bool usb_mount_is_usable(const usb_mount_t* m) {
    return m && (m->state == USB_READY || m->state == USB_LOW_SPACE);
}

static bool usb_mount_is_readable(const usb_mount_t* m) {
    return usb_mount_is_usable(m) || (m && (m->state == USB_FULL || m->state == USB_READ_ONLY));
}

void usb_init(const config_t* cfg) {
    s_cfg = cfg;
    atomic_store(&s_largest_backup, 0);
    pthread_mutex_lock(&s_selection_lock);
    memset(&s_last_selected, 0, sizeof(s_last_selected));
    pthread_mutex_unlock(&s_selection_lock);
}

static bool usb_mount_path_allowed(const char* p) {
    if (!p || !p[0] || strcmp(p, "auto") == 0) return true;
    size_t base_len = strlen(USB_MOUNT_BASE);
    if (strncmp(p, USB_MOUNT_BASE, base_len) != 0) return false;
    if (p[base_len] < '0' || p[base_len] > '7') return false;
    return p[base_len + 1] == '\0';
}

static bool usb_mount_info(const char* p, usb_mount_t* out) {
    usb_mount_t m = {0};
    struct stat st;
    if (lstat(p, &st) != 0 || !S_ISDIR(st.st_mode)) return false;
    snprintf(m.path, sizeof(m.path), "%s", p);
#ifdef USB_OBSERVATION_TEST
    extern bool usb_test_mount_observation(const char*, usb_mount_t*);
    if (!usb_test_mount_observation(p, &m)) return false;
#else
#ifdef USB_HAVE_BSD_STATFS
    struct statfs sf;
    if (statfs(p,&sf)) { usb_classify_mount(&m,0,false); if (out) *out=m; return true; }
    if (!memchr(sf.f_mntonname,0,sizeof(sf.f_mntonname)) || strcmp(sf.f_mntonname,p)) return false;
    // One filesystem observation supplies capacity, format, flags and device.
    // BSD permits negative available blocks; those are not free capacity.
    uint64_t unit=(uint64_t)sf.f_bsize, blocks=(uint64_t)sf.f_blocks;
    int64_t available=(int64_t)sf.f_bavail;
    if (unit && blocks && blocks <= UINT64_MAX / unit && available >= 0 &&
        (uint64_t)available <= blocks) {
        m.free_bytes=(uint64_t)available*unit; m.total_bytes=blocks*unit; m.space_known=true;
    }
    m.mount_flags=sf.f_flags;
    m.writable=!(sf.f_flags & MNT_RDONLY) && access(p,W_OK)==0;
    snprintf(m.fs_type,sizeof(m.fs_type),"%.*s",(int)sizeof(sf.f_fstypename),sf.f_fstypename);
    snprintf(m.device,sizeof(m.device),"%.*s",(int)sizeof(sf.f_mntfromname),sf.f_mntfromname);
#else
    struct statvfs vfs;
    if (statvfs(p, &vfs) != 0) { usb_classify_mount(&m,0,false); if (out) *out=m; return true; }
    uint64_t unit = vfs.f_frsize ? vfs.f_frsize : vfs.f_bsize;
    if (unit && vfs.f_blocks && vfs.f_blocks <= UINT64_MAX / unit && vfs.f_bavail <= vfs.f_blocks) {
        m.free_bytes=(uint64_t)vfs.f_bavail*unit; m.total_bytes=(uint64_t)vfs.f_blocks*unit;
        m.space_known=true;
    }
    m.mount_flags=vfs.f_flag;
    m.writable=!(vfs.f_flag & ST_RDONLY) && access(p, W_OK)==0;
#ifdef USB_IDENTITY_TEST
    strcpy(m.fs_type,"exfat");
#endif
#endif
#endif
    char helper[USB_PATH_MAX];
    int n=snprintf(helper,sizeof(helper),"%s/This is Read Only partition.txt",p);
    if (n>0 && (size_t)n<sizeof(helper) && !lstat(helper,&st) && S_ISREG(st.st_mode))
        strcpy(m.reason,"auxiliary_partition");
    usb_classify_mount(&m,0,false);
    usb_observe_identity(&m);
    if (out) *out=m;
    return true;
}

static uint32_t read_le32(const unsigned char* p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

bool usb_read_exfat_volume_identity(const char* device_path, char out[65]) {
    if (!out) return false;
    out[0] = '\0';
    if (!device_path) return false;
    int fd = open(device_path, O_RDONLY);
    if (fd < 0) return false;
    unsigned char boot[512];
    bool ok = pread(fd, boot, sizeof(boot), 0) == (ssize_t)sizeof(boot);
    close(fd);
    if (!ok || memcmp(boot + 3, "EXFAT   ", 8) != 0 ||
        boot[510] != 0x55 || boot[511] != 0xaa ||
        !read_le32(boot + 0x64) || boot[0x68] != 0 || boot[0x69] != 1 ||
        boot[0x6c] < 9 || boot[0x6c] > 12 ||
        (unsigned)boot[0x6c] + boot[0x6d] > 25 ||
        !read_le32(boot + 0x50) || !read_le32(boot + 0x54) ||
        !read_le32(boot + 0x58) || !read_le32(boot + 0x5c) ||
        read_le32(boot + 0x60) < 2 ||
        (boot[0x6e] != 1 && boot[0x6e] != 2)) return false;
    char serial[9], geometry[69];
    snprintf(serial, sizeof(serial), "%08x", read_le32(boot + 0x64));
    for (size_t i = 0; i < 32; i++)
        snprintf(geometry + i * 2, 3, "%02x", boot[0x40 + i]);
    snprintf(geometry + 64, 5, "%02x%02x", boot[0x6c], boot[0x6d]);
    // Filesystem identity, not physical-device attestation: bit-cloned
    // volumes can share a serial/geometry. Never substitute mount slot,
    // label, device node or f_fsid when the real identifier is unavailable.
    const char* parts[] = {"usb-exfat-volume-v1", serial, geometry};
    return dest_identity_hash(parts, 3, out);
}

static bool utf16le_label(const unsigned char* p, size_t units,
                          char* out, size_t out_sz) {
    size_t n = 0;
    for (size_t i = 0; i < units; i++) {
        uint32_t cp = (uint32_t)p[i * 2] | ((uint32_t)p[i * 2 + 1] << 8);
        if (cp >= 0xd800 && cp <= 0xdbff && i + 1 < units) {
            uint32_t lo = (uint32_t)p[(i + 1) * 2] |
                          ((uint32_t)p[(i + 1) * 2 + 1] << 8);
            if (lo >= 0xdc00 && lo <= 0xdfff) {
                cp = 0x10000 + ((cp - 0xd800) << 10) + (lo - 0xdc00);
                i++;
            }
        }
        unsigned char enc[4];
        size_t count = 0;
        if (cp < 0x80) enc[count++] = (unsigned char)cp;
        else if (cp < 0x800) {
            enc[count++] = (unsigned char)(0xc0 | (cp >> 6));
            enc[count++] = (unsigned char)(0x80 | (cp & 0x3f));
        } else if (cp < 0x10000 && !(cp >= 0xd800 && cp <= 0xdfff)) {
            enc[count++] = (unsigned char)(0xe0 | (cp >> 12));
            enc[count++] = (unsigned char)(0x80 | ((cp >> 6) & 0x3f));
            enc[count++] = (unsigned char)(0x80 | (cp & 0x3f));
        } else if (cp <= 0x10ffff) {
            enc[count++] = (unsigned char)(0xf0 | (cp >> 18));
            enc[count++] = (unsigned char)(0x80 | ((cp >> 12) & 0x3f));
            enc[count++] = (unsigned char)(0x80 | ((cp >> 6) & 0x3f));
            enc[count++] = (unsigned char)(0x80 | (cp & 0x3f));
        }
        if (!count || n + count >= out_sz) return false;
        memcpy(out + n, enc, count);
        n += count;
    }
    out[n] = '\0';
    return n > 0;
}

bool usb_read_exfat_volume_label(const char* device_path,
                                 char* out, size_t out_sz) {
    if (!device_path || !out || out_sz < 2) return false;
    out[0] = '\0';
    int fd = open(device_path, O_RDONLY);
    if (fd < 0) return false;
    unsigned char boot[512];
    bool ok = pread(fd, boot, sizeof(boot), 0) == (ssize_t)sizeof(boot) &&
              memcmp(boot + 3, "EXFAT   ", 8) == 0;
    uint32_t fat_sector = ok ? read_le32(boot + 0x50) : 0;
    uint32_t heap_sector = ok ? read_le32(boot + 0x58) : 0;
    uint32_t cluster_count = ok ? read_le32(boot + 0x5c) : 0;
    uint32_t cluster = ok ? read_le32(boot + 0x60) : 0;
    unsigned bps_shift = ok ? boot[0x6c] : 0;
    unsigned spc_shift = ok ? boot[0x6d] : 0;
    if (!ok || bps_shift < 9 || bps_shift > 12 || spc_shift > 13 ||
        cluster < 2 || cluster > cluster_count + 1 || !cluster_count) {
        close(fd);
        return false;
    }
    uint64_t bps = 1ULL << bps_shift;
    uint64_t spc = 1ULL << spc_shift;
    uint64_t cluster_bytes = bps * spc;
    if (!cluster_bytes || cluster_bytes > 32ULL * 1024ULL * 1024ULL) {
        close(fd);
        return false;
    }

    // Volume label entry type 0x83 lives in the root directory. Scan bounded
    // FAT chains read-only; most labels are in the first few entries.
    for (unsigned chain = 0; chain < 256; chain++) {
        uint64_t base = (uint64_t)heap_sector * bps +
                        (uint64_t)(cluster - 2) * cluster_bytes;
        for (uint64_t pos = 0; pos + 32 <= cluster_bytes; pos += 32) {
            unsigned char entry[32];
            if (pread(fd, entry, sizeof(entry), (off_t)(base + pos)) !=
                (ssize_t)sizeof(entry)) {
                close(fd);
                return false;
            }
            if (entry[0] == 0x00) { close(fd); return false; }
            if (entry[0] == 0x83) {
                size_t units = entry[1];
                bool label_ok = units > 0 && units <= 15 &&
                    utf16le_label(entry + 2, units, out, out_sz);
                close(fd);
                return label_ok;
            }
        }
        unsigned char next_raw[4];
        uint64_t fat_off = (uint64_t)fat_sector * bps + (uint64_t)cluster * 4;
        if (pread(fd, next_raw, sizeof(next_raw), (off_t)fat_off) != 4) break;
        uint32_t next = read_le32(next_raw);
        if (next >= 0xfffffff8U) break;
        if (next < 2 || next > cluster_count + 1 || next == cluster) break;
        cluster = next;
    }
    close(fd);
    return false;
}

static void usb_load_display_name(usb_mount_t* m) {
    if (!m) return;
    char path[USB_PATH_MAX], json[512] = {0};
    snprintf(path, sizeof(path), "%s/%s/.drive.json", m->path, usb_folder());
    FILE* f = fopen(path, "rb");
    size_t n = f ? fread(json, 1, sizeof(json) - 1, f) : 0;
    if (f) fclose(f);
    json[n] = '\0';
    if (n && json_get_string(json, "name", m->display_name,
                             sizeof(m->display_name)) && m->display_name[0]) {
        snprintf(m->label_source, sizeof(m->label_source), "custom");
        return;
    }
#ifdef USB_HAVE_BSD_STATFS
    struct statfs sfs;
    if (statfs(m->path, &sfs) == 0 &&
        strstr(sfs.f_fstypename, "exfat") != NULL &&
        strncmp(sfs.f_mntfromname, "/dev/", 5) == 0 &&
        usb_read_exfat_volume_label(sfs.f_mntfromname, m->display_name,
                                    sizeof(m->display_name))) {
        snprintf(m->label_source, sizeof(m->label_source), "exfat");
        return;
    }
#endif
    const char* number = m->path + strlen(m->path);
    while (number > m->path && number[-1] >= '0' && number[-1] <= '9') number--;
    snprintf(m->display_name, sizeof(m->display_name), "USB drive%s%s",
             *number ? " " : "", number);
    snprintf(m->label_source, sizeof(m->label_source), "fallback");
}

static size_t usb_observe_mounts_current(usb_mount_t* out, size_t max_out) {
    size_t count=0;
    for (unsigned i=0;i<8;i++) {
        char path[64]; usb_mount_t m;
        snprintf(path,sizeof(path),"%s%u",USB_MOUNT_BASE,i);
        if (!usb_mount_info(path,&m)) continue;
        usb_load_display_name(&m);
        m.selected=CFG && !strcmp(CFG->usb.mount_path,path);
        if (out && count<max_out) out[count]=m;
        count++;
    }
    return count;
}
size_t usb_observe_mounts(usb_mount_t* out,size_t max_out) {
    USB_CFG_BEGIN();return usb_observe_mounts_current(out,max_out);
}
size_t usb_list_mounts(usb_mount_t* out, size_t max_out) {
    usb_mount_t mounts[8]; size_t found=usb_observe_mounts(mounts,8),count=0;
    for(size_t i=0;i<found;i++) if(usb_mount_is_usable(&mounts[i])) {
        if(out && count<max_out) out[count]=mounts[i]; count++;
    }
    return count;
}

// Existing copies remain readable when free space or mount flags prohibit writes.
// Keep usb_list_mounts restricted to writable targets for Import/staging callers.
static size_t usb_catalog_mounts(usb_mount_t* out, size_t max_out) {
    usb_mount_t mounts[8]; size_t found=usb_observe_mounts_current(mounts,8),count=0;
    for(size_t i=0;i<found;i++) if(usb_mount_is_readable(&mounts[i])) {
        if(out && count<max_out) out[count]=mounts[i]; count++;
    }
    return count;
}

static bool usb_display_name_clean(const char* in, char out[64]) {
    if (!in) return false;
    while (*in == ' ' || *in == '\t') in++;
    size_t n = 0;
    for (; *in && n < 40; in++) {
        unsigned char c = (unsigned char)*in;
        if (c < 0x20 || c == 0x7f || c == '/' || c == '\\' || c == '"')
            return false;
        out[n++] = (char)c;
    }
    while (n && (out[n - 1] == ' ' || out[n - 1] == '\t')) n--;
    out[n] = '\0';
    return true;
}

bool usb_set_display_name(const char* mount_path,const char* name) {
    USB_CFG_BEGIN();usb_mount_t mount;char clean[64];
    if(!mount_path || !mount_path[0] || !strcmp(mount_path,"auto") || !usb_mount_path_allowed(mount_path) ||
       !usb_mount_info(mount_path,&mount) || !usb_mount_is_usable(&mount) || !mount.volume_id[0] ||
       !usb_display_name_clean(name,clean)) return false;
    int fd=open(mount_path,O_RDONLY|O_DIRECTORY|O_NOFOLLOW);if(fd<0)return false;
    s_write_mountfd=fd;s_write_mount=mount;int root=usb_write_root(fd);bool ok=false;
    if(root>=0 && usb_mount_same(fd,&mount,512,true)) {
        if(!clean[0]) ok=!unlinkat(root,".drive.json",0) || errno==ENOENT;
        else {
            int tmp=toston_openat(root,".drive.json.tmp",O_WRONLY|O_CREAT|O_EXCL|O_NOFOLLOW,0600);
            if(tmp>=0) {
                char json[256];int n=snprintf(json,sizeof(json),"{\"name\":\"%s\",\"created_by\":\"TostónSync\",\"version\":1}\n",clean);
                ok=n>0 && (size_t)n<sizeof(json) && write(tmp,json,(size_t)n)==n && !fsync(tmp);
                if(close(tmp)) ok=false;
                if(ok) ok=usb_mount_same(fd,&mount,0,false) && !renameat(root,".drive.json.tmp",root,".drive.json");
                if(!ok && usb_mount_same(fd,&mount,0,false)) unlinkat(root,".drive.json.tmp",0);
            }
        }
    }
    if(root>=0)close(root);s_write_mountfd=-1;close(fd);return ok;
}

// UI and writers use the same selected-volume observation.
static bool usb_detect_current(char* out,size_t out_sz) {
    if(!out || !out_sz) return false;
    out[0]=0;usb_mount_t selected;
    usb_observe_snapshot_current(&selected,NULL,0);
    if(!selected.selected) return false;
    // Detection is a worker/action operation; passive observations only read this preference.
    pthread_mutex_lock(&s_selection_lock);
    s_last_selected=selected;
    pthread_mutex_unlock(&s_selection_lock);
    snprintf(out,out_sz,"%s",selected.path);return true;
}

bool usb_detect(char* out, size_t out_sz) {
    USB_CFG_BEGIN();
    return usb_detect_current(out, out_sz);
}

static size_t usb_observe_snapshot_current(usb_mount_t* out,usb_mount_t* mounts,size_t capacity) {
    usb_mount_t observed[8]; size_t n=usb_observe_mounts_current(observed,8),usable=0,best=n;
    for(size_t i=0;i<n;i++) if(usb_mount_is_usable(&observed[i])) {
        usable++;
        if(best==n || observed[i].free_bytes>observed[best].free_bytes) best=i;
    }
    const char* selected=CFG && CFG->usb.mount_path[0]?CFG->usb.mount_path:"auto";
    usb_mount_t last;
    pthread_mutex_lock(&s_selection_lock); last=s_last_selected; pthread_mutex_unlock(&s_selection_lock);
    bool retained=false;
    if (!strcmp(selected,"auto") && last.volume_id[0]) {
        for (size_t i=0;i<n;i++) if (usb_mount_is_usable(&observed[i]) &&
                !strcmp(last.volume_id,observed[i].volume_id)) {best=i;retained=true;break;}
    }
    for(size_t i=0;i<n;i++) if(!strcmp(selected,observed[i].path)) {best=i;break;}
    if(best==n && n) best=0;
    for(size_t i=0;i<n;i++) {
        observed[i].usable_count=usable;
        observed[i].selected=i==best && usb_mount_is_usable(&observed[i]);
        strcpy(observed[i].selection_reason,!observed[i].selected?"none":
            strcmp(selected,"auto") && !strcmp(selected,observed[i].path)?"manual":
            retained?"last_used":usable==1?"only_drive":"most_free_space");
        if(mounts && i<capacity) mounts[i]=observed[i];
    }
    if(out) {
        memset(out,0,sizeof(*out));out->state=USB_NOT_CONNECTED;strcpy(out->reason,"not_connected");
        if(best<n) *out=observed[best];
    }
    return n;
}
size_t usb_observe_snapshot(usb_mount_t* selected,usb_mount_t* mounts,size_t capacity) {
    USB_CFG_BEGIN();return usb_observe_snapshot_current(selected,mounts,capacity);
}
bool usb_observe_selected(usb_mount_t* out) {
    if(!out) return false;
    return usb_observe_snapshot(out,NULL,0)>0;
}

bool usb_is_present(void) {
    char m[64];
    return usb_detect(m, sizeof(m));
}

bool usb_free_space(uint64_t* free_bytes,uint64_t* total_bytes) {
    usb_mount_t selected;usb_observe_selected(&selected);
    if(!selected.selected || !selected.space_known) return false;
    if(free_bytes) *free_bytes=selected.free_bytes;
    if(total_bytes) *total_bytes=selected.total_bytes;
    return true;
}


static const char* usb_folder(void) {
    if (s_cfg && CFG->usb.folder[0]) return CFG->usb.folder;
    return "TostónSync";
}

// Build <mount>/<folder>/<user_alias>/<title_id>. Returns false if no drive.
static bool usb_path_component(const char* value) {
    if (!value || !value[0] || strcmp(value, ".") == 0 ||
        strcmp(value, "..") == 0) return false;
    for (const unsigned char* p = (const unsigned char*)value; *p; p++)
        if (*p < 0x20 || *p == 0x7f || *p == '/' || *p == '\\') return false;
    return true;
}

// Resolve one physical child, never merge duplicate logical identities. Reads
// leave names untouched; only a write may rename one bare-code directory.
static bool usb_resolve_child(const char* parent, const char* key,
                               const char* desired, bool title, bool create,
                               bool rename_readable, char out[128]) {
    char code[32];
    bool coded = backup_folder_code(key, title, code, sizeof(code));
    DIR* d = opendir(parent);
    if (!d) return false;
    char chosen[128] = {0};
    bool chosen_bare = false;
    size_t matches = 0;
    bool ok = true;
    for (;;) {
        errno = 0;
        struct dirent* e = readdir(d);
        if (!e) { if (errno) ok = false; break; }
        if (!strcmp(e->d_name, ".") || !strcmp(e->d_name, "..")) continue;
        char found[32];
        bool match = coded
            ? backup_folder_code(e->d_name, title, found, sizeof(found)) && !strcmp(found, code)
            : !strcmp(e->d_name, key);
        if (!match) continue;
        struct stat st;
        if (!usb_path_component(e->d_name) || strlen(e->d_name) >= sizeof(chosen) ||
            toston_fstatat(dirfd(d), e->d_name, &st, AT_SYMLINK_NOFOLLOW) || !S_ISDIR(st.st_mode)) {
            ok = false; break;
        }
        matches++;
        bool bare = coded ? strlen(e->d_name) == strlen(code) : !strcmp(e->d_name, key);
        if (!chosen[0] || (bare && !chosen_bare) ||
            (bare == chosen_bare && strcmp(e->d_name, chosen) < 0)) {
            snprintf(chosen, sizeof(chosen), "%s", e->d_name);
            chosen_bare = bare;
        }
    }
    if (ok && !matches && create) {
        const char* name = coded ? desired : key;
        if (!usb_path_component(name) || strlen(name) >= sizeof(chosen)) ok = false;
        else {
            if (!usb_write_revalidate(dirfd(d),parent) || (toston_mkdirat(dirfd(d), name, 0755) && errno != EEXIST)) ok = false;
            struct stat st;
            if (ok && (toston_fstatat(dirfd(d), name, &st, AT_SYMLINK_NOFOLLOW) || !S_ISDIR(st.st_mode))) ok = false;
            if (ok) snprintf(chosen, sizeof(chosen), "%s", name);
        }
    } else if (ok && matches == 1 && create && coded &&
               (chosen_bare || rename_readable) && strcmp(chosen, desired)) {
        struct stat target;
        errno = 0;
        if (!usb_path_component(desired) || strlen(desired) >= sizeof(chosen)) ok = false;
        else if (toston_fstatat(dirfd(d), desired, &target, AT_SYMLINK_NOFOLLOW) == 0 || errno != ENOENT) ok = false;
        else if (!usb_write_revalidate(dirfd(d),parent)) ok=false;
        else if (renameat(dirfd(d), chosen, dirfd(d), desired) == 0)
            snprintf(chosen, sizeof(chosen), "%s", desired);
        else log_warn("usb: readable folder rename failed; retaining original %s", chosen);
    }
    if (matches > 1)
        log_warn("usb: duplicate backup folders for %s; using %s, no merge or pruning across folders", coded ? code : key, chosen);
    if (ok && chosen[0]) {
        struct stat st;
        if (toston_fstatat(dirfd(d), chosen, &st, AT_SYMLINK_NOFOLLOW) || !S_ISDIR(st.st_mode)) ok = false;
    } else ok = false;
    if (ok) snprintf(out, 128, "%s", chosen);
    if (closedir(d)) ok = false;
    return ok;
}

static bool usb_backup_dir(char mount[64], char dir[USB_PATH_MAX],
                            const char* user, const char* title, bool create) {
    const char* key = (user && user[0]) ? user : "default";
    const char* folder = usb_folder();
    if (!folder[0] || folder[0] == '/' || strchr(folder, '\\')) return false;
    for (const char* p = folder; *p;) {
        const char* end = strchr(p, '/');
        size_t n = end ? (size_t)(end - p) : strlen(p);
        if ((n == 1 && p[0] == '.') ||
            (n == 2 && p[0] == '.' && p[1] == '.')) return false;
        for (size_t i = 0; i < n; i++)
            if ((unsigned char)p[i] < 0x20 || p[i] == 0x7f) return false;
        if (!end) break;
        p = end + 1;
    }
    if (!usb_path_component(key) || !usb_path_component(title)) return false;
    if(s_write_mountfd>=0) {
        if(!usb_mount_same(s_write_mountfd,&s_write_mount,0,false)) return false;
        snprintf(mount,64,"%s",s_write_mount.path);
    } else if (!create) {
        usb_mount_t observed;
        usb_observe_snapshot_current(&observed,NULL,0);
        if (!usb_mount_is_readable(&observed)) return false;
        snprintf(mount,64,"%s",observed.path);
    } else if(!usb_detect_current(mount,64)) return false;
    char root[USB_PATH_MAX], user_dir[USB_PATH_MAX], user_name[128], title_name[128];
    int n = snprintf(root, sizeof(root), "%s/%s", mount, folder);
    if (n <= 0 || (size_t)n >= sizeof(root)) return false;
    if (create && (s_write_mountfd<0 || !usb_mkdir_relative(s_write_mountfd,folder))) return false;
    struct stat root_st;
    if (lstat(root, &root_st) || !S_ISDIR(root_st.st_mode)) return false;
    backup_names_t names = {0};
    if (!backup_names_current(key, title, NULL, "Manual", 0, &names)) {
        char code[32];
        if (backup_folder_code(key, false, code, sizeof(code))) return false;
        snprintf(names.user_folder, sizeof(names.user_folder), "%s", key);
        snprintf(names.title_folder, sizeof(names.title_folder), "%s", title);
    }
    if (!usb_resolve_child(root, key, names.user_folder, false, create, true, user_name)) return false;
    n = snprintf(user_dir, sizeof(user_dir), "%s/%s", root, user_name);
    if (n <= 0 || (size_t)n >= sizeof(user_dir) ||
        !usb_resolve_child(user_dir, title, names.title_folder, true, create,
                           names.title_rename_requested, title_name)) return false;
    n = snprintf(dir, USB_PATH_MAX, "%s/%s", user_dir, title_name);
    return n > 0 && n < USB_PATH_MAX;
}

static bool usb_marker(int dirfd, const char* name, bool create, char out[65]) {
    out[0]='\0';
    int fd=toston_openat(dirfd,name,O_RDONLY|O_NOFOLLOW|O_NONBLOCK,0);
    if(fd<0 && errno==ENOENT && create) {
        unsigned char random[32]; char value[66];
        int randomfd=open("/dev/urandom",O_RDONLY);
        ssize_t got=randomfd>=0?read(randomfd,random,sizeof(random)):-1;
        if(randomfd>=0) close(randomfd);
        if(got!=(ssize_t)sizeof(random)) return false;
        for(size_t i=0;i<sizeof(random);i++) snprintf(value+i*2,3,"%02x",random[i]);
        value[64]='\n'; value[65]=0;
        int created=toston_openat(dirfd,name,O_WRONLY|O_CREAT|O_EXCL|O_NOFOLLOW,0600);
        if(created>=0) {
            bool ok=write(created,value,65)==65;
            if(ok && fsync(created)) ok=false;
            if(close(created)) ok=false;
            if(!ok) return false; // Preserve an uncertain marker; never replace its identity.
        } else if(errno!=EEXIST) return false;
        fd=toston_openat(dirfd,name,O_RDONLY|O_NOFOLLOW|O_NONBLOCK,0);
    }
    if(fd<0) return false;
    struct stat st; char value[66]={0};
    bool ok=!fstat(fd,&st) && S_ISREG(st.st_mode) && st.st_size==65 &&
        read(fd,value,sizeof(value))==65 && value[64]=='\n';
    close(fd); value[64]=0;
    if(!ok || !dest_fingerprint_hex(value)) return false;
    memcpy(out,value,65); return true;
}

static bool usb_volume_identity(int dirfd, const char* mount, char out[65]) {
    out[0]='\0';
#ifdef USB_IDENTITY_TEST
    extern bool usb_test_volume_identity(int,const char*,char[65]);
    return usb_test_volume_identity(dirfd,mount,out);
#elif defined(USB_HAVE_BSD_STATFS)
    struct statfs sfs;
    if(fstatfs(dirfd,&sfs) || !memchr(sfs.f_fstypename,0,sizeof(sfs.f_fstypename)) ||
       !memchr(sfs.f_mntfromname,0,sizeof(sfs.f_mntfromname))) return false;
    bool exfat=!strcmp(sfs.f_fstypename,"exfat")||!strcmp(sfs.f_fstypename,"exfatfs");
    if(exfat && !strncmp(sfs.f_mntfromname,"/dev/",5) && usb_read_exfat_volume_identity(sfs.f_mntfromname,out)) return true;
    if(!exfat && strcmp(sfs.f_fstypename,"msdosfs") && strcmp(sfs.f_fstypename,"fat32") && strcmp(sfs.f_fstypename,"vfat")) return false;
    (void)mount;
    char marker[65],geometry[96];
    bool ok=usb_marker(dirfd,".tostonsync-volume-id",false,marker);
    if(!ok) return false;
    snprintf(geometry,sizeof(geometry),"%llu:%llu",(unsigned long long)sfs.f_bsize,(unsigned long long)sfs.f_blocks);
    const char* parts[]={"usb-fat-volume-v1",marker,sfs.f_fstypename,geometry};
    return dest_identity_hash(parts,4,out);
#else
    (void)dirfd; (void)mount; return false;
#endif
}

static void usb_observe_identity_at(int fd,usb_mount_t* m) {
    char filesystem[65],marker[65],geometry[64];m->volume_id[0]=0;m->identity_confirmed=false;
    bool known=usb_volume_identity(fd,m->path,filesystem);
    bool marked=usb_marker(fd,".tostonsync-volume-id",false,marker);
    if(!known) return;
    if(!marked) {
        struct stat st;
        if(!toston_fstatat(fd,".tostonsync-volume-id",&st,AT_SYMLINK_NOFOLLOW) || errno!=ENOENT) return;
        memcpy(m->volume_id,filesystem,65); return;
    }
    snprintf(geometry,sizeof(geometry),"%llu",(unsigned long long)m->total_bytes);
    const char* parts[]={"usb-volume-marker-v1",marker,filesystem,m->fs_type,geometry};
    m->identity_confirmed=dest_identity_hash(parts,5,m->volume_id);
}
static void usb_observe_identity(usb_mount_t* m) {
    int fd=open(m->path,O_RDONLY|O_DIRECTORY|O_NOFOLLOW);
    if(fd<0)return;usb_observe_identity_at(fd,m);close(fd);
}

static bool usb_mount_same(int fd,const usb_mount_t* expected,uint64_t incoming,bool known) {
    usb_mount_t current; struct stat opened,resolved;
    if(!usb_mount_info(expected->path,&current) || fstat(fd,&opened) ||
       lstat(expected->path,&resolved) || opened.st_dev!=resolved.st_dev || opened.st_ino!=resolved.st_ino) {
        s_copy_failure="volume_changed"; return false;
    }
    usb_classify_mount(&current,incoming,known);
    if(!usb_mount_is_usable(&current)) {s_copy_failure=usb_state_name(current.state);return false;}
    usb_mount_t held=*expected;usb_observe_identity_at(fd,&held);
    if(strcmp(held.volume_id,current.volume_id) || strcmp(expected->fs_type,current.fs_type) || expected->total_bytes!=current.total_bytes ||
       strcmp(expected->device,current.device) || strcmp(expected->volume_id,current.volume_id)) {
        s_copy_failure="volume_changed"; return false;
    }
    return true;
}

static bool usb_write_revalidate(int fd,const char* path) {
    struct stat a,b;
    if(s_write_mountfd<0 || !usb_mount_same(s_write_mountfd,&s_write_mount,0,false) ||
       fstat(fd,&a) || lstat(path,&b) || a.st_dev!=b.st_dev || a.st_ino!=b.st_ino) {
        s_copy_failure="volume_changed";return false;
    }
    return true;
}
static bool usb_mkdir_relative(int root,const char* relative) {
    char path[USB_PATH_MAX];snprintf(path,sizeof(path),"%s",relative);
    int fd=dup(root);char* cursor=NULL;bool ok=fd>=0;
    for(char* part=strtok_r(path,"/",&cursor);ok && part;part=strtok_r(NULL,"/",&cursor)) {
        if(!usb_path_component(part) || !usb_mount_same(root,&s_write_mount,0,false)) {ok=false;break;}
        int next=toston_openat(fd,part,O_RDONLY|O_DIRECTORY|O_NOFOLLOW,0);
        if(next<0 && errno==ENOENT) {
            if(toston_mkdirat(fd,part,0755) && errno!=EEXIST) {ok=false;break;}
            next=toston_openat(fd,part,O_RDONLY|O_DIRECTORY|O_NOFOLLOW,0);
        }
        if(next<0) {ok=false;break;} close(fd);fd=next;
    }
    if(fd>=0) close(fd);return ok;
}

static int usb_write_root(int mountfd) {
    if(!usb_mkdir_relative(mountfd,usb_folder())) return -1;
    char path[USB_PATH_MAX];int n=snprintf(path,sizeof(path),"%s",usb_folder());
    if(n<=0 || (size_t)n>=sizeof(path))return -1;
    int fd=dup(mountfd);char* cursor=NULL;
    for(char* part=strtok_r(path,"/",&cursor);fd>=0 && part;part=strtok_r(NULL,"/",&cursor)) {
        if(!usb_path_component(part)){close(fd);return -1;}
        int next=toston_openat(fd,part,O_RDONLY|O_DIRECTORY|O_NOFOLLOW,0);close(fd);fd=next;
    }
    return fd;
}

bool usb_select_volume_identity(const char* mount) {
    USB_CFG_BEGIN(); usb_mount_t m; s_copy_failure="";
    if(!mount || !mount[0] || !strcmp(mount,"auto") || !usb_mount_path_allowed(mount) ||
       !usb_mount_info(mount,&m) || !usb_mount_is_usable(&m)) {s_copy_failure="not_usable";return false;}
    int fd=open(mount,O_RDONLY|O_DIRECTORY|O_NOFOLLOW); char marker[65];
    bool ok=fd>=0 && usb_mount_same(fd,&m,0,false) && usb_marker(fd,".tostonsync-volume-id",true,marker);
    if(ok) {usb_observe_identity_at(fd,&m);ok=m.identity_confirmed && usb_mount_same(fd,&m,0,false);}
    if(fd>=0) close(fd);
    if(!ok && !s_copy_failure[0]) s_copy_failure="identity_required";
    return ok;
}

static bool usb_directory_identity(const char* mount, const char* dir,
                                    int dirfd, char out[65]) {
    out[0] = '\0';
    usb_mount_t observed;
    if(!usb_mount_info(mount,&observed) || !observed.volume_id[0]) return false;
    const char* volume=observed.volume_id;
    char canonical_mount[PATH_MAX], canonical_dir[PATH_MAX];
    struct stat opened, resolved;
    if (!realpath(mount, canonical_mount) || !realpath(dir, canonical_dir) ||
        fstat(dirfd, &opened) != 0 || stat(canonical_dir, &resolved) != 0 ||
        opened.st_dev != resolved.st_dev || opened.st_ino != resolved.st_ino)
        return false;
    size_t prefix = strlen(canonical_mount);
    if (strncmp(canonical_mount, canonical_dir, prefix) != 0 ||
        canonical_dir[prefix] != '/' || !canonical_dir[prefix + 1]) return false;
    const char* parts[] = {"usb-backup-v1", volume, canonical_dir + prefix + 1};
    return dest_identity_hash(parts, 3, out);
}

static bool usb_confirmed_identity(int dirfd,const char* location,bool create,char out[65]) {
    char marker[65]; out[0]=0;
    if(!location[0] || !usb_marker(dirfd,".tostonsync-destination-id",create,marker)) return false;
    const char* parts[]={"usb-confirmed-backup-v1",location,marker};
    return dest_identity_hash(parts,3,out);
}

bool usb_backup_identity(const char* user_alias, const char* title_id,
                         char out[65]) {
    if (!out) return false;
    out[0] = '\0';
    USB_CFG_BEGIN();
    if (!s_cfg || !s_cfg_have || !CFG->usb.enabled) return false;
    char mount[64], dir[USB_PATH_MAX];
    if (!usb_backup_dir(mount, dir, user_alias, title_id, false)) return false;
    int dirfd = open(dir, O_RDONLY | O_DIRECTORY | O_NOFOLLOW);
    if (dirfd < 0) return false;
    char location[65] = {0};
    bool ok = usb_directory_identity(mount, dir, dirfd, location) &&
              usb_confirmed_identity(dirfd, location, false, out);
    close(dirfd);
    return ok;
}

bool usb_backup_exists(const char* user_alias, const char* title_id,
                        const char* filename, uint64_t expected_size,
                        const char* expected_identity) {
    USB_CFG_BEGIN();
    if (!s_cfg || !s_cfg_have || !CFG->usb.enabled || !expected_size ||
        !dest_fingerprint_hex(expected_identity) ||
        !usb_path_component(filename)) return false;
    size_t len = strlen(filename);
    if (len <= 4 || strcmp(filename + len - 4, ".zip")) return false;
    char mount[64], dir[USB_PATH_MAX], location[65], identity[65];
    if (!usb_backup_dir(mount, dir, user_alias, title_id, false)) return false;
    int dirfd = open(dir, O_RDONLY | O_DIRECTORY | O_NOFOLLOW);
    if (dirfd < 0) return false;
    struct stat st;
    bool ok = usb_directory_identity(mount, dir, dirfd, location) &&
              usb_confirmed_identity(dirfd, location, false, identity) &&
              strcmp(identity, expected_identity) == 0 &&
              fstatat(dirfd, filename, &st, AT_SYMLINK_NOFOLLOW) == 0 &&
              S_ISREG(st.st_mode) && st.st_size > 0 &&
              (uint64_t)st.st_size == expected_size &&
              usb_directory_identity(mount, dir, dirfd, location) &&
              usb_confirmed_identity(dirfd, location, false, identity) &&
              strcmp(identity, expected_identity) == 0;
    close(dirfd);
    return ok;
}

// Keep the owned descriptor open through publication/cleanup so its inode
// cannot be reused for a replacement pathname after the stream is closed.
static bool usb_owned_temp(int parent, const char* name, int owned,
                           uint64_t expected_size, bool complete) {
    struct stat opened, named;
    return owned>=0 && !fstat(owned,&opened) && S_ISREG(opened.st_mode) &&
        !fstatat(parent,name,&named,AT_SYMLINK_NOFOLLOW) && S_ISREG(named.st_mode) &&
        opened.st_dev==named.st_dev && opened.st_ino==named.st_ino &&
        (!complete || (opened.st_size>=0 && (uint64_t)opened.st_size==expected_size &&
                       named.st_size==opened.st_size));
}

typedef struct {
    uint64_t bytes, read_ms, validate_ms, write_ms, fsync_ms, publish_ms, last_write_ms;
    uint64_t validations, writes, max_write;
} usb_copy_metrics_t;
#define USB_COPY_BUFFER (1024U*1024U)
#define USB_COPY_REVALIDATE_BYTES (8U*1024U*1024U)
static uint64_t usb_copy_now_ms(void) {
    struct timespec t;
    if (clock_gettime(CLOCK_MONOTONIC,&t)) return 0;
    return (uint64_t)t.tv_sec*1000U+(uint64_t)t.tv_nsec/1000000U;
}
static void usb_copy_log(const usb_copy_metrics_t* m, const char* outcome) {
    log_info("usb-copy: %s bytes=%llu read_ms=%llu revalidate_ms=%llu write_ms=%llu fsync_ms=%llu publication_ms=%llu last_write_ms=%llu validations=%llu writes=%llu max_write_bytes=%llu",
        outcome,(unsigned long long)m->bytes,(unsigned long long)m->read_ms,
        (unsigned long long)m->validate_ms,(unsigned long long)m->write_ms,
        (unsigned long long)m->fsync_ms,(unsigned long long)m->publish_ms,
        (unsigned long long)m->last_write_ms,(unsigned long long)m->validations,
        (unsigned long long)m->writes,(unsigned long long)m->max_write);
}
static bool usb_copy_cancelled(void) {
    if (!backup_control_cancelled()) return false;
    s_copy_failure="canceled";return true;
}
static bool usb_copy_mount_same(int fd,const usb_mount_t* m,uint64_t bytes,bool known,
                                 usb_copy_metrics_t* metrics) {
    uint64_t start=usb_copy_now_ms();
    bool ok=usb_mount_same(fd,m,bytes,known);
    metrics->validate_ms+=usb_copy_now_ms()-start;metrics->validations++;
    return ok;
}
static bool usb_copy_validate(int fd,const usb_mount_t* m,uint64_t remaining,
                              usb_copy_metrics_t* metrics) {
    bool ok=usb_copy_mount_same(fd,m,remaining,true,metrics);
    return ok && !usb_copy_cancelled();
}
// One owned 1 MiB buffer. Cancellation never waits for a second write or a
// hidden stdio flush; a blocked kernel call retains all job/FD ownership.
static bool usb_copy_buffered(FILE* in,int out,int mountfd,const usb_mount_t* m,
    uint64_t bytes,size_t chunk,usb_copy_metrics_t* metrics,bool synthetic) {
    if (!chunk || chunk>USB_COPY_BUFFER) return false;
    unsigned char* buffer=malloc(USB_COPY_BUFFER);
    if (!buffer) {s_copy_failure="write_failed";return false;}
    if (synthetic) memset(buffer,0x5a,USB_COPY_BUFFER);
    uint64_t last_check=usb_copy_now_ms(),checked=0,last_log=last_check,logged=0;
    bool ok=false;
    while (metrics->bytes<bytes) {
        if (usb_copy_cancelled()) goto done;
        size_t want=bytes-metrics->bytes<chunk?(size_t)(bytes-metrics->bytes):chunk;
        uint64_t start=usb_copy_now_ms();
        size_t got=synthetic?want:fread(buffer,1,want,in);
        metrics->read_ms+=usb_copy_now_ms()-start;
        if (got!=want) {s_copy_failure="read_failed";goto done;}
        if (usb_copy_cancelled()) goto done;
        uint64_t now=usb_copy_now_ms();
        if (now-last_check>=2000 || metrics->bytes-checked>=USB_COPY_REVALIDATE_BYTES) {
            if (!usb_copy_validate(mountfd,m,bytes-metrics->bytes,metrics)) goto done;
            last_check=usb_copy_now_ms();checked=metrics->bytes;
        }
        if (usb_copy_cancelled()) goto done;
        start=usb_copy_now_ms();
        ssize_t written=write(out,buffer,want);
        metrics->last_write_ms=usb_copy_now_ms()-start;
        metrics->write_ms+=metrics->last_write_ms;metrics->writes++;
        if (want>metrics->max_write) metrics->max_write=want;
        if (written>0) {metrics->bytes+=(uint64_t)written;jobs_progress_add((uint64_t)written);}
        // Check first, including short/error writes, to preserve the user's cancel.
        if (usb_copy_cancelled()) goto done;
        if (written!=(ssize_t)want) {s_copy_failure="write_failed";goto done;}
        now=usb_copy_now_ms();
        if (now-last_log>=5000 || metrics->bytes-logged>=USB_COPY_REVALIDATE_BYTES) {
            usb_copy_log(metrics,"progress");last_log=now;logged=metrics->bytes;
        }
    }
    if (!synthetic && (fgetc(in)!=EOF || ferror(in))) {s_copy_failure="read_failed";goto done;}
    if (usb_copy_cancelled()) goto done;
    uint64_t start=usb_copy_now_ms();
    int rc=fsync(out);metrics->fsync_ms+=usb_copy_now_ms()-start;
    if (usb_copy_cancelled()) goto done;
    if (rc) {s_copy_failure="write_failed";goto done;}
    ok=true;
 done:
    free(buffer);return ok;
}

// Diagnostic deadline only; the physically tested backup copy loop stays unchanged.
static bool usb_probe_phase(int out, int mountfd, const usb_mount_t* mount,
                             size_t chunk, usb_copy_metrics_t* metrics) {
    const uint64_t bytes = 16U * 1024U * 1024U;
    const uint64_t start = usb_copy_now_ms();
    unsigned char* buffer = calloc(1, chunk);
    if (!buffer) {s_copy_failure="memory_unavailable";return false;}
    bool ok = false;
    jobs_phase(jobs_bound(), "usb", chunk == USB_COPY_BUFFER ? "test_1MiB" : "test_64KiB", bytes, true);
    if (!usb_copy_validate(mountfd, mount, bytes, metrics)) goto done;
    while (metrics->bytes < bytes) {
        if (usb_copy_cancelled()) goto done;
        if (usb_copy_now_ms() - start >= 20000) {s_copy_failure="test_timeout";goto done;}
        uint64_t before = usb_copy_now_ms();
        ssize_t n = write(out, buffer, chunk);
        metrics->last_write_ms = usb_copy_now_ms() - before;
        metrics->write_ms += metrics->last_write_ms;metrics->writes++;
        metrics->max_write = chunk;
        if (n > 0) {metrics->bytes += (uint64_t)n;jobs_progress_add((uint64_t)n);}
        if (usb_copy_cancelled()) goto done;
        if (n != (ssize_t)chunk) {s_copy_failure="write_failed";goto done;}
        if (usb_copy_now_ms() - start >= 20000) {s_copy_failure="test_timeout";goto done;}
    }
    if (usb_copy_cancelled()) goto done;
    uint64_t before = usb_copy_now_ms();
    int rc = fsync(out);metrics->fsync_ms += usb_copy_now_ms() - before;
    if (usb_copy_cancelled()) goto done;
    if (rc) {s_copy_failure="write_failed";goto done;}
    if (usb_copy_now_ms() - start >= 20000) {s_copy_failure="test_timeout";goto done;}
    ok = true;
 done:
    free(buffer);return ok;
}

bool usb_test_write(char* mount_out,size_t mount_out_sz,char* detail,size_t detail_sz) {
    USB_CFG_BEGIN();s_copy_failure="";char mount[64];usb_mount_t observed;
    if (!usb_detect_current(mount,sizeof(mount)) || !usb_mount_info(mount,&observed)) {
        if (detail&&detail_sz) snprintf(detail,detail_sz,"No usable USB volume detected");s_copy_failure="not_usable";return false;
    }
    if (!observed.identity_confirmed) {
        if (detail&&detail_sz) snprintf(detail,detail_sz,"Confirm this drive first");s_copy_failure="identity_unconfirmed";return false;
    }
    const uint64_t half=16U*1024U*1024U;
    int fd=open(mount,O_RDONLY|O_DIRECTORY|O_NOFOLLOW),root=-1,probe=-1;
    bool ok=false,owned=false;char name[80]={0};usb_copy_metrics_t a={0},b={0};
    if (fd<0 || !usb_copy_mount_same(fd,&observed,2*half,true,&a)) goto done;
    // Read-only traversal: this diagnostic never creates folders or markers.
    char folder[USB_PATH_MAX];snprintf(folder,sizeof(folder),"%s",usb_folder());
    root=dup(fd);char* cursor=NULL;
    for (char* part=strtok_r(folder,"/",&cursor);root>=0&&part;part=strtok_r(NULL,"/",&cursor)) {
        if (!usb_path_component(part)) {close(root);root=-1;break;}
        int next=toston_openat(root,part,O_RDONLY|O_DIRECTORY|O_NOFOLLOW,0);close(root);root=next;
    }
    if (root<0 || usb_copy_cancelled()) goto done;
    static atomic_ulong sequence;
    snprintf(name,sizeof(name),".write-test-%ld-%lu",(long)getpid(),atomic_fetch_add(&sequence,1));
    probe=toston_openat(root,name,O_WRONLY|O_CREAT|O_EXCL|O_NOFOLLOW,0600);
    if (probe<0) goto done;
    owned=true;
    ok=usb_probe_phase(probe,fd,&observed,USB_COPY_BUFFER,&b);
    usb_copy_log(&b,"test_1MiB");
    if (ok) {
        ok=usb_probe_phase(probe,fd,&observed,65536,&a);
        usb_copy_log(&a,"test_64KiB");
    }
 done:
    // Exact owned inode only. A replaced volume or name is never cleaned up.
    if (owned && (!usb_copy_mount_same(fd,&observed,0,false,&b) ||
        !usb_owned_temp(root,name,probe,0,false) || unlinkat(root,name,0))) {ok=false;s_copy_failure="test_cleanup_unknown";}
    if (probe>=0 && close(probe)) ok=false;
    if (root>=0) close(root);if(fd>=0)close(fd);
    if (mount_out&&mount_out_sz)snprintf(mount_out,mount_out_sz,"%s",mount);
    if (detail&&detail_sz) snprintf(detail,detail_sz,
        "%s; 64 KiB: %llu B, write %llu ms, fsync %llu ms; 1 MiB: %llu B, write %llu ms, fsync %llu ms",
        ok?"USB write test completed":!strcmp(s_copy_failure,"test_timeout")?"USB write test partial: phase deadline reached":
        !strcmp(s_copy_failure,"canceled")?"USB write test canceled":"USB write test failed; inspect logs",
        (unsigned long long)a.bytes,(unsigned long long)a.write_ms,(unsigned long long)a.fsync_ms,
        (unsigned long long)b.bytes,(unsigned long long)b.write_ms,(unsigned long long)b.fsync_ms);
    return ok;
}

static bool usb_copy_backup_in_folder(const char* user_alias,
    const char* title_id,const char* filename,const char* local_zip_path,
    char out_identity[65],const char* subfolder,bool allow_marker) {
    if(out_identity) out_identity[0]=0;
    USB_CFG_BEGIN(); s_copy_failure="";
    if(!s_cfg || !s_cfg_have || !CFG->usb.enabled || !usb_path_component(filename) || !local_zip_path) {
        s_copy_failure="not_usable";return false;
    }
    FILE* in=fopen(local_zip_path,"rb"); struct stat source;
    if(!in || fstat(fileno(in),&source) || !S_ISREG(source.st_mode) || source.st_size<=0) {
        if(in) fclose(in);s_copy_failure="read_failed";return false;
    }
    uint64_t bytes=(uint64_t)source.st_size;
    char mount[64]={0},dir[USB_PATH_MAX]={0},legacy[65]={0};
    usb_mount_t observed;
    int mountfd=-1,dirfd=-1,outfd=-1,owned_temp=-1;
    usb_copy_metrics_t metrics={0};
    char temp[180]={0}; bool ok=false,temp_created=false,publication_held=false,published=false;
    bool setup_complete=false;uint64_t setup_start=usb_copy_now_ms();
    if(!usb_detect_current(mount,sizeof(mount))) {
        usb_mount_t rejected;usb_observe_snapshot_current(&rejected,NULL,0);
        s_copy_failure=usb_state_name(rejected.state);goto done;
    }
    if(!usb_mount_info(mount,&observed)) {s_copy_failure="volume_changed";goto done;}
    usb_classify_mount(&observed,bytes,true);
    if(!usb_mount_is_usable(&observed)) {s_copy_failure=!strcmp(observed.reason,"file_too_large")?"file_too_large":usb_state_name(observed.state);goto done;}
    mountfd=open(mount,O_RDONLY|O_DIRECTORY|O_NOFOLLOW);
    if(mountfd<0 || !usb_copy_mount_same(mountfd,&observed,bytes,true,&metrics)) goto done;
    if(!observed.identity_confirmed && !allow_marker) {
        char legacy_mount[64],legacy_dir[USB_PATH_MAX],location[65];
        if(usb_backup_dir(legacy_mount,legacy_dir,user_alias,title_id,false) && !strcmp(legacy_mount,mount)) {
            int old=open(legacy_dir,O_RDONLY|O_DIRECTORY|O_NOFOLLOW);
            if(old>=0) {
                if(usb_directory_identity(mount,legacy_dir,old,location)) usb_confirmed_identity(old,location,false,legacy);
                close(old);
            }
        }
        if(!legacy[0]) {s_copy_failure="identity_required";goto done;}
    }
    if(allow_marker && !observed.identity_confirmed) {
        char marker[65];
        if(!usb_marker(mountfd,".tostonsync-volume-id",true,marker) || !usb_mount_info(mount,&observed) || !observed.identity_confirmed) {s_copy_failure="identity_required";goto done;}
    }
    if(!observed.volume_id[0]) {s_copy_failure="identity_required";goto done;}
    if(!usb_copy_mount_same(mountfd,&observed,bytes,true,&metrics)) goto done;
    s_write_mountfd=mountfd;s_write_mount=observed;
    bool directory_ok=usb_backup_dir(mount,dir,user_alias,title_id,true);
    if(!directory_ok || !usb_copy_mount_same(mountfd,&observed,bytes,true,&metrics)) goto done;
    if(subfolder) {
        char child[USB_PATH_MAX];int n=snprintf(child,sizeof(child),"%s/%s",dir,subfolder);
        if(n<=0 || (size_t)n>=sizeof(child) ||
           (size_t)n+1+strlen(filename)>=USB_PATH_MAX) goto done;
        int parent=open(dir,O_RDONLY|O_DIRECTORY|O_NOFOLLOW);
        if(parent<0) goto done;
        bool made=usb_copy_mount_same(mountfd,&observed,bytes,true,&metrics) &&
            (!toston_mkdirat(parent,subfolder,0700) || errno==EEXIST);
        close(parent);if(!made) goto done;
        snprintf(dir,sizeof(dir),"%s",child);
    }
    if(strlen(dir)+1+strlen(filename)>=USB_PATH_MAX) goto done;
    dirfd=open(dir,O_RDONLY|O_DIRECTORY|O_NOFOLLOW);
    if(dirfd<0 || !usb_copy_mount_same(mountfd,&observed,bytes,true,&metrics)) goto done;
    char identity[65]={0};
    if(!usb_directory_identity(mount,dir,dirfd,identity)) {s_copy_failure="identity_required";goto done;}
    int n=snprintf(temp,sizeof(temp),".%s.part-%ld",filename,(long)getpid());
    if(n<=0 || (size_t)n>=sizeof(temp)) goto done;
    // An existing partial is evidence, not permission to overwrite it.
    outfd=toston_openat(dirfd,temp,O_WRONLY|O_CREAT|O_EXCL|O_NOFOLLOW,0600);
    if(outfd<0) {s_copy_failure="write_failed";goto done;}
    temp_created=true; owned_temp=dup(outfd);
    if(owned_temp<0) {s_copy_failure="write_failed";goto done;}
    // Opening includes discovery, marker/directory identity and write admission.
    metrics.validate_ms=usb_copy_now_ms()-setup_start;setup_complete=true;
    if (!usb_copy_buffered(in,outfd,mountfd,&observed,bytes,USB_COPY_BUFFER,&metrics,false)) goto done;
    if (close(outfd)) {outfd=-1;s_copy_failure="write_failed";goto done;} outfd=-1;
    char current[65];struct stat opened,resolved;
    uint64_t final_validation_start=usb_copy_now_ms(),volume_before=metrics.validate_ms;
    bool identity_ok=usb_copy_mount_same(mountfd,&observed,0,false,&metrics) &&
       usb_directory_identity(mount,dir,dirfd,current) && !strcmp(current,identity) &&
       !fstat(dirfd,&opened) && !lstat(dir,&resolved) && opened.st_dev==resolved.st_dev && opened.st_ino==resolved.st_ino;
    metrics.validate_ms+=usb_copy_now_ms()-final_validation_start-(metrics.validate_ms-volume_before);
    if(!identity_ok) {if (!s_copy_failure[0]) s_copy_failure="volume_changed";goto done;}
    struct stat source_after;
    if (fstat(fileno(in),&source_after) || source_after.st_dev!=source.st_dev ||
        source_after.st_ino!=source.st_ino || source_after.st_size!=source.st_size ||
        source_after.st_mtime!=source.st_mtime || source_after.st_ctime!=source.st_ctime) {
        s_copy_failure="read_failed";goto done;
    }
    if (usb_copy_cancelled()) goto done;
    if (!usb_owned_temp(dirfd,temp,owned_temp,bytes,true)) {s_copy_failure="publication_failed";goto done;}
    if (!backup_control_publish_begin()) {s_copy_failure="canceled";goto done;}
    publication_held=true;
    uint64_t publication_start=usb_copy_now_ms();
    int publication_rc=renameat(dirfd,temp,dirfd,filename);
    metrics.publish_ms+=usb_copy_now_ms()-publication_start;
    published=publication_rc==0;
    if (publication_rc) {s_copy_failure="publication_failed";goto done;}
    temp_created=false;
    uint64_t durability_start=usb_copy_now_ms();sync();
    metrics.fsync_ms+=usb_copy_now_ms()-durability_start;
    if(!usb_copy_mount_same(mountfd,&observed,0,false,&metrics)) goto done;
    char confirmed[65]={0};
    if(!subfolder && usb_copy_mount_same(mountfd,&observed,0,false,&metrics))
        usb_confirmed_identity(dirfd,identity,allow_marker,confirmed);
    if(out_identity && !subfolder) snprintf(out_identity,65,"%s",confirmed);
    ok=true;
 done:
    if(!setup_complete)metrics.validate_ms=usb_copy_now_ms()-setup_start;
    s_write_mountfd=-1;
    if(outfd>=0) close(outfd);
    if(in) fclose(in);
    // Never touch a replacement volume during failure cleanup.
    const char* first_failure=s_copy_failure;
    if(temp_created && dirfd>=0 && mountfd>=0 &&
       (publication_held || (publication_held=backup_control_publish_begin())) &&
       usb_copy_mount_same(mountfd,&observed,0,false,&metrics) &&
       usb_owned_temp(dirfd,temp,owned_temp,0,false)) unlinkat(dirfd,temp,0);
    if(first_failure[0]) s_copy_failure=first_failure;
    if(owned_temp>=0) close(owned_temp);
    if(dirfd>=0) close(dirfd);
    if(mountfd>=0) close(mountfd);
    usb_copy_log(&metrics,ok?"complete":s_copy_failure[0]?s_copy_failure:"failed");
    if(!ok) {
        if(!s_copy_failure[0])s_copy_failure="write_failed";
        log_warn("usb: backup stopped: %s; no automatic retry",s_copy_failure);
    }
    // The whole publication (including durability/identity) excludes cancellation.
    if(publication_held)backup_control_publish_end(published,1U);
    return ok;
}

bool usb_copy_backup_authorized(const char* user,const char* title,const char* filename,
    const char* source,char out_identity[65],bool individual,bool allow_marker) {
    return usb_copy_backup_in_folder(user,title,filename,source,out_identity,
        individual?"Individual saves":NULL,allow_marker);
}
bool usb_copy_backup_identified(const char* user,const char* title,const char* filename,
    const char* source,char out_identity[65]) {
    return usb_copy_backup_authorized(user,title,filename,source,out_identity,false,false);
}
bool usb_copy_backup_individual_identified(const char* user,const char* title,const char* filename,
    const char* source,char out_identity[65]) {
    return usb_copy_backup_authorized(user,title,filename,source,out_identity,true,false);
}
bool usb_copy_backup(const char* user,const char* title,const char* filename,const char* source) {
    return usb_copy_backup_identified(user,title,filename,source,NULL);
}

size_t usb_list_versions(const char* user_alias, const char* title_id,
                         usb_version_t* out, size_t max_out) {
    if (!out || max_out == 0 || !title_id) return 0;
    USB_CFG_BEGIN();
    // Catalog walks every physical folder, including duplicate logical codes.
    // Never resolve one chosen write folder and silently hide the other copies.
    enum { CAP = 4096 };
    usb_backup_t* entries = calloc(CAP, sizeof(*entries));
    if (!entries) return 0;
    size_t count = usb_catalog_scan(entries, CAP, NULL);
    const char* user = user_alias && user_alias[0] ? user_alias : "default";
    char user_code[32], title_code[16];
    if (backup_folder_code(user, false, user_code, sizeof(user_code))) user = user_code;
    if (backup_folder_code(title_id, true, title_code, sizeof(title_code))) title_id = title_code;
    size_t n = 0;
    for (size_t i = 0; i < count && n < max_out; i++) {
        if (strcmp(entries[i].user, user) || strcmp(entries[i].title_id, title_id)) continue;
        usb_version_t* v = &out[n];
        memset(v, 0, sizeof(*v));
        snprintf(v->path, sizeof(v->path), "%s", entries[i].path);
        snprintf(v->name, sizeof(v->name), "%s", entries[i].name);
        v->size_bytes = entries[i].size_bytes;
        v->created_unix = entries[i].created_unix;
        n++;
    }
    free(entries);

    // Newest first (insertion sort — version counts are small).
    for (size_t i = 1; i < n; i++) {
        usb_version_t key = out[i];
        size_t j = i;
        while (j > 0 && out[j - 1].created_unix < key.created_unix) {
            out[j] = out[j - 1];
            j--;
        }
        out[j] = key;
    }
    return n;
}

static bool usb_backup_newer(const usb_backup_t* a, const usb_backup_t* b) {
    if (a->created_unix != b->created_unix)
        return a->created_unix > b->created_unix;
    return strcmp(a->name, b->name) > 0;
}

static bool usb_name_safe_for_catalog(const char* s) {
    if (!s || !s[0] || s[0] == '.') return false;
    for (size_t i = 0; s[i]; i++) {
        unsigned char c = (unsigned char)s[i];
        if (c == '/' || c == '\\' || c < 0x20 || c == 0x7f) return false;
    }
    return true;
}

static bool usb_library_file_stamp(const struct stat* st, char out[65]) {
    char fields[256];
#ifdef __APPLE__
    long mns = st->st_mtimespec.tv_nsec, cns = st->st_ctimespec.tv_nsec;
#else
    long mns = st->st_mtim.tv_nsec, cns = st->st_ctim.tv_nsec;
#endif
    snprintf(fields, sizeof(fields), "%llu:%llu:%llu:%lld:%ld:%lld:%ld",
             (unsigned long long)st->st_dev, (unsigned long long)st->st_ino,
             (unsigned long long)st->st_size, (long long)st->st_mtime, mns,
             (long long)st->st_ctime, cns);
    const char* parts[] = {"usb-library-file-v1", fields};
    return dest_identity_hash(parts, 2, out);
}

static struct dirent* usb_catalog_next(DIR* dir, const char** reason) {
    errno = 0;
#ifdef USB_IDENTITY_TEST
    extern struct dirent* usb_test_catalog_readdir(DIR*);
    struct dirent* entry = usb_test_catalog_readdir(dir);
#else
    struct dirent* entry = readdir(dir);
#endif
    if (!entry && errno && (!*reason || !strcmp(*reason,"entry_unconfirmed"))) *reason = "directory_read_failed";
    return entry;
}

static bool usb_catalog_hidden(DIR* dir, const char* name, const char** reason) {
    if (name[0] != '.') return false;
    if (!strcmp(name, ".") || !strcmp(name, "..")) return true;
    struct stat st;
    if (fstatat(dirfd(dir), name, &st, AT_SYMLINK_NOFOLLOW) != 0) {
        if (!*reason || !strcmp(*reason,"entry_unconfirmed")) *reason = "entry_unavailable";
    } else if (S_ISDIR(st.st_mode) || S_ISLNK(st.st_mode)) {
        if (!*reason || !strcmp(*reason,"entry_unconfirmed")) *reason = "hidden_directory";
    }
    return true;
}

static bool usb_catalog_directory_same(int fd, const char* path) {
    struct stat pinned, current;
    return fstat(fd, &pinned) == 0 && lstat(path, &current) == 0 &&
           S_ISDIR(current.st_mode) && pinned.st_dev == current.st_dev &&
           pinned.st_ino == current.st_ino;
}

size_t usb_catalog_scan(usb_backup_t* out, size_t max_out, catalog_scan_t* scan) {
    catalog_scan_t state = {CATALOG_UNAVAILABLE, "not_configured", false};
    if (!scan) scan = &state;
    *scan = state;
    USB_CFG_BEGIN();
    if (!s_cfg || !s_cfg_have || !out || !max_out) {
        scan->configured = s_cfg != NULL;
        scan->reason = "configuration_unavailable";
        return 0;
    }
    usb_mount_t mounts[8];
    size_t mn = usb_catalog_mounts(mounts, 8), n = 0;
    scan->configured = mn > 0 || CFG->usb.enabled;
    bool readable = false, capped = false;
    const char* reason = NULL;
#define USB_CATALOG_GAP(value) do { if (!reason || !strcmp(reason,"entry_unconfirmed")) reason = value; } while (0)
    // A known backup tree in a slot whose readable filesystem cannot be
    // confirmed is not proof that the Library is empty.
    for (unsigned slot = 0; slot < 8; slot++) {
        char mount[64], root[USB_PATH_MAX];
        snprintf(mount, sizeof(mount), "%s%u", USB_MOUNT_BASE, slot);
        bool found = false;
        for (size_t i = 0; i < mn; i++) if (!strcmp(mount, mounts[i].path)) found = true;
        if (found) continue;
        snprintf(root, sizeof(root), "%s/%s", mount, usb_folder());
        struct stat st;
        if (lstat(root, &st) == 0 || errno != ENOENT) {
            scan->configured = true;
            USB_CATALOG_GAP("mount_unavailable");
        }
    }
    if (!mn) {
        scan->reason = reason ? reason : (scan->configured ? "usb_disconnected" : "not_configured");
        return 0;
    }
    for (size_t mi = 0; mi < mn && !capped; mi++) {
        size_t first_volume = n;
        char root[USB_PATH_MAX], volume[65] = {0};
        int mountfd = open(mounts[mi].path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW);
        if (mountfd < 0) { USB_CATALOG_GAP("mount_unavailable"); continue; }
        if (!usb_volume_identity(mountfd, mounts[mi].path, volume))
            USB_CATALOG_GAP("destination_unconfirmed");
        int rn = snprintf(root, sizeof(root), "%s/%s", mounts[mi].path, usb_folder());
        if (rn <= 0 || (size_t)rn >= sizeof(root)) {
            USB_CATALOG_GAP("path_too_long"); close(mountfd); continue;
        }
        struct stat root_stat;
        DIR* users = NULL;
        if (lstat(root, &root_stat) != 0) {
            if (errno == ENOENT && volume[0]) readable = true;
            else USB_CATALOG_GAP("directory_unavailable");
        } else if (!S_ISDIR(root_stat.st_mode)) USB_CATALOG_GAP("unsafe_entry");
        else {
            users = opendir(root);
            if (!users) USB_CATALOG_GAP("directory_unavailable");
        }
        if (users) {
            readable = true;
            struct dirent* ue;
            while (!capped && (ue = usb_catalog_next(users, &reason)) != NULL) {
                if (usb_catalog_hidden(users, ue->d_name, &reason)) continue;
                if (!usb_name_safe_for_catalog(ue->d_name)) { USB_CATALOG_GAP("invalid_name"); continue; }
                char user_dir[USB_PATH_MAX];
                int un = snprintf(user_dir, sizeof(user_dir), "%s/%s", root, ue->d_name);
                if (un <= 0 || (size_t)un >= sizeof(user_dir)) { USB_CATALOG_GAP("path_too_long"); continue; }
                struct stat ust;
                if (lstat(user_dir, &ust) != 0) { USB_CATALOG_GAP("entry_unavailable"); continue; }
                if (S_ISREG(ust.st_mode)) continue; // metadata file, not a user directory
                if (!S_ISDIR(ust.st_mode)) { USB_CATALOG_GAP("unsafe_entry"); continue; }
                DIR* titles = opendir(user_dir);
                if (!titles) { USB_CATALOG_GAP("directory_unavailable"); continue; }
                size_t first_user = n;
                struct dirent* te;
                while (!capped && (te = usb_catalog_next(titles, &reason)) != NULL) {
                    if (usb_catalog_hidden(titles, te->d_name, &reason)) continue;
                    if (!usb_name_safe_for_catalog(te->d_name)) { USB_CATALOG_GAP("invalid_name"); continue; }
                    char title_dir[USB_PATH_MAX];
                    int tn = snprintf(title_dir, sizeof(title_dir), "%s/%s", user_dir, te->d_name);
                    if (tn <= 0 || (size_t)tn >= sizeof(title_dir)) { USB_CATALOG_GAP("path_too_long"); continue; }
                    struct stat tst;
                    if (lstat(title_dir, &tst) != 0) { USB_CATALOG_GAP("entry_unavailable"); continue; }
                    if (S_ISREG(tst.st_mode)) continue;
                    if (!S_ISDIR(tst.st_mode)) { USB_CATALOG_GAP("unsafe_entry"); continue; }
                    DIR* files = opendir(title_dir);
                    if (!files) { USB_CATALOG_GAP("directory_unavailable"); continue; }
                    size_t first = n;
                    char location[65] = {0}, identity[65] = {0};
                    if (usb_directory_identity(mounts[mi].path, title_dir, dirfd(files), location))
                        usb_confirmed_identity(dirfd(files), location, false, identity);
                    struct stat marker_stat;
                    bool older = mounts[mi].identity_confirmed && volume[0] && !identity[0] && location[0] &&
                        fstatat(dirfd(files), ".tostonsync-destination-id", &marker_stat, AT_SYMLINK_NOFOLLOW) != 0 && errno == ENOENT;
                    struct dirent* fe;
                    while (!capped && (fe = usb_catalog_next(files, &reason)) != NULL) {
                        size_t length = strlen(fe->d_name);
                        if (length < 4 || strcmp(fe->d_name + length - 4, ".zip")) continue;
                        if (fe->d_name[0] == '.') { USB_CATALOG_GAP("hidden_archive"); continue; }
                        if (!usb_name_safe_for_catalog(fe->d_name)) { USB_CATALOG_GAP("invalid_name"); continue; }
                        usb_backup_t entry = {0};
                        snprintf(entry.volume_id,sizeof(entry.volume_id),"%s",mounts[mi].volume_id);
                        snprintf(entry.mount,sizeof(entry.mount),"%s",mounts[mi].path);
                        char user_code[32], title_code[16];
                        const char* user = backup_folder_code(ue->d_name, false, user_code, sizeof(user_code)) ? user_code : ue->d_name;
                        if (!backup_folder_code(te->d_name, true, title_code, sizeof(title_code))) {
                            USB_CATALOG_GAP("invalid_title_id"); continue;
                        }
                        int user_n = snprintf(entry.user, sizeof(entry.user), "%s", user);
                        int title_n = snprintf(entry.title_id, sizeof(entry.title_id), "%s", title_code);
                        int name_n = snprintf(entry.name, sizeof(entry.name), "%s", fe->d_name);
                        int path_n = snprintf(entry.path, sizeof(entry.path), "%s/%s", title_dir, fe->d_name);
                        if (user_n <= 0 || (size_t)user_n >= sizeof(entry.user) ||
                            title_n <= 0 || (size_t)title_n >= sizeof(entry.title_id) ||
                            name_n <= 0 || (size_t)name_n >= sizeof(entry.name) ||
                            path_n <= 0 || (size_t)path_n >= sizeof(entry.path)) {
                            USB_CATALOG_GAP("path_too_long"); continue;
                        }
                        struct stat fst;
                        if (fstatat(dirfd(files), fe->d_name, &fst, AT_SYMLINK_NOFOLLOW) != 0 ||
                            !S_ISREG(fst.st_mode) || fst.st_size <= 0) { USB_CATALOG_GAP("entry_unavailable"); continue; }
                        if (n == max_out) { USB_CATALOG_GAP("catalog_limit"); capped = true; break; }
                        entry.size_bytes = (uint64_t)fst.st_size;
                        entry.created_unix = (int64_t)fst.st_mtime;
                        snprintf(entry.destination_identity, sizeof(entry.destination_identity), "%s", identity);
                        entry.older_unconfirmed = older;
                        if (!identity[0]) USB_CATALOG_GAP(older ? "entry_unconfirmed" : "destination_unconfirmed");
                        usb_library_file_stamp(&fst, entry.file_stamp);
                        snprintf(entry.destination_label, sizeof(entry.destination_label),
                                 "USB %s · %s · destination=%.12s", mounts[mi].display_name,
                                 title_dir, identity[0] ? identity : "unknown");
                        out[n++] = entry;
                    }
                    char confirmed[65] = {0}, final_location[65] = {0};
                    bool same_directory = usb_catalog_directory_same(dirfd(files), title_dir);
                    bool same_location = usb_directory_identity(mounts[mi].path, title_dir, dirfd(files), final_location) && !strcmp(location, final_location);
                    bool still_older = older && fstatat(dirfd(files), ".tostonsync-destination-id", &marker_stat, AT_SYMLINK_NOFOLLOW) != 0 && errno == ENOENT;
                    bool same_marker = older ? still_older : usb_confirmed_identity(dirfd(files), location, false, confirmed) && !strcmp(identity, confirmed);
                    if (!same_directory || !same_location || !same_marker) {
                        if (!same_directory || n > first) USB_CATALOG_GAP("destination_changed");
                        for (size_t i = first; i < n; i++) {out[i].destination_identity[0] = '\0'; out[i].older_unconfirmed = false;}
                    }
                    if (closedir(files) != 0) USB_CATALOG_GAP("directory_read_failed");
                }
                if (!usb_catalog_directory_same(dirfd(titles), user_dir)) {
                    USB_CATALOG_GAP("destination_changed");
                    for (size_t i = first_user; i < n; i++) {out[i].destination_identity[0] = '\0'; out[i].older_unconfirmed = false;}
                }
                if (closedir(titles) != 0) USB_CATALOG_GAP("directory_read_failed");
            }
            if (!usb_catalog_directory_same(dirfd(users), root)) {
                USB_CATALOG_GAP("destination_changed");
                n = first_volume;
            }
            if (closedir(users) != 0) USB_CATALOG_GAP("directory_read_failed");
        }
        char confirmed_volume[65]; usb_mount_t current_mount, held_mount=mounts[mi];
        usb_observe_identity_at(mountfd,&held_mount);
        if (!volume[0] || !usb_volume_identity(mountfd, mounts[mi].path, confirmed_volume) ||
            strcmp(volume, confirmed_volume) || !usb_mount_info(mounts[mi].path,&current_mount) ||
            !usb_mount_is_readable(&current_mount) || strcmp(mounts[mi].volume_id,current_mount.volume_id) ||
            strcmp(mounts[mi].volume_id,held_mount.volume_id) ||
            !usb_catalog_directory_same(mountfd, mounts[mi].path)) {
            USB_CATALOG_GAP("destination_changed");
            n = first_volume;
        }
        close(mountfd);
    }

    for (size_t i = 1; i < n; i++) {
        usb_backup_t key = out[i];
        size_t j = i;
        while (j > 0 && usb_backup_newer(&key, &out[j - 1])) {
            out[j] = out[j - 1];
            j--;
        }
        out[j] = key;
    }
    scan->state = reason ? (readable || n ? CATALOG_PARTIAL : CATALOG_UNAVAILABLE)
                         : (n ? CATALOG_COMPLETE : CATALOG_EMPTY);
    scan->reason = reason ? reason : "";
#undef USB_CATALOG_GAP
    return n;
}

size_t usb_list_all_versions(usb_backup_t* out, size_t max_out) {
    return usb_catalog_scan(out, max_out, NULL);
}

static bool usb_retention_identity(int dirfd, const char* mount,
                                    const char* dir, const char* expected) {
    char location[65], identity[65]; usb_mount_t observed;
    return usb_mount_info(mount,&observed) && usb_mount_is_usable(&observed) &&
           usb_directory_identity(mount, dir, dirfd, location) &&
           usb_confirmed_identity(dirfd, location, false, identity) &&
           strcmp(identity, expected) == 0;
}

static bool usb_retention_file(int dirfd, const char* name,
                                const struct stat* listed) {
    struct stat current;
    char current_stamp[65], listed_stamp[65];
    return fstatat(dirfd, name, &current, AT_SYMLINK_NOFOLLOW) == 0 &&
           S_ISREG(current.st_mode) && usb_library_file_stamp(&current, current_stamp) &&
           usb_library_file_stamp(listed, listed_stamp) && !strcmp(current_stamp, listed_stamp);
}

bool usb_enforce_retention_identified(const char* user_alias,
                                      const char* title_id,
                                      const char* keep_filename,
                                      const char* expected_identity) {
    USB_CFG_BEGIN();
    if (!s_cfg || !s_cfg_have || !CFG->usb.enabled) return false;
    if (CFG->retention.max_versions <= 0) return true;
    if (!dest_fingerprint_hex(expected_identity) ||
        (keep_filename && !usb_path_component(keep_filename))) return false;
    char mount[64], dir[USB_PATH_MAX];
    if (!usb_backup_dir(mount, dir, user_alias, title_id, false)) return false;
    int dirfd = open(dir, O_RDONLY | O_DIRECTORY | O_NOFOLLOW);
    if (dirfd < 0) return false;
    if (!usb_retention_identity(dirfd, mount, dir, expected_identity)) {
        close(dirfd);
        log_warn("usb: retention skipped; accepted destination not confirmed");
        return false;
    }
    // ponytail: keep the existing 256-version bound; overflow skips cleanup
    // rather than deciding retention from a truncated catalog.
    enum { MAX = 256 };
    typedef struct { usb_version_t version; struct stat st; } retention_entry_t;
    retention_entry_t list[MAX];
    size_t n = 0;
    int scanfd = dup(dirfd);
    DIR* scan = scanfd >= 0 ? fdopendir(scanfd) : NULL;
    if (!scan) { if (scanfd >= 0) close(scanfd); close(dirfd); return false; }
    bool ok = true;
    for (;;) {
        errno = 0;
        struct dirent* e = readdir(scan);
        if (!e) { if (errno) ok = false; break; }
        size_t len = strlen(e->d_name);
        if (e->d_name[0] == '.' || len < 4 || strcmp(e->d_name + len - 4, ".zip"))
            continue;
        if (n == MAX || !usb_path_component(e->d_name) ||
            fstatat(dirfd, e->d_name, &list[n].st, AT_SYMLINK_NOFOLLOW) != 0 ||
            !S_ISREG(list[n].st.st_mode)) { ok = false; break; }
        usb_version_t* v = &list[n].version;
        int pn = snprintf(v->path, sizeof(v->path), "%s/%s", dir, e->d_name);
        int nn = snprintf(v->name, sizeof(v->name), "%s", e->d_name);
        if (pn < 0 || (size_t)pn >= sizeof(v->path) ||
            nn < 0 || (size_t)nn >= sizeof(v->name)) { ok = false; break; }
        v->size_bytes = (uint64_t)list[n].st.st_size;
        v->created_unix = (int64_t)list[n].st.st_mtime;
        n++;
    }
    if (closedir(scan) != 0) ok = false;
    if (!ok || !usb_retention_identity(dirfd, mount, dir, expected_identity)) {
        close(dirfd);
        log_warn("usb: retention skipped; incomplete listing or destination changed");
        return false;
    }
    // Newest first, preserving the existing max_versions policy.
    for (size_t i = 1; i < n; i++)
        for (size_t j = i; j > 0 &&
             list[j - 1].version.created_unix < list[j].version.created_unix; j--) {
            retention_entry_t tmp = list[j - 1];
            list[j - 1] = list[j];
            list[j] = tmp;
        }
    // A future mtime on an older archive must not prune the copy we just
    // promised. Count it first for this pass; do not create a permanent favorite.
    if (keep_filename) {
        bool found = false;
        for (size_t i = 0; i < n; i++)
            if (strcmp(list[i].version.name, keep_filename) == 0) {
                retention_entry_t fresh = list[i];
                memmove(list + 1, list, i * sizeof(*list));
                list[0] = fresh;
                found = list[0].st.st_size > 0;
                break;
            }
        if (!found) { close(dirfd); return false; }
    }
    int keep = CFG->retention.max_versions;
    int pruned = 0;
    for (size_t i = (size_t)keep; i < n; i++) {
        if (protect_is(list[i].version.path)) continue;  // favorites are never pruned
        if (!usb_retention_identity(dirfd, mount, dir, expected_identity) ||
            (keep_filename && !usb_retention_file(dirfd, keep_filename, &list[0].st)) ||
            !usb_retention_file(dirfd, list[i].version.name, &list[i].st) ||
            unlinkat(dirfd, list[i].version.name, 0) != 0) {
            ok = false;
            log_warn("usb: retention stopped; destination/file changed or delete failed");
            break;
        }
        pruned++;
    }
    close(dirfd);
    if (pruned)
        log_info("usb: pruned %d old version(s) for %s/%s",
                 pruned, user_alias ? user_alias : "default", title_id);
    return ok;
}

void usb_enforce_retention(const char* user_alias, const char* title_id,
                           const char* keep_filename) {
    char identity[65];
    if (usb_backup_identity(user_alias, title_id, identity))
        usb_enforce_retention_identified(user_alias, title_id, keep_filename, identity);
}

bool usb_delete_backup_identified(const char* path, uint64_t expected_size,
                                  const char* expected_identity,
                                  const char* expected_file_stamp) {
    USB_CFG_BEGIN();
    if (!s_cfg || !s_cfg_have || !path || !expected_size ||
        !dest_fingerprint_hex(expected_identity) ||
        !dest_fingerprint_hex(expected_file_stamp) || strstr(path, "..")) return false;
    const char* name = strrchr(path, '/');
    if (!name || !usb_path_component(++name)) return false;
    size_t len = strlen(name);
    if (len <= 4 || strcmp(name + len - 4, ".zip")) return false;
    usb_mount_t mounts[8];
    size_t count = usb_list_mounts(mounts, 8);
    for (size_t i = 0; i < count; i++) {
        char root[USB_PATH_MAX], dir[USB_PATH_MAX];
        int rn = snprintf(root, sizeof(root), "%s/%s", mounts[i].path, usb_folder());
        if (rn <= 0 || (size_t)rn >= sizeof(root) ||
            strncmp(path, root, (size_t)rn) || path[rn] != '/') continue;
        const char* user = path + rn + 1;
        const char* title = strchr(user, '/');
        const char* file = title ? strchr(title + 1, '/') : NULL;
        if (!title || title == user || !file || file != name - 1) return false;
        if ((size_t)(title - user) >= 128) return false;
        for (const unsigned char* p = (const unsigned char*)user;
             p < (const unsigned char*)title; p++)
            if (*p < 0x20 || *p == 0x7f || *p == '\\') return false;
        size_t title_len = (size_t)(file - title - 1);
        char title_name[128], title_code[16];
        if (!title_len || title_len >= sizeof(title_name)) return false;
        memcpy(title_name, title + 1, title_len); title_name[title_len] = '\0';
        if (!backup_folder_code(title_name, true, title_code, sizeof(title_code))) return false;
        size_t dlen = (size_t)(name - 1 - path);
        if (dlen >= sizeof(dir)) return false;
        memcpy(dir, path, dlen); dir[dlen] = '\0';
        int fd = open(dir, O_RDONLY | O_DIRECTORY | O_NOFOLLOW);
        if (fd < 0) return false;
        struct stat listed;
        char stamp[65];
        bool ok = usb_retention_identity(fd, mounts[i].path, dir, expected_identity) &&
                  fstatat(fd, name, &listed, AT_SYMLINK_NOFOLLOW) == 0 &&
                  S_ISREG(listed.st_mode) && listed.st_size > 0 &&
                  (uint64_t)listed.st_size == expected_size &&
                  usb_library_file_stamp(&listed, stamp) && !strcmp(stamp, expected_file_stamp) &&
                  usb_retention_identity(fd, mounts[i].path, dir, expected_identity) &&
                  usb_retention_file(fd, name, &listed) && unlinkat(fd, name, 0) == 0;
        close(fd);
        if (ok) log_info("usb: deleted confirmed Library archive %s", path);
        else log_warn("usb: Library delete refused; destination/file is unconfirmed");
        return ok;
    }
    return false;
}

// Compatibility symbol only: current deletion requires a bound catalog ticket.
bool usb_delete_backup(const char* path) {
    (void)path;
    // A path alone cannot prove which volume produced the caller's catalog.
    return false;
}

// Separate, read-only Individual Library namespace. No Full policy consumes it.
static int usb_individual_child(int parent, const char* code, bool title,
                                char name[256], const char** reason) {
    int copy = dup(parent);
    DIR* dir = copy < 0 ? NULL : fdopendir(copy);
    if (!dir) { if (copy >= 0) close(copy); *reason = "directory_unavailable"; return -1; }
    unsigned matched = 0, examined = 0;
    struct dirent* entry;
    while ((entry = usb_catalog_next(dir, reason))) {
        if (!strcmp(entry->d_name, ".") || !strcmp(entry->d_name, "..")) continue;
        if (++examined > 4096) { *reason = "directory_limit"; break; }
        char found[32];
        if (!backup_folder_code(entry->d_name, title, found, sizeof(found)) || strcmp(found, code)) continue;
        struct stat st;
        if (fstatat(parent, entry->d_name, &st, AT_SYMLINK_NOFOLLOW) || !S_ISDIR(st.st_mode) ||
            !usb_name_safe_for_catalog(entry->d_name) || strlen(entry->d_name) >= 256) {
            *reason = "unsafe_entry"; continue;
        }
        snprintf(name, 256, "%s", entry->d_name); matched++;
    }
    closedir(dir);
    if (*reason) return -1;
    if (matched > 1) { *reason = "ambiguous_folder"; return -1; }
    if (!matched) return -2;
    int fd = openat(parent, name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW);
    if (fd < 0) *reason = "directory_unavailable";
    return fd;
}

size_t usb_individual_scan(const char* user, const char* title,
                          individual_backup_t* out, size_t cap, catalog_scan_t* scan) {
    catalog_scan_t local;
    if (!scan) scan = &local;
    *scan = (catalog_scan_t){CATALOG_UNAVAILABLE, "configuration_unavailable", false};
    USB_CFG_BEGIN();
    char uid[32], tid[16];
    if (!s_cfg || !s_cfg_have || !out || !cap || cap > INDIVIDUAL_CATALOG_MAX ||
        !backup_folder_code(user, false, uid, sizeof(uid)) ||
        !backup_folder_code(title, true, tid, sizeof(tid)) || !usb_path_component(usb_folder())) return 0;
    scan->configured = CFG->usb.enabled;
    usb_mount_t mounts[8]; size_t count = usb_catalog_mounts(mounts, 8), n = 0;
    const char* reason = NULL;
    for (unsigned slot = 0; slot < 8; slot++) {
        char mount[64], root[768]; bool listed = false;
        snprintf(mount, sizeof(mount), "%s%u", USB_MOUNT_BASE, slot);
        for (size_t i = 0; i < count; i++) if (!strcmp(mount, mounts[i].path)) listed = true;
        if (listed) continue;
        snprintf(root, sizeof(root), "%s/%s", mount, usb_folder());
        struct stat st;
        if (!lstat(root, &st) || errno != ENOENT) reason = "mount_unavailable";
    }
    if (!count) { scan->reason = reason ? reason : "usb_disconnected"; return 0; }
    scan->configured = true;
    for (size_t m = 0; m < count; m++) {
        int fds[5] = {-1,-1,-1,-1,-1}; char paths[5][768], uname[256], tname[256];
        size_t first = n; const char* gap = NULL;
        snprintf(paths[0], sizeof(paths[0]), "%s", mounts[m].path);
        fds[0] = open(paths[0], O_RDONLY | O_DIRECTORY | O_NOFOLLOW);
        if (fds[0] < 0) { reason = "mount_unavailable"; continue; }
        char volume[65];
        if (!usb_volume_identity(fds[0], paths[0], volume)) gap = "destination_unconfirmed";
        int len = snprintf(paths[1], sizeof(paths[1]), "%s/%s", paths[0], usb_folder());
        if (len < 0 || (size_t)len >= sizeof(paths[1])) gap = "path_too_long";
        if (!gap) fds[1] = openat(fds[0], usb_folder(), O_RDONLY | O_DIRECTORY | O_NOFOLLOW);
        if (!gap && fds[1] < 0 && errno != ENOENT) gap = "directory_unavailable";
        if (!gap && fds[1] >= 0) {
            fds[2] = usb_individual_child(fds[1], uid, false, uname, &gap);
            if (fds[2] >= 0) {
                len = snprintf(paths[2], sizeof(paths[2]), "%s/%s", paths[1], uname);
                if (len < 0 || (size_t)len >= sizeof(paths[2])) gap = "path_too_long";
                if (!gap) fds[3] = usb_individual_child(fds[2], tid, true, tname, &gap);
            }
            if (!gap && fds[3] >= 0) {
                len = snprintf(paths[3], sizeof(paths[3]), "%s/%s", paths[2], tname);
                if (len < 0 || (size_t)len >= sizeof(paths[3])) gap = "path_too_long";
                if (!gap) fds[4] = openat(fds[3], "Individual saves", O_RDONLY | O_DIRECTORY | O_NOFOLLOW);
                if (!gap && fds[4] < 0 && errno != ENOENT) gap = "directory_unavailable";
            }
            if (!gap && fds[4] >= 0) {
                len = snprintf(paths[4], sizeof(paths[4]), "%s/Individual saves", paths[3]);
                char identity[65];
                if (len < 0 || (size_t)len >= sizeof(paths[4])) gap = "path_too_long";
                else if (!usb_directory_identity(paths[0], paths[4], fds[4], identity)) gap = "destination_unconfirmed";
                if (!gap) {
                    struct stat directory; char inode[64], location[65];
                    snprintf(location, sizeof(location), "%s", identity);
                    if (fstat(fds[4], &directory)) gap = "destination_unconfirmed";
                    else {
                        snprintf(inode, sizeof(inode), "%llu:%llu", (unsigned long long)directory.st_dev,
                                 (unsigned long long)directory.st_ino);
                        const char* parts[] = {"usb-individual-folder-v1", location, inode};
                        if (!dest_identity_hash(parts, 3, identity)) gap = "destination_unconfirmed";
                    }
                }
                int copy = gap ? -1 : dup(fds[4]); DIR* files = copy < 0 ? NULL : fdopendir(copy);
                if (!gap && !files) { if (copy >= 0) close(copy); gap = "directory_unavailable"; }
                unsigned examined = 0; struct dirent* entry;
                while (files && (entry = usb_catalog_next(files, &gap))) {
                    if (!strcmp(entry->d_name, ".") || !strcmp(entry->d_name, "..")) continue;
                    if (++examined > 4096) { gap = "directory_limit"; break; }
                    size_t length = strlen(entry->d_name);
                    if (length < 4 || strcmp(entry->d_name + length - 4, ".zip")) continue;
                    individual_backup_t row; struct stat st;
                    if (!individual_catalog_label(uid, tid, "usb", entry->d_name, &row) ||
                        fstatat(fds[4], entry->d_name, &st, AT_SYMLINK_NOFOLLOW) || !S_ISREG(st.st_mode) ||
                        st.st_size < 22 || (uint64_t)st.st_size > INDIVIDUAL_MAX_BYTES) {
                        gap = "invalid_individual_archive"; continue;
                    }
                    if (n == cap) { gap = "catalog_limit"; break; }
                    char canonical[768];
                    if (!realpath(paths[4], canonical)) { gap = "destination_unconfirmed"; continue; }
                    len = snprintf(row.ref, sizeof(row.ref), "%s/%s", canonical, entry->d_name);
                    if (len < 0 || (size_t)len >= sizeof(row.ref)) { gap = "path_too_long"; continue; }
                    snprintf(row.parent_ref, sizeof(row.parent_ref), "%s", canonical);
                    snprintf(row.destination_identity, sizeof(row.destination_identity), "%s", identity);
                    snprintf(row.volume_id,sizeof(row.volume_id),"%s",mounts[m].volume_id);
                    snprintf(row.mount,sizeof(row.mount),"%s",mounts[m].path);
                    row.size_bytes = (uint64_t)st.st_size;
                    usb_library_file_stamp(&st, row.file_stamp); out[n++] = row;
                }
                if (files) closedir(files);
            }
        }
        usb_mount_t current_mount, held_mount=mounts[m];
        usb_observe_identity_at(fds[0],&held_mount);
        bool moved = !usb_mount_info(mounts[m].path,&current_mount) ||
            !usb_mount_is_readable(&current_mount) || strcmp(mounts[m].volume_id,current_mount.volume_id) ||
            strcmp(mounts[m].volume_id,held_mount.volume_id);
        for (size_t i = 0; i < 5; i++) if (fds[i] >= 0 && !usb_catalog_directory_same(fds[i], paths[i])) moved = true;
        for (size_t i = 0; i < 5; i++) if (fds[i] >= 0) close(fds[i]);
        if (moved) { n = first; gap = "destination_changed"; }
        if (gap && !reason) reason = gap;
    }
    scan->state = reason ? CATALOG_PARTIAL : (n ? CATALOG_COMPLETE : CATALOG_EMPTY);
    scan->reason = reason; return n;
}

static int usb_individual_open(const individual_backup_t* item) {
    // Every ancestor is opened without following links, not just the last file.
    if (item->ref[0] != '/') return -1;
    char path[768]; snprintf(path, sizeof(path), "%s", item->ref + 1);
    int fd = open("/", O_RDONLY | O_DIRECTORY | O_NOFOLLOW); char* save = NULL;
    for (char* part = strtok_r(path, "/", &save); part; part = strtok_r(NULL, "/", &save)) {
        if (!strcmp(part, ".") || !strcmp(part, "..")) { close(fd); return -1; }
        bool last = !save || !*save;
        int next = openat(fd, part, O_RDONLY | O_NOFOLLOW | (last ? 0 : O_DIRECTORY));
        close(fd); fd = next; if (fd < 0) return -1;
    }
    struct stat st; char stamp[65];
    if (fstat(fd, &st) || !S_ISREG(st.st_mode) || st.st_size < 22 ||
        (uint64_t)st.st_size != item->size_bytes || !usb_library_file_stamp(&st, stamp) ||
        strcmp(stamp, item->file_stamp)) { close(fd); return -1; }
    return fd;
}

static bool usb_individual_stream(int source, int target, const individual_backup_t* item) {
    sha256_ctx_t hash; sha256_init(&hash); uint64_t total = 0; unsigned char data[65536];
    for (;;) {
        ssize_t got = read(source, data, sizeof(data));
        if (got < 0) { if (errno == EINTR) continue; return false; }
        if (!got) break;
        if ((uint64_t)got > item->size_bytes - total) return false;
        total += (uint64_t)got; sha256_update(&hash, data, (size_t)got);
        size_t offset = 0;
        while (target >= 0 && offset < (size_t)got) {
            ssize_t written = write(target, data + offset, (size_t)got - offset);
            if (written < 0 && errno == EINTR) continue;
            if (written <= 0) return false; offset += (size_t)written;
        }
    }
    unsigned char digest[32]; char hex[65]; sha256_final(&hash, digest);
    for (size_t i = 0; i < 32; i++) snprintf(hex + i*2, 3, "%02x", digest[i]);
    struct stat st; char stamp[65];
    return total == item->size_bytes && (!item->checksum[0] || !strcmp(hex, item->checksum)) &&
        !fstat(source, &st) && usb_library_file_stamp(&st, stamp) && !strcmp(stamp, item->file_stamp);
}

bool usb_individual_revalidate(const individual_backup_t* item) {
    if (!individual_catalog_item_valid(item, "usb")) return false;
    individual_backup_t* rows = calloc(INDIVIDUAL_CATALOG_MAX, sizeof(*rows));
    if (!rows) return false;
    catalog_scan_t scan; size_t n = usb_individual_scan(item->user, item->title_id, rows, INDIVIDUAL_CATALOG_MAX, &scan);
    bool same = false;
    if (scan.state == CATALOG_COMPLETE) for (size_t i = 0; i < n; i++)
        if (individual_catalog_same(item, rows + i)) same = true;
    free(rows);
    if (same && item->checksum[0]) {
        int fd = usb_individual_open(item); same = fd >= 0 && usb_individual_stream(fd, -1, item);
        if (fd >= 0) close(fd);
    }
    return same;
}

bool usb_individual_download_bounded(const individual_backup_t* item, const char* local_path,
                                     char* err, size_t err_sz) {
    bool ok = false; int source = -1, target = -1;
    if (!local_path || !local_path[0] || !usb_individual_revalidate(item)) goto done;
    source = usb_individual_open(item); if (source < 0) goto done;
    target = open(local_path, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW, 0600);
    if (target < 0) goto done;
    ok = usb_individual_stream(source, target, item) && !fsync(target) && usb_individual_revalidate(item);
done:
    if (source >= 0) close(source);
    if (target >= 0) { if (close(target)) ok = false; if (!ok) unlink(local_path); }
    if (!ok && err && err_sz) snprintf(err, err_sz, "Individual source changed or bounded copy failed.");
    return ok;
}
