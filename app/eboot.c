// TostónSync native dashboard entry. No payload CRT / payload_args_t ABI.
// The raw syscall entry and static _start follow ps5-payload-sdk's
// samples/install_app/eboot.c, Copyright (C) 2025 John Törnblom, GPL-3.0-or-later.
// Sony NIDs below were generated with the SDK's prospero-nid tool.
#include <stddef.h>
#include <stdint.h>
#include "../src/version.h"

enum { S_EXIT=1, S_READ=3, S_OPEN=5, S_CLOSE=6, S_FCNTL=92,
       S_SOCKET=97, S_CONNECT=98, S_SETSOCKOPT=105, S_GETSOCKOPT=118,
       S_FLOCK=131, S_SENDTO=133, S_SHUTDOWN=134, S_POLL=209,
       S_CLOCK=232, S_SLEEP=240, S_LSEEK=478, S_DLSYM=591, S_KLOG=601 };
enum { P_EINTR=4, P_AGAIN=35, P_INPROGRESS=36, P_REFUSED=61,
       P_IN=1, P_OUT=4, P_NVAL=32, P_NOSIGNAL=0x20000 };
#define PORT_FILE "/data/tostonsync/.port"
#define ELF_FILE "/data/tostonsync/tostonsync.elf"
#define LOCK_FILE "/data/tostonsync/.launcher.lock"
#define DEFAULT_PORT 1993
#define LOADER_PORT 9021
#define MAX_ELF (16 * 1024 * 1024)
struct p_time { int64_t sec, ns; };
struct p_poll { int fd; short events, revents; };
struct p_address { uint8_t len, family; uint16_t port; uint8_t ip[4], zero[8]; };

#ifdef APP_LAUNCHER_TEST
static long app_syscall(long, long, long, long, long, long, long);
#else
static long app_syscall(long n, long a, long b, long c, long d, long e, long f) {
    register long r10 __asm__("r10") = d;
    register long r8 __asm__("r8") = e;
    register long r9 __asm__("r9") = f;
    unsigned long ret;
    unsigned char failed;
    __asm__ __volatile__("syscall" : "=a"(ret), "=@ccc"(failed),
        "+r"(r10), "+r"(r8), "+r"(r9), "+d"(c)
        : "a"(n), "D"(a), "S"(b) : "rcx", "r11", "memory");
    return failed ? -(long)ret : (long)ret;
}
#endif
#define SC(n,a,b,c,d,e,f) app_syscall(n,(long)(a),(long)(b),(long)(c),(long)(d),(long)(e),(long)(f))

static size_t text_len(const char *s) { size_t n=0; while (s[n]) n++; return n; }
static int bytes_equal(const char *a, const char *b, size_t n) {
    for (size_t i=0; i<n; i++) if (a[i]!=b[i]) return 0;
    return 1;
}
static void zero_bytes(void *p, size_t n) {
    unsigned char *b=p; for (size_t i=0; i<n; i++) b[i]=0;
}
static void close_fd(int fd) { if (fd>=0) (void)SC(S_CLOSE,fd,0,0,0,0,0); }
static int64_t now_ms(void) {
    struct p_time t;
    if (SC(S_CLOCK,4,&t,0,0,0,0)<0 || t.sec<0 || t.sec>INT64_MAX/1000-30 ||
        t.ns<0 || t.ns>=1000000000)
        return -1;
    return t.sec*1000+t.ns/1000000;
}
static int remaining(int64_t deadline) {
    int64_t now=now_ms();
    if (now<0 || now>=deadline) return 0;
    return (int)(deadline-now);
}
static int wait_fd(int fd, short events, int64_t deadline) {
    for (;;) {
        int left=remaining(deadline); if (!left) return 0;
        struct p_poll p={fd,events,0};
        long rc=SC(S_POLL,&p,1,left,0,0,0);
        if (rc==-P_EINTR) continue;
        return rc>0 && !(p.revents&P_NVAL);
    }
}

// All sockets are nonblocking. A timeout/error is never evidence of absence.
static int connect_local(int port, int64_t deadline, int *refused) {
    *refused=0;
    long fd=SC(S_SOCKET,2,1,0,0,0,0);
    if (fd<0) return -1;
    int yes=1;
    if (SC(S_FCNTL,fd,4,4,0,0,0)<0 ||
        SC(S_SETSOCKOPT,fd,0xffff,0x0800,&yes,sizeof(yes),0)<0) {
        close_fd((int)fd); return -1;
    }
    struct p_address a={16,2,0,{127,0,0,1},{0}};
    a.port=(uint16_t)(((unsigned)port>>8)|((unsigned)port<<8));
    long rc=SC(S_CONNECT,fd,&a,sizeof(a),0,0,0);
    if (rc==-P_INPROGRESS || rc==-P_EINTR) {
        int err=0; unsigned len=sizeof(err);
        if (!wait_fd((int)fd,P_OUT,deadline) ||
            SC(S_GETSOCKOPT,fd,0xffff,0x1007,&err,&len,0)<0 || len!=sizeof(err)) {
            close_fd((int)fd); return -1;
        }
        rc=-(long)err;
    }
    if (rc<0) {
        *refused=rc==-P_REFUSED; close_fd((int)fd); return -1;
    }
    return (int)fd;
}
static int send_all(int fd, const void *data, size_t n, int64_t deadline) {
    const unsigned char *p=data;
    while (n) {
        if (!wait_fd(fd,P_OUT,deadline)) return 0;
        long rc=SC(S_SENDTO,fd,p,n,P_NOSIGNAL,0,0);
        if (rc==-P_EINTR || rc==-P_AGAIN) continue;
        if (rc<=0 || (size_t)rc>n) return 0;
        p+=rc; n-=(size_t)rc;
    }
    return 1;
}
static int read_exact(int fd, void *data, size_t n) {
    unsigned char *p=data;
    unsigned interrupts=0;
    while (n) {
        long rc=SC(S_READ,fd,p,n,0,0,0);
        if (rc==-P_EINTR && ++interrupts<32) continue;
        if (rc<=0 || (size_t)rc>n) return 0;
        p+=rc; n-=(size_t)rc;
    }
    return 1;
}
// Missing is distinct from malformed/unreadable: fallback UI probing is safe,
// but an uncertain marker cannot authorize starting another daemon.
static int read_decimal_file(const char *path, unsigned max, unsigned *value) {
    int fd=(int)SC(S_OPEN,path,0x104,0,0,0,0); // RDONLY|NOFOLLOW|NONBLOCK
    if (fd<0) return fd==-2 ? 0 : -1; // ENOENT only
    char b[16]; size_t n=0; unsigned interrupts=0;
    while (n<sizeof(b)) {
        long rc=SC(S_READ,fd,b+n,sizeof(b)-n,0,0,0);
        if (rc==-P_EINTR && ++interrupts<32) continue;
        if (rc<0) { n=sizeof(b); break; }
        if (!rc) break;
        n+=(size_t)rc;
    }
    close_fd(fd);
    if (!n || n==sizeof(b)) return -1;
    size_t i=0; unsigned number=0;
    while (i<n) {
        // Preserve the full-width promotion across the syscall return boundary.
        volatile unsigned byte_value=(unsigned char)b[i];
        if(byte_value<'0'||byte_value>'9')break;
        unsigned digit_value=byte_value-'0';i++;
        if (number>(max-digit_value)/10) return -1;
        number=number*10+digit_value;
    }
    if (!i || !number || number>max) return -1;
    if (i<n && b[i]=='\r') i++;
    if (i<n && b[i]=='\n') i++;
    if (i!=n) return -1;
    *value=number; return 1;
}
static int read_port(int *uncertain) {
    unsigned port=DEFAULT_PORT;
    *uncertain=read_decimal_file(PORT_FILE,65535,&port)<0;
    return (int)port;
}
// Small bounded JSON validator, not a substring identity check: nested/string
// values cannot impersonate the top-level app/version, nor can truncated JSON.
static void skip_space(const char **p) {
    while (**p==' ' || **p=='\t' || **p=='\r' || **p=='\n') (*p)++;
}
static int digit(char c) { return c>='0' && c<='9'; }
static int json_string(const char **p, const char **start, size_t *len) {
    if (*(*p)++!='"') return 0;
    const char *s=*p;
    while (**p && **p!='"') {
        unsigned char c=(unsigned char)*(*p)++;
        if (c<32) return 0;
        if (c=='\\') {
            c=(unsigned char)*(*p)++;
            if (c=='u') {
                for (int i=0; i<4; i++) {
                    char h=*(*p)++;
                    if (!digit(h) && !(h>='a' && h<='f') && !(h>='A' && h<='F')) return 0;
                }
            } else if (!c || !(c=='"' || c=='\\' || c=='/' || c=='b' || c=='f' || c=='n' || c=='r' || c=='t')) return 0;
        }
    }
    if (**p!='"') return 0;
    *start=s; *len=(size_t)(*p-s); (*p)++; return 1;
}
static int valid_version(const char *s, size_t n) {
    int groups=1, count=0;
    for (size_t i=0; i<n; i++) {
        if (digit(s[i])) { if (++count>9) return 0; }
        else if (s[i]=='.' && count && groups<3) { groups++; count=0; }
        else return 0;
    }
    return count && groups==3;
}
static int json_value(const char **p, int depth, unsigned *identity) {
    if (depth>16) return 0;
    skip_space(p);
    if (**p=='{' || **p=='[') {
        char close=**p=='{' ? '}' : ']'; (*p)++; skip_space(p);
        if (**p==close) { (*p)++; return 1; }
        for (;;) {
            const char *key=0; size_t keylen=0;
            if (close=='}') {
                if (!json_string(p,&key,&keylen)) return 0;
                skip_space(p); if (*(*p)++!=':') return 0; skip_space(p);
            }
            unsigned bit=0;
            if (depth==0 && key) {
                if (keylen==3 && bytes_equal(key,"app",3)) bit=1;
                if (keylen==7 && bytes_equal(key,"version",7)) bit=2;
            }
            if (bit) {
                const char *v; size_t n;
                if ((*identity&bit) || !json_string(p,&v,&n)) return 0;
                if (bit==1 && (n!=text_len("TostónSync") || !bytes_equal(v,"TostónSync",n))) return 0;
                if (bit==2 && !valid_version(v,n)) return 0;
                *identity|=bit;
            } else if (!json_value(p,depth+1,identity)) return 0;
            skip_space(p);
            if (**p==close) { (*p)++; return 1; }
            if (*(*p)++!=',') return 0;
            skip_space(p);
        }
    }
    if (**p=='"') { const char *s; size_t n; return json_string(p,&s,&n); }
    const char *s=*p;
    if (**p=='-') (*p)++;
    if (digit(**p)) {
        if (**p=='0') (*p)++; else while (digit(**p)) (*p)++;
        if (**p=='.') { (*p)++; if (!digit(**p)) return 0; while (digit(**p)) (*p)++; }
        if (**p=='e' || **p=='E') {
            (*p)++; if (**p=='+' || **p=='-') (*p)++;
            if (!digit(**p)) return 0; while (digit(**p)) (*p)++;
        }
        return 1;
    }
    *p=s;
    const char *words[]={"true","false","null"};
    for (int i=0; i<3; i++) {
        size_t n=text_len(words[i]);
        size_t j=0; while (j<n && (*p)[j] && (*p)[j]==words[i][j]) j++;
        if (j==n) { *p+=n; return 1; }
    }
    return 0;
}
static int status_identity(const char *body) {
    unsigned identity=0; const char *p=body;
    skip_space(&p);
    if (*p!='{' || !json_value(&p,0,&identity)) return 0;
    skip_space(&p); return !*p && identity==3;
}
static int header_is(const char *a, size_t n, const char *b) {
    if (n!=text_len(b)) return 0;
    for (size_t i=0; i<n; i++) {
        char c=a[i]; if (c>='A' && c<='Z') c+=32;
        if (c!=b[i]) return 0;
    }
    return 1;
}
// 0=incomplete, -1=invalid/foreign, 1=complete real status.
static int parse_http(char *b, size_t n) {
    if (n<16) return 0;
    if (!(bytes_equal(b,"HTTP/1.1 200 ",13) || bytes_equal(b,"HTTP/1.0 200 ",13))) return -1;
    size_t end=0;
    for (size_t i=0; i+3<n; i++) if (bytes_equal(b+i,"\r\n\r\n",4)) { end=i+4; break; }
    if (!end) return 0;
    size_t pos=0, length=0; int have_length=0;
    while (pos+1<end && !(b[pos]=='\r' && b[pos+1]=='\n')) pos++;
    pos+=2;
    while (pos+2<end) {
        size_t line=pos, colon=pos;
        while (pos+1<end && !(b[pos]=='\r' && b[pos+1]=='\n')) pos++;
        while (colon<pos && b[colon]!=':') colon++;
        if (colon==pos) return -1;
        if (header_is(b+line,colon-line,"transfer-encoding")) return -1;
        if (header_is(b+line,colon-line,"content-length")) {
            if (have_length++) return -1;
            size_t v=colon+1; while (v<pos && (b[v]==' ' || b[v]=='\t')) v++;
            if (v==pos) return -1;
            for (; v<pos; v++) {
                if (!digit(b[v]) || length>8192) return -1;
                length=length*10+(size_t)(b[v]-'0');
            }
        }
        pos+=2;
    }
    if (!have_length || !length || length>8191-end) return -1;
    if (n<end+length) return 0;
    if (n!=end+length) return -1;
    b[n]=0;
    return status_identity(b+end) ? 1 : -1;
}
enum { STATUS_UNKNOWN, STATUS_REFUSED, STATUS_READY };
static int probe_status(int port, int64_t deadline) {
    int refused=0, fd=connect_local(port,deadline,&refused);
    if (fd<0) return refused ? STATUS_REFUSED : STATUS_UNKNOWN;
    const char request[]="GET /api/status HTTP/1.0\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n";
    char b[8192]; size_t n=0; int result=STATUS_UNKNOWN;
    if (!send_all(fd,request,sizeof(request)-1,deadline)) goto out;
    while (n<sizeof(b)-1 && wait_fd(fd,P_IN,deadline)) {
        long rc=SC(S_READ,fd,b+n,sizeof(b)-1-n,0,0,0);
        if (rc==-P_EINTR || rc==-P_AGAIN) continue;
        if (rc<=0 || (size_t)rc>sizeof(b)-1-n) break;
        int bad=0; for (long i=0; i<rc; i++) if (!b[n+(size_t)i]) bad=1;
        if (bad) break;
        n+=(size_t)rc; b[n]=0;
        int parsed=parse_http(b,n);
        if (parsed<0) break;
        if (parsed>0) { result=STATUS_READY; break; }
    }
out: close_fd(fd); return result;
}

static uint64_t le(const unsigned char *p, int n) {
    uint64_t v=0; for (int i=n-1; i>=0; i--) v=(v<<8)|p[i]; return v;
}
// Validate the installed ELF's complete segment layout before a loader sees it.
static int validate_elf(int fd, size_t *size) {
    long end=SC(S_LSEEK,fd,0,2,0,0,0);
    if (end<64 || end>MAX_ELF || SC(S_LSEEK,fd,0,0,0,0,0)!=0) return 0;
    unsigned char h[64], p[56];
    if (!read_exact(fd,h,sizeof(h)) || !bytes_equal((char*)h,"\177ELF",4) ||
        h[4]!=2 || h[5]!=1 || h[6]!=1 ||
        (le(h+16,2)!=2 && le(h+16,2)!=3) || le(h+18,2)!=62 || le(h+20,4)!=1 ||
        le(h+52,2)!=64 || le(h+54,2)!=56) return 0;
    uint64_t entry=le(h+24,8), off=le(h+32,8), count=le(h+56,2);
    if (!entry || !count || count>128 || off<64 || off>(uint64_t)end ||
        count*56>(uint64_t)end-off || SC(S_LSEEK,fd,off,0,0,0,0)!=(long)off) return 0;
    int executable=0;
    for (uint64_t i=0; i<count; i++) {
        if (!read_exact(fd,p,sizeof(p))) return 0;
        uint64_t poff=le(p+8,8), addr=le(p+16,8), file=le(p+32,8), mem=le(p+40,8);
        if (poff>(uint64_t)end || file>(uint64_t)end-poff) return 0;
        if (le(p,4)==1) {
            if (file>mem || addr+mem<addr) return 0;
            if ((le(p+4,4)&1) && entry>=addr && entry-addr<mem) executable=1;
        }
    }
    if (!executable || SC(S_LSEEK,fd,0,0,0,0,0)!=0) return 0;
    *size=(size_t)end; return 1;
}
static int send_installed_elf(void) {
    int file=(int)SC(S_OPEN,ELF_FILE,0x104,0,0,0,0), fd=-1, ok=0;
    size_t size=0;
    if (file<0 || !validate_elf(file,&size)) goto out;
    int64_t now=now_ms(); if (now<0) goto out;
    int64_t deadline=now+5000;
    int refused=0; fd=connect_local(LOADER_PORT,deadline,&refused);
    if (fd<0) goto out;
    unsigned char b[8192]; size_t sent=0;
    while (sent<size && remaining(deadline)) {
        size_t want=size-sent; if (want>sizeof(b)) want=sizeof(b);
        if (!read_exact(file,b,want) || !send_all(fd,b,want,deadline)) goto out;
        sent+=want;
    }
    if (sent!=size) goto out;
    // Signal EOF without waiting for the daemon's persistent stdout channel.
    ok=SC(S_SHUTDOWN,fd,1,0,0,0,0)==0;
out: close_fd(fd); close_fd(file); return ok;
}

typedef int (*load_module_fn)(const char*,size_t,const void*,unsigned,const void*,int*);
typedef int (*browser_fn)(const char*,void*);
typedef int (*user_init_fn)(void*);
typedef int (*user_term_fn)(void);
typedef int (*notify_fn)(int,void*,size_t,int);
static void *resolve(int handle, const char *name, const char *nid) {
    void *p=0;
    if (SC(S_DLSYM,handle,name,&p,0,0,0)==0 && p) return p;
    p=0; if (SC(S_DLSYM,handle,nid,&p,0,0,0)==0) return p;
    return 0;
}
static void *kernel_symbol(const char *name, const char *nid) {
    void *p=resolve(1,name,nid); return p ? p : resolve(0x2001,name,nid);
}
static void diagnostic(const char *message) {
    (void)SC(S_KLOG,7,message,0,0,0,0);
    notify_fn notify=(notify_fn)kernel_symbol("sceKernelSendNotificationRequest","zl7hupSO0C0");
    if (notify) {
        struct { char reserved[45], message[3075]; } req;
        zero_bytes(&req,sizeof(req));
        size_t n=text_len(message); if (n>=sizeof(req.message)) n=sizeof(req.message)-1;
        for (size_t i=0; i<n; i++) req.message[i]=message[i];
        (void)notify(0,&req,sizeof(req),0);
    }
}
static int load_sony(load_module_fn load, const char *common, const char *extended) {
    int result=0, handle=load(common,0,0,0,0,&result);
    if (handle<0) handle=load(extended,0,0,0,0,&result);
    return handle;
}
static int open_browser(int port) {
    load_module_fn load=(load_module_fn)kernel_symbol("sceKernelLoadStartModule","wzvqT4UqKX8");
    if (!load) return 0;
    int service=load_sony(load,"/system/common/lib/libSceSystemService.sprx",
        "/system_ex/common_ex/lib/libSceSystemService.sprx");
    int user=load_sony(load,"/system/common/lib/libSceUserService.sprx",
        "/system_ex/common_ex/lib/libSceUserService.sprx");
    if (service<0 || user<0) return 0;
    browser_fn browser=(browser_fn)resolve(service,"sceSystemServiceLaunchWebBrowser","-+3hY+y8bNo");
    user_init_fn initialize=(user_init_fn)resolve(user,"sceUserServiceInitialize","j3YMu1MVNNo");
    user_term_fn terminate=(user_term_fn)resolve(user,"sceUserServiceTerminate","bwFjS+bX9mA");
    if (!browser || !initialize || !terminate || initialize(0)!=0) return 0;
    char url[40]="http://127.0.0.1:", digits[5];
    size_t n=text_len(url), d=0;
    do { digits[d++]=(char)('0'+port%10); port/=10; } while (port);
    while (d) url[n++]=digits[--d]; url[n++]='/'; url[n]=0;
    int ok=browser(url,0)==0;
    (void)terminate(); return ok;
}
static int app_main(void) {
    int uncertain=0, result=1, lock=-1, port=read_port(&uncertain);
    (void)SC(S_KLOG,7,"TostónSync dashboard v" TOSTONSYNC_VERSION "\n",0,0,0,0);
    int64_t now=now_ms();
    if (now<0) { diagnostic("TostónSync: cannot read monotonic clock."); return 1; }
    int state=probe_status(port,now+1500);
    if (state==STATUS_READY) goto browser;
    if (state!=STATUS_REFUSED || uncertain) {
        diagnostic("TostónSync: local status is unknown. No payload was sent."); return 1;
    }
    lock=(int)SC(S_OPEN,LOCK_FILE,0x306,0600,0,0,0); // RDWR|CREAT|NOFOLLOW|NONBLOCK
    if (lock<0 || SC(S_FLOCK,lock,6,0,0,0,0)<0) {
        diagnostic("TostónSync: launcher busy or lock unavailable. No payload was sent."); goto out;
    }
    // Another click may have completed between the first probe and the lock.
    port=read_port(&uncertain); now=now_ms();
    if (now<0) goto out;
    state=probe_status(port,now+1500);
    if (state==STATUS_READY) goto browser;
    // Launch eligibility is UI health only; the daemon must acquire its own
    // canonical lifecycle reservation before operational initialization.
    if (state!=STATUS_REFUSED || uncertain) {
        diagnostic("TostónSync: status changed. No payload was sent."); goto out;
    }
    if (!send_installed_elf()) {
        diagnostic("TostónSync: cannot send installed ELF. Check the file and elfldr on port 9021."); goto out;
    }
    now=now_ms(); if (now<0) goto out;
    int64_t deadline=now+20000;
    while (remaining(deadline)) {
        port=read_port(&uncertain); now=now_ms(); if (now<0) break;
        int64_t probe_end=now+1000; if (probe_end>deadline) probe_end=deadline;
        if (probe_status(port,probe_end)==STATUS_READY) goto browser;
        struct p_time pause={0,100000000};
        (void)SC(S_SLEEP,&pause,0,0,0,0,0);
    }
    diagnostic("TostónSync: ELF sent, but daemon readiness was not confirmed. No retry was sent.");
    goto out;
browser:
    if (open_browser(port)) result=0;
    else diagnostic("TostónSync: daemon is ready, but the PS5 browser could not open.");
out: close_fd(lock); return result;
}
#ifndef APP_LAUNCHER_TEST
void _start(void) {
    (void)SC(S_EXIT,app_main(),0,0,0,0,0);
    __builtin_trap();
}
#endif
