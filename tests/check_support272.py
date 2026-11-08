#!/usr/bin/env python3
"""Request-owned support bundles and prepared descriptors; synthetic local files only."""
from pathlib import Path
import os,shlex,subprocess,tempfile,sys
sys.dont_write_bytecode=True
from check_lifecycle import function
R=Path(__file__).resolve().parents[1]
C=r'''
#include <assert.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include "config.h"
#include "watcher.h"
#include "version.h"
#include "http_security.h"
#include "diagnostic_text.h"
static unsigned checks;
#define CHECK(x) do{checks++;if(!(x)){fprintf(stderr,"FAIL %d: %s\n",__LINE__,#x);abort();}}while(0)
static config_t cfg;static bool s_prepare_download=true,entropy_failure,compression_failure;
static unsigned bundles;
static int fixture_open(const char*path,int flags,...){mode_t mode=0;if(flags&O_CREAT){va_list a;va_start(a,flags);mode=va_arg(a,int);va_end(a);}if(entropy_failure&&!strcmp(path,"/dev/urandom")){errno=EIO;return -1;}return open(path,flags,mode);}
#define open fixture_open
static char wire[65536];static size_t used;
static bool send_all(int fd,const void* data,size_t n){(void)fd;CHECK(used+n<sizeof(wire));memcpy(wire+used,data,n);used+=n;wire[used]=0;return true;}
static void reply_json(int fd,int code,const char* text){char h[64];snprintf(h,sizeof(h),"HTTP/1.1 %d Result\r\n\r\n",code);send_all(fd,h,strlen(h));send_all(fd,text,strlen(text));}
static void reply_text(int fd,int code,const char*text){reply_json(fd,code,text);}
static void reply_file(int fd,const char*p,const char*t){(void)fd;(void)p;(void)t;CHECK(false);}
void log_warn(const char*fmt,...){(void)fmt;}
bool config_snapshot(config_t*out){*out=cfg;return true;}
void config_to_json(const config_t*c,char*out,size_t n){(void)c;snprintf(out,n,"{\"client_secret_set\":true}");}
gdrive_state_t gdrive_get_state(void){return GDRIVE_STATE_NOT_CONFIGURED;}
static const char*state_to_str(gdrive_state_t s){(void)s;return "not_connected";}
bool protect_is(const char*n){(void)n;return false;}
void watcher_release_backup_file(const char*p,bool temporary){(void)p;(void)temporary;CHECK(false);}
/* GLOBALS */
/* CATALOG */
static size_t build_backup_catalog(backup_catalog_item_t*out,size_t n,const char*filter){CHECK(n&&filter);strcpy(out[0].source,"usb");strcpy(out[0].user,"Alex \"[one]\"");strcpy(out[0].title_id,"PPSA00001");return 1;}
typedef bool (*diagnostic_sink_t)(const char*,size_t,void*);
static char* read_file(const char*p){FILE*f=fopen(p,"rb");CHECK(f);CHECK(!fseek(f,0,SEEK_END));long n=ftell(f);CHECK(n>=0);rewind(f);char*b=calloc(n+1,1);CHECK(b);CHECK(fread(b,1,n,f)==(size_t)n);CHECK(!fclose(f));return b;}
bool zip_compress_directory(const char*dir,const char*zip,bool deflate,uint32_t*crc,uint64_t*sz){
 (void)deflate;(void)crc;(void)sz;bundles++;DIR*d=opendir(dir);CHECK(d);unsigned count=0;struct dirent*e;while((e=readdir(d))){if(!strcmp(e->d_name,".")||!strcmp(e->d_name,".."))continue;CHECK(strcmp(e->d_name,"tokens.json"));char p[512];snprintf(p,sizeof(p),"%s/%s",dir,e->d_name);char*s=read_file(p);CHECK(!strstr(s,"SYNTHETIC-KEY"));CHECK(!strstr(s,"synthetic-token"));if(!strcmp(e->d_name,"catalog.jsonl"))CHECK(strstr(s,"Alex \\\"[one]\\\""));free(s);count++;}CHECK(!closedir(d));CHECK(count==4);FILE*f=fopen(zip,"wb");CHECK(f);CHECK(fputs("synthetic bundle",f)>=0);CHECK(!fclose(f));return !compression_failure;
}
/* PROTOTYPES */
/* FUNCTIONS */
static unsigned active(void){unsigned n=0;for(unsigned i=0;i<HTTP_PREPARED_MAX;i++)n+=s_prepared[i].active;return n;}
static void clear(void){used=0;wire[0]=0;}
static void no_scratch(void){DIR*d=opendir(cfg.paths.state_dir);CHECK(d);struct dirent*e;while((e=readdir(d)))CHECK(strncmp(e->d_name,"debug_bundle.",13));CHECK(!closedir(d));char p[512];snprintf(p,sizeof(p),"%s/debug_bundle/tokens.json",cfg.paths.state_dir);char*s=read_file(p);CHECK(!strcmp(s,"synthetic-token"));free(s);}
static void expire(void){for(unsigned i=0;i<HTTP_PREPARED_MAX;i++)if(s_prepared[i].active)s_prepared[i].expires=0;release_prepared();CHECK(!active());}
static void request(int status){clear();handle_debug_bundle(1);char expect[64];snprintf(expect,sizeof(expect),"HTTP/1.1 %d",status);CHECK(strstr(wire,expect));no_scratch();}
int main(int argc,char**argv){CHECK(argc==2);snprintf(cfg.paths.state_dir,sizeof(cfg.paths.state_dir),"%s",argv[1]);strcpy(cfg.paths.saves_root,"/synthetic/[saves]");char p[512];snprintf(p,sizeof(p),"%s/debug_bundle",argv[1]);CHECK(!mkdir(p,0700));strcat(p,"/tokens.json");FILE*f=fopen(p,"w");CHECK(f);CHECK(fputs("synthetic-token",f)>=0);CHECK(!fclose(f));snprintf(p,sizeof(p),"%s/sync.log",argv[1]);f=fopen(p,"wb");CHECK(f);const char log[]="safe\0-----BEGIN " "PRIVATE KEY-----\nSYNTHETIC-KEY\n-----END PRIVATE KEY-----\nlast\n";CHECK(fwrite(log,1,sizeof(log)-1,f)==sizeof(log)-1);CHECK(!fclose(f));
 request(200);CHECK(active()==1);clear();read_prepared(1,s_prepared[0].id);CHECK(strstr(wire,"200 OK")&&strstr(wire,"synthetic bundle"));expire();
 request(200);int fd=s_prepared[0].file;expire();CHECK(fcntl(fd,F_GETFD)<0&&errno==EBADF);no_scratch();
 entropy_failure=true;request(503);CHECK(!active());entropy_failure=false;
 compression_failure=true;request(500);CHECK(!active());compression_failure=false;
 CHECK(!unlink(p));CHECK(!symlink("debug_bundle/tokens.json",p));unsigned before=bundles;request(500);CHECK(bundles==before);CHECK(!unlink(p));f=fopen(p,"w");CHECK(f);CHECK(fputs("safe\n",f)>=0);CHECK(!fclose(f));
 for(unsigned i=0;i<HTTP_PREPARED_MAX;i++)request(200);CHECK(active()==HTTP_PREPARED_MAX);request(503);CHECK(strstr(wire,"downloads_busy"));expire();no_scratch();printf("PASS support custody: %u assertions\n",checks);
}
'''
NAMES=('jappendf','jappendc','jappend_json_string','diagnostic_visit','diagnostic_open','diagnostic_write','dbg_copy','dbg_write','dbg_discard_owned','handle_debug_bundle','prepared_identity','reply_prepared','read_prepared','release_prepared')
def run(mutant=None):
 source=(R/'src/httpd.c').read_text()
 if mutant:
  old,new=mutant;assert source.count(old)==1;source=source.replace(old,new,1)
 globals=source[source.index('#define HTTP_PREPARED_MAX'):source.index('static void reply_prepared')]
 catalog=source[source.index('#define BACKUP_CATALOG_MAX'):source.index('// A ticket references server-owned')]
 funcs=[function(source,n)for n in NAMES]
 text=C.replace('/* GLOBALS */',globals).replace('/* CATALOG */',catalog).replace('/* PROTOTYPES */','\n'.join(f.split('{',1)[0]+';'for f in funcs)).replace('/* FUNCTIONS */','\n'.join(funcs))
 with tempfile.TemporaryDirectory(prefix='support272-')as d:
  w=Path(d);(w/'state').mkdir();(w/'test.c').write_text(text)
  cmd=shlex.split(os.environ.get('HOST_CC','cc'))+['-std=gnu11','-Wall','-Wextra','-Werror','-pthread','-I'+str(R/'src')]+shlex.split(os.environ.get('HOST_TEST_FLAGS',''))+[str(w/'test.c'),'-o',str(w/'test')];subprocess.run(cmd,check=True)
  result=subprocess.run([str(w/'test'),str(w/'state')],capture_output=bool(mutant),text=True)
  if mutant:assert result.returncode,'surviving support mutant'
  else:result.check_returncode()
if __name__=='__main__':
 run()
 if '--mutants'in sys.argv:
  for m in [('if (owned && unlink(path))','if (false && owned && unlink(path))'),('    dbg_discard_owned(dir,zip);\n}', '    (void)dir;(void)zip;\n}')]:run(m)
  print('PASS 2 support cleanup mutants')
