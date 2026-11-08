#!/usr/bin/env python3
"""Production settings/session/HTTP boundaries; local synthetic state, no network."""
import os,sys,subprocess,tempfile,shlex,argparse
from pathlib import Path
sys.dont_write_bytecode=True
from check_lifecycle import function
ROOT=Path(__file__).resolve().parents[1]
PREFIX=r'''
#include <assert.h>
#include <stdio.h>
#include <stdarg.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <time.h>
#include "config.c"
#include "http_security.h"
#include "diagnostic_text.h"
#include "sha256.h"
#include "json.h"
#include "restore_selection.h"
bool fs_mkdir_p(const char* p){(void)p;return true;}
static config_t cfg;
static const config_t* s_cfg=&cfg;
static unsigned checks;
#define CHECK(x) do{checks++;if(!(x)){fprintf(stderr,"FAIL line %d: %s\n",__LINE__,#x);abort();}}while(0)
static char wire[131072];static size_t wire_len;
static bool send_all(int fd,const void* p,size_t n){(void)fd;CHECK(wire_len+n<sizeof(wire));memcpy(wire+wire_len,p,n);wire_len+=n;wire[wire_len]=0;return true;}
static void observation_store(int status,const char* type,const void* body,size_t size){(void)status;(void)type;(void)body;(void)size;}
static const char* s_restore_request;
static void observe_restore_request(const char* m,const char* p){(void)m;(void)p;}
static char captured_log[4096];
void log_warn(const char* fmt,...){va_list ap;va_start(ap,fmt);vsnprintf(captured_log,sizeof(captured_log),fmt,ap);va_end(ap);}
static uint8_t s_auth_nonce[32],s_login_nonce[32];static bool s_auth_nonce_ready;
static time_t s_login_expires;
static pthread_mutex_t s_auth_lock=PTHREAD_MUTEX_INITIALIZER;
typedef struct{uint32_t addr;time_t window_start,blocked_until;unsigned failures;}login_rate_t;
static login_rate_t s_login_rates[8],s_login_global;
static pthread_mutex_t s_login_rate_lock=PTHREAD_MUTEX_INITIALIZER;
#define HTTP_INITIAL_CAP (16*1024)
#define TOSTONSYNC_STARTUP_VALIDATION_ONLY 0
typedef bool (*diagnostic_sink_t)(const char*,size_t,void*);
typedef struct{char* text;size_t used,capacity;bool tail;}diagnostic_buffer_t;
/* FIELD_TYPE */
/* PROTOTYPES */
/* FUNCTIONS */
static void reset_wire(void){wire_len=0;wire[0]=0;}
static char* ini_read(const char* path){FILE*f=fopen(path,"rb");CHECK(f);CHECK(!fseek(f,0,SEEK_END));long n=ftell(f);CHECK(n>=0);rewind(f);char*b=calloc(n+1,1);CHECK(b);CHECK(fread(b,1,n,f)==(size_t)n);CHECK(!fclose(f));return b;}
static void load(const char* path){FILE*f=fopen(path,"w");CHECK(f);CHECK(fputs("[titles]\napp_defaults_applied=true\n[triggers]\nmodes=manual\n[usb]\nenabled=true\n",f)>=0);CHECK(!fclose(f));CHECK(config_load(&cfg,path));}
static void rejected(const char* path,const char* endpoint,const char* body,size_t length){config_t before=cfg;char*old=ini_read(path);CHECK(!http_settings_request(endpoint,body,length));CHECK(!memcmp(&before,&cfg,sizeof(cfg)));char*now=ini_read(path);CHECK(!strcmp(old,now));free(old);free(now);}
static void legacy_ini_tests(const char* path){
 FILE*f=fopen(path,"w");CHECK(f);CHECK(fputs("; example = \"unfinished\n[titles]\napp_defaults_applied=true\n[general]\nui_password = \"1234\"\n[users]\n00000001 = \"Alex\"\n[console]\nname = \"unfinished\n",f)>=0);CHECK(!fclose(f));
 char*before=ini_read(path);CHECK(config_load(&cfg,path));char*after=ini_read(path);CHECK(!strcmp(before,after));free(before);free(after);
 CHECK(!strcmp(cfg.general.ui_password,"\"1234\""));CHECK(!strcmp(cfg.console.name,"\"unfinished"));CHECK(!strcmp(cfg.users.entries[0].alias,"\"Alex\""));
 CHECK(config_save());CHECK(config_load(&cfg,path));CHECK(!strcmp(cfg.general.ui_password,"\"1234\""));CHECK(!strcmp(cfg.console.name,"\"unfinished"));CHECK(!strcmp(cfg.users.entries[0].alias,"\"Alex\""));load(path);
}
static void failed_auth_tests(const char* path){
 CHECK(config_set_ui_auth(true,"original",false));CHECK(auth_login_begin());char token[33],header[256];auth_token("original",token);snprintf(header,sizeof(header),"Cookie: tostonsync_auth=%s\r\n\r\n",token);
 char tmp[512];snprintf(tmp,sizeof(tmp),"%s.tmp",path);CHECK(!mkdir(tmp,0700));cfg_general_t before=cfg.general;char*original=ini_read(path);
 CHECK(!config_set_ui_auth(false,NULL,false));CHECK(!memcmp(&before,&cfg.general,sizeof(before)));CHECK(cookie_has_auth(header,"original"));
 CHECK(!config_set_ui_auth(true,"replacement",true));CHECK(!memcmp(&before,&cfg.general,sizeof(before)));CHECK(cookie_has_auth(header,"original"));char*after=ini_read(path);CHECK(!strcmp(original,after));free(after);free(original);CHECK(!rmdir(tmp));
 CHECK(config_set_ui_auth(false,NULL,false));before=cfg.general;CHECK(!mkdir(tmp,0700));CHECK(!config_set_ui_auth(true,"new",true));CHECK(!memcmp(&before,&cfg.general,sizeof(before)));CHECK(!rmdir(tmp));
 char target[512];snprintf(target,sizeof(target),"%s.rename-directory",path);CHECK(!mkdir(target,0700));snprintf(cfg.ini_path,sizeof(cfg.ini_path),"%s",target);before=cfg.general;CHECK(!config_set_ui_auth(true,"rename-failure",false));CHECK(!memcmp(&before,&cfg.general,sizeof(before)));CHECK(!rmdir(target));load(path);
}
static void settings_tests(const char* path){
 const char* patches[]={"{\"console\":{\"name\":\"x\\n[usb]\\nenabled=false\"}}","{\"gdrive\":{\"client_secret\":\"x\\r[usb]\"}}","{\"console\":{\"name\":\"a\\u0000tail\"}}","{\"console\":{\"name\":\"a\\u007f\"}}","{\"console\":{\"name\":\"a\\u0085\"}}","{\"console\":{\"name\":\"good\",\"name\":\"bad\"}}","{\"console\":{\"name\":null}}","{\"console\":{\"name\":17}}","{\"console\":{\"name\":{\"name\":\"bad\"}}}","{\"usb\":{\"enabled\":false},\"console\":{\"name\":\"x\\t\"}}","{\"titles\":{\"exclude\":[\"x\\n[usb]\"]}}"};
 for(size_t i=0;i<sizeof(patches)/sizeof(patches[0]);i++){rejected(path,"/api/config",patches[i],strlen(patches[i]));CHECK(!config_apply_json(patches[i]));}
 const char nul[]="{\"console\":{\"name\":\"a\0tail\"}}";rejected(path,"/api/config",nul,sizeof(nul)-1);
 const char* title="{\"title_id\":\"x\\n[usb]\\nenabled\",\"name\":\"false\"}";rejected(path,"/api/titles/alias",title,strlen(title));
 const char* auth="{\"enabled\":true,\"code\":\"x\\n[usb]\"}";rejected(path,"/api/auth/set",auth,strlen(auth));
 for(unsigned c=1;c<32;c++){char b[128];snprintf(b,sizeof(b),"{\"console\":{\"name\":\"x%c\"}}",c);rejected(path,"/api/config",b,strlen(b));}
 CHECK(!config_set_ui_auth(true,"x\r[usb]",false));CHECK(!config_set_title_alias("x\n[usb]\nenabled","false"));CHECK(!config_set_user_alias("x\n[usb]","false"));
 char long_patch[600];memset(long_patch,'x',sizeof(long_patch));memcpy(long_patch,"{\"console\":{\"name\":\"",20);strcpy(long_patch+500,"\"}}");rejected(path,"/api/config",long_patch,strlen(long_patch));
 const char* valid="{\"console\":{\"name\":\"[Álex] ™ ®\"},\"gdrive\":{\"root_folder\":\"Café [backups]\"}}";
 CHECK(http_settings_request("/api/config",valid,strlen(valid)));CHECK(config_apply_json(valid));CHECK(!strcmp(cfg.console.name,"[Álex] ™ ®"));CHECK(config_load(&cfg,path));CHECK(!strcmp(cfg.console.name,"[Álex] ™ ®"));
 CHECK(config_apply_json("{\"console\":{\"name\":\" [Café]; ™ \"}}"));CHECK(config_load(&cfg,path));CHECK(!strcmp(cfg.console.name," [Café]; ™ "));
 CHECK(config_set_ui_auth(true," alpha;beta ",false));CHECK(config_load(&cfg,path));CHECK(!strcmp(cfg.general.ui_password," alpha;beta "));
 CHECK(config_apply_json("{\"console\":{\"name\":\"Caf\\u00e9\"}}"));CHECK(!strcmp(cfg.console.name,"Café"));
 CHECK(config_apply_json("{\"retention\":{},\"other\":{\"max_versions\":1}}"));CHECK(cfg.retention.max_versions==10);
 strcpy(cfg.console.name,"x\n[usb]");char*before=ini_read(path);CHECK(!config_save());char*after=ini_read(path);CHECK(!strcmp(before,after));free(before);free(after);load(path);
 reset_wire();handle_auth_set(0,"{\"enabled\": true, \"code\": \"[á]123\", \"reset_on_boot\": false}");CHECK(strstr(wire,"200 OK"));CHECK(cfg.general.ui_auth_enabled&&!strcmp(cfg.general.ui_password,"[á]123"));
 reset_wire();handle_title_alias(0,"{\"title_id\":\"PPSA00001\",\"name\":\"Caf\\u00e9 [™]\"}");CHECK(strstr(wire,"200 OK"));CHECK(!strcmp(config_title_alias_for("PPSA00001"),"Café [™]"));
}
static bool boundary(const char* host,const char* origin){char b[2048];int n=snprintf(b,sizeof(b),"POST /api/update/start HTTP/1.1\r\nHost: %s\r\n%s%s%sContent-Type: application/json\r\nContent-Length: 2\r\n\r\n",host,origin?"Origin: ":"",origin?origin:"",origin?"\r\n":"");return http_request_boundary(b,n,1993,"console.test");}
static void header_tests(void){
 CHECK(boundary("192.0.2.7:1993","http://192.0.2.7:1993"));CHECK(boundary("127.0.0.1:1993",NULL));CHECK(boundary("localhost:1993",NULL));CHECK(boundary("[::1]:1993","http://[::1]:1993"));CHECK(boundary("console.test:1993","http://console.test:1993"));
 CHECK(!boundary("evil.test:1993",NULL));CHECK(!boundary("192.0.2.7:1993","http://evil.test:1993"));CHECK(!boundary("192.0.2.7:1993","null"));CHECK(!boundary("192.0.2.7:1993","http://192.0.2.8:1993"));CHECK(!boundary("192.0.2.7:1994",NULL));CHECK(!boundary("user@192.0.2.7:1993",NULL));CHECK(!boundary("192.0.2.7:1993\r\nHost: evil.test",NULL));CHECK(!boundary("192.0.2.7:1993","http://192.0.2.7:1993\r\nOrigin: http://evil.test"));
 CHECK(!boundary("192.0.2.7:1993\r\nContent-Type: text/plain",NULL));
 const char* routes[]={"/api/status","/api/update/start","/api/update/chunk?id=fixture","/api/update/finish","/api/update/restart"};struct sockaddr_in peer={.sin_family=AF_INET};inet_pton(AF_INET,"127.0.0.1",&peer.sin_addr);
 for(unsigned i=0;i<5;i++){char b[1024];int n=snprintf(b,sizeof(b),"%s %s HTTP/1.0\r\nHost: 192.0.2.7:1993\r\n\r\n",i?"POST":"GET",routes[i]);CHECK(!authorize_request_headers(b,n,0,&peer));}
 char b[1024];int n=snprintf(b,sizeof(b),"GET /api/status HTTP/1.0\r\nHost: evil.test:1993\r\n\r\n");CHECK(authorize_request_headers(b,n,0,&peer)==-8);
 reset_wire();reply_json(0,200,"{}");CHECK(strstr(wire,"X-Frame-Options: DENY"));CHECK(strstr(wire,"frame-ancestors 'none'"));CHECK(strstr(wire,"Referrer-Policy: no-referrer"));
}
static void session_tests(void){
 auth_nonce_init();CHECK(s_auth_nonce_ready);uint8_t boot[32];memcpy(boot,s_auth_nonce,32);CHECK(auth_login_begin());char token[33];auth_token("[á]123",token);char header[512];snprintf(header,sizeof(header),"HTTP/1.1\r\nCookie: other=a; tostonsync_auth=%s\r\n\r\n",token);CHECK(cookie_has_auth(header,"[á]123"));
 char bad[512];snprintf(bad,sizeof(bad),"HTTP/1.1\r\nX-Cookie: tostonsync_auth=%s\r\n\r\n",token);CHECK(!cookie_has_auth(bad,"[á]123"));
 snprintf(bad,sizeof(bad),"HTTP/1.1\r\nCookie: tostonsync_auth=%sx\r\n\r\n",token);CHECK(!cookie_has_auth(bad,"[á]123"));
 snprintf(bad,sizeof(bad),"HTTP/1.1\r\nCookie: tostonsync_auth=%s; tostonsync_auth=%s\r\n\r\n",token,token);CHECK(!cookie_has_auth(bad,"[á]123"));
 s_login_expires=time(NULL)-1;CHECK(!cookie_has_auth(header,"[á]123"));CHECK(auth_login_begin());auth_token("[á]123",token);snprintf(header,sizeof(header),"Cookie: tostonsync_auth=%s\r\n\r\n",token);CHECK(cookie_has_auth(header,"[á]123"));reset_wire();handle_logout(0);CHECK(!cookie_has_auth(header,"[á]123"));CHECK(!memcmp(boot,s_auth_nonce,32));
 CHECK(auth_login_begin());CHECK(!cookie_has_auth(header,"[á]123"));CHECK(!memcmp(boot,s_auth_nonce,32));
 CHECK(!request_is_public("POST","/api/logout"));auth_token("[á]123",token);snprintf(header,sizeof(header),"Cookie: tostonsync_auth=%s\r\n\r\n",token);
 reset_wire();handle_auth_set(0,"{\"enabled\":true,\"code\":\"another\"}");handle_auth_set(0,"{\"enabled\":true,\"code\":\"[á]123\"}");CHECK(auth_login_begin());CHECK(!cookie_has_auth(header,"[á]123"));CHECK(!memcmp(boot,s_auth_nonce,32));

 memset(s_login_rates,0,sizeof(s_login_rates));memset(&s_login_global,0,sizeof(s_login_global));for(unsigned i=1;i<=20;i++)login_rate_record(i,false);CHECK(login_rate_limited(999));
}
static void diagnostics_tests(const char* directory){
 char marker[512]="update: phase=previous/end image=1 sha256=1234abcdef";char expected[512];strcpy(expected,marker);
 CHECK(diagnostic_redact(marker,strlen(marker),"1","1234")==strlen(expected));CHECK(!strcmp(marker,expected));

 const char* secrets[]={"access_token=synthetic-access","refresh_token: synthetic-refresh","client_secret=synthetic-client","Authorization: Bearer synthetic-bearer","ya29.synthetic",("-----BEGIN " "PRIVATE KEY-----\nSYNTHETIC-KEY\n-----END PRIVATE KEY-----")};
 for(unsigned i=0;i<sizeof(secrets)/sizeof(secrets[0]);i++){char b[1024];snprintf(b,sizeof(b),"before\n%s\nafter\n",secrets[i]);size_t n=diagnostic_redact(b,strlen(b),NULL,NULL);CHECK(n==strlen(b));CHECK(!strstr(b,"synthetic"));CHECK(!strstr(b,"SYNTHETIC-KEY"));CHECK(strstr(b,"before")&&strstr(b,"after"));}
 char path[512],copy[512];snprintf(path,sizeof(path),"%s/log",directory);snprintf(copy,sizeof(copy),"%s/log-copy",directory);FILE*f=fopen(path,"w");CHECK(f);CHECK(fputs("safe\naccess_token=synthetic-access\nlast\n",f)>=0);CHECK(!fclose(f));char*original=ini_read(path);
 size_t n;char*text=diagnostic_read_file(path,false,&n);CHECK(text&&!strstr(text,"synthetic-access"));free(text);CHECK(dbg_copy(path,copy));char*after=ini_read(path);CHECK(!strcmp(original,after));free(original);free(after);text=ini_read(copy);CHECK(!strstr(text,"synthetic-access"));free(text);

 f=fopen(path,"w");CHECK(f);char chunk[1024];memset(chunk,'a',1022);chunk[1022]='\n';chunk[1023]=0;for(unsigned i=0;i<20000;i++)CHECK(fwrite(chunk,1,1023,f)==1023);CHECK(fputs("-----BEGIN " "PRIVATE KEY-----\nSYNTHETIC-KEY\n-----END PRIVATE KEY-----\nlast\n",f)>=0);CHECK(!fclose(f));
 text=diagnostic_read_file(path,true,&n);CHECK(text&&n<=65536&&!strstr(text,"SYNTHETIC-KEY")&&strstr(text,"last"));free(text);
 f=fopen(path,"wb");CHECK(f);const char nul_pem[]="safe\0-----BEGIN " "PRIVATE KEY-----\nSYNTHETIC-KEY\n-----END PRIVATE KEY-----\nlast\n";CHECK(fwrite(nul_pem,1,sizeof(nul_pem)-1,f)==sizeof(nul_pem)-1);CHECK(!fclose(f));
 for(unsigned tail=0;tail<2;tail++){text=diagnostic_read_file(path,tail,&n);CHECK(text&&!strstr(text,"SYNTHETIC-KEY")&&strstr(text,"last"));free(text);}
 CHECK(!unlink(copy));CHECK(dbg_copy(path,copy));text=ini_read(copy);CHECK(!strstr(text,"SYNTHETIC-KEY"));free(text);
 reset_wire();handle_client_log(0,"{\"message\":\"Drive upload failed\",\"detail\":\"access_token=synthetic-access\"}");CHECK(strstr(wire,"200 OK"));CHECK(!strstr(captured_log,"synthetic"));
}
int main(int argc,char**argv){CHECK(argc==3);load(argv[1]);legacy_ini_tests(argv[1]);settings_tests(argv[1]);header_tests();session_tests();failed_auth_tests(argv[1]);diagnostics_tests(argv[2]);printf("PASS security boundaries: %u runtime assertions\n",checks);}
'''
NAMES=('reply','reply_json','reply_text','http_settings_flat','http_settings_request','http_setting_text','http_setting_bool','handle_title_alias','handle_auth_set','auth_random','auth_nonce_init','auth_login_begin','auth_token','str_eq','cookie_has_auth','snapshot_ui_auth','login_rate_slot','login_rate_limited','login_rate_record','handle_logout','request_is_public','peer_is_loopback','authorize_request_headers','diagnostic_visit','diagnostic_open','diagnostic_buffer','diagnostic_read_file','diagnostic_write','dbg_copy','handle_client_log')
def run(mutant=None):
 with tempfile.TemporaryDirectory(prefix='security272-') as folder:
  work=Path(folder);source=(ROOT/'src/httpd.c').read_text();headers={n:(ROOT/'src'/n).read_text() for n in ('config.c','settings_input.h','http_security.h','diagnostic_text.h')}
  if mutant:
   file,old,new=mutant
   if file=='httpd.c':assert source.count(old)==1;source=source.replace(old,new,1)
   else:assert headers[file].count(old)==1;headers[file]=headers[file].replace(old,new,1)
  for n,s in headers.items():(work/n).write_text(s)
  fields=source[source.index('typedef struct { const char* name; int kind; size_t capacity; bool required; }'):source.index('static bool http_settings_flat')]
  functions=[function(source,n)for n in NAMES]
  text=PREFIX.replace('/* FIELD_TYPE */',fields).replace('/* PROTOTYPES */','\n'.join(f.split('{',1)[0]+';'for f in functions)).replace('/* FUNCTIONS */','\n'.join(functions))
  (work/'test.c').write_text(text)
  command=shlex.split(os.environ.get('HOST_CC','cc'))+['-std=gnu11','-Wall','-Wextra','-Werror','-Wno-unused-function','-pthread','-I'+str(work),'-I'+str(ROOT/'src')]+shlex.split(os.environ.get('HOST_TEST_FLAGS',''))+[str(work/'test.c'),str(ROOT/'src/json.c'),str(ROOT/'src/sha256.c'),str(ROOT/'src/restore_selection.c'),'-o',str(work/'test')]
  subprocess.run(command,check=True)
  result=subprocess.run([str(work/'test'),str(work/'settings.ini'),str(work)],capture_output=bool(mutant),text=True)
  if mutant:assert result.returncode!=0,'SURVIVING MUTANT '+mutant[0]
  else:result.check_returncode()
if __name__=='__main__':
 parser=argparse.ArgumentParser();parser.add_argument('--mutants',action='store_true');args=parser.parse_args();run()
 if args.mutants:
  mutants=[('settings_input.h','if(!settings_scalar(cp))return false;','if(false)return false;'),('http_security.h','if(observed!=(unsigned)port)return false;','(void)port;if(false)return false;'),('http_security.h','if(!configured||!*configured||strcasecmp(host,configured))return false;','(void)configured;if(false)return false;'),('httpd.c','if(now<=0||now>=expires)return false;','(void)now;if(false)return false;'),('diagnostic_text.h','redact|=diagnostic_contains(text+read,n,sensitive[i]);','redact|=false&&(sensitive[i]!=NULL);')]
  for m in mutants:run(m)
  print('PASS',len(mutants),'negative security mutants')
