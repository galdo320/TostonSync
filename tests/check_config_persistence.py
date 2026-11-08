#!/usr/bin/env python3
"""Offline production-INI persistence: absence, explicit choices and every save API."""
import os
from pathlib import Path
import shlex
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
SOURCE = r'''
#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include "config.c"

bool fs_mkdir_p(const char* path) { (void)path; return true; }
static config_t cfg;
static const char* path;
static unsigned assertions;
#define CHECK(c) do { assert(c); assertions++; } while (0)
static const char seed[]="[titles]\napp_defaults_applied=true\n[triggers]\nmodes=manual\n";
static void load(const char* body) {
    FILE* f=fopen(path,"w"); CHECK(f); CHECK(fputs(body,f)>=0); CHECK(!fclose(f));
    CHECK(config_load(&cfg,path));
}
static char* read_ini(void) {
    FILE* f=fopen(path,"r"); CHECK(f); CHECK(!fseek(f,0,SEEK_END));
    long n=ftell(f); CHECK(n>=0); CHECK(!fseek(f,0,SEEK_SET));
    char* text=calloc((size_t)n+1,1); CHECK(text); CHECK(fread(text,1,(size_t)n,f)==(size_t)n);
    CHECK(!fclose(f)); return text;
}
static bool allowed(const char* value,const char* extra) {
    if (!strcmp(value,"titles.app_defaults_applied") || !strcmp(value,"triggers.modes")) return true;
    size_t n=strlen(value); const char* p=extra;
    while (p && *p) { const char* end=strchr(p,',');size_t len=end?(size_t)(end-p):strlen(p);
        if (len==n && !strncmp(p,value,n)) return true; p=end?end+1:NULL; }
    return false;
}
static void only(const char* extra,size_t count) {
    char* text=read_ini(); char section[80]=""; size_t keys=0;
    for (char* p=strtok(text,"\n");p;p=strtok(NULL,"\n")) {
        if (!strcmp(p,"; tostonsync-string-encoding:json-v1")) continue;
        if (sscanf(p,"[%79[^]]]",section)==1) continue;
        char key[100]; if (sscanf(p,"%99s =",key)!=1) continue;
        char canonical[200];snprintf(canonical,sizeof(canonical),"%s.%s",section,key);
        if (!allowed(canonical,extra)) fprintf(stderr,"Unexpected persisted key %s; allowed %s\n",canonical,extra);
        CHECK(allowed(canonical,extra));keys++;
    }
    CHECK(keys==count);free(text);
    struct stat st; CHECK(!stat(path,&st)); CHECK((st.st_mode&0777)==0600);
}
static void without_defaults(const char* extra,size_t count) {
    only(extra,count); char* text=read_ini();CHECK(!strstr(text,"update_auto_check"));
    CHECK(!strstr(text,"notifications ="));CHECK(!strstr(text,"retry_max_attempts"));
    CHECK(!strstr(text,"client_secret"));free(text);
}
static void api_paths(void) {
    load(seed);CHECK(config_set_display_alias("0A1B2C3D","Fixture Fat"));
    without_defaults("display_users.0a1b2c3d",3);
    CHECK(config_load(&cfg,path));CHECK(!strcmp(cfg.display_users.entries[0].alias,"Fixture Fat"));
    CHECK(config_set_display_alias("0a1b2c3d",""));without_defaults("display_users.0a1b2c3d",3);
    CHECK(config_load(&cfg,path));CHECK(!cfg.display_users.entries[0].alias[0]);
    load(seed);CHECK(config_set_user_alias("00000001","Friendly"));without_defaults("users.00000001",3);
    CHECK(config_set_user_alias("00000001",""));without_defaults("users.00000001",3);
    load(seed);CHECK(config_set_title_alias("PPSA00001","Fixture title"));without_defaults("title_names.PPSA00001",3);
    CHECK(config_set_title_alias("PPSA00001",""));without_defaults("",2);
    CHECK(config_load(&cfg,path));CHECK(!cfg.title_aliases.count);
    load(seed);CHECK(config_set_title_backup("PPSA00001",false));without_defaults("titles.exclude",3);
    CHECK(config_set_title_backup("PPSA00001",true));without_defaults("titles.exclude",3);
    CHECK(config_load(&cfg,path));CHECK(!cfg.titles.exclude_count);
    load(seed);CHECK(config_set_title_hidden("PPSA00001",true));without_defaults("titles.hidden",3);
    CHECK(config_set_title_hidden("PPSA00001",false));without_defaults("titles.hidden",3);
    CHECK(config_load(&cfg,path));CHECK(!cfg.titles.hidden_count);
    load(seed);CHECK(config_set_ui_auth(true,"1234",true));
    without_defaults("general.ui_auth_enabled,general.ui_password,general.ui_auth_reset_on_boot",5);
    CHECK(config_reset_ui_auth());without_defaults("general.ui_auth_enabled,general.ui_password,general.ui_auth_reset_on_boot",5);
    CHECK(config_load(&cfg,path));CHECK(!cfg.general.ui_auth_enabled&&!cfg.general.ui_password[0]);
    load(seed);CHECK(config_set_ui_auth(false,"",false));without_defaults("",2);
    load(seed);CHECK(config_reset_ui_auth());without_defaults("",2);
    load(seed);bool changed=false;CHECK(config_backup_timezone_sync("auto","offset:-04:00",&changed)==CFG_BACKUP_TIMEZONE_OK&&changed);
    without_defaults("display.backup_timezone_offset",3);
    CHECK(config_backup_timezone_sync("auto","offset:-04:00",&changed)==CFG_BACKUP_TIMEZONE_OK&&!changed);
    load(seed);snprintf(cfg.console.name,sizeof(cfg.console.name),"Direct save");CHECK(config_save());without_defaults("console.console_name",3);
    CHECK(config_load(&cfg,path));CHECK(!strcmp(cfg.console.name,"Direct save"));
    load(seed);CHECK(config_apply_json("{\"general\":{\"language\":\"es\"}}"));without_defaults("general.language",3);
    CHECK(config_apply_json("{\"general\":{\"language\":\"en\"}}"));without_defaults("general.language",3);
    CHECK(config_load(&cfg,path));CHECK(!strcmp(cfg.general.language,"en"));
    load(seed);CHECK(config_apply_json("{}"));without_defaults("",2);
    CHECK(config_apply_json("{\"general\":{\"update_auto_check\":true}}"));without_defaults("",2);
}
static void explicit_defaults(void) {
    // Every canonical key, including an empty explicit value, survives unrelated saves.
    for (size_t i=0;i<INI_FIELD_COUNT;i++) {
        load(seed); FILE* f=fopen(path,"a");CHECK(f);
        fprintf(f,"[%s]\n",s_fields[i].section);config_write_field(f,&s_fields[i]);CHECK(!fclose(f));
        CHECK(config_load(&cfg,path));CHECK(config_set_display_alias("00000002","Explicit defaults"));
        char extra[200];snprintf(extra,sizeof(extra),"%s.%s,display_users.00000002",s_fields[i].section,s_fields[i].key);
        bool base=!strcmp(s_fields[i].key,"app_defaults_applied") || (!strcmp(s_fields[i].section,"triggers")&&!strcmp(s_fields[i].key,"modes"));
        only(extra,base?3:4);
    }
    load("[general]\nupdate_auto_check=true\nnotifications=true\n[titles]\napp_defaults_applied=true\n[triggers]\nmodes=manual\n");
    CHECK(config_set_display_alias("00000001","No drift"));
    only("general.update_auto_check,general.notifications,display_users.00000001",5);
    CHECK(config_load(&cfg,path));CHECK(config_apply_json("{\"general\":{\"update_auto_check\":false}}"));
    CHECK(config_apply_json("{\"general\":{\"update_auto_check\":true}}"));
    only("general.update_auto_check,general.notifications,display_users.00000001",5);
    char* text=read_ini();CHECK(strstr(text,"update_auto_check = true"));free(text);
}
static void legacy_and_first_run(void) {
    load("[general]\ntime_format=auto\n[console]\nname=This PS5\ntype=PS5\nrole=main\n[titles]\napp_defaults_applied=true\n[triggers]\nmodes=manual\n");
    CHECK(config_set_display_alias("00000001","Legacy"));
    without_defaults("display.time_format,console.console_name,console.console_type,console.console_role,display_users.00000001",7);
    CHECK(config_load(&cfg,path));CHECK(!strcmp(cfg.general.time_format,"auto")&&!strcmp(cfg.console.name,"This PS5"));
    // Preserve the existing one-time app migration without freezing unrelated defaults.
    load("[triggers]\nmodes=manual\n");without_defaults("titles.exclude,titles.hidden",4);
    CHECK(cfg.titles.app_defaults_applied&&cfg.titles.exclude_count==1&&cfg.titles.hidden_count==1);
    CHECK(config_set_title_backup("PPSA01650",true));CHECK(config_set_title_hidden("PPSA01650",false));
    CHECK(config_load(&cfg,path));CHECK(!cfg.titles.exclude_count&&!cfg.titles.hidden_count);
    CHECK(!unlink(path));CHECK(config_load(&cfg,path));
    char* text=read_ini();CHECK(!strstr(text,"update_auto_check"));CHECK(!strstr(text,"notifications"));
    CHECK(strstr(text,"app_defaults_applied = true"));free(text);
    CHECK(config_load(&cfg,path));CHECK(cfg.general.update_auto_check&&cfg.general.notifications&&cfg.usb.enabled);
    // Observational startup remains read-only and does not migrate or pin defaults.
    load(seed);char* before=read_ini();CHECK(config_load_observational(&cfg,path));char* after=read_ini();CHECK(!strcmp(before,after));free(before);free(after);
}
static void nondefault_roundtrip(void) {
    load("[general]\nhttp_port=2113\nnotifications=false\nupdate_auto_check=false\nnotification_level=all\nlog_level=debug\nlog_max_bytes=4096\nlanguage=es\nlanguage_prompt_seen=true\nui_auth_enabled=true\nui_password=1234\nui_auth_reset_on_boot=true\nopen_browser=false\n"
         "[display]\ntime_format=24h\ndisplay_timezone=UTC\nbackup_timezone_offset=offset:+00:00\n"
         "[console]\nconsole_name=Fixture console\nconsole_type=PS5 Pro\nconsole_role=secondary\n"
         "[cloud]\nprovider=gdrive\n[gdrive]\nclient_id=synthetic-client\nclient_secret=synthetic-secret\nroot_folder=Fixture Drive\nuse_appdata=true\ncustom_ca=true\n"
         "[usb]\nenabled=false\nmount=/mnt/usb3\nfolder=Fixture USB\n"
         "[ftp]\nenabled=true\nhost=192.0.2.80\nport=8021\nuser=fixture\npass=synthetic-password\nremote_path=/fixture\n"
         "[destinations]\norder=ftp, usb\nfallback=false\n[triggers]\nmodes=manual\nlive_backup_mode=aggressive\nidle_seconds=12\ninterval_seconds=34\nchange_settle_seconds=45\n"
         "[retention]\nmax_versions=17\nmax_total_size_per_title=7GB\nmax_total_size_global=16GB\nmin_change_bytes=12\ndedup_by_hash=false\n"
         "[titles]\nexclude=PPSA00001\ninclude_only=PPSA00002\nhidden=PPSA00003\napp_defaults_applied=true\n"
         "[users]\n00000001=Fixture user\n[title_names]\nPPSA00001=Fixture game\n"
         "[paths]\nsaves_root=/fixture/saves\nstate_dir=/fixture/state\nstaging_dir=/fixture/staging\n"
         "[advanced]\nzip_mode=store\nupload_workers=2\nretry_max_attempts=3\nretry_backoff_ms=1000\n"
         "[crypto]\nuse_kernel_resign=true\nauto_fallback_on_failure=false\nfix_zeroed_sfo=true\n");
    CHECK(config_set_display_alias("00000001","Presentation only"));
    config_t before=cfg;CHECK(config_load(&cfg,path));CHECK(!memcmp(&before,&cfg,sizeof(cfg)));
    CHECK(!cfg.crypto.use_kernel_resign&&!cfg.crypto.fix_zeroed_sfo);
    CHECK(cfg.retention.max_versions==17&&!strcmp(cfg.retention.max_total_size_global_str,"16GB"));
    CHECK(!cfg.destinations.fallback&&cfg.destinations.order_count==1&&!strcmp(cfg.destinations.order[0],"usb"));
}
static void partial_and_failure(void) {
    load(seed);CHECK(config_apply_json("{\"retention\":{\"max_versions\":17,\"min_change_bytes\":43}}"));
    CHECK(config_apply_json("{\"retention\":{\"dedup_by_hash\":false}}"));
    CHECK(cfg.retention.max_versions==17&&cfg.retention.min_change_bytes==43&&!cfg.retention.dedup_by_hash);
    CHECK(!strcmp(cfg.retention.max_total_size_per_title_str,"5GB")&&!strcmp(cfg.retention.max_total_size_global_str,"13GB"));
    without_defaults("retention.max_versions,retention.min_change_bytes,retention.dedup_by_hash",5);
    CHECK(config_apply_json("{\"retention\":{\"max_versions\":0}}"));CHECK(cfg.retention.max_versions==0&&cfg.retention.min_change_bytes==43);
    CHECK(config_apply_json("{\"retention\":{\"min_change_bytes\":0}}"));CHECK(cfg.retention.min_change_bytes==0);
    load(seed);CHECK(config_apply_json("{\"retention\":{},\"other\":{\"max_versions\":1,\"min_change_bytes\":1}}"));
    CHECK(cfg.retention.max_versions==10&&cfg.retention.min_change_bytes==0);without_defaults("",2);
    load(seed);char* before=read_ini();char tmp[1024];snprintf(tmp,sizeof(tmp),"%s.tmp",path);CHECK(!mkdir(tmp,0700));
    CHECK(!config_set_display_alias("00000003","Not persisted"));CHECK(!cfg.display_users.count);
    char* after=read_ini();CHECK(!strcmp(before,after));free(before);free(after);CHECK(!rmdir(tmp));
    CHECK(config_set_display_alias("00000003","Saved after failure"));without_defaults("display_users.00000003",3);
    CHECK(config_apply_json("{\"display\":{\"display_timezone\":\"UTC\"}}"));
    bool changed=false;CHECK(config_backup_timezone_sync("UTC","offset:+00:00",&changed)==CFG_BACKUP_TIMEZONE_OK&&changed);
    CHECK(config_apply_json("{\"display\":{\"display_timezone\":\"auto\"}}"));
    CHECK(config_load(&cfg,path));CHECK(!cfg.general.backup_timezone_offset[0]);
}
int main(int argc,char** argv) {
    CHECK(argc==2);path=argv[1];api_paths();explicit_defaults();legacy_and_first_run();nondefault_roundtrip();partial_and_failure();
    printf("PASS sparse INI: %u runtime assertions; %zu explicit-default fields; every save API, legacy aliases, migration, omitted keys, clearing and failed writes\n",assertions,INI_FIELD_COUNT);
}
'''
with tempfile.TemporaryDirectory(prefix="config-persistence-") as directory:
    temporary = Path(directory)
    harness = temporary / "config-persistence.c"
    harness.write_text(SOURCE)
    compiler = shlex.split(os.environ.get("HOST_CC", "cc"))
    flags = ["-std=gnu11", "-Wall", "-Wextra", "-Werror", "-pthread", "-I" + str(ROOT / "src")]
    flags += shlex.split(os.environ.get("HOST_TEST_FLAGS", ""))
    binary = temporary / "config-persistence"
    subprocess.run(compiler + flags + [str(harness), str(ROOT / "src/json.c"), "-o", str(binary)], check=True)
    subprocess.run([str(binary), str(temporary / "synthetic.ini")], check=True, timeout=30)
