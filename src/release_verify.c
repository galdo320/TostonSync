#include "release_verify.h"
#include "sha256.h"
#include "at_io.h"
#include "crc32.h"
#include "third_party/puff.h"
#include "third_party/monocypher/monocypher-ed25519.h"
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static bool fail(char* error, size_t cap, const char* reason) {
    if (error && cap) snprintf(error, cap, "%s", reason);
    return false;
}
static void hash_hex(const void* data, size_t length, char out[65]) {
    unsigned char digest[32]; sha256_ctx_t c; sha256_init(&c);
    sha256_update(&c, data, length); sha256_final(&c, digest);
    for (unsigned i=0;i<32;i++) snprintf(out+i*2,3,"%02x",digest[i]);
}
static bool hex_hash(const char* s) {
    if (strlen(s)!=64) return false;
    for (unsigned i=0;i<64;i++) if (!((s[i]>='0'&&s[i]<='9')||(s[i]>='a'&&s[i]<='f'))) return false;
    return true;
}
static bool version_parts(const char* s, unsigned parts[3]) {
    if (!s) return false;
    for (unsigned i=0;i<3;i++) {
        const char* start=s; unsigned v=0;
        if (*s<'0'||*s>'9') return false;
        while (*s>='0'&&*s<='9') { if (v>99999) return false; v=v*10+(unsigned)(*s++-'0'); }
        if (s-start>1 && *start=='0') return false;
        parts[i]=v;
        if (i<2) { if (*s++!='.') return false; } else if (*s) return false;
    }
    return true;
}
int release_version_compare(const char* a,const char* b) {
    unsigned x[3],y[3]; if (!version_parts(a,x)||!version_parts(b,y)) return 2;
    for(unsigned i=0;i<3;i++) if(x[i]!=y[i]) return x[i]<y[i]?-1:1;
    return 0;
}

// This bounded parser validates the entire document, not a first matching key.
// Tokens retain source spans; untrusted strings are decoded only into bounded outputs.
#define TOKENS_MAX 8192
#define DEPTH_MAX 24
typedef struct { size_t begin,end,next; char kind; } token_t;
typedef struct { const unsigned char* p; size_t size,pos,count; token_t* t; } parser_t;
static void ws(parser_t* p) { while(p->pos<p->size && strchr(" \t\r\n",p->p[p->pos]) && p->p[p->pos]) p->pos++; }
static int hval(unsigned char c) { return c>='0'&&c<='9'?c-'0':c>='a'&&c<='f'?c-'a'+10:c>='A'&&c<='F'?c-'A'+10:-1; }
static bool codepoint(const unsigned char* s,size_t n,size_t* i,uint32_t* cp) {
    if (*i>=n) return false;
    unsigned c=s[(*i)++];
    if (c=='\\') {
        if (*i>=n) return false;
        c=s[(*i)++]; const char* escapes="\"\\/bfnrt"; const char* values="\"\\/\b\f\n\r\t";
        const char* hit=c?strchr(escapes,(int)c):NULL;
        if(hit) { *cp=(unsigned char)values[hit-escapes];return true; }
        if(c!='u'||n-*i<4) return false;
        uint32_t v=0;for(unsigned j=0;j<4;j++){int d=hval(s[(*i)++]);if(d<0)return false;v=v*16+(unsigned)d;}
        if(v>=0xd800&&v<=0xdbff){
            if(n-*i<6||s[*i]!='\\'||s[*i+1]!='u')return false;
            *i+=2;uint32_t low=0;for(unsigned j=0;j<4;j++){int d=hval(s[(*i)++]);if(d<0)return false;low=low*16+(unsigned)d;}
            if(low<0xdc00||low>0xdfff)return false;
            v=0x10000+((v-0xd800)<<10)+(low-0xdc00);
        } else if(v>=0xdc00&&v<=0xdfff)return false;
        if(!v)return false;*cp=v;return true;
    }
    if(c<0x20||c=='"') return false;
    if(c<0x80){*cp=c;return true;}
    unsigned more;uint32_t v,min;
    if(c>=0xc2&&c<=0xdf){more=1;v=c&31;min=0x80;}
    else if(c>=0xe0&&c<=0xef){more=2;v=c&15;min=0x800;}
    else if(c>=0xf0&&c<=0xf4){more=3;v=c&7;min=0x10000;}else return false;
    if(n-*i<more)return false;
    for(unsigned j=0;j<more;j++){c=s[(*i)++];if((c&0xc0)!=0x80)return false;v=(v<<6)|(c&63);}
    if(v<min||v>0x10ffff||(v>=0xd800&&v<=0xdfff))return false;
    *cp=v;return true;
}
static bool string_out(const parser_t* p,size_t id,char* out,size_t cap,bool truncate) {
    if(id>=p->count||p->t[id].kind!='s'||!cap)return false;
    size_t i=p->t[id].begin+1,end=p->t[id].end-1,used=0;
    while(i<end){uint32_t cp;if(!codepoint(p->p,end,&i,&cp))return false;
        unsigned char b[4];size_t n;
        if(cp<0x80){b[0]=(unsigned char)cp;n=1;}
        else if(cp<0x800){b[0]=0xc0|(cp>>6);b[1]=0x80|(cp&63);n=2;}
        else if(cp<0x10000){b[0]=0xe0|(cp>>12);b[1]=0x80|((cp>>6)&63);b[2]=0x80|(cp&63);n=3;}
        else{b[0]=0xf0|(cp>>18);b[1]=0x80|((cp>>12)&63);b[2]=0x80|((cp>>6)&63);b[3]=0x80|(cp&63);n=4;}
        if(used+n>=cap){if(!truncate)return false;break;}
        memcpy(out+used,b,n);used+=n;
    }
    out[used]=0;return true;
}
static bool parse_value(parser_t* p,unsigned depth,size_t* id) {
    ws(p);if(depth>DEPTH_MAX||p->pos>=p->size||p->count==TOKENS_MAX)return false;
    size_t t=p->count++;*id=t;p->t[t].begin=p->pos;
    unsigned c=p->p[p->pos++];p->t[t].kind=(char)c;
    if(c=='"') {
        p->t[t].kind='s';bool closed=false;
        while(p->pos<p->size){if(p->p[p->pos]=='"'){p->pos++;closed=true;break;}uint32_t cp;if(!codepoint(p->p,p->size,&p->pos,&cp))return false;}
        if(!closed)return false;
    } else if(c=='{'||c=='[') {
        ws(p);unsigned close=c=='{'?'}':']';
        if(p->pos<p->size&&p->p[p->pos]==close)p->pos++;
        else for(;;){size_t child;
            if(c=='{') {
                if(p->pos>=p->size||p->p[p->pos]!='"'||!parse_value(p,depth+1,&child))return false;
                char key[129],prior[129];if(!string_out(p,child,key,sizeof(key),false))return false;
                for(size_t k=t+1;k<child;){if(!string_out(p,k,prior,sizeof(prior),false)||!strcmp(key,prior))return false;k=p->t[p->t[k].next].next;}
                ws(p);if(p->pos>=p->size||p->p[p->pos++]!=':')return false;
            }
            if(!parse_value(p,depth+1,&child))return false;
            ws(p);if(p->pos>=p->size)return false;c=p->p[p->pos++];
            if(c==close)break;if(c!=',')return false;ws(p);c=close=='}'?'{':'[';
        }
    } else if(c=='t'||c=='f'||c=='n') {
        const char* v=c=='t'?"true":c=='f'?"false":"null";size_t n=strlen(v);
        if(p->size-p->t[t].begin<n||memcmp(p->p+p->t[t].begin,v,n))return false;p->pos=p->t[t].begin+n;
    } else {
        p->t[t].kind='n';size_t start=p->t[t].begin;p->pos=start;
        if(p->p[p->pos]=='-')p->pos++;
        if(p->pos>=p->size)return false;
        if(p->p[p->pos]=='0')p->pos++;
        else {if(p->p[p->pos]<'1'||p->p[p->pos]>'9')return false;while(p->pos<p->size&&p->p[p->pos]>='0'&&p->p[p->pos]<='9')p->pos++;}
        if(p->pos<p->size&&p->p[p->pos]=='.'){size_t a=++p->pos;while(p->pos<p->size&&p->p[p->pos]>='0'&&p->p[p->pos]<='9')p->pos++;if(a==p->pos)return false;}
        if(p->pos<p->size&&(p->p[p->pos]=='e'||p->p[p->pos]=='E')){p->pos++;if(p->pos<p->size&&(p->p[p->pos]=='+'||p->p[p->pos]=='-'))p->pos++;size_t a=p->pos;while(p->pos<p->size&&p->p[p->pos]>='0'&&p->p[p->pos]<='9')p->pos++;if(a==p->pos)return false;}
    }
    p->t[t].end=p->pos;p->t[t].next=p->count;return true;
}
static bool document(parser_t* p,const void* bytes,size_t n,size_t limit) {
    memset(p,0,sizeof(*p));if(!bytes||!n||n>limit||memchr(bytes,0,n))return false;
    p->p=bytes;p->size=n;p->t=calloc(TOKENS_MAX,sizeof(*p->t));if(!p->t)return false;
    size_t root;bool ok=parse_value(p,0,&root);ws(p);
    if(!ok||p->pos!=n||p->t[0].kind!='{'){free(p->t);p->t=NULL;return false;}return true;
}
static size_t field(const parser_t* p,size_t object,const char* name) {
    if(object>=p->count||p->t[object].kind!='{')return SIZE_MAX;
    for(size_t i=object+1;i<p->t[object].next;){char k[129];if(!string_out(p,i,k,sizeof(k),false))return SIZE_MAX;size_t v=p->t[i].next;if(!strcmp(k,name))return v;i=p->t[v].next;}
    return SIZE_MAX;
}
static bool strfield(const parser_t* p,size_t o,const char* k,char* out,size_t cap){return string_out(p,field(p,o,k),out,cap,false);}
static bool uintfield(const parser_t* p,size_t o,const char* k,uint64_t* out){
    size_t t=field(p,o,k);if(t>=p->count||p->t[t].kind!='n')return false;
    uint64_t n=0;for(size_t i=p->t[t].begin;i<p->t[t].end;i++){unsigned c=p->p[i];if(c<'0'||c>'9'||n>(UINT64_MAX-(c-'0'))/10)return false;n=n*10+c-'0';}*out=n;return true;
}
static bool falsefield(const parser_t* p,const char* key){size_t t=field(p,0,key);return t<p->count&&p->t[t].kind=='f';}
static bool asset_name(const char* s){size_t n=strlen(s);if(!n||n>=128||s[0]=='.')return false;for(size_t i=0;i<n;i++)if(!((s[i]>='A'&&s[i]<='Z')||(s[i]>='a'&&s[i]<='z')||(s[i]>='0'&&s[i]<='9')||strchr(" ._-",s[i])))return false;return true;}
bool release_parse_listing(const void* bytes,size_t n,release_listing_t* out,char* error,size_t cap){
    if(!out)return fail(error,cap,"release_invalid");memset(out,0,sizeof(*out));parser_t p;
    if(!document(&p,bytes,n,RELEASE_LISTING_MAX))return fail(error,cap,"release_invalid");
    bool ok=strfield(&p,0,"tag_name",out->tag,sizeof(out->tag))&&out->tag[0]=='v'&&release_version_compare(out->tag+1,out->tag+1)==0&&falsefield(&p,"draft")&&falsefield(&p,"prerelease");
    if(ok)snprintf(out->version,sizeof(out->version),"%s",out->tag+1);
    size_t notes=field(&p,0,"body");
    if(notes<p.count&&p.t[notes].kind=='s') {
        // A truncated body can still offer a binary, but never authenticated notes.
        bool complete=string_out(&p,notes,out->notes,sizeof(out->notes),false);
        if(complete) hash_hex(out->notes,strlen(out->notes),out->notes_sha256);
        else out->notes[0]=0;
    }
    else if(notes<p.count&&(p.t[notes].kind!='n'||p.t[notes].end-p.t[notes].begin!=4||memcmp(p.p+p.t[notes].begin,"null",4)))ok=false;
    size_t a=field(&p,0,"assets");if(a>=p.count||p.t[a].kind!='[')ok=false;
    if(ok)for(size_t i=a+1;i<p.t[a].next;i=p.t[i].next){
        if(out->count==RELEASE_ASSETS_MAX){ok=false;break;}release_asset_t* v=&out->assets[out->count];
        if(!strfield(&p,i,"name",v->name,sizeof(v->name))||!asset_name(v->name)||!uintfield(&p,i,"size",&v->size)){ok=false;break;}
        for(size_t j=0;j<out->count;j++)if(!strcmp(v->name,out->assets[j].name))ok=false;
        out->count++;
    }
    // Prefer the named v2 contract; never fall back after a malformed v2 pair.
    bool v2=false,manifest=false,signature=false;
    for(size_t i=0;i<out->count;i++) if(!strcmp(out->assets[i].name,RELEASE_MANIFEST_V2_NAME)||!strcmp(out->assets[i].name,RELEASE_SIGNATURE_V2_NAME))v2=true;
    snprintf(out->manifest_name,sizeof(out->manifest_name),"%s",v2?RELEASE_MANIFEST_V2_NAME:RELEASE_MANIFEST_NAME);
    snprintf(out->signature_name,sizeof(out->signature_name),"%s",v2?RELEASE_SIGNATURE_V2_NAME:RELEASE_SIGNATURE_NAME);
    for(size_t i=0;i<out->count;i++){release_asset_t* a=&out->assets[i];if(!strcmp(a->name,out->manifest_name))manifest=a->size>0&&a->size<=RELEASE_MANIFEST_MAX;if(!strcmp(a->name,out->signature_name))signature=a->size==64;}
    free(p.t);if(!ok||!manifest||!signature)return fail(error,cap,ok?"release_assets_missing":"release_invalid");return true;
}
bool release_verify_manifest(const void* bytes,size_t n,const void* sig,size_t sn,const char* running,const release_listing_t* listing,release_manifest_t* out,char* error,size_t cap){
    if(!out||!listing||!bytes||!n||n>RELEASE_MANIFEST_MAX||!sig||sn!=64)return fail(error,cap,"manifest_invalid");
    if(crypto_ed25519_check(sig,release_public_keys[0],bytes,n)&&crypto_ed25519_check(sig,release_public_keys[1],bytes,n))return fail(error,cap,"signature_invalid");
    memset(out,0,sizeof(*out));parser_t p;if(!document(&p,bytes,n,RELEASE_MANIFEST_MAX))return fail(error,cap,"manifest_invalid");
    uint64_t schema=0;size_t fields=0;for(size_t i=1;i<p.t[0].next;i=p.t[p.t[i].next].next)fields++;
    bool modern=uintfield(&p,0,"schema",&schema)&&schema==3;
    int client=release_version_compare(running,"0.5.266");
    bool ok=(modern||(client==-1&&((schema==1&&fields==10&&strcmp(listing->manifest_name,RELEASE_MANIFEST_V2_NAME))||
        (schema==2&&fields==11&&!strcmp(listing->manifest_name,RELEASE_MANIFEST_V2_NAME)))))&&
        strfield(&p,0,"version",out->version,sizeof(out->version))&&strfield(&p,0,"build",out->build,sizeof(out->build))&&
        strfield(&p,0,"min_version",out->min_version,sizeof(out->min_version))&&strfield(&p,0,"asset",out->asset,sizeof(out->asset))&&
        strfield(&p,0,"asset_sha256",out->asset_sha256,sizeof(out->asset_sha256))&&uintfield(&p,0,"asset_size",&out->asset_size);
    if(modern) {
        // Schema 3 is the stable base contract. Additive fields are signed but optional;
        // required new semantics must raise min_version before older clients install.
        snprintf(out->elf,sizeof(out->elf),"%s",out->asset);
        snprintf(out->sha256,sizeof(out->sha256),"%s",out->asset_sha256);out->size=out->asset_size;
        ok=ok&&listing->count==3&&!strcmp(listing->manifest_name,RELEASE_MANIFEST_NAME)&&
            !strcmp(listing->signature_name,RELEASE_SIGNATURE_NAME)&&release_version_compare(out->min_version,"0.5.266")!=2&&
            release_version_compare(out->min_version,"0.5.266")>=0;
    } else ok=ok&&strfield(&p,0,"elf",out->elf,sizeof(out->elf))&&strfield(&p,0,"sha256",out->sha256,sizeof(out->sha256))&&uintfield(&p,0,"size",&out->size);
    if(schema>=2) ok=ok&&strfield(&p,0,"notes_sha256",out->notes_sha256,sizeof(out->notes_sha256))&&hex_hash(out->notes_sha256);
    free(p.t);
    if(!ok||!out->build[0]||!hex_hash(out->sha256)||!hex_hash(out->asset_sha256)||out->size<64||out->size>RELEASE_BYTES_MAX||out->asset_size<22||out->asset_size>RELEASE_BYTES_MAX)return fail(error,cap,"manifest_invalid");
    for(size_t i=0;out->build[i];i++)if((unsigned char)out->build[i]<32||(unsigned char)out->build[i]>126)return fail(error,cap,"manifest_invalid");
    int newer=release_version_compare(out->version,running),minimum=release_version_compare(running,out->min_version);
    if(newer==2||minimum==2||strcmp(out->version,listing->version))return fail(error,cap,"manifest_version_invalid");
    if(newer<=0)return fail(error,cap,"update_not_newer");
    if(minimum<0)return fail(error,cap,"minimum_version_not_met");
    char asset[128],elf[128];
    snprintf(asset,sizeof(asset),modern?"TostonSync-v%s.elf":"TostonSync-v%s-public.zip",out->version);
    snprintf(elf,sizeof(elf),modern?"TostonSync-v%s.elf":"TostonSync v%s.elf",out->version);
    if(strcmp(asset,out->asset)||strcmp(elf,out->elf))return fail(error,cap,"manifest_asset_invalid");
    bool found=false;for(size_t i=0;i<listing->count;i++)if(!strcmp(listing->assets[i].name,out->asset)&&listing->assets[i].size==out->asset_size)found=true;
    if(!found)return fail(error,cap,"release_assets_missing");
    out->notes_verified=schema>=2&&listing->notes_sha256[0]&&!strcmp(out->notes_sha256,listing->notes_sha256);
    if(modern&&!out->notes_verified)return fail(error,cap,"release_notes_mismatch");
    hash_hex(bytes,n,out->candidate_id);return true;
}
bool release_asset_url(const char* tag,const char* asset,char* out,size_t cap){
    if(!tag||tag[0]!='v'||release_version_compare(tag+1,tag+1)!=0||!asset||!asset_name(asset)||!out||!cap)return false;
    int n=snprintf(out,cap,"https://github.com/galdo320/TostonSync/releases/download/%s/",tag);if(n<0||(size_t)n>=cap)return false;size_t used=(size_t)n;
    for(const unsigned char* p=(const unsigned char*)asset;*p;p++){if(*p==' '){if(cap-used<=3)return false;memcpy(out+used,"%20",3);used+=3;}else{if(cap-used<=1)return false;out[used++]=(char)*p;}}out[used]=0;return true;
}
static uint16_t u16(const unsigned char* p){return (uint16_t)(p[0]|((unsigned)p[1]<<8));}
static uint32_t u32(const unsigned char* p){return (uint32_t)p[0]|((uint32_t)p[1]<<8)|((uint32_t)p[2]<<16)|((uint32_t)p[3]<<24);}
static bool bounds(size_t offset,size_t length,size_t size){return offset<=size&&length<=size-offset;}
bool release_extract_elf(int fd,const release_manifest_t* m,void** elf,size_t* length,char* error,size_t cap){
    if(elf)*elf=NULL;if(length)*length=0;
    if(!m||!elf||!length||m->asset_size<22||m->asset_size>RELEASE_BYTES_MAX||m->size<64||m->size>RELEASE_BYTES_MAX)return fail(error,cap,"asset_invalid");
    toston_stat_guard_t guard=TOSTON_STAT_GUARD_INIT;int stat_rc=toston_fstat(fd,&guard.value);
    if(stat_rc||!toston_stat_guard_valid(&guard)||!S_ISREG(guard.value.st_mode)||guard.value.st_size<0||(uint64_t)guard.value.st_size!=m->asset_size)return fail(error,cap,"asset_size_mismatch");
    size_t n=(size_t)m->asset_size;unsigned char* b=malloc(n);if(!b)return fail(error,cap,"out_of_memory");
    size_t used=0;while(used<n){ssize_t r=pread(fd,b+used,n-used,(off_t)used);if(r<=0){free(b);return fail(error,cap,"asset_read_failed");}used+=(size_t)r;}
    char hash[65];hash_hex(b,n,hash);if(strcmp(hash,m->asset_sha256)){free(b);return fail(error,cap,"asset_sha256_mismatch");}
    if(!strcmp(m->asset,m->elf)) {
        if(m->asset_size!=m->size||strcmp(m->asset_sha256,m->sha256)) {free(b);return fail(error,cap,"elf_sha256_mismatch");}
        *elf=b;*length=n;return true;
    }
    // Historical schema-1/2 API fixtures only: .266 production admission rejects
    // those manifests before a candidate exists, so its download is always raw ELF.
    const char* why="zip_invalid";unsigned char* result=NULL;bool ok=false;
    // Our publisher emits a single-disk ZIP32 with no archive comment. No extraction
    // paths are opened, and no other member is decompressed or installed.
    size_t eo=n-22;if(u32(b+eo)!=0x06054b50||u16(b+eo+4)||u16(b+eo+6)||u16(b+eo+20)||u16(b+eo+8)!=u16(b+eo+10))goto done;
    size_t count=u16(b+eo+10),cd=u32(b+eo+16),cdsize=u32(b+eo+12);
    if(!count||count>256||!bounds(cd,cdsize,eo)||cd+cdsize!=eo)goto done;
    size_t pos=cd,match=SIZE_MAX;
    for(size_t i=0;i<count;i++){
        if(!bounds(pos,46,eo)||u32(b+pos)!=0x02014b50)goto done;
        size_t name=u16(b+pos+28),extra=u16(b+pos+30),comment=u16(b+pos+32),span=46+name+extra+comment;
        if(!name||name>1024||!bounds(pos,span,eo)||memchr(b+pos+46,0,name)||u16(b+pos+34))goto done;
        if(name==strlen(m->elf)&&!memcmp(b+pos+46,m->elf,name)){if(match!=SIZE_MAX)goto done;match=pos;}
        pos+=span;
    }
    if(pos!=eo||match==SIZE_MAX)goto done;
    const unsigned char* r=b+match;size_t compressed=u32(r+20),original=u32(r+24),local=u32(r+42),name=u16(r+28);unsigned flags=u16(r+8),method=u16(r+10),type=u32(r+38)>>16;
    if(original!=m->size||(flags&~(8u|2048u))||(method!=0&&method!=8)||(type&S_IFMT&&((type&S_IFMT)!=S_IFREG))||!bounds(local,30,cd)||u32(b+local)!=0x04034b50)goto done;
    const unsigned char* l=b+local;size_t lname=u16(l+26),extra=u16(l+28),data=local+30+lname+extra;
    if(lname!=name||u16(l+6)!=flags||u16(l+8)!=method||!bounds(local+30,lname+extra,cd)||memcmp(l+30,r+46,name)||!bounds(data,compressed,cd))goto done;
    if(!(flags&8)&&(u32(l+14)!=u32(r+16)||u32(l+18)!=compressed||u32(l+22)!=original))goto done;
    result=malloc(original);if(!result){why="out_of_memory";goto done;}
    if(method==0){if(compressed!=original)goto done;memcpy(result,b+data,original);}
    else {unsigned long out=(unsigned long)original,in=(unsigned long)compressed;if(puff(result,&out,b+data,&in)!=0||out!=original||in!=compressed)goto done;}
    if(crc32_finish(crc32_update(crc32_init(),result,original))!=u32(r+16))goto done;
    hash_hex(result,original,hash);if(strcmp(hash,m->sha256)){why="elf_sha256_mismatch";goto done;}
    *elf=result;*length=original;result=NULL;ok=true;
done:free(b);free(result);return ok?true:fail(error,cap,why);
}
