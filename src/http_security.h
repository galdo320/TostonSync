#ifndef TOSTONSYNC_HTTP_SECURITY_H
#define TOSTONSYNC_HTTP_SECURITY_H
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <ctype.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <strings.h>
#define HTTP_SECURITY_HEADERS \
    "X-Frame-Options: DENY\r\n" \
    "Referrer-Policy: no-referrer\r\n" \
    "Content-Security-Policy: default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data: blob: https:; connect-src 'self' https://oauth2.googleapis.com https://www.googleapis.com; object-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'\r\n"

// Parse one authority, without DNS or forwarded-header trust.
static inline bool http_authority(const char* value,int port,const char* configured,char host[254]) {
    if(!value||!*value||strlen(value)>=300)return false;
    const char* start=value,*end;bool ipv6=*value=='[';
    if(ipv6){start++;end=strchr(start,']');if(!end)return false;}
    else{end=strchr(start,':');if(!end)end=start+strlen(start);}
    size_t n=(size_t)(end-start);if(!n||n>=254)return false;memcpy(host,start,n);host[n]=0;
    const char* suffix=end+(ipv6?1:0);unsigned observed=80;
    if(*suffix){if(*suffix++!=':'||!*suffix)return false;observed=0;
        for(;*suffix;suffix++){if(*suffix<'0'||*suffix>'9')return false;observed=observed*10+(unsigned)(*suffix-'0');if(observed>65535)return false;}}
    if(observed!=(unsigned)port)return false;
    unsigned char address[16];
    if(inet_pton(ipv6?AF_INET6:AF_INET,host,address)==1)return true;
    if(ipv6)return false;
    if(!strcasecmp(host,"localhost"))return true;
    if(!configured||!*configured||strcasecmp(host,configured))return false;
    size_t label=0;
    for(size_t i=0;i<n;i++){unsigned char c=host[i];
        if(c=='.'){if(!label||host[i-1]=='-')return false;label=0;continue;}
        if(!((c>='a'&&c<='z')||(c>='A'&&c<='Z')||(c>='0'&&c<='9')||c=='-')||(!label&&c=='-')||++label>63)return false;}
    return label&&host[n-1]!='-';
}
static inline bool http_request_boundary(const char* data,size_t size,int port,const char* configured) {
    if(!data||size<4||size>16384||memchr(data,0,size))return false;
    const char* limit=data+size;const char* line=memchr(data,'\r',size);
    if(!line||line+1>=limit||line[1]!='\n')return false;
    const char* sp=memchr(data,' ',(size_t)(line-data));if(!sp||sp+1>=line||sp[1]!='/')return false;
    const char* tail=memchr(sp+1,' ',(size_t)(line-sp-1));if(!tail)return false;
    if((line-tail!=9)|| (memcmp(tail+1,"HTTP/1.0",8)&&memcmp(tail+1,"HTTP/1.1",8)))return false;
    const char* q=memchr(sp+1,'?',(size_t)(tail-sp-1));
    if((size_t)((q?q:tail)-sp-1)>=512||(q&&(size_t)(tail-q-1)>=512))return false;
    for(const char* p=sp+1;p<tail;p++)if((unsigned char)*p<=32||(unsigned char)*p==127||*p=='#'||*p=='\\')return false;
    char host[300]="",origin[320]="",ctype[128]="";unsigned seen=0;
    const char* p=line+2;
    while(p<limit-2){
        const char* e=memchr(p,'\r',(size_t)(limit-p));if(!e||e+1>=limit||e[1]!='\n')return false;
        if(e==p)break;
        const char* colon=memchr(p,':',(size_t)(e-p));if(!colon||colon==p)return false;
        for(const char* k=p;k<colon;k++)if(!isalnum((unsigned char)*k)&&!strchr("!#$%&'*+-.^_`|~",*k))return false;
        const char* v=colon+1;while(v<e&&(*v==' '||*v=='\t'))v++;const char* ve=e;while(ve>v&&(ve[-1]==' '||ve[-1]=='\t'))ve--;
        for(const char* k=v;k<ve;k++)if((unsigned char)*k<32||(unsigned char)*k==127)return false;
        size_t key=(size_t)(colon-p),len=(size_t)(ve-v);unsigned bit=0;char* out=NULL;size_t cap=0;
        if(key==4&&!strncasecmp(p,"Host",4)){bit=1;out=host;cap=sizeof(host);}
        if(key==6&&!strncasecmp(p,"Origin",6)){bit=2;out=origin;cap=sizeof(origin);}
        if(key==12&&!strncasecmp(p,"Content-Type",12)){bit=4;out=ctype;cap=sizeof(ctype);}
        if(bit){if((seen&bit)||!len||len>=cap)return false;seen|=bit;memcpy(out,v,len);out[len]=0;}
        p=e+2;
    }
    if(p!=limit-2||p[0]!='\r'||p[1]!='\n'||!(seen&1))return false;
    char hostname[254];if(!http_authority(host,port,configured,hostname))return false;
    if(seen&2){char other[254];if(strncmp(origin,"http://",7)||!http_authority(origin+7,port,configured,other)||strcasecmp(hostname,other))return false;}
    return true;
}
#endif
