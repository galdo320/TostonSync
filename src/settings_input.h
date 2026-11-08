// Strict, bounded JSON for settings. Backup and Restore parsers are unchanged.
#ifndef TOSTONSYNC_SETTINGS_INPUT_H
#define TOSTONSYNC_SETTINGS_INPUT_H
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <limits.h>
enum { SET_OBJECT, SET_ARRAY, SET_STRING, SET_BOOL, SET_INT, SET_NULL };
typedef struct { int kind, first, next; char key[64], text[256]; long long number; bool boolean; } settings_value_t;
typedef struct { const char *p, *end; unsigned used; settings_value_t values[512]; } settings_json_t;
static inline bool settings_scalar(uint32_t cp) {
    return cp>=32 && !(cp>=127&&cp<=159) && cp<=0x10ffff && !(cp>=0xd800&&cp<=0xdfff);
}
static inline bool settings_utf8(const unsigned char** p,const unsigned char* end,uint32_t* cp) {
    if(*p==end)return false;unsigned c=*(*p)++,n;uint32_t min;
    if(c<128){*cp=c;return settings_scalar(c);}
    if(c>=0xc2&&c<=0xdf){n=1;min=0x80;c&=31;}
    else if(c>=0xe0&&c<=0xef){n=2;min=0x800;c&=15;}
    else if(c>=0xf0&&c<=0xf4){n=3;min=0x10000;c&=7;}
    else return false;
    while(n--){if(*p==end||(**p&0xc0)!=0x80)return false;c=(c<<6)|(*(*p)++&63);}
    *cp=c;return c>=min&&settings_scalar(c);
}
static inline bool settings_text_valid(const char* text) {
    if(!text)return false;const unsigned char* p=(const unsigned char*)text,*end=p+strlen(text);uint32_t cp;
    while(p<end)if(!settings_utf8(&p,end,&cp))return false;return true;
}
static inline void settings_space(settings_json_t* d){while(d->p<d->end&&strchr(" \t\r\n",*d->p))d->p++;}
static inline bool settings_hex(settings_json_t* d,uint32_t* n) {
    *n=0;for(unsigned i=0;i<4;i++){if(d->p==d->end)return false;unsigned c=(unsigned char)*d->p++;
        unsigned v=c>='0'&&c<='9'?c-'0':c>='a'&&c<='f'?c-'a'+10:c>='A'&&c<='F'?c-'A'+10:16;
        if(v==16)return false;*n=(*n<<4)|v;}return true;
}
static inline bool settings_string(settings_json_t* d,char* out,size_t cap) {
    if(d->p==d->end||*d->p++!='"')return false;size_t n=0;
    while(d->p<d->end&&*d->p!='"') {
        uint32_t cp;const unsigned char* p=(const unsigned char*)d->p;
        if(*d->p=='\\') {
            if(++d->p==d->end)return false;unsigned c=(unsigned char)*d->p++;
            if(c=='"'||c=='\\'||c=='/')cp=c;
            else if(c=='u') {
                if(!settings_hex(d,&cp))return false;
                if(cp>=0xd800&&cp<=0xdbff){uint32_t lo;
                    if(d->end-d->p<2||d->p[0]!='\\'||d->p[1]!='u')return false;d->p+=2;
                    if(!settings_hex(d,&lo)||lo<0xdc00||lo>0xdfff)return false;
                    cp=0x10000+((cp-0xd800)<<10)+(lo-0xdc00);}
            }else return false;
        }else{if(!settings_utf8(&p,(const unsigned char*)d->end,&cp))return false;d->p=(const char*)p;}
        if(!settings_scalar(cp))return false;unsigned char b[4];size_t len;
        if(cp<128){b[0]=cp;len=1;}
        else if(cp<0x800){b[0]=0xc0|(cp>>6);b[1]=0x80|(cp&63);len=2;}
        else if(cp<0x10000){b[0]=0xe0|(cp>>12);b[1]=0x80|((cp>>6)&63);b[2]=0x80|(cp&63);len=3;}
        else{b[0]=0xf0|(cp>>18);b[1]=0x80|((cp>>12)&63);b[2]=0x80|((cp>>6)&63);b[3]=0x80|(cp&63);len=4;}
        if(n+len>=cap)return false;memcpy(out+n,b,len);n+=len;
    }
    if(d->p==d->end)return false;d->p++;out[n]=0;return true;
}
static inline int settings_value(settings_json_t* d,unsigned depth) {
    settings_space(d);if(depth>4||d->p==d->end||d->used==512)return -1;
    int id=(int)d->used++;settings_value_t* v=&d->values[id];v->first=v->next=-1;
    if(*d->p=='{'||*d->p=='[') {
        bool object=*d->p++=='{';v->kind=object?SET_OBJECT:SET_ARRAY;char end=object?'}':']';int last=-1;
        settings_space(d);if(d->p<d->end&&*d->p==end){d->p++;return id;}
        for(;;){char key[64]="";
            if(object){if(!settings_string(d,key,sizeof(key)))return -1;settings_space(d);
                if(d->p==d->end||*d->p++!=':')return -1;
                for(int i=v->first;i>=0;i=d->values[i].next)if(!strcmp(key,d->values[i].key))return -1;}
            int child=settings_value(d,depth+1);if(child<0)return -1;strcpy(d->values[child].key,key);
            if(last<0)v->first=child;else d->values[last].next=child;last=child;
            settings_space(d);if(d->p==d->end)return -1;if(*d->p==end){d->p++;return id;}
            if(*d->p++!=',')return -1;settings_space(d);
        }
    }
    if(*d->p=='"'){v->kind=SET_STRING;return settings_string(d,v->text,sizeof(v->text))?id:-1;}
    const char* words[]={"true","false","null"};
    for(unsigned i=0;i<3;i++){size_t n=strlen(words[i]);if((size_t)(d->end-d->p)>=n&&!memcmp(d->p,words[i],n)){
        d->p+=n;v->kind=i==2?SET_NULL:SET_BOOL;v->boolean=i==0;return id;}}
    const char* start=d->p;if(*d->p=='-')d->p++;
    if(d->p==d->end||*d->p<'0'||*d->p>'9')return -1;
    if(*d->p=='0')d->p++;else while(d->p<d->end&&*d->p>='0'&&*d->p<='9')d->p++;
    if(d->p-start>20)return -1;char number[22];memcpy(number,start,(size_t)(d->p-start));number[d->p-start]=0;
    errno=0;v->number=strtoll(number,NULL,10);if(errno)return -1;v->kind=SET_INT;return id;
}
static inline settings_json_t* settings_parse(const char* body,size_t length) {
    if(!body||!length||length>65536||memchr(body,0,length))return NULL;
    settings_json_t* d=calloc(1,sizeof(*d));if(!d)return NULL;d->p=body;d->end=body+length;
    int root=settings_value(d,0);settings_space(d);
    if(root!=0||d->values[0].kind!=SET_OBJECT||d->p!=d->end){free(d);return NULL;}return d;
}
static inline const settings_value_t* settings_member(const settings_json_t* d,const settings_value_t* object,const char* name) {
    if(!d||!object||object->kind!=SET_OBJECT)return NULL;
    for(int i=object->first;i>=0;i=d->values[i].next)if(!strcmp(d->values[i].key,name))return &d->values[i];return NULL;
}
#endif
