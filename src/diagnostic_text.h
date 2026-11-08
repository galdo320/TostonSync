#ifndef TOSTONSYNC_DIAGNOSTIC_TEXT_H
#define TOSTONSYNC_DIAGNOSTIC_TEXT_H
#include <stdbool.h>
#include <stddef.h>
#include <string.h>
#include <strings.h>
// Drop the entire line, rather than guessing where a credential value ends.
static inline bool diagnostic_contains(const char* text,size_t length,const char* needle) {
    size_t n=needle?strlen(needle):0;if(!n||n>length)return false;
    for(size_t i=0;i+n<=length;i++)if(!strncasecmp(text+i,needle,n))return true;return false;
}
static inline size_t diagnostic_redact_state(char* text,size_t length,bool* state) {
    static const char* sensitive[]={"access_token","refresh_token","client_secret","device_code","user_code=","authorization:","bearer ","ya29.","1//","GOCSPX-","private key","body=","error_description","ui_password","password=","\"password\""};
    size_t read=0,write=0;bool pem=*state;
    while(read<length){size_t end=read;while(end<length&&text[end]!='\n')end++;
        size_t n=end-read;bool redact=pem||memchr(text+read,0,n)!=NULL;
        bool begin=diagnostic_contains(text+read,n,"-----BEGIN"),finish=diagnostic_contains(text+read,n,"-----END");
        if(begin)pem=true;redact|=pem;
        for(size_t i=0;i<sizeof(sensitive)/sizeof(sensitive[0]);i++)redact|=diagnostic_contains(text+read,n,sensitive[i]);

        if(redact){const char marker[]="[redacted]";size_t m=n<sizeof(marker)-1?n:sizeof(marker)-1;memcpy(text+write,marker,m);write+=m;}
        else{memmove(text+write,text+read,n);write+=n;}
        if(finish)pem=false;if(end<length)text[write++]='\n';read=end+(end<length);
    }
    *state=pem;text[write]=0;return write;
}
static inline size_t diagnostic_redact(char* text,size_t length,const char* secret,const char* access_code) {
    (void)secret;(void)access_code; // Arbitrary PIN substrings must not hide phase/hash evidence.
    bool state=false;return diagnostic_redact_state(text,length,&state);
}
#endif
