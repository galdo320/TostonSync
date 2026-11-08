// Local Ed25519 key generation/signing. Private material is never printed.
#include "third_party/monocypher/monocypher-ed25519.h"
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/random.h>
#include <unistd.h>
static int read_exact(const char* path,void* bytes,size_t size,int secret){
    int fd=open(path,O_RDONLY|O_NOFOLLOW);struct stat st;
    int ok=fd>=0&&fstat(fd,&st)==0&&S_ISREG(st.st_mode)&&st.st_nlink==1&&st.st_size==(off_t)size&&(!secret||(st.st_uid==getuid()&&(st.st_mode&0777)==0600));
    size_t used=0;while(ok&&used<size){ssize_t n=read(fd,(char*)bytes+used,size-used);if(n<=0)ok=0;else used+=(size_t)n;}
    if(fd>=0&&close(fd))ok=0;return ok;
}
static int write_new(const char* path,const void* bytes,size_t size){
    int fd=open(path,O_WRONLY|O_CREAT|O_EXCL|O_NOFOLLOW,0600);if(fd<0)return 0;
    size_t used=0;int ok=1;while(used<size){ssize_t n=write(fd,(const char*)bytes+used,size-used);if(n<=0){ok=0;break;}used+=(size_t)n;}
    if(fsync(fd))ok=0;if(close(fd))ok=0;return ok;
}
int main(int argc,char** argv){
    int ok=0;unsigned char secret[64]={0},public[32]={0},seed[32]={0},signature[64]={0},message[4096]={0};
    if(argc==3&&!strcmp(argv[1],"keygen")){
        if(mkdir(argv[2],0700))goto done;
        struct stat st;if(lstat(argv[2],&st)||!S_ISDIR(st.st_mode)||st.st_uid!=getuid()||(st.st_mode&0777)!=0700)goto done;
        const char* roles[]={"primary","backup"};ok=1;
        for(unsigned i=0;i<2&&ok;i++){
            if(getentropy(seed,sizeof(seed))){ok=0;break;}
            crypto_ed25519_key_pair(secret,public,seed);
            char path[4096];int n=snprintf(path,sizeof(path),"%s/%s.secret",argv[2],roles[i]);
            ok=n>0&&(size_t)n<sizeof(path)&&write_new(path,secret,sizeof(secret));
            n=snprintf(path,sizeof(path),"%s/%s.pub",argv[2],roles[i]);
            ok=ok&&n>0&&(size_t)n<sizeof(path)&&write_new(path,public,sizeof(public));
            crypto_wipe(secret,sizeof(secret));crypto_wipe(seed,sizeof(seed));
        }
        int fd=open(argv[2],O_RDONLY|O_DIRECTORY|O_NOFOLLOW);if(fd<0||fsync(fd))ok=0;if(fd>=0&&close(fd))ok=0;
    } else if(argc==5&&(!strcmp(argv[1],"sign")||!strcmp(argv[1],"verify"))){
        struct stat st;if(lstat(argv[3],&st)||!S_ISREG(st.st_mode)||st.st_size<1||st.st_size>(off_t)sizeof(message))goto done;
        size_t size=(size_t)st.st_size;if(!read_exact(argv[3],message,size,0))goto done;
        if(!strcmp(argv[1],"sign")){
            if(!read_exact(argv[2],secret,sizeof(secret),1))goto done;
            memcpy(seed,secret,32);unsigned char expected[64];crypto_ed25519_key_pair(expected,public,seed);
            ok=crypto_verify64(secret,expected)==0;crypto_wipe(expected,sizeof(expected));if(!ok)goto done;
            crypto_ed25519_sign(signature,secret,message,size);
            ok=crypto_ed25519_check(signature,public,message,size)==0&&write_new(argv[4],signature,sizeof(signature));
        }else ok=read_exact(argv[2],public,sizeof(public),0)&&read_exact(argv[4],signature,sizeof(signature),0)&&crypto_ed25519_check(signature,public,message,size)==0;
    }
done:
    crypto_wipe(secret,sizeof(secret));crypto_wipe(seed,sizeof(seed));crypto_wipe(message,sizeof(message));
    if(!ok)fputs("release-sign: operation failed; no private material logged\n",stderr);
    return ok?0:1;
}
