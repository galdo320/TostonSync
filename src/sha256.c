#include "sha256.h"

#include <fcntl.h>
#include <string.h>
#include <unistd.h>

static const uint32_t K[64] = {
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
    0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
    0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
    0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
    0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
    0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
};

static uint32_t rotr(uint32_t x, unsigned n) { return (x >> n) | (x << (32 - n)); }

static void transform(sha256_ctx_t* c, const uint8_t b[64]) {
    uint32_t w[64];
    for (int i = 0; i < 16; i++)
        w[i] = ((uint32_t)b[i*4] << 24) | ((uint32_t)b[i*4+1] << 16) |
               ((uint32_t)b[i*4+2] << 8) | b[i*4+3];
    for (int i = 16; i < 64; i++) {
        uint32_t s0 = rotr(w[i-15],7) ^ rotr(w[i-15],18) ^ (w[i-15] >> 3);
        uint32_t s1 = rotr(w[i-2],17) ^ rotr(w[i-2],19) ^ (w[i-2] >> 10);
        w[i] = w[i-16] + s0 + w[i-7] + s1;
    }
    uint32_t a=c->state[0], d=c->state[3], e=c->state[4], h=c->state[7];
    uint32_t b0=c->state[1], c0=c->state[2], f=c->state[5], g=c->state[6];
    for (int i = 0; i < 64; i++) {
        uint32_t s1=rotr(e,6)^rotr(e,11)^rotr(e,25);
        uint32_t ch=(e&f)^((~e)&g);
        uint32_t t1=h+s1+ch+K[i]+w[i];
        uint32_t s0=rotr(a,2)^rotr(a,13)^rotr(a,22);
        uint32_t maj=(a&b0)^(a&c0)^(b0&c0);
        uint32_t t2=s0+maj;
        h=g; g=f; f=e; e=d+t1; d=c0; c0=b0; b0=a; a=t1+t2;
    }
    c->state[0]+=a; c->state[1]+=b0; c->state[2]+=c0; c->state[3]+=d;
    c->state[4]+=e; c->state[5]+=f; c->state[6]+=g; c->state[7]+=h;
}

void sha256_init(sha256_ctx_t* c) {
    static const uint32_t init[8] = {0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,
                                     0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19};
    memset(c, 0, sizeof(*c));
    memcpy(c->state, init, sizeof(init));
}

void sha256_update(sha256_ctx_t* c, const void* data, size_t len) {
    const uint8_t* p = (const uint8_t*)data;
    c->total += len;
    while (len) {
        size_t n = 64 - c->used;
        if (n > len) n = len;
        memcpy(c->block + c->used, p, n);
        c->used += n; p += n; len -= n;
        if (c->used == 64) { transform(c, c->block); c->used = 0; }
    }
}

void sha256_final(sha256_ctx_t* c, uint8_t out[32]) {
    uint64_t bits = c->total * 8;
    c->block[c->used++] = 0x80;
    if (c->used > 56) {
        while (c->used < 64) c->block[c->used++] = 0;
        transform(c, c->block); c->used = 0;
    }
    while (c->used < 56) c->block[c->used++] = 0;
    for (int i = 7; i >= 0; i--) c->block[c->used++] = (uint8_t)(bits >> (i*8));
    transform(c, c->block);
    for (int i = 0; i < 8; i++) {
        out[i*4]=(uint8_t)(c->state[i]>>24); out[i*4+1]=(uint8_t)(c->state[i]>>16);
        out[i*4+2]=(uint8_t)(c->state[i]>>8); out[i*4+3]=(uint8_t)c->state[i];
    }
    memset(c, 0, sizeof(*c));
}

bool sha256_file_hex(const char* path, char out[65]) {
    if (!path || !out) return false;
    int fd = open(path, O_RDONLY);
    if (fd < 0) return false;
    sha256_ctx_t c; sha256_init(&c);
    uint8_t buf[32768], hash[32];
    bool ok = true;
    for (;;) {
        ssize_t n = read(fd, buf, sizeof(buf));
        if (n == 0) break;
        if (n < 0) { ok = false; break; }
        sha256_update(&c, buf, (size_t)n);
    }
    close(fd);
    if (!ok) { memset(&c, 0, sizeof(c)); return false; }
    sha256_final(&c, hash);
    static const char hex[] = "0123456789abcdef";
    for (int i = 0; i < 32; i++) { out[i*2]=hex[hash[i]>>4]; out[i*2+1]=hex[hash[i]&15]; }
    out[64] = '\0';
    memset(hash, 0, sizeof(hash));
    return true;
}
