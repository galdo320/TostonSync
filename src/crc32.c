// TostónSync — CRC32 implementation (lazy table, IEEE polynomial 0xedb88320).

#include "crc32.h"

#include <pthread.h>

static uint32_t s_table[256];
static pthread_once_t s_init_once = PTHREAD_ONCE_INIT;

static void build_table(void) {
    for (uint32_t n = 0; n < 256; n++) {
        uint32_t c = n;
        for (int k = 0; k < 8; k++)
            c = (c & 1) ? (0xedb88320u ^ (c >> 1)) : (c >> 1);
        s_table[n] = c;
    }
}

uint32_t crc32_init(void) { return 0xffffffffu; }

uint32_t crc32_update(uint32_t state, const void* data, size_t n) {
    pthread_once(&s_init_once, build_table);
    const unsigned char* p = (const unsigned char*)data;
    for (size_t i = 0; i < n; i++)
        state = s_table[(state ^ p[i]) & 0xff] ^ (state >> 8);
    return state;
}

uint32_t crc32_finish(uint32_t state) { return state ^ 0xffffffffu; }

uint32_t crc32_buf(const void* data, size_t n) {
    return crc32_finish(crc32_update(crc32_init(), data, n));
}
