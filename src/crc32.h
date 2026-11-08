// TostónSync — CRC32 (IEEE 802.3 polynomial), the variant used by ZIP.
#ifndef TOSTONSYNC_CRC32_H
#define TOSTONSYNC_CRC32_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

// Streaming API. Start with crc32_init(), feed bytes with
// crc32_update(), finalize with crc32_finish(). The return value of
// crc32_finish() is the ZIP-compatible CRC32.
uint32_t crc32_init(void);
uint32_t crc32_update(uint32_t state, const void* data, size_t n);
uint32_t crc32_finish(uint32_t state);

// One-shot convenience.
uint32_t crc32_buf(const void* data, size_t n);

#ifdef __cplusplus
}
#endif
#endif
