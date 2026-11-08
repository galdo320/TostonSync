// TostónSync — PS5/PS4 param.sfo (PSF) reader/writer. See sfo.h.

#include "sfo.h"

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

// PSF on-disk layout (little-endian, public format):
//   header[20]: magic "\0PSF", ver, key_off@8, data_off@12, n_entries@16
//   index[16]*n: key_off(u16), fmt(u16), len(u32), max(u32), data_off(u32)
//   key table (null-terminated strings), then data table (max-padded values)
#define SFO_MAGIC0 0x00
#define SFO_MAGIC1 0x50  // 'P'
#define SFO_MAGIC2 0x53  // 'S'
#define SFO_MAGIC3 0x46  // 'F'

#define PARAMS_HMAC_OFFSET 0x08  // HMAC sits 8 bytes into the PARAMS blob

static uint16_t rd_u16(const uint8_t* p) {
    return (uint16_t)(p[0] | (p[1] << 8));
}
static uint32_t rd_u32(const uint8_t* p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}
static void wr_u16(uint8_t* p, uint16_t v) { p[0] = v & 0xff; p[1] = (v >> 8) & 0xff; }
static void wr_u32(uint8_t* p, uint32_t v) {
    p[0] = v & 0xff; p[1] = (v >> 8) & 0xff;
    p[2] = (v >> 16) & 0xff; p[3] = (v >> 24) & 0xff;
}

static uint8_t* read_whole(const char* path, size_t* out_len) {
    int fd = open(path, O_RDONLY);
    if (fd < 0) return NULL;
    struct stat st;
    if (fstat(fd, &st) != 0 || st.st_size <= 0 || st.st_size > 1 << 20) {
        close(fd);
        return NULL;
    }
    size_t len = (size_t)st.st_size;
    uint8_t* buf = (uint8_t*)malloc(len);
    if (!buf) { close(fd); return NULL; }
    size_t got = 0;
    while (got < len) {
        ssize_t r = read(fd, buf + got, len - got);
        if (r <= 0) break;
        got += (size_t)r;
    }
    close(fd);
    if (got != len) { free(buf); return NULL; }
    *out_len = len;
    return buf;
}

// Copy a bounded, NUL-terminated string value out of the data table.
static void copy_str_value(char* dst, size_t dst_sz,
                           const uint8_t* val, uint32_t len) {
    if (!dst || dst_sz == 0) return;
    size_t n = len;
    if (n >= dst_sz) n = dst_sz - 1;
    // values are usually NUL-terminated; stop at the first NUL anyway
    size_t i = 0;
    for (; i < n && val[i]; i++) dst[i] = (char)val[i];
    dst[i] = '\0';
}

int sfo_parse(const char* path, sfo_info_t* out) {
    if (!path || !out) return -1;
    memset(out, 0, sizeof(*out));

    size_t len = 0;
    uint8_t* buf = read_whole(path, &len);
    if (!buf) return -1;
    if (len < 20) { free(buf); return -1; }

    // all-zero (corrupted) detection over the first chunk
    int all_zero = 1;
    size_t check = len < 256 ? len : 256;
    for (size_t i = 0; i < check; i++)
        if (buf[i]) { all_zero = 0; break; }
    if (all_zero) { free(buf); out->zeroed = true; return -2; }

    if (buf[0] != SFO_MAGIC0 || buf[1] != SFO_MAGIC1 ||
        buf[2] != SFO_MAGIC2 || buf[3] != SFO_MAGIC3) {
        free(buf);
        return -1;
    }

    uint32_t key_off  = rd_u32(buf + 8);
    uint32_t data_off = rd_u32(buf + 12);
    uint32_t n        = rd_u32(buf + 16);
    if (key_off > len || data_off > len || n > 4096 ||
        (uint64_t)20 + (uint64_t)n * 16 > len) {
        free(buf);
        return -1;
    }

    for (uint32_t i = 0; i < n; i++) {
        const uint8_t* idx = buf + 20 + (size_t)i * 16;
        uint16_t koff   = rd_u16(idx);
        uint32_t plen   = rd_u32(idx + 4);
        uint32_t doff   = rd_u32(idx + 12);

        if ((size_t)key_off + koff >= len) continue;
        const char* key = (const char*)(buf + key_off + koff);
        // ensure the key is NUL-terminated within the buffer
        size_t kmax = len - (key_off + koff);
        if (!memchr(key, '\0', kmax)) continue;

        if ((uint64_t)data_off + doff > len) continue;
        const uint8_t* val = buf + data_off + doff;
        uint32_t avail = (uint32_t)(len - (data_off + doff));
        if (plen > avail) plen = avail;

        if (strcmp(key, "TITLE_ID") == 0)
            copy_str_value(out->title_id, sizeof(out->title_id), val, plen);
        else if (strcmp(key, "SAVEDATA_DIRECTORY") == 0)
            copy_str_value(out->dir_name, sizeof(out->dir_name), val, plen);
        else if (strcmp(key, "MAINTITLE") == 0 || strcmp(key, "TITLE") == 0)
            copy_str_value(out->main_title, sizeof(out->main_title), val, plen);
        else if (strcmp(key, "SUBTITLE") == 0)
            copy_str_value(out->sub_title, sizeof(out->sub_title), val, plen);
        else if (strcmp(key, "DETAIL") == 0)
            copy_str_value(out->detail, sizeof(out->detail), val, plen);
        else if (strcmp(key, "FORMAT") == 0)
            copy_str_value(out->format, sizeof(out->format), val, plen);
        else if (strcmp(key, "ACCOUNT_ID") == 0 && plen >= 8)
            out->account_id = (uint64_t)rd_u32(val) |
                              ((uint64_t)rd_u32(val + 4) << 32);
        else if (strcmp(key, "USER_ID") == 0 && plen >= 4)
            out->user_id = rd_u32(val);
        else if (strcmp(key, "SAVEDATA_BLOCKS") == 0 && plen >= 4)
            out->blocks = (plen >= 8) ? ((uint64_t)rd_u32(val) |
                          ((uint64_t)rd_u32(val + 4) << 32)) : rd_u32(val);
        else if (strcmp(key, "SYSTEM_BLOCKS") == 0 && plen >= 4)
            out->system_blocks = (plen >= 8) ? ((uint64_t)rd_u32(val) |
                          ((uint64_t)rd_u32(val + 4) << 32)) : rd_u32(val);
        else if (strcmp(key, "PARAMS") == 0 && plen >= 8) {
            out->user_param = rd_u32(val);
            if (!out->user_id) out->user_id = rd_u32(val + 0x04);
            if (plen >= PARAMS_HMAC_OFFSET + SFO_HMAC_LEN) {
                const uint8_t* h = val + PARAMS_HMAC_OFFSET;
                int nz = 0;
                for (int b = 0; b < SFO_HMAC_LEN; b++)
                    if (h[b]) { nz = 1; break; }
                if (nz) {
                    memcpy(out->hmac, h, SFO_HMAC_LEN);
                    out->has_hmac = true;
                }
            }
        } else if (strcmp(key, "USER_PARAM") == 0 && plen >= 4) {
            out->user_param = rd_u32(val);
        }
    }

    if (!out->game_title_id[0])
        snprintf(out->game_title_id, sizeof(out->game_title_id), "%s",
                 out->title_id);
    free(buf);
    return 0;
}

bool sfo_read_hmac(const char* path, uint8_t hmac[SFO_HMAC_LEN]) {
    sfo_info_t info;
    if (sfo_parse(path, &info) != 0) return false;
    if (!info.has_hmac) return false;
    memcpy(hmac, info.hmac, SFO_HMAC_LEN);
    return true;
}

bool sfo_patch_identity(const char* path, uint64_t account_id,
                        uint32_t user_id) {
    return sfo_patch_identity_hmac(path, account_id, user_id, NULL);
}

bool sfo_patch_identity_hmac(const char* path, uint64_t account_id,
                             uint32_t user_id,
                             const uint8_t hmac[SFO_HMAC_LEN]) {
    if (!path || (!account_id && !user_id && !hmac)) return true;

    size_t len = 0;
    uint8_t* buf = read_whole(path, &len);
    if (!buf) return false;
    bool ok = false;
    bool account_done = (account_id == 0);
    bool user_done = (user_id == 0);
    bool hmac_done = (hmac == NULL);

    if (len < 20 || buf[0] != SFO_MAGIC0 || buf[1] != SFO_MAGIC1 ||
        buf[2] != SFO_MAGIC2 || buf[3] != SFO_MAGIC3)
        goto done;

    uint32_t key_off  = rd_u32(buf + 8);
    uint32_t data_off = rd_u32(buf + 12);
    uint32_t n        = rd_u32(buf + 16);
    if (key_off > len || data_off > len || n > 4096 ||
        (uint64_t)20 + (uint64_t)n * 16 > len)
        goto done;

    int fd = open(path, O_RDWR);
    if (fd < 0) goto done;

    ok = true;
    for (uint32_t i = 0; i < n; i++) {
        const uint8_t* idx = buf + 20 + (size_t)i * 16;
        uint16_t koff = rd_u16(idx);
        uint32_t plen = rd_u32(idx + 4);
        uint32_t doff = rd_u32(idx + 12);

        if ((size_t)key_off + koff >= len) continue;
        const char* key = (const char*)(buf + key_off + koff);
        size_t kmax = len - (key_off + koff);
        if (!memchr(key, '\0', kmax)) continue;
        if ((uint64_t)data_off + doff > len) continue;

        off_t pos = (off_t)(data_off + doff);
        uint8_t tmp[8];
        if (!account_done && strcmp(key, "ACCOUNT_ID") == 0 && plen >= 8) {
            wr_u32(tmp, (uint32_t)account_id);
            wr_u32(tmp + 4, (uint32_t)(account_id >> 32));
            if (pwrite(fd, tmp, 8, pos) != 8) ok = false;
            account_done = true;
        } else if (!user_done && strcmp(key, "USER_ID") == 0 && plen >= 4) {
            wr_u32(tmp, user_id);
            if (pwrite(fd, tmp, 4, pos) != 4) ok = false;
            user_done = true;
        } else if (strcmp(key, "PARAMS") == 0) {
            if (!user_done && plen >= 8) {
                wr_u32(tmp, user_id);
                if (pwrite(fd, tmp, 4, pos + 0x04) != 4) ok = false;
                user_done = true;
            }
            if (!hmac_done && plen >= PARAMS_HMAC_OFFSET + SFO_HMAC_LEN) {
                if (pwrite(fd, hmac, SFO_HMAC_LEN,
                           pos + PARAMS_HMAC_OFFSET) != SFO_HMAC_LEN)
                    ok = false;
                hmac_done = true;
            }
        }
    }

    if (fsync(fd) != 0) ok = false;
    if (close(fd) != 0) ok = false;
    if (!account_done || !user_done || !hmac_done) ok = false;

done:
    free(buf);
    return ok;
}

// 15 standard PS5 save keys, alphabetical (the order the system emits).
static const char* const SFO_KEYS[] = {
    "ACCOUNT_ID", "ATTRIBUTE", "CATEGORY", "DETAIL", "FORMAT",
    "LINEAGE_ID", "MAINTITLE", "PARAMS", "SAVEDATA_BLOCKS",
    "SAVEDATA_DIRECTORY", "SAVEDATA_LIST_PARAM", "SAVEDATA_REVISION",
    "SUBTITLE", "SYSTEM_BLOCKS", "TITLE_ID"
};
#define SFO_NKEYS ((int)(sizeof(SFO_KEYS) / sizeof(SFO_KEYS[0])))

// param value formats
#define FMT_BIN 0x0004
#define FMT_STR 0x0204
#define FMT_U32 0x0404

int sfo_write(const char* path, const sfo_info_t* in, const uint8_t* hmac) {
    if (!path || !in) return -1;
    enum { SFO_BUF = 4096 };
    uint8_t buf[SFO_BUF];
    memset(buf, 0, sizeof(buf));

    uint32_t key_off = 20 + SFO_NKEYS * 16;
    uint32_t key_total = 0;
    for (int i = 0; i < SFO_NKEYS; i++)
        key_total += (uint32_t)strlen(SFO_KEYS[i]) + 1;
    uint32_t data_off = key_off + key_total;
    if (data_off % 4) data_off += 4 - (data_off % 4);
    if (data_off > SFO_BUF) return -1;

    buf[0] = SFO_MAGIC0; buf[1] = SFO_MAGIC1;
    buf[2] = SFO_MAGIC2; buf[3] = SFO_MAGIC3;
    buf[4] = 0x01; buf[5] = 0x01;
    wr_u32(buf + 8, key_off);
    wr_u32(buf + 12, data_off);
    wr_u32(buf + 16, (uint32_t)SFO_NKEYS);

    // key table
    uint32_t kpos = 0;
    for (int i = 0; i < SFO_NKEYS; i++) {
        size_t kl = strlen(SFO_KEYS[i]) + 1;
        memcpy(buf + key_off + kpos, SFO_KEYS[i], kl);
        kpos += (uint32_t)kl;
    }

    const char* fmt_str = (in->format[0] == 'o') ? "obs" : "ppr"; // obs=PS4
    const char* dir = in->dir_name[0] ? in->dir_name : "savedata0";
    const char* mt  = in->main_title[0] ? in->main_title : in->title_id;
    const char* gt  = in->game_title_id[0] ? in->game_title_id : in->title_id;

    uint32_t dpos = 0;
    kpos = 0;
    for (int i = 0; i < SFO_NKEYS; i++) {
        uint8_t* idx = buf + 20 + (size_t)i * 16;
        wr_u16(idx, (uint16_t)kpos);
        const char* k = SFO_KEYS[i];
        uint16_t fmt = FMT_STR;
        uint32_t plen = 0, pmax = 0;
        uint8_t* d = buf + data_off + dpos;
        if (data_off + dpos > SFO_BUF) return -1;

        if (!strcmp(k, "ACCOUNT_ID")) {
            fmt = FMT_BIN; plen = pmax = 8;
            wr_u32(d, (uint32_t)in->account_id);
            wr_u32(d + 4, (uint32_t)(in->account_id >> 32));
        } else if (!strcmp(k, "ATTRIBUTE")) {
            fmt = FMT_U32; plen = pmax = 4;
        } else if (!strcmp(k, "CATEGORY")) {
            plen = 3; pmax = 4; memcpy(d, "sd", 3);
        } else if (!strcmp(k, "DETAIL")) {
            const char* s = in->detail;
            plen = (uint32_t)strlen(s) + 1; pmax = 1024;
            if (plen > pmax) plen = pmax;
            memcpy(d, s, plen ? plen - 1 : 0);
        } else if (!strcmp(k, "FORMAT")) {
            plen = 3; pmax = 4; memcpy(d, fmt_str, 3);
        } else if (!strcmp(k, "LINEAGE_ID")) {
            fmt = FMT_BIN; plen = pmax = 16;
        } else if (!strcmp(k, "MAINTITLE")) {
            plen = (uint32_t)strlen(mt) + 1; pmax = 128;
            if (plen > pmax) plen = pmax;
            memcpy(d, mt, plen - 1);
        } else if (!strcmp(k, "PARAMS")) {
            fmt = FMT_BIN; plen = pmax = 1024;
            wr_u32(d, in->user_param);
            wr_u32(d + 0x04, in->user_id);
            if (hmac) memcpy(d + PARAMS_HMAC_OFFSET, hmac, SFO_HMAC_LEN);
            wr_u32(d + 0x28, 1);
            strncpy((char*)(d + 0x2C), in->title_id, 12);
            strncpy((char*)(d + 0x38), gt, 12);
            wr_u32(d + 0x54, 2);
        } else if (!strcmp(k, "SAVEDATA_BLOCKS")) {
            fmt = FMT_BIN; plen = pmax = 8;
            wr_u32(d, (uint32_t)in->blocks);
            wr_u32(d + 4, (uint32_t)(in->blocks >> 32));
        } else if (!strcmp(k, "SAVEDATA_DIRECTORY")) {
            plen = (uint32_t)strlen(dir) + 1; pmax = 32;
            if (plen > pmax) plen = pmax;
            memcpy(d, dir, plen - 1);
        } else if (!strcmp(k, "SAVEDATA_LIST_PARAM")) {
            fmt = FMT_U32; plen = pmax = 4;
        } else if (!strcmp(k, "SAVEDATA_REVISION")) {
            fmt = FMT_BIN; plen = pmax = 16;
        } else if (!strcmp(k, "SUBTITLE")) {
            const char* s = in->sub_title;
            plen = (uint32_t)strlen(s) + 1; pmax = 128;
            if (plen > pmax) plen = pmax;
            memcpy(d, s, plen ? plen - 1 : 0);
        } else if (!strcmp(k, "SYSTEM_BLOCKS")) {
            fmt = FMT_BIN; plen = pmax = 8;
            wr_u32(d, (uint32_t)in->system_blocks);
            wr_u32(d + 4, (uint32_t)(in->system_blocks >> 32));
        } else if (!strcmp(k, "TITLE_ID")) {
            plen = (uint32_t)strlen(in->title_id) + 1; pmax = 12;
            if (plen > pmax) plen = pmax;
            memcpy(d, in->title_id, plen - 1);
        }

        if (data_off + dpos + pmax > SFO_BUF) return -1;
        wr_u16(idx + 2, fmt);
        wr_u32(idx + 4, plen);
        wr_u32(idx + 8, pmax);
        wr_u32(idx + 12, dpos);
        dpos += pmax;
        kpos += (uint32_t)strlen(k) + 1;
    }

    uint32_t total = data_off + dpos;
    char tmp[1100];
    int nn = snprintf(tmp, sizeof(tmp), "%s.tostonsync_tmp", path);
    if (nn <= 0 || (size_t)nn >= sizeof(tmp)) return -1;
    int fd = open(tmp, O_CREAT | O_WRONLY | O_TRUNC, 0644);
    if (fd < 0) return -1;
    size_t off = 0;
    int ok = 1;
    while (off < total) {
        ssize_t w = write(fd, buf + off, total - off);
        if (w <= 0) { ok = 0; break; }
        off += (size_t)w;
    }
    if (fsync(fd) != 0) ok = 0;
    if (close(fd) != 0) ok = 0;
    if (ok && rename(tmp, path) != 0) ok = 0;
    if (!ok) { unlink(tmp); return -1; }
    return 0;
}
