// TostónSync — sealed-key extractor. See pfs_keys.h.
//
// The unwrap is a single ioctl on /dev/pfsmgr. The buffer layout the
// kernel expects:
//
//      offset 0x00 .. 0x60   sealed key (input)
//      offset 0x60 .. 0x80   plain key  (output, on success)
//      offset 0x80 .. 0x100  reserved   (touched by the kernel)
//
// We zero a 0x100-byte heap buffer, drop the sealed key at the front,
// hand it to the kernel, and copy the plain key out. The buffer is
// freed straight away so the secret does not linger.

#include "pfs_keys.h"
#include "log.h"

#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <unistd.h>

#define PFSMGR_DEVICE        "/dev/pfsmgr"
#define PFSMGR_DECRYPT_IOCTL 0xc0845302UL

#define SEALED_KEY_OFFSET    0x800   // inside the save image
#define SEALED_KEY_SIZE      PFS_SEALED_KEY_SIZE
#define PLAIN_KEY_OUT_OFFSET 0x60    // inside the ioctl buffer
#define IOCTL_BUF_SIZE       0x100

bool pfs_decrypt_sealed_key_buffer(uint8_t sealed_in[0x60],
                                   uint8_t out_plain[PFS_PLAIN_KEY_SIZE]) {
    if (!sealed_in || !out_plain) return false;

    // Heap-allocate so a stray kernel write past 0x80 can't trample the
    // local stack frame. Zero so any "uninitialized" bits the kernel
    // reads are deterministic.
    uint8_t* buf = (uint8_t*)calloc(1, IOCTL_BUF_SIZE);
    if (!buf) return false;
    memcpy(buf, sealed_in, SEALED_KEY_SIZE);

    log_info("pfs: [bc] opening %s", PFSMGR_DEVICE);
    int dev = open(PFSMGR_DEVICE, O_RDWR);
    if (dev < 0) {
        log_warn("pfs: cannot open %s — is kstuff loaded?", PFSMGR_DEVICE);
        free(buf);
        return false;
    }

    log_info("pfs: [bc] calling ioctl 0x%lx (dev=%d)",
             (unsigned long)PFSMGR_DECRYPT_IOCTL, dev);
    int ret = ioctl(dev, (unsigned long)PFSMGR_DECRYPT_IOCTL, buf);
    log_info("pfs: [bc] ioctl returned %d", ret);
    close(dev);

    if (ret < 0) {
        log_warn("pfs: sealed-key unwrap ioctl failed (ret=%d)", ret);
        // Wipe before free so the failed call doesn't leave secrets in
        // freelist memory.
        memset(buf, 0, IOCTL_BUF_SIZE);
        free(buf);
        return false;
    }

    memcpy(out_plain, buf + PLAIN_KEY_OUT_OFFSET, PFS_PLAIN_KEY_SIZE);
    memset(buf, 0, IOCTL_BUF_SIZE);
    free(buf);
    return true;
}

bool pfs_decrypt_save_key(const char* save_image_path,
                          uint8_t     out_plain[PFS_PLAIN_KEY_SIZE]) {
    if (!save_image_path || !out_plain) return false;

    int fd = open(save_image_path, O_RDONLY);
    if (fd < 0) {
        log_warn("pfs: cannot open save image %s", save_image_path);
        return false;
    }

    log_info("pfs: [bc] reading sealed key @0x%x (%d bytes) from %s",
             SEALED_KEY_OFFSET, SEALED_KEY_SIZE, save_image_path);
    uint8_t sealed[SEALED_KEY_SIZE];
    ssize_t r = pread(fd, sealed, SEALED_KEY_SIZE, SEALED_KEY_OFFSET);
    close(fd);
    log_info("pfs: [bc] sealed-key pread got %zd", r);

    if (r != SEALED_KEY_SIZE) {
        log_warn("pfs: short read of sealed key (%zd of %d) from %s",
                 r, SEALED_KEY_SIZE, save_image_path);
        memset(sealed, 0, sizeof(sealed));
        return false;
    }

    bool ok = pfs_decrypt_sealed_key_buffer(sealed, out_plain);
    memset(sealed, 0, sizeof(sealed));   // don't leak the wrapped key
    return ok;
}

bool pfs_read_sealed_key(const char* save_image_path,
                         uint8_t out_sealed[PFS_SEALED_KEY_SIZE]) {
    if (!save_image_path || !out_sealed) return false;
    int fd = open(save_image_path, O_RDONLY);
    if (fd < 0) return false;
    bool ok = (pread(fd, out_sealed, PFS_SEALED_KEY_SIZE,
                     SEALED_KEY_OFFSET) == (ssize_t)PFS_SEALED_KEY_SIZE);
    close(fd);
    if (ok && memcmp(out_sealed, "pfsSKKey", 8) != 0) ok = false;
    if (!ok) memset(out_sealed, 0, PFS_SEALED_KEY_SIZE);
    return ok;
}

bool pfs_save_images_share_sealed_key(const char* a, const char* b) {
    uint8_t ka[PFS_SEALED_KEY_SIZE], kb[PFS_SEALED_KEY_SIZE];
    bool ok = pfs_read_sealed_key(a, ka) && pfs_read_sealed_key(b, kb) &&
              memcmp(ka, kb, PFS_SEALED_KEY_SIZE) == 0;
    memset(ka, 0, sizeof(ka));
    memset(kb, 0, sizeof(kb));
    return ok;
}
