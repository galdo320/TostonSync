// TostónSync — QR rendering helper built on Project Nayuki's
// qrcodegen.c. The renderer itself is in third_party/qrcodegen.[ch] —
// this file just turns its bitmap into SVG.

#include "qrcode.h"
#include "third_party/qrcodegen.h"

#include <stdio.h>

// --------------------------------------------------------------------
// SVG renderer — used by the HTML UI.
// --------------------------------------------------------------------

size_t qr_render_svg(const char* text, int module_px,
                     char* out, size_t out_sz) {
    if (!text || !out || out_sz < 256) return 0;
    if (module_px < 1) module_px = 6;

    uint8_t qrcode[qrcodegen_BUFFER_LEN_MAX];
    uint8_t tempBuf[qrcodegen_BUFFER_LEN_MAX];
    if (!qrcodegen_encodeText(text, tempBuf, qrcode,
                              qrcodegen_Ecc_MEDIUM,
                              qrcodegen_VERSION_MIN,
                              qrcodegen_VERSION_MAX,
                              qrcodegen_Mask_AUTO,
                              true)) {
        return 0;
    }

    int size   = qrcodegen_getSize(qrcode);
    int border = 4;
    int dim    = (size + 2 * border) * module_px;

    char* p   = out;
    char* end = out + out_sz;

    int n = snprintf(p, end - p,
        "<svg xmlns=\"http://www.w3.org/2000/svg\" "
        "viewBox=\"0 0 %d %d\" width=\"%d\" height=\"%d\" "
        "shape-rendering=\"crispEdges\">"
        "<rect width=\"100%%\" height=\"100%%\" fill=\"#fff\"/>"
        "<path fill=\"#000\" d=\"",
        dim, dim, dim, dim);
    if (n < 0 || (p += n) >= end) return 0;

    for (int y = 0; y < size; y++) {
        for (int x = 0; x < size; x++) {
            if (!qrcodegen_getModule(qrcode, x, y)) continue;
            n = snprintf(p, end - p, "M%d %dh%dv%dh-%dz",
                (x + border) * module_px,
                (y + border) * module_px,
                module_px, module_px, module_px);
            if (n < 0 || (p += n) >= end) return 0;
        }
    }
    n = snprintf(p, end - p, "\"/></svg>");
    if (n < 0 || (p += n) >= end) return 0;

    return (size_t)(p - out);
}
