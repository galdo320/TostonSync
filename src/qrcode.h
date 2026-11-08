// TostónSync — Thin wrapper around Project Nayuki's QR-Code-generator C
// implementation. We embed `qrcodegen.c` / `qrcodegen.h` from
// https://github.com/nayuki/QR-Code-generator (MIT) under src/third_party/
// and expose one helper tailored to our use case:
//
//   qr_render_svg() — render the Device Flow verification URL to an
//   inline SVG that the embedded HTML UI can drop straight into a
//   <div>. The phone scans it, jumps to google.com/device with the
//   user_code pre-filled, and the rest is a single tap on the phone.
//
// The helper writes into caller-provided buffers; no heap allocation
// happens inside the renderer.

#ifndef TOSTONSYNC_QRCODE_H
#define TOSTONSYNC_QRCODE_H

#include <stdbool.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

// Render `text` as an SVG string. The SVG is a self-contained <svg>
// element with viewBox and explicit width/height. Returns the number
// of bytes written (excluding the terminating NUL), or 0 on failure.
//
// `module_px` is the rendered size of one QR "module" — values from
// 4 to 12 are reasonable. A border of 4 modules is added per the spec.
size_t qr_render_svg(const char* text,
                     int         module_px,
                     char*       out,
                     size_t      out_sz);

#ifdef __cplusplus
}
#endif
#endif // TOSTONSYNC_QRCODE_H
