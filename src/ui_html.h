// TostónSync — embedded Settings UI.
//
// Three string literals: the HTML page, the CSS, and the JS. The httpd
// serves them as static assets. No external CDN dependency — every
// asset is contained in this header so the UI works on a LAN with no
// internet (which is the common case on a jailbroken console behind
// NanoDNS).

#ifndef TOSTONSYNC_UI_HTML_H
#define TOSTONSYNC_UI_HTML_H

#define TOSTON_SUPPORT_URL "https://ko-fi.com/galdo"

#ifdef __cplusplus
extern "C" {
#endif

extern const char UI_HTML_INDEX[];
extern const char UI_CSS_APP[];
extern const char UI_JS_APP[];
extern const char UI_SVG_LOGO[];

#ifdef __cplusplus
}
#endif
#endif
