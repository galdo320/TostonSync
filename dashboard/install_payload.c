// TostónSync — dashboard app installer payload.
//
// This mirrors ps5-payload-sdk's samples/install_app payload: after the app
// files are copied into /user/app/<TITLE_ID>, this payload asks the shell's app
// install utility to register the title so it appears on the dashboard.

#include <stdio.h>

int sceAppInstUtilInitialize(void);
int sceAppInstUtilAppInstallTitleDir(const char* title_id,
                                     const char* base_dir,
                                     void* reserved);

#ifndef TITLE_ID
#define TITLE_ID "TOST10001"
#endif

int main(int argc, char** argv) {
    (void)argc;
    (void)argv;

    int err = sceAppInstUtilInitialize();
    if (err) {
        printf("sceAppInstUtilInitialize: %x\n", err);
        return -1;
    }

    err = sceAppInstUtilAppInstallTitleDir(TITLE_ID, "/user/app/", 0);
    if (err) {
        printf("sceAppInstUtilAppInstallTitleDir(%s): %x\n", TITLE_ID, err);
        return -1;
    }

    printf("TostónSync dashboard app installed: %s\n", TITLE_ID);
    return 0;
}
