# TostónSync — top-level build.
#
# Targets:
#   make             — build bin/TostonSync v<VERSION>.elf (daemon delivery)
#   make app         — build bin/TostonSync Launcher v<VERSION>.elf
#   make dashboard-files
#                    — build dashboard app files without creating a PKG
#   make dashboard-install
#                    — install the dashboard icon through FTP + elfldr
#   make daemon-install
#                    — upload bin/tostonsync.elf to /data/tostonsync over FTP
#   make daemon-run  — send bin/tostonsync.elf to elfldr on PS5_PORT
#   make status      — print http://PS5_HOST:1993/api/status
#   make log         — print the live TostónSync log from the daemon
#   make app-pkg     — wrap the App into TostónSync.pkg (requires fpkg tooling)
#   make all         — daemon + App
#   make clean
#
# Requires PS5_PAYLOAD_SDK pointing at ps5-payload-dev's ps5-payload-sdk.
# (On macOS use `gmake`.)

LOCAL_PAYLOAD_SDK := $(abspath build/sdk-v0.43/ps5-payload-sdk)
# Prefer the project-pinned SDK over an old shell export. An explicit make
# command-line PS5_PAYLOAD_SDK=... still overrides this and must pass the gate.
PS5_PAYLOAD_SDK := $(if $(wildcard $(LOCAL_PAYLOAD_SDK)/bin/prospero-clang),$(LOCAL_PAYLOAD_SDK),/opt/ps5-payload-sdk)
PS5_HOST ?=
PS5_PORT ?= 9021
PS5_WEB_PORT ?= 1993
PS5_FTP_PORT ?= 2121
TARGET ?=
TARGETS_FILE ?= .tostonsync-targets.json
TARGET_ENV = python3 tools/ps5_target.py env --file "$(TARGETS_FILE)" --target "$(TARGET)" --host "$(PS5_HOST)" --payload-port "$(PS5_PORT)" --web-port "$(PS5_WEB_PORT)" --ftp-port "$(PS5_FTP_PORT)"

# The SDK ships a self-contained compiler wrapper that knows the PS5
# target triple, sysroot, crt and linker script. We use it directly so
# we don't depend on any particular SDK makefile layout.
CC := $(PS5_PAYLOAD_SDK)/bin/prospero-clang
PS5_DEPLOY := $(PS5_PAYLOAD_SDK)/bin/prospero-deploy

.PHONY: check-ps5-sdk sdk-setup
sdk-setup:
	python3 tools/payload_sdk.py install

check-ps5-sdk:
	@[ -x "$(CC)" ] || \
	  (echo "error: PS5_PAYLOAD_SDK is wrong or unset."; \
	   echo "       Expected prospero-clang at $(CC)"; \
	   echo "       Run gmake sdk-setup, then re-run."; exit 1)
	@python3 tools/payload_sdk.py check --sdk "$(PS5_PAYLOAD_SDK)"

# Quiet by default: hide the long prospero-clang / prospero-deploy command
# lines so a normal build/deploy reads like a tool, not a developer console.
# Pass V=1 (or VERBOSE=1) to print the full commands for debugging.
ifeq ($(V)$(VERBOSE),)
Q := @
else
Q :=
endif

# Single source of truth for the version shown in friendly build messages.
VERSION := $(shell sed -n 's/.*TOSTONSYNC_VERSION "\([0-9.][0-9.]*\)".*/\1/p' src/version.h)

# --------------------------------------------------------------------
# Daemon (tostonsync.elf)
# --------------------------------------------------------------------

DAEMON      := bin/tostonsync.elf
TEST_DIR    := build/test
CERT_BUNDLE := certs/google-we2-wr2.pem
CERT_HEADER := build/generated/google_cert_bundle.h
PUBLIC_CERT_BUNDLE := certs/public-metadata-roots.pem
PUBLIC_CERT_HEADER := build/generated/public_metadata_cert_bundle.h
RELEASE_CERT_BUNDLE := certs/release-roots.pem
RELEASE_CERT_HEADER := build/generated/release_cert_bundle.h
SUPPORT_QR := assets/support/tostonsync-kofi-qr.png
SUPPORT_HEADER := build/generated/support_qr.h
.DEFAULT_GOAL := daemon
DAEMON_SRCS := \
  src/main.c \
  src/lifecycle.c \
  src/lifecycle_native.c \
  src/instance_lock.c \
  src/update.c \
  src/github_update.c \
  src/release_verify.c \
  src/release_keys.c \
  src/third_party/monocypher/monocypher.c \
  src/third_party/monocypher/monocypher-ed25519.c \
  src/jobs.c \
  src/config.c \
  src/backup_names.c \
  src/log.c \
  src/fs.c \
  src/save_metadata.c \
  src/session_saves.c \
  src/save_image_hash.c \
  src/pfs_attributes.c \
  src/pfs_mode_trial.c \
  src/zip.c \
  src/crc32.c \
  src/sha256.c \
  src/import_session.c \
  src/individual_restore.c \
  src/restore_selection.c \
  src/portable_transaction.c \
  src/raw_selected.c \
  src/raw_selected_transaction.c \
  src/raw_selected_native.c \
  src/raw_selected_preflight.c \
  src/raw_selected_commit.c \
  src/paired_capture.c \
  src/paired_backup.c \
  src/migration_inspect.c \
  src/json.c \
  src/http_client.c \
  src/gdrive.c \
  src/usb.c \
  src/history.c \
  src/backup_job_state.c \
  src/backup_retry.c \
  src/titlename.c \
  src/retention.c \
  src/pfs_keys.c \
  src/savemount.c \
  src/pfs_resign.c \
  src/sfo.c \
  src/sdimg_restore.c \
  src/sdimg_expansion.c \
  src/watcher.c \
  src/protect.c \
  src/metacache.c \
  src/public_metadata.c \
  src/title_catalog.c \
  src/public_artwork.c \
  src/httpd.c \
  src/qrcode.c \
  src/third_party/qrcodegen.c \
  src/third_party/puff.c \
  src/third_party/sqlite3.c \
  src/ui_html.c

# qrcodegen.c is vendored from Project Nayuki at build time. See
# src/third_party/VENDOR_QRCODEGEN.txt for the one-line curl command.
ifeq (,$(wildcard src/third_party/qrcodegen.c))
$(error src/third_party/qrcodegen.c is missing — \
        see src/third_party/VENDOR_QRCODEGEN.txt)
endif
ifeq (,$(wildcard src/third_party/sqlite3.c))
$(error src/third_party/sqlite3.c is missing — \
        see src/third_party/VENDOR_SQLITE.txt)
endif

# Keep ISO C11 while explicitly exposing POSIX/BSD prototypes such as
# strdup, fseeko/ftello, localtime_r, strnlen and pread. Treat missing
# prototypes as hard failures so 64-bit pointers/offsets cannot be
# silently truncated by implicit-int fallback.
CFLAGS  += -O2 -D_DEFAULT_SOURCE -Wall -Wextra -Wno-unused-parameter \
           -Werror=implicit-function-declaration -std=c11 -Isrc -Ibuild/generated \
           -DSQLITE_THREADSAFE=0 -DSQLITE_OMIT_LOAD_EXTENSION \
           -DSQLITE_OMIT_DEPRECATED
# On-screen toasts use sceKernelSendNotificationRequest (libkernel, always
# linked) — there is no separate -lSceNotification to link, and trying to
# link it can fail with "library not found".
LDFLAGS += -lSceHttp2 -lSceHttp -lSceSsl -lSceNet -lSceNetCtl -lSceSystemService -lSceUserService \
           -lSceFsInternalForVsh -lSceRandom \
           -lpthread
# -lSceHttp (libSceHttp v1) is linked alongside -lSceHttp2 so the libSceHttp
# trust self-test (sceHttpInit / sceHttpsLoadCert / sceHttpsGetSslError /
# sceHttpsSetMinSslVersion) resolves at runtime. Without it those weak symbols
# stay NULL and the self-test reports "Init=0 LoadCert=0". libSceHttp2 stays for
# the existing request path; do not remove it.
# -lSceFsInternalForVsh supplies sceFsInitMountSaveDataOpt /
# sceFsMountSaveData / sceFsUmountSaveData (used by src/savemount.c).
# This is the library name the ps5-payload-sdk and other PS5 jailbreak
# payloads use for the savedata mount surface; there is no -lSceFs.

# Version bumps are explicit so normal and parallel builds are reproducible.
# Use `gmake release` to prepare a deploy with a new patch number.
.PHONY: bump-version
bump-version:
	@MAJMIN=`sed -n 's/.*TOSTONSYNC_VERSION "\([0-9][0-9]*\.[0-9][0-9]*\)\.[0-9][0-9]*".*/\1/p' src/version.h`; \
	 PATCH=`sed -n 's/.*TOSTONSYNC_VERSION "[0-9][0-9]*\.[0-9][0-9]*\.\([0-9][0-9]*\)".*/\1/p' src/version.h`; \
	 NEW=`expr $$PATCH + 1`; \
	 sed "s/#define TOSTONSYNC_VERSION \"[0-9.]*\"/#define TOSTONSYNC_VERSION \"$$MAJMIN.$$NEW\"/" src/version.h > src/version.h.new && \
	 mv src/version.h.new src/version.h; \
	 echo "TostónSync version -> $$MAJMIN.$$NEW"

$(CERT_HEADER): $(CERT_BUNDLE) tools/embed_text.py
	@python3 tools/embed_text.py $(CERT_BUNDLE) $@

$(PUBLIC_CERT_HEADER): $(PUBLIC_CERT_BUNDLE) tools/embed_text.py
	@python3 tools/embed_text.py $(PUBLIC_CERT_BUNDLE) $@ PUBLIC_METADATA_CERT_BUNDLE TOSTONSYNC_PUBLIC_METADATA_CERT_BUNDLE_H

$(RELEASE_CERT_HEADER): $(RELEASE_CERT_BUNDLE) tools/embed_text.py
	@python3 tools/embed_text.py $(RELEASE_CERT_BUNDLE) $@ RELEASE_CERT_BUNDLE TOSTONSYNC_RELEASE_CERT_BUNDLE_H

$(SUPPORT_HEADER): $(SUPPORT_QR) tools/embed_text.py
	@python3 tools/embed_text.py $(SUPPORT_QR) $@ SUPPORT_QR_PNG TOSTONSYNC_SUPPORT_QR_H

$(DAEMON): $(DAEMON_SRCS) Makefile tools/check_syscall_registers.py tools/payload_sdk.py tests/check_payload_runtime.py tests/fixtures/payload_runtime_kernel_v0.43.c src/version.h src/pfs_candidate_publish.h src/at_io.h $(CERT_HEADER) $(PUBLIC_CERT_HEADER) $(RELEASE_CERT_HEADER) $(SUPPORT_HEADER) $(PS5_PAYLOAD_SDK)/target/lib/crt1.o | check-ps5-sdk
	@mkdir -p bin
	@echo "Building TostónSync v$(VERSION)…"
	$(Q)$(CC) $(CFLAGS) -o $@ $(DAEMON_SRCS) $(LDFLAGS) || \
	  { echo "Build failed. Re-run with 'gmake V=1' to see the full compiler command."; exit 1; }
	@python3 tests/check_payload_runtime.py --elf "$@" --objdump "$(shell $(PS5_PAYLOAD_SDK)/bin/prospero-llvm-config --bindir)/llvm-objdump" || \
	  { rm -f "$@"; echo "Invalid linked payload runtime; ELF was not retained."; exit 1; }
	@python3 tools/check_syscall_registers.py "$@" --objdump "$(shell $(PS5_PAYLOAD_SDK)/bin/prospero-llvm-config --bindir)/llvm-objdump"
	@echo "Build complete: $(DAEMON)"

.PHONY: daemon
daemon: $(DAEMON)
	@python3 tools/public_release.py elf daemon

# Local lifecycle helpers; build only. No target here sends a payload or signal.
LIFECYCLE_HELPERS := bin/lifecycle-inspect.elf bin/lifecycle-stop.elf bin/lifecycle-verify.elf
.PHONY: lifecycle-helpers
lifecycle-helpers: $(LIFECYCLE_HELPERS)

$(LIFECYCLE_HELPERS): tools/lifecycle_helper.c src/lifecycle.c src/lifecycle_native.c src/lifecycle.h src/lifecycle_ipc.h src/version.h | check-ps5-sdk
	@mkdir -p bin
	$(Q)$(CC) $(CFLAGS) -DLIFE_HELPER_MODE=$(if $(findstring inspect,$@),1,$(if $(findstring stop,$@),2,3)) -o "$@" tools/lifecycle_helper.c src/lifecycle.c src/lifecycle_native.c -lpthread
	@python3 tests/check_payload_runtime.py --elf "$@" --objdump "$(shell $(PS5_PAYLOAD_SDK)/bin/prospero-llvm-config --bindir)/llvm-objdump"
	@python3 tools/public_release.py elf $(if $(findstring inspect,$@),inspect,$(if $(findstring stop,$@),stop,verify))

# One-time legacy observation only. Never built/sent by daemon or lifecycle flows.
LEGACY_INSPECT := bin/legacy-inspect.elf
.PHONY: legacy-inspect check-legacy-inspect
legacy-inspect: $(LEGACY_INSPECT)
	@cp "$(LEGACY_INSPECT)" "bin/TostonSync Legacy Inspect v1.0.0.elf"

check-legacy-inspect: $(LEGACY_INSPECT)
	@python3 tests/check_legacy_inspect.py --elf "$(LEGACY_INSPECT)"

# Private read-only capture probe: never copied to bin or public packages.
PAIRED_CAPTURE_PROBE := build/private/paired-capture-probe-v$(VERSION).elf
PAIRED_CAPTURE_PROBE_OBJECTS := build/private/paired-capture-probe-main.o build/private/paired-capture-probe-reader.o build/private/paired-capture-probe-sha256.o
PAIRED_CAPTURE_PROBE_FLAGS := $(CFLAGS) -DPAIRED_CAPTURE_READONLY_PROBE -fno-builtin -ffunction-sections -fdata-sections
.PHONY: paired-capture-probe check-paired-capture-probe
paired-capture-probe: $(PAIRED_CAPTURE_PROBE)

check-paired-capture-probe: $(PAIRED_CAPTURE_PROBE)
	@python3 tests/check_paired_capture_probe.py --elf "$(PAIRED_CAPTURE_PROBE)"

build/private/paired-capture-probe-main.o: tools/paired_capture_probe.c src/paired_capture.h src/at_io.h src/version.h Makefile | check-ps5-sdk
	@mkdir -p build/private
	$(Q)$(CC) $(PAIRED_CAPTURE_PROBE_FLAGS) -c "$<" -o "$@"

build/private/paired-capture-probe-reader.o: src/paired_capture.c src/paired_capture.h src/at_io.h src/sha256.h Makefile | check-ps5-sdk
	@mkdir -p build/private
	$(Q)$(CC) $(PAIRED_CAPTURE_PROBE_FLAGS) -c "$<" -o "$@"

build/private/paired-capture-probe-sha256.o: src/sha256.c src/sha256.h Makefile | check-ps5-sdk
	@mkdir -p build/private
	$(Q)$(CC) $(PAIRED_CAPTURE_PROBE_FLAGS) -c "$<" -o "$@"

$(PAIRED_CAPTURE_PROBE): $(PAIRED_CAPTURE_PROBE_OBJECTS) tests/check_paired_capture_probe.py Makefile $(PS5_PAYLOAD_SDK)/target/lib/crt1.o | check-ps5-sdk
	@mkdir -p build/private
	$(Q)$(CC) $(PAIRED_CAPTURE_PROBE_FLAGS) -Wl,--gc-sections -Wl,-Map,build/private/paired-capture-probe-v$(VERSION).map -o "$@" $(PAIRED_CAPTURE_PROBE_OBJECTS)
	@python3 tests/check_paired_capture_probe.py --elf-only "$@"

$(LEGACY_INSPECT): tools/legacy_inspect.c tools/legacy_inspect_native.h tools/legacy_inspect_bootstrap.c src/lifecycle_native.c src/lifecycle.h src/version.h tests/check_legacy_inspect.py | check-ps5-sdk
	@mkdir -p bin
	$(Q)$(CC) $(CFLAGS) -fno-builtin -nostartfiles -nodefaultlibs -ffunction-sections -fdata-sections -fvisibility=hidden -Wl,--gc-sections -o "$@" tools/legacy_inspect.c tools/legacy_inspect_bootstrap.c src/lifecycle_native.c
	@python3 tests/check_legacy_inspect.py --elf "$@"

# --------------------------------------------------------------------
# Menu App (eboot)
# --------------------------------------------------------------------

.PHONY: app
app: app/eboot.elf
	@python3 tools/public_release.py elf launcher

app/eboot.elf: app/eboot.c app/Makefile src/version.h $(PS5_PAYLOAD_SDK)/samples/install_app/eboot.x | check-ps5-sdk
	$(MAKE) -C app eboot.elf PS5_PAYLOAD_SDK=$(PS5_PAYLOAD_SDK)

# --------------------------------------------------------------------
# PKG packaging — wraps app/eboot.elf + sce_sys/ into TostónSync.pkg.
# Requires a fake-PKG tool on PATH (e.g. `prospero-pkg` or similar);
# we don't ship one. The recipe is left as a placeholder hook.
# --------------------------------------------------------------------

.PHONY: app-pkg
app-pkg: app
	@which prospero-pkg >/dev/null 2>&1 || \
	  (echo "error: prospero-pkg not found; no PKG was created." \
	   "; use dashboard-files for the no-PKG app"; exit 1)
	prospero-pkg --param-json app/sce_sys/param.sfo.json \
	             --icon assets/tostonsync_icon_512.png \
	             --eboot app/eboot.elf \
	             --output bin/TostónSync.pkg

# --------------------------------------------------------------------
# Dashboard app installer — no PKG tooling required.
# Based on ps5-payload-sdk/samples/install_app, with our eboot as the
# native tile executable. It starts the installed daemon via local elfldr
# only when stopped, then opens its verified loopback UI.
# --------------------------------------------------------------------

DASH_TITLE_ID := TOST10001
DASH_BUILD := build/dashboard/$(DASH_TITLE_ID)
DASH_UI_BIN := build/dashboard/TostonSyncLauncher.bin
DASH_INSTALL_PAYLOAD := build/dashboard/install_dashboard.elf
DASH_RELEASE_FILES := $(DASH_BUILD)/eboot.bin \
                      $(DASH_BUILD)/sce_sys/param.json \
                      $(DASH_BUILD)/sce_sys/param.json.system \
                      $(DASH_BUILD)/sce_sys/icon0.png \
                      $(DASH_INSTALL_PAYLOAD)
PS5_DAEMON_DIR := /data/tostonsync
DASH_AUTHID := 0x3800000000000022
DASH_FW_VERSION := 0x07590001
DASH_AUTHINFO := 00 00 00 00 00 00 00 00 00 00 00 00 00 1C 00 40 00 FF 00 00 00 00 00 80 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 80 00 40 00 40 00 00 00 00 00 00 00 80 00 00 00 00 00 00 00 08 00 40 FF FF 00 00 00 F0 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00

.PHONY: dashboard-files dashboard-install daemon-install install-daemon daemon-run run-daemon status log targets target-info check-dashboard-tools check-ftp-tools check-run-tools

check-ftp-tools:
	@command -v curl >/dev/null 2>&1 || \
	  (echo "error: curl is required for FTP installs."; exit 1)

check-dashboard-tools:
	@command -v curl >/dev/null 2>&1 || \
	  (echo "error: curl is required for dashboard-install."; exit 1)
	@command -v socat >/dev/null 2>&1 || \
	  (echo "error: socat is required by $(PS5_DEPLOY)."; \
	   echo "       Install it on macOS with: brew install socat"; exit 1)
	@[ -x "$(PS5_DEPLOY)" ] || \
	  (echo "error: prospero-deploy was not found at $(PS5_DEPLOY)."; \
	   echo "       Set PS5_PAYLOAD_SDK=/opt/ps5-payload-sdk and re-run."; exit 1)

check-run-tools:
	@command -v socat >/dev/null 2>&1 || \
	  (echo "error: socat is required to send the daemon."; \
	   echo "       Install it on macOS with: brew install socat"; exit 1)
	@[ -x "$(PS5_DEPLOY)" ] || \
	  (echo "error: prospero-deploy was not found at $(PS5_DEPLOY)."; \
	   echo "       Set PS5_PAYLOAD_SDK=/opt/ps5-payload-sdk and re-run."; exit 1)

dashboard-files: $(DASH_RELEASE_FILES)
	@python3 tools/public_release.py elf installer

$(DASH_UI_BIN): app/eboot.elf
	@mkdir -p $(@D)
	python3 $(PS5_PAYLOAD_SDK)/samples/install_app/make_fself.py \
	  --ptype fake --paid $(DASH_AUTHID) \
	  --auth-info "$(DASH_AUTHINFO)" \
	  --app-version $(DASH_FW_VERSION) \
	  --fw-version $(DASH_FW_VERSION) \
	  $< $@

$(DASH_BUILD)/eboot.bin: $(DASH_UI_BIN)
	@mkdir -p $(@D)
	cp $< $@

$(DASH_BUILD)/sce_sys/param.json: dashboard/$(DASH_TITLE_ID)/sce_sys/param.json
	@mkdir -p $(@D)
	cp $< $@

$(DASH_BUILD)/sce_sys/param.json.system: dashboard/$(DASH_TITLE_ID)/sce_sys/param.json.system
	@mkdir -p $(@D)
	cp $< $@

$(DASH_BUILD)/sce_sys/icon0.png: assets/tostonsync_icon_512.png
	@mkdir -p $(@D)
	cp $< $@

$(DASH_INSTALL_PAYLOAD): dashboard/install_payload.c Makefile $(PS5_PAYLOAD_SDK)/target/lib/crt1.o | check-ps5-sdk
	@mkdir -p $(@D)
	$(CC) $(CFLAGS) -DTITLE_ID=\"$(DASH_TITLE_ID)\" \
	  -o $@ $< \
	  -lSceIpmi -lSceAppInstUtil -lSceUserService -lSceSystemService

dashboard-install: $(DAEMON) dashboard-files check-dashboard-tools
	@set -eu; target_env=$$($(TARGET_ENV)) || exit $$?; eval "$$target_env"; \
	  url="ftp://$$PS5_TARGET_HOST:$$PS5_TARGET_FTP_PORT"; \
	  echo "Target console: $$PS5_TARGET_NAME"; \
	  echo "Host: $$PS5_TARGET_HOST"; \
	  echo "Installing launcher + daemon; not starting or replacing the daemon."; \
	  ftp() { curl --fail --silent --show-error --connect-timeout 5 --max-time 120 "$$@"; }; \
	  mkdir_ftp() { ftp -Q "MKD $$1" "$$url/" >/dev/null 2>&1 || \
	    ftp --list-only "$$url$$1/" >/dev/null; }; \
	  ftp -Q "MTRW" "$$url/" > /dev/null; \
	  mkdir_ftp "$(PS5_DAEMON_DIR)"; \
	  ftp -T "$(DAEMON)" "$$url$(PS5_DAEMON_DIR)/tostonsync.elf.upload"; \
	  ftp -Q "RNFR $(PS5_DAEMON_DIR)/tostonsync.elf.upload" \
	      -Q "RNTO $(PS5_DAEMON_DIR)/tostonsync.elf" "$$url/" > /dev/null; \
	  mkdir_ftp "/system_ex/app/$(DASH_TITLE_ID)"; \
	  mkdir_ftp "/system_ex/app/$(DASH_TITLE_ID)/sce_sys"; \
	  mkdir_ftp "/user/app/$(DASH_TITLE_ID)"; \
	  mkdir_ftp "/user/app/$(DASH_TITLE_ID)/sce_sys"; \
	  ftp -T "$(DASH_BUILD)/eboot.bin" "$$url/system_ex/app/$(DASH_TITLE_ID)/eboot.bin"; \
	  ftp -T "$(DASH_BUILD)/sce_sys/param.json" "$$url/user/app/$(DASH_TITLE_ID)/sce_sys/param.json"; \
	  ftp -T "$(DASH_BUILD)/sce_sys/icon0.png" "$$url/user/app/$(DASH_TITLE_ID)/sce_sys/icon0.png"; \
	  $(PS5_DEPLOY) -h "$$PS5_TARGET_HOST" -p "$$PS5_TARGET_PAYLOAD_PORT" $(DASH_INSTALL_PAYLOAD); \
	  ftp -T "$(DASH_BUILD)/sce_sys/param.json.system" "$$url/system_ex/app/$(DASH_TITLE_ID)/sce_sys/param.json"; \
	  echo "Files sent. Confirm the TostónSync icon on the PS5; transport success alone is not registration proof."

daemon-install: $(DAEMON) check-ftp-tools
	@target_env=$$($(TARGET_ENV)) || exit $$?; eval "$$target_env"; \
	  url="ftp://$$PS5_TARGET_HOST:$$PS5_TARGET_FTP_PORT"; \
	  echo "Target console: $$PS5_TARGET_NAME"; \
	  echo "Host: $$PS5_TARGET_HOST"; \
	  curl -Q "MKD $(PS5_DAEMON_DIR)" "$$url" > /dev/null || true; \
	  curl -T "$(DAEMON)" "$$url$(PS5_DAEMON_DIR)/tostonsync.elf"

install-daemon: daemon-install

daemon-run: $(DAEMON) check-run-tools
	@target_env=$$($(TARGET_ENV)) || exit $$?; eval "$$target_env"; \
	  echo "Target console: $$PS5_TARGET_NAME"; \
	  echo "Host: $$PS5_TARGET_HOST"; \
	  echo "Payload port: $$PS5_TARGET_PAYLOAD_PORT"; \
	  echo "Web UI: http://$$PS5_TARGET_HOST:$$PS5_TARGET_WEB_PORT/"; \
	  echo "Note: this address may change if your router assigns a new IP."; \
	  echo "Deploying to PS5: $${PS5_TARGET_HOST}:$${PS5_TARGET_PAYLOAD_PORT}…"; \
	  $(PS5_DEPLOY) -h "$$PS5_TARGET_HOST" -p "$$PS5_TARGET_PAYLOAD_PORT" $(DAEMON); rc=$$?; \
	  if [ $$rc -eq 0 ]; then echo "Deploy complete."; \
	  elif [ $$rc -eq 130 ] || [ $$rc -eq 2 ]; then echo "TostónSync session stopped by user."; \
	  else echo "Deploy failed: could not connect to $$PS5_TARGET_HOST:$$PS5_TARGET_PAYLOAD_PORT."; \
	       echo "Check that elfldr/payload loader is running on the PS5."; \
	       echo "(run 'gmake V=1 daemon-run' for full output)"; exit 1; fi

run-daemon: daemon-run

targets:
	@python3 tools/ps5_target.py list --file "$(TARGETS_FILE)"

target-info:
	@python3 tools/ps5_target.py info --file "$(TARGETS_FILE)" --target "$(TARGET)" --host "$(PS5_HOST)" --payload-port "$(PS5_PORT)" --web-port "$(PS5_WEB_PORT)" --ftp-port "$(PS5_FTP_PORT)"

status:
	@target_env=$$($(TARGET_ENV)) || exit $$?; eval "$$target_env"; \
	  curl -fs "http://$$PS5_TARGET_HOST:$$PS5_TARGET_WEB_PORT/api/status" 2>/dev/null || \
	  { echo "TostónSync is not running at http://$$PS5_TARGET_HOST:$$PS5_TARGET_WEB_PORT/"; \
	    echo "Start it with: gmake daemon-run TARGET=$$PS5_TARGET_KEY"; exit 1; }

log:
	@target_env=$$($(TARGET_ENV)) || exit $$?; eval "$$target_env"; \
	  tmp=`mktemp "$${TMPDIR:-/tmp}/tostonsync-log.XXXXXX"`; ok=; \
	  trap 'rm -f "$$tmp"' EXIT; \
	  for i in 1 2 3 4 5; do \
	    if curl -fs "http://$$PS5_TARGET_HOST:$$PS5_TARGET_WEB_PORT/api/log" -o "$$tmp" 2>/dev/null; then ok=1; break; fi; \
	    sleep 1; \
	  done; \
	  [ "$$ok" ] || { echo "TostónSync is not running at http://$$PS5_TARGET_HOST:$$PS5_TARGET_WEB_PORT/"; \
	    echo "Start it with: gmake daemon-run TARGET=$$PS5_TARGET_KEY"; exit 1; }; \
	  tail -n 120 "$$tmp"

# --------------------------------------------------------------------
.PHONY: all clean check check-browser release release-zip public-package public-scan
all: daemon app

# Optional real-browser UI check; requires Playwright and Chrome on the host.
check-browser:
	node tests/check_security272_browser.js
	node tests/check_ui269_browser.js
	node tests/check_ux270_browser.js
	node tests/check_ux270_keyboard_browser.js
	node tests/check_action268_browser.js
	node tests/check_defects268_browser.js
	node tests/check_cancel267_browser.js
	node tests/check_release266_about_browser.js
	node tests/check_github_update_browser.js
	node tests/check_coherence_browser.js
	node tests/check_usability_browser.js
	node tests/check_usb_states_browser.js
	node tests/check_ui261_browser.js
	node tests/check_cold_ui_browser.js
	node tests/check_navigation_observation_browser.js
	node tests/check_shared_game_card_browser.js
	node tests/check_status_data_browser.js
	node tests/check_game_page_browser.js
	node tests/check_game_page_regressions_browser.js
	node tests/check_game_page_callbacks_browser.js
	node tests/check_settings_route_observation_browser.js
	node tests/check_drive_read_session_browser.js
	node tests/check_update_errors_browser.js
	node tests/check_inspection_message_browser.js
	node tests/check_games_browser.js
	node tests/check_settings_redesign_browser.js
	node tests/check_support_report_browser.js
	node tests/check_jobs_browser.js
	node tests/check_browser_flow.js
	node tests/check_public_metadata_browser.js
	node tests/check_backup_destination_browser.js
	node tests/check_cooperative_stop_browser.js
	node tests/check_individual_backup_browser.js
	node tests/check_individual_session_browser.js
	node tests/check_individual_restore_browser.js
	node tests/check_session_saves_browser.js
	node tests/check_library_clarity_browser.js
	node tests/check_drive_unified_browser.js
	node tests/check_update_file_browser.js
	node tests/check_restart_update_browser.js
	node tests/check_update_info_browser.js

check: $(SUPPORT_HEADER)
	python3 tests/check_notice268.py
	python3 tests/check_receipt268.py
	python3 tests/check_receipt_adapters268.py
	python3 tests/check_routes268.py
	python3 tests/check_errors268.py
	python3 tests/check_scratch268.py
	python3 tests/check_probe268.py
	python3 tests/check_probe_order268.py
	python3 tests/check_probe_worker268.py
	python3 tests/check_raw_readback268.py
	python3 tests/check_restore_fidelity271.py
	python3 tests/check_assertion271.py
	python3 tests/check_security272.py --mutants
	python3 tests/check_support272.py --mutants
	python3 tests/check_public_export272.py
	python3 tests/check_assertion272.py
	python3 tests/check_evidence_preservation.py
	python3 tests/check_usb_transfer267.py
	python3 tests/check_usb_probe267.py
	python3 tests/check_cancel267_capture.py
	python3 tests/check_cancel267_cleanup.py
	python3 tests/check_cancel267_http.py
	python3 tests/check_cancel267_journal.py
	python3 tests/check_cancel267_routing.py
	python3 tests/check_cancel267_individual.py
	python3 tests/check_rollback267.py
	python3 tests/check_rollback267_api.py
	node tests/check_cancel267_ui.js
	python3 tests/check_config_persistence.py
	python3 tests/check_fixture_admissions.py
	python3 tests/check_fixture_dispatch.py
	node tests/check_ui_dependencies.js
	node tests/check_fixture_normalization.js
	python3 tests/check_release266_about.py
	python3 tests/check_start_mac266.py
	python3 tests/check_release266_controller.py
	python3 tests/check_release266_tools.py
	python3 tests/check_release_verify.py
	python3 tests/check_release_http.py
	python3 tests/check_release_https.py
	python3 tests/check_github_update.py
	python3 tests/check_sign_release.py
	node tests/check_github_update_ui.js
	python3 tests/check_coherence_native.py
	python3 tests/check_usability_native.py
	python3 tests/check_license_notices.py
	node tests/check_usability_ui.js
	python3 tests/check_physical_evidence.py
	node tests/check_coherence_ui.js
	node tests/check_physical_browser_policy.js
	python3 tests/check_coherence_protected.py
	python3 tests/check_usb_volumes_protected.py
	python3 tests/check_usb_states.py
	python3 tests/check_usb_terminal_retry.py
	node tests/check_usb_states_ui.js
	node tests/check_ui261.js
	python3 tests/check_syscall_observation_protected.py
	python3 tests/test_syscall_registers.py
	python3 tests/check_syscall_constraints.py
	python3 tests/check_cold_ui_protected.py
	python3 tests/check_update_observation.py
	node tests/check_cold_ui.js
	python3 tests/check_observation_protected.py
	python3 tests/check_readonly_observers.py
	python3 tests/check_import_maintenance.py
	python3 tests/check_http_observation_routes.py
	python3 tests/check_prepared_downloads.py
	node tests/check_navigation_observation_ui.js
	python3 tests/check_shared_card_protected.py
	node tests/check_version_fixture.js
	node tests/check_shared_game_card_ui.js
	python3 tests/check_status_data_protected.py
	python3 tests/check_history_status.py
	python3 tests/check_history269.py
	python3 tests/check_config269.py
	python3 tests/check_retry269.py
	python3 tests/check_job_recovery269.py
	node tests/check_ui269.js
	node tests/check_ux270_models.js
	node tests/check_ux270_consent.js
	python3 tests/check_restore_uid270.py
	python3 tests/check_restore_uid270_rollbacks.py
	python3 tests/check_import_uid270.py
	node tests/check_restore_uid270_ui.js
	python3 tests/check_status_observation.py
	node tests/check_status_data_ui.js
	python3 tests/check_update_window_protected.py
	python3 tests/check_restart_snapshot_protected.py
	python3 tests/check_update_window.py
	python3 tests/check_update_abi_log_protected.py
	python3 tests/check_log_durable.py
	python3 tests/check_update_trace.py
	python3 tests/check_game_page_protected.py
	node tests/check_game_page_ui.js
	node tests/check_game_page_rebase.js
	python3 tests/check_update_route_diagnostics_protected.py
	python3 tests/check_update_identity_detail.py
	node tests/check_settings_route_observation_ui.js
	python3 tests/check_drive_read_session.py
	python3 tests/check_update_identity_protected.py
	python3 tests/check_update_identity.py
	python3 tests/check_capture_mount_ownership_protected.py
	python3 tests/check_savemount_ownership.py
	python3 tests/check_capture_recovery_ownership.py
	python3 tests/check_update_previous_diagnostic_protected.py
	python3 tests/check_update_previous_diagnostic.py
	node tests/check_update_errors_ui.js
	python3 tests/check_update_jobs_observation.py
	python3 tests/check_update_export_protected.py
	python3 tests/check_update_at_io.py
	python3 tests/check_export_scratch.py
	node tests/check_inspection_message_ui.js
	python3 tests/check_games_protected.py
	python3 tests/check_games_layout.py
	node tests/check_games_ui.js
	python3 tests/check_inspection_scratch_protected.py
	python3 tests/check_inspection_scratch.py
	python3 tests/check_settings_redesign_protected.py
	python3 tests/check_settings_layout.py
	node tests/check_settings_redesign_ui.js
	python3 tests/check_native_entropy_protected.py
	python3 tests/check_native_entropy.py
	python3 tests/check_boot_identity_protected.py
	python3 tests/check_boot_identity.py
	python3 tests/check_errors_support_protected.py
	node tests/errors_support_fixture.js
	node tests/check_errors_support_ui.js
	node tests/check_support_report_ui.js
	node tests/check_c2_destinations_ui.js
	python3 tests/check_jobs_protected.py
	python3 tests/check_jobs.py
	python3 tests/check_jobs_watcher.py
	python3 tests/check_jobs_http.py
	python3 tests/check_jobs_observers.py
	node tests/check_jobs_ui.js
	python3 tests/check_individual_manifest_protected.py
	python3 tests/check_individual_manifest.py
	python3 tests/check_restart_update_protected.py
	python3 tests/check_update_info_protected.py
	python3 tests/check_launcher_presence.py
	node tests/check_update_info_ui.js
	python3 tests/check_restart_update.py
	python3 tests/check_start_mac.py
	python3 tests/check_start_mac_package.py
	node tests/check_restart_update_ui.js
	python3 tests/check_update_file_protected.py
	python3 tests/check_update_file.py
	python3 tests/check_update_file_http.py
	node tests/check_update_file_ui.js
	python3 tests/check_startup_validation.py
	python3 tests/check_startup_validation_http.py
	python3 tests/check_operational_startup.py
	python3 tests/check_import_observation.py
	python3 tests/check_lifecycle.py
	python3 tests/check_cooperative_stop.py
	python3 tests/check_web_stop_shutdown.py
	python3 tests/check_cooperative_stop_protected.py
	python3 tests/check_lifecycle_inspect.py
	python3 tests/check_manual_backup_policy.py
	python3 tests/check_app_launcher.py
	python3 tests/check_startup_ui.py
	python3 tests/check_instance_reservation.py
	python3 tests/check_sdk_setup.py
	python3 tests/check_payload_runtime.py
	python3 tests/check_dashboard_install.py
	python3 tests/check_title_names.py
	python3 tests/check_public_metadata.py
	python3 tests/check_title_catalog.py
	python3 tests/check_public_artwork.py
	python3 tests/check_public_http.py
	python3 tests/check_public_cert_release.py
	python3 tests/check_public_metadata_request.py
	node tests/check_public_metadata_ui.js
	mkdir -p $(TEST_DIR)
	node tests/check_ui.js
	node tests/check_import_ui_state.js
	node tests/check_import_slot_selection.js
	node tests/check_raw_selected_ui.js
	node tests/check_container_actions_ui.js
	node tests/check_private_slot_descriptions_ui.js
	node tests/check_backup_destination_ui.js
	node tests/check_timezone_drive_225.js
	node tests/check_cooperative_stop_ui.js
	node tests/check_restore_safety.js
	node tests/check_restore_uid.js
	node tests/check_restore_users.js
	node tests/check_portable_export.js
	python3 tests/check_raw_recovery_reader.py
	python3 tests/check_raw_recovery_archive.py
	python3 tests/check_raw_recovery_controller.py
	python3 tests/check_raw_recovery_api.py
	python3 tests/check_target_check_request.py
	python3 tests/check_save_metadata.py
	python3 tests/check_save_metadata_diagnostics.py
	python3 tests/check_private_slot_descriptions.py
	python3 tests/check_save_metadata_request.py
	python3 tests/check_session_saves.py
	python3 tests/check_session_saves_watcher.py
	node tests/check_session_saves_ui.js
	python3 tests/check_save_image_hash.py
	python3 tests/check_pfs_attributes.py
	python3 tests/check_pfs_mode_trial.py
	python3 tests/check_candidate_publication.py
	python3 tests/check_candidate_publication_request.py
	python3 tests/check_savemount_publication.py
	python3 tests/check_zip_diagnostics.py
	python3 tests/check_raw_selected_export.py
	python3 tests/check_paired_capture.py
	python3 tests/check_migration_inspect_diagnostic.py
	python3 tests/check_paired_capture_reporting.py
	python3 tests/check_paired_backup.py
	python3 tests/check_raw_selected_request.py
	python3 tests/check_raw_selected_api.py
	python3 tests/check_raw_selected_contract.py
	python3 tests/check_raw_selected_transaction.py
	python3 tests/check_raw_selected_commit_guard.py
	python3 tests/check_raw_selected_preflight.py
	python3 tests/check_raw_selected_commit.py
	python3 tests/check_raw_claim_durability.py
	python3 tests/check_import_preservation.py
	python3 tests/check_rollback_transaction.py
	python3 tests/check_sdimg_expansion.py
	python3 tests/check_restore_io_failures.py
	python3 tests/check_native_restore_modes.py
	python3 tests/check_restore_selective.py
	python3 tests/check_portable_transaction.py
	python3 tests/check_restore_selection.py
	python3 tests/check_individual_library_providers.py
	python3 tests/check_individual_import_binding.py
	python3 tests/check_individual_restore_bridge.py
	python3 tests/check_individual_restore_routes.py
	node tests/check_individual_restore_ui.js
	node tests/check_library_clarity_ui.js
	node tests/check_drive_unified_ui.js
	node tests/check_drive_settings_ui.js
	python3 tests/check_individual_restore_protected.py
	python3 tests/check_target_preflight_slots.py
	python3 tests/check_target_preflight_sqlite.py
	python3 tests/check_target_preflight_guard.py
	python3 tests/check_backup_admission.py
	python3 tests/check_http_receive.py
	python3 tests/check_http_send.py
	python3 tests/check_http_context_lifetime.py
	python3 tests/check_target_selection.py
	node tests/check_import_pipeline.js
	node tests/check_import_review_cache.js
	node tests/check_audit_0598.js
	node tests/check_google_cert_release.js
	node tests/check_support.js
	PYTHONDONTWRITEBYTECODE=1 python3 tests/check_public_scan.py
	cc -std=c11 -Isrc tests/dest_dedup_harness.c src/sha256.c -o $(TEST_DIR)/dest_dedup_test
	$(TEST_DIR)/dest_dedup_test
	python3 tests/check_destination_receipts.py
	python3 tests/check_destination_copy.py
	python3 tests/check_backup_failure.py
	python3 tests/check_backup_names.py
	python3 tests/check_backup_save_names.py
	python3 tests/check_individual_destinations.py
	python3 tests/check_individual_catalog_selection.py
	python3 tests/check_individual_backup_api.py
	node tests/check_individual_backup_ui.js
	node tests/check_individual_session_ui.js
	node tests/check_ui_metadata_compact.js
	python3 tests/check_individual_backup_protected.py
	python3 tests/check_backup_timezone.py
	python3 tests/check_drive_session_presence.py
	python3 tests/check_timezone_drive_protected.py
	python3 tests/check_backup_messages.py
	python3 tests/check_backup_naming_adapter.py
	node tests/check_readable_backup_ui.js
	python3 tests/check_drive_naming.py
	python3 tests/check_destination_naming.py
	python3 tests/check_retention.py
	python3 tests/check_drive_usage.py
	python3 tests/check_drive_retention.py
	python3 tests/check_drive_catalog.py
	python3 tests/check_library_delete.py
	python3 tests/check_library_protection.py
	node tests/check_library_delete_ui.js
	node tests/check_library_catalog_ui.js
	python3 tests/check_drive_identity.py
	python3 tests/check_drive_recovery.py
	python3 tests/check_drive_lazy.py
	cc -std=c11 -Isrc tests/pem_split_harness.c -o $(TEST_DIR)/pem_split_test
	$(TEST_DIR)/pem_split_test
	cc -std=c11 -Isrc tests/resume_recovery_harness.c -o $(TEST_DIR)/resume_recovery_test
	$(TEST_DIR)/resume_recovery_test
	cc -std=c11 -D_DEFAULT_SOURCE -Isrc tests/notification_policy_harness.c \
	  src/log.c -o $(TEST_DIR)/notification_policy_test
	$(TEST_DIR)/notification_policy_test $(TEST_DIR)/notification-state
	cc -std=c11 -Isrc tests/live_cadence_harness.c -o $(TEST_DIR)/live_cadence_test
	$(TEST_DIR)/live_cadence_test
	cc -std=c11 -D_DEFAULT_SOURCE -Isrc tests/backup_job_state_harness.c \
	  src/backup_job_state.c -o $(TEST_DIR)/backup_job_state_test
	$(TEST_DIR)/backup_job_state_test $(TEST_DIR)/backup-job.state
	cc -std=c11 -D_DEFAULT_SOURCE -Isrc tests/backup_retry_harness.c \
	  src/backup_retry.c src/sha256.c -o $(TEST_DIR)/backup_retry_test
	$(TEST_DIR)/backup_retry_test $(TEST_DIR)/backup-retry.state
	python3 tests/check_backup_retry.py
	cc -std=c11 -D_DEFAULT_SOURCE -D_FILE_OFFSET_BITS=64 -Isrc \
	  tests/import_session_harness.c src/import_session.c src/restore_selection.c src/sha256.c src/lifecycle.c -pthread \
	  -o $(TEST_DIR)/import_session_test
	rm -rf $(TEST_DIR)/import-session-state
	$(TEST_DIR)/import_session_test $(TEST_DIR)/import-session-state start
	$(TEST_DIR)/import_session_test $(TEST_DIR)/import-session-state resume
	$(TEST_DIR)/import_session_test $(TEST_DIR)/import-session-state fallback
	rm -rf $(TEST_DIR)/import-session-state
	$(TEST_DIR)/import_session_test $(TEST_DIR)/import-session-state retain
	rm -rf $(TEST_DIR)/import-session-state
	$(TEST_DIR)/import_session_test $(TEST_DIR)/import-session-state recover
	rm -rf $(TEST_DIR)/import-session-state
	$(TEST_DIR)/import_session_test $(TEST_DIR)/import-session-state recover-start
	$(TEST_DIR)/import_session_test $(TEST_DIR)/import-session-state recover-interrupted
	rm -rf $(TEST_DIR)/import-session-state
	$(TEST_DIR)/import_session_test $(TEST_DIR)/import-session-state recover-checkpoint
	$(TEST_DIR)/import_session_test $(TEST_DIR)/import-session-state recover-interrupted
	rm -rf $(TEST_DIR)/import-session-state
	$(TEST_DIR)/import_session_test $(TEST_DIR)/import-session-state recover-publish-crash
	$(TEST_DIR)/import_session_test $(TEST_DIR)/import-session-state recover-interrupted
	rm -rf $(TEST_DIR)/import-session-state
	$(TEST_DIR)/import_session_test $(TEST_DIR)/import-session-state recover-success
	$(TEST_DIR)/import_session_test $(TEST_DIR)/import-session-state recover-resume
	$(TEST_DIR)/import_session_test $(TEST_DIR)/import-session-state recover-corrupt
	$(TEST_DIR)/import_session_test $(TEST_DIR)/import-session-state recover-corrupt-restart
	rm -rf $(TEST_DIR)/import-session-state
	$(TEST_DIR)/import_session_test $(TEST_DIR)/import-session-state recover-success
	$(TEST_DIR)/import_session_test $(TEST_DIR)/import-session-state recover-source-change
	$(TEST_DIR)/import_session_test $(TEST_DIR)/import-session-state recover-source-restart
	rm -rf $(TEST_DIR)/import-session-state
	$(TEST_DIR)/import_session_test $(TEST_DIR)/import-session-state recover-success
	$(TEST_DIR)/import_session_test $(TEST_DIR)/import-session-state recover-partial
	$(TEST_DIR)/import_session_test $(TEST_DIR)/import-session-state recover-partial-restart
	cc -std=c11 -Isrc tests/google_matrix_harness.c -o $(TEST_DIR)/google_matrix_test
	$(TEST_DIR)/google_matrix_test
	cc -std=c11 -D_DEFAULT_SOURCE -Isrc tests/backup_lock_harness.c \
	  -o $(TEST_DIR)/backup_lock_test
	$(TEST_DIR)/backup_lock_test $(TEST_DIR)/backup.same-title.lock
	cc -std=c11 -D_DEFAULT_SOURCE -Isrc \
	  tests/sha256_harness.c src/sha256.c -o $(TEST_DIR)/sha256_test
	$(TEST_DIR)/sha256_test
	cc -std=c11 -D_DEFAULT_SOURCE -Isrc \
	  tests/sfo_identity_harness.c src/sfo.c -o $(TEST_DIR)/sfo_identity_test
	$(TEST_DIR)/sfo_identity_test $(TEST_DIR)/param.sfo
	cc -std=c11 -D_DEFAULT_SOURCE $(HOST_TEST_FLAGS) -Isrc \
	  -DUSB_NO_BSD_STATFS -DUSB_IDENTITY_TEST \
	  -DTEST_ROOT='"$(TEST_DIR)/tostonsync_usb_mounts"' \
	  -DUSB_MOUNT_BASE='"$(TEST_DIR)/tostonsync_usb_mounts/usb"' \
	  tests/usb_harness.c src/usb.c src/jobs.c src/protect.c src/json.c src/sha256.c \
	  src/backup_names.c tests/backup_names_metadata_stub.c \
	  -o $(TEST_DIR)/usb_test
	rm -rf $(abspath $(TEST_DIR))/tostonsync_usb_mounts
	$(TEST_DIR)/usb_test
	cc -std=c11 -D_DEFAULT_SOURCE -D_FILE_OFFSET_BITS=64 -Isrc \
	  tests/zip_extract_harness.c src/zip.c src/crc32.c src/sha256.c \
	  src/third_party/puff.c -o $(TEST_DIR)/zip_test
	python3 tests/check_zip_safety.py $(TEST_DIR)/zip_test
	rm -rf $(abspath $(TEST_DIR))/tostonsync_zip_src $(abspath $(TEST_DIR))/tostonsync_zip_out $(abspath $(TEST_DIR))/tostonsync_test.zip
	mkdir -p $(abspath $(TEST_DIR))/tostonsync_zip_src/nested
	printf 'tostonsync-zip-test\n' > $(abspath $(TEST_DIR))/tostonsync_zip_src/nested/save.bin
	$(TEST_DIR)/zip_test pack $(abspath $(TEST_DIR))/tostonsync_zip_src $(abspath $(TEST_DIR))/tostonsync_test.zip
	$(TEST_DIR)/zip_test $(abspath $(TEST_DIR))/tostonsync_test.zip $(abspath $(TEST_DIR))/tostonsync_zip_out
	diff -r $(abspath $(TEST_DIR))/tostonsync_zip_src $(abspath $(TEST_DIR))/tostonsync_zip_out
	@a=`$(TEST_DIR)/zip_test packsha $(abspath $(TEST_DIR))/tostonsync_zip_src $(abspath $(TEST_DIR))/tostonsync_sha_a.zip one`; \
	 b=`$(TEST_DIR)/zip_test packsha $(abspath $(TEST_DIR))/tostonsync_zip_src $(abspath $(TEST_DIR))/tostonsync_sha_b.zip two`; \
	 test "$$a" = "$$b" || { echo "SHA fingerprint changed with manifest"; exit 1; }; \
	 printf 'uostonsync-zip-test\n' > $(abspath $(TEST_DIR))/tostonsync_zip_src/nested/save.bin; \
	 c=`$(TEST_DIR)/zip_test packsha $(abspath $(TEST_DIR))/tostonsync_zip_src $(abspath $(TEST_DIR))/tostonsync_sha_c.zip two`; \
	 test "$$a" != "$$c" || { echo "SHA fingerprint missed same-size content change"; exit 1; }; \
	 echo "ZIP SHA-256 OK: stable metadata, same-size content change detected"
	rm -rf $(TEST_DIR)/zip-sha-out
	$(TEST_DIR)/zip_test $(abspath $(TEST_DIR))/tostonsync_sha_a.zip $(TEST_DIR)/zip-sha-out
	test -f $(TEST_DIR)/zip-sha-out/PPSA00001/checksums.json
	grep -Eq '"PPSA00001/nested/save.bin": "[0-9a-f]{64}"' \
	  $(TEST_DIR)/zip-sha-out/PPSA00001/checksums.json
	@echo "ZIP per-file checksums OK"
	cc -std=c11 -D_DEFAULT_SOURCE -D_FILE_OFFSET_BITS=64 -Isrc \
	  tests/migration_inspect_harness.c src/migration_inspect.c src/paired_capture.c src/zip.c \
	  src/crc32.c src/sha256.c src/sfo.c src/json.c \
	  src/third_party/puff.c -o $(TEST_DIR)/migration_test
	$(TEST_DIR)/migration_test --plan-self-test
	$(TEST_DIR)/migration_test --checksum-self-test
	$(TEST_DIR)/migration_test --layout-self-test
	$(TEST_DIR)/migration_test --slot-limit-self-test
	rm -rf $(abspath $(TEST_DIR))/tostonsync_migration_bad $(abspath $(TEST_DIR))/tostonsync_migration_bad.zip
	mkdir -p $(abspath $(TEST_DIR))/tostonsync_migration_bad/PPSA00001/sdimg_Test
	printf 'save-data\n' > $(abspath $(TEST_DIR))/tostonsync_migration_bad/PPSA00001/sdimg_Test/data.bin
	printf '{"format":"tostonsync.migration_decrypted","title_id":"PPSA00001","source_console_name":"PS5 Test","source_console_type":"PS5 Pro","source_user_uid":"00000000","created_at_utc":"2026-07-10T00:48:17Z","created_at_epoch":1783644497}\n' \
	  > $(abspath $(TEST_DIR))/tostonsync_migration_bad/PPSA00001/manifest.json
	printf '{"PPSA00001/sdimg_Test/data.bin":"0000000000000000000000000000000000000000000000000000000000000000"}\n' \
	  > $(abspath $(TEST_DIR))/tostonsync_migration_bad/PPSA00001/checksums.json
	$(TEST_DIR)/zip_test pack $(abspath $(TEST_DIR))/tostonsync_migration_bad $(abspath $(TEST_DIR))/tostonsync_migration_bad.zip
	$(TEST_DIR)/migration_test $(abspath $(TEST_DIR))/tostonsync_migration_bad.zip 2>/dev/null | \
	  grep -q 'Backup checksum verification failed'
	$(TEST_DIR)/migration_test $(abspath $(TEST_DIR))/tostonsync_migration_bad.zip 2>/dev/null | \
	  grep -q '"source_console_name":"PS5 Test"'
	$(TEST_DIR)/migration_test $(abspath $(TEST_DIR))/tostonsync_migration_bad.zip 2>/dev/null | \
	  grep -q '"source_user_uid":"00000000"'
	rm -rf $(abspath $(TEST_DIR))/tostonsync_raw $(abspath $(TEST_DIR))/tostonsync_raw.zip
	mkdir -p $(abspath $(TEST_DIR))/tostonsync_raw/PPSA08084
	printf x > $(abspath $(TEST_DIR))/tostonsync_raw/PPSA08084/sdimg_SystemSave0
	printf x > $(abspath $(TEST_DIR))/tostonsync_raw/PPSA08084/sdimg_AutoSave0
	printf x > $(abspath $(TEST_DIR))/tostonsync_raw/PPSA08084/sdimg_ManualSave0
	printf x > $(abspath $(TEST_DIR))/tostonsync_raw/PPSA08084/sdimg_sce_bu_SystemSave0
	printf x > $(abspath $(TEST_DIR))/tostonsync_raw/PPSA08084/sdimg_sce_bu_AutoSave0
	printf x > $(abspath $(TEST_DIR))/tostonsync_raw/PPSA08084/sdimg_sce_bu_ManualSave0
	$(TEST_DIR)/zip_test pack $(abspath $(TEST_DIR))/tostonsync_raw $(abspath $(TEST_DIR))/tostonsync_raw.zip
	$(TEST_DIR)/migration_test $(abspath $(TEST_DIR))/tostonsync_raw.zip | grep -q '"raw_completeness":"complete"'
	$(TEST_DIR)/migration_test $(abspath $(TEST_DIR))/tostonsync_raw.zip | grep -q '"restore_strategy":"exact"'
	rm $(abspath $(TEST_DIR))/tostonsync_raw/PPSA08084/sdimg_sce_bu_ManualSave0 $(abspath $(TEST_DIR))/tostonsync_raw.zip
	$(TEST_DIR)/zip_test pack $(abspath $(TEST_DIR))/tostonsync_raw $(abspath $(TEST_DIR))/tostonsync_raw.zip
	$(TEST_DIR)/migration_test $(abspath $(TEST_DIR))/tostonsync_raw.zip | grep -q '"raw_completeness":"active_only_warning"'
	rm $(abspath $(TEST_DIR))/tostonsync_raw/PPSA08084/sdimg_sce_bu_SystemSave0 \
	  $(abspath $(TEST_DIR))/tostonsync_raw/PPSA08084/sdimg_sce_bu_AutoSave0 $(abspath $(TEST_DIR))/tostonsync_raw.zip
	$(TEST_DIR)/zip_test pack $(abspath $(TEST_DIR))/tostonsync_raw $(abspath $(TEST_DIR))/tostonsync_raw.zip
	$(TEST_DIR)/migration_test $(abspath $(TEST_DIR))/tostonsync_raw.zip | \
	  grep -q '"raw_completeness":"active_only_no_service_images"'

release-zip: $(DAEMON) $(CERT_BUNDLE) dashboard-files lifecycle-helpers
	@python3 tools/public_release.py release

release: bump-version
	$(MAKE) --no-print-directory release-zip

public-package: $(DAEMON) dashboard-files lifecycle-helpers
	python3 tools/public_release.py package

public-scan:
	python3 tools/public_release.py scan

clean:
	rm -rf bin build/dashboard
	$(MAKE) -C app clean PS5_PAYLOAD_SDK=$(PS5_PAYLOAD_SDK)

.PHONY: test-public
test-public:
	python3 tools/test_public.py
