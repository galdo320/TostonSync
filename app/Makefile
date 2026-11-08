# Build the menu App eboot.
#
# Requires PS5_PAYLOAD_SDK to point at ps5-payload-dev's ps5-payload-sdk.
# (On macOS use `gmake`.)

PS5_PAYLOAD_SDK ?= /opt/ps5-payload-sdk

CC := $(PS5_PAYLOAD_SDK)/bin/prospero-clang
LD := $(PS5_PAYLOAD_SDK)/bin/prospero-lld
NATIVE_SCRIPT := $(PS5_PAYLOAD_SDK)/samples/install_app/eboot.x
.DEFAULT_GOAL := eboot.elf

.PHONY: check-sdk
check-sdk:
	@[ -x "$(CC)" ] || \
	  (echo "error: expected prospero-clang at $(CC)"; exit 1)
	@[ -x "$(LD)" ] && [ -f "$(NATIVE_SCRIPT)" ] || \
	  (echo "error: SDK native install_app linker script/tools missing"; exit 1)

TARGET := eboot.elf
SRCS   := eboot.c

NATIVE_FLAGS := -Os -Wall -Wextra -Werror -std=c11 -ffreestanding \
                -fno-builtin -fno-stack-protector

eboot.o: $(SRCS) ../src/version.h Makefile | check-sdk
	$(CC) $(CFLAGS) $(NATIVE_FLAGS) -c -o $@ $(SRCS)

# The normal SDK compiler links a payload-only CRT expecting payload_args_t.
# A dashboard process has a native entry ABI, so link our bare _start instead.
$(TARGET): eboot.o $(NATIVE_SCRIPT) | check-sdk
	$(LD) --static -T "$(NATIVE_SCRIPT)" -e _start -o $@ eboot.o

clean:
	rm -f $(TARGET) eboot.o

.PHONY: clean
