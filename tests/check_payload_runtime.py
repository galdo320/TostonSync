#!/usr/bin/env python3
"""Offline regression for the real SDK v0.43 firmware dispatcher.

Compile upstream __kernel_init on the host; mock only firmware, kernel access,
and symbol resolution. No target ELF, PS5 syscall, network, or save is executed.
Optional --elf checks the actual linked entry/dispatch with LLVM disassembly.
The pinned SDK checker separately verifies the production CRT's provenance.
"""
import argparse
import os
from pathlib import Path
import re
import shutil
import struct
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "tests/fixtures/payload_runtime_kernel_v0.43.c"

PREFIX = r'''
#include <assert.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
typedef struct {
    int (*sys_dynlib_dlsym)(int, const char*, void*);
    int* rwpipe;
    int* rwpair;
    uintptr_t kpipe_addr, kdata_base_addr;
    int* payloadout;
} payload_args_t;
static int rw_pair[2], rw_pipe[2];
static unsigned long pipe_addr;
static unsigned long KERNEL_ADDRESS_DATA_BASE, KERNEL_ADDRESS_TEXT_BASE;
static unsigned long KERNEL_ADDRESS_ALLPROC, KERNEL_ADDRESS_SECURITY_FLAGS;
static unsigned long KERNEL_ADDRESS_ROOTVNODE, KERNEL_ADDRESS_BUS_DATA_DEVICES;
static unsigned long KERNEL_OFFSET_VMSPACE_P_ROOT, KERNEL_OFFSET_VMSPACE_VM_PMAP;
static unsigned long KERNEL_ADDRESS_TARGETID, KERNEL_ADDRESS_QA_FLAGS;
static unsigned long KERNEL_ADDRESS_UTOKEN_FLAGS, KERNEL_ADDRESS_PRISON0;
static unsigned long KERNEL_ADDRESS_DMAP_BASE, KERNEL_ADDRESS_IOMMU_SOFTC;
static uint32_t firmware;
static int firmware_calls, prison_calls, dmap_calls, iommu_calls, resolve_calls;
static int fail_dmap, fail_iommu, fail_resolve;
static uint32_t kernel_get_fw_version(void) { firmware_calls++; return firmware; }
static unsigned long kernel_get_ucred_prison(int pid) {
    assert(pid == 0); prison_calls++; return 0xabc0;
}
static unsigned long kernel_find_dmap_base(void) {
    dmap_calls++; return fail_dmap ? 0 : 0xabc1;
}
static unsigned long kernel_find_iommu_softc(void) {
    iommu_calls++; return fail_iommu ? 0 : 0xabc2;
}
static int* mock_errno(void) { static int value; return &value; }
static int mock_resolve(unsigned handle) {
    resolve_calls++; assert(handle == 1 || handle == 0x2001);
    return fail_resolve == 2 ? 0 : fail_resolve == 1 ? handle == 0x2001 : 1;
}
// Darwin's errno.h already declares __error; rename only the runtime's field.
#define __error mock_error_symbol
static int* (*__error)(void);
#define KERNEL_DLSYM(handle, field) (mock_resolve(handle) ? ((field)=mock_errno, 1) : 0)
'''

SUFFIX = r'''
static const unsigned long BASE = 0x10000000;
static int pipes[2] = {10, 11}, pairs[2] = {12, 13};
static payload_args_t args;
static void prepare(uint32_t fw) {
    firmware = fw;
    firmware_calls = prison_calls = dmap_calls = iommu_calls = resolve_calls = 0;
    fail_dmap = fail_iommu = fail_resolve = 0;
    args = (payload_args_t){.rwpipe=pipes, .rwpair=pairs,
                           .kpipe_addr=0x1000, .kdata_base_addr=BASE};
    pipes[0]=10; pipes[1]=11; pairs[0]=12; pairs[1]=13;
}
static void addresses(unsigned long text, unsigned long allproc,
                      unsigned long security, unsigned long root,
                      unsigned long devices) {
    assert(KERNEL_ADDRESS_TEXT_BASE == BASE - text);
    assert(KERNEL_ADDRESS_ALLPROC == BASE + allproc);
    assert(KERNEL_ADDRESS_SECURITY_FLAGS == BASE + security);
    assert(KERNEL_ADDRESS_ROOTVNODE == BASE + root);
    assert(KERNEL_ADDRESS_BUS_DATA_DEVICES == BASE + devices);
    assert(KERNEL_OFFSET_VMSPACE_P_ROOT == 0x1d0);
    assert(KERNEL_OFFSET_VMSPACE_VM_PMAP == 0x2e8);
    assert(KERNEL_ADDRESS_TARGETID == BASE + security + 9);
    assert(KERNEL_ADDRESS_QA_FLAGS == BASE + security + 0x24);
    assert(KERNEL_ADDRESS_UTOKEN_FLAGS == BASE + security + 0x8c);
    assert(KERNEL_ADDRESS_PRISON0 == 0xabc0);
    assert(KERNEL_ADDRESS_DMAP_BASE == 0xabc1);
    assert(KERNEL_ADDRESS_IOMMU_SOFTC == 0xabc2);
    assert(firmware_calls == 1 && prison_calls == 1);
    assert(dmap_calls == 1 && iommu_calls == 1 && resolve_calls == 1);
}
int main(void) {
    prepare(0x13600000);
    if (__kernel_init(&args) != 0) {
        fputs("Runtime does not accept firmware 13.60\n", stderr);
        return 7;
    }
    addresses(0xCC0000, 0x28C9E80, 0xD9C064, 0x314B510, 0x2098228);
    prepare(0x13600001); // Revision bits must not change the firmware family.
    assert(__kernel_init(&args) == 0);
    addresses(0xCC0000, 0x28C9E80, 0xD9C064, 0x314B510, 0x2098228);
    for (uint32_t fw=0x13000000; fw<=0x13200000; fw+=0x200000) {
        prepare(fw); assert(__kernel_init(&args) == 0);
        addresses(0xCB0000, 0x28C5E00, 0xD99064, 0x3133510, 0x20981E8);
    }
    const uint32_t adjacent[] = {0x13400000, 0x13420000};
    for (unsigned i=0; i<sizeof(adjacent)/sizeof(*adjacent); i++) {
        prepare(adjacent[i]); assert(__kernel_init(&args) == 0);
        addresses(0xCB0000, 0x28C9E80, 0xD99064, 0x3137510, 0x20981E8);
    }
    const uint32_t unknown[] = {0, 0x13610000, 0x13800000, 0x14000000};
    for (unsigned i=0; i<sizeof(unknown)/sizeof(*unknown); i++) {
        prepare(unknown[i]); assert(__kernel_init(&args) == -ENOSYS);
        assert(!prison_calls && !dmap_calls && !iommu_calls && !resolve_calls);
    }
    for (unsigned i=0; i<4; i++) {
        prepare(0x13600000);
        (i<2 ? pipes : pairs)[i%2] = -1;
        assert(__kernel_init(&args) == -EBADF && !firmware_calls);
    }
    prepare(0x13600000); args.kpipe_addr=0;
    assert(__kernel_init(&args) == -EFAULT && !firmware_calls);
    prepare(0x13600000); args.kdata_base_addr=0;
    assert(__kernel_init(&args) == -EFAULT && !firmware_calls);
    prepare(0x13600000); fail_dmap=1;
    assert(__kernel_init(&args) == -ENOSYS && !iommu_calls && !resolve_calls);
    prepare(0x13600000); fail_iommu=1;
    assert(__kernel_init(&args) == -ENOSYS && !resolve_calls);
    prepare(0x13600000); fail_resolve=1;
    assert(__kernel_init(&args) == 0 && resolve_calls == 2);
    prepare(0x13600000); fail_resolve=2;
    assert(__kernel_init(&args) == -1 && resolve_calls == 2);
    puts("Payload runtime dispatch OK: real upstream 13.60 offsets, previous firmware, unknown firmware and initialization failures");
    return 0;
}
'''


def host_check(source):
    with tempfile.TemporaryDirectory(prefix="toston-runtime-") as temporary:
        binary = Path(temporary) / "runtime-check"
        subprocess.run([os.environ.get("HOST_CC", "cc"), "-std=c11", "-Wall",
                        "-Wextra", "-Werror", "-x", "c", "-", "-o", str(binary)],
                       input=PREFIX + source + SUFFIX, text=True, check=True)
        return subprocess.run([str(binary)], capture_output=True, text=True, timeout=5)


def linked_check(path, objdump):
    data = path.read_bytes()
    assert data[:6] == b"\x7fELF\x02\x01", "expected little-endian ELF64"
    assert struct.unpack_from("<H", data, 18)[0] == 62, "expected x86-64 payload"
    entry = struct.unpack_from("<Q", data, 24)[0]
    if not objdump:
        objdump = shutil.which("llvm-objdump")
        if not objdump and shutil.which("xcrun"):
            objdump = subprocess.check_output(["xcrun", "--find", "llvm-objdump"], text=True).strip()
    assert objdump, "LLVM objdump is required for the optional linked-ELF check"
    output = subprocess.check_output([objdump, "-d", "--disassemble-symbols=_start,__crt_start,__kernel_init", str(path)], text=True)
    headers = list(re.finditer(r"(?m)^([0-9a-f]+) <([^>]+)>:\n", output))
    functions = {match[2]: (int(match[1], 16), output[match.end():headers[i+1].start() if i+1<len(headers) else len(output)])
                 for i, match in enumerate(headers)}
    assert all(name in functions for name in ("_start", "__crt_start", "__kernel_init")), "old/incomplete payload CRT"
    assert functions["_start"][0] == entry, "ELF entry is not the aligned SDK entry"
    start = functions["_start"][1]
    assert re.search(r"andq\s+\$-0x10,\s*%rsp", start), "missing loader stack alignment"
    assert re.search(r"callq.*<__crt_start>", start), "entry does not call the SDK CRT"
    crt = functions["__crt_start"][1]
    assert re.search(r"callq.*<__kernel_init>", crt), "firmware dispatcher is not used by startup"
    assert re.search(r"callq.*<main>", crt), "CRT does not reach production main"
    # This complements executable source dispatch and the pinned CRT digest:
    # inspect the linked dispatch function, not a firmware string elsewhere.
    assert re.search(r"cmpl\s+\$0x13600000,.*\n.*\bj(?:e|ne)\s+0x", functions["__kernel_init"][1]), "linked firmware dispatcher lacks 13.60"
    print("Linked payload ABI OK: ELF entry aligns stack, calls CRT/firmware dispatch/main, and contains the 13.60 dispatch branch; not executed")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--elf", type=Path)
    parser.add_argument("--objdump")
    args = parser.parse_args()
    source = FIXTURE.read_text()
    result = host_check(source)
    assert result.returncode == 0, result.stdout + result.stderr
    print(result.stdout.strip())
    missing_case, count = re.subn(r"  case 0x13600000:\n.*?    break;\n", "", source, count=1, flags=re.S)
    assert count == 1
    negative = host_check(missing_case)
    assert negative.returncode == 7 and "does not accept firmware 13.60" in negative.stderr, "13.60 regression negative control did not fail"
    print("Payload runtime negative control OK: removing the real 13.60 case is rejected")
    if args.elf:
        linked_check(args.elf, args.objdump)


if __name__ == "__main__":
    main()
