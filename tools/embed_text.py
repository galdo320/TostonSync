#!/usr/bin/env python3
"""Turn one small release asset into a C byte array."""

from pathlib import Path
import sys


source, target = map(Path, sys.argv[1:3])
symbol = sys.argv[3] if len(sys.argv) > 3 else "GOOGLE_CERT_BUNDLE"
guard = sys.argv[4] if len(sys.argv) > 4 else "TOSTONSYNC_GOOGLE_CERT_BUNDLE_H"
data = source.read_bytes()
rows = [
    f"// Generated from {source.as_posix()}. Do not edit.\n",
    f"#ifndef {guard}\n",
    f"#define {guard}\n",
    f"static const unsigned char {symbol}[] = {{\n",
]
for pos in range(0, len(data), 12):
    rows.append("    " + ", ".join(f"0x{b:02x}" for b in data[pos : pos + 12]) + ",\n")
rows += [
    "};\n",
    f"#define {symbol}_LEN {len(data)}u\n",
    "#endif\n",
]
target.parent.mkdir(parents=True, exist_ok=True)
target.write_text("".join(rows), encoding="ascii")
