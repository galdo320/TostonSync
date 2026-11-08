#!/usr/bin/env python3
"""Offline INSPECT JSON -> one lifecycle_ipc.h stdin frame; never sends it."""
import argparse
import json
import re
import struct
import sys

# Project-owned protocol 1 on the little-endian PS5 target, not a kernel ABI.
FRAME = struct.Struct("<8I32sqqqQ4I65s32s64s256s7x8i192s")
assert FRAME.size == 760
MODES = {"stop": 2, "verify": 3}
IDENTITY_FIELDS = {
    "pid", "start_sec", "start_usec", "module_base", "nonce", "version",
    "build", "module", "kernel_identity_known", "module_known", "process_model",
}
CHECKS = ("import_work", "recovery", "mounts", "gate", "checkpoint")
COUNTS = ("jobs", "queued", "operations")
REPORT_FIELDS = {"ok", "identity", "state", "reason", *CHECKS, *COUNTS}


def exact_fields(value, names, label):
    if not isinstance(value, dict) or value.keys() != names:
        raise ValueError(f"{label} requires exactly the protocol 1 fields")


def integer(value, low, high, label):
    if type(value) is not int or not low <= value <= high:
        raise ValueError(f"{label} must be an integer in [{low}, {high}]")
    return value


def text(value, capacity, label, allow_empty=False):
    if not isinstance(value, str) or "\0" in value or (not value and not allow_empty):
        raise ValueError(f"{label} must be a NUL-free string")
    if not allow_empty and value.lower() == "unknown":
        raise ValueError(f"{label} identity is UNKNOWN")
    encoded = value.encode("utf-8", errors="strict")
    if len(encoded) >= capacity:
        raise ValueError(f"{label} exceeds its {capacity - 1}-byte wire limit")
    return encoded


def serialize_inspect(report, command):
    """Validate a complete INSPECT result and preserve its identity exactly."""
    if command not in MODES:
        raise ValueError("command must be stop or verify")
    exact_fields(report, REPORT_FIELDS, "INSPECT result")
    if report["ok"] is not True:
        raise ValueError("INSPECT must report ok=true; BLOCKED is not identity proof")
    integer(report["state"], 0, 4, "state")
    for name in COUNTS:
        integer(report[name], 0, 2**31 - 1, name)
    for name in CHECKS:
        integer(report[name], -1, 1, name)  # UNKNOWN stays UNKNOWN, never PASS.
    text(report["reason"], 192, "reason", allow_empty=True)
    identity = report["identity"]
    exact_fields(identity, IDENTITY_FIELDS, "identity")
    if identity["kernel_identity_known"] is not True or identity["module_known"] is not True:
        raise ValueError("both kernel and module identity must be known")
    pid = integer(identity["pid"], 2, 2**31 - 1, "pid")
    sec = integer(identity["start_sec"], 1, 2**63 - 1, "start_sec")
    usec = integer(identity["start_usec"], 0, 999999, "start_usec")
    base = integer(identity["module_base"], 1, 2**64 - 1, "module_base")
    model = integer(identity["process_model"], 0, 2, "process_model")
    nonce = identity["nonce"]
    if not isinstance(nonce, str) or re.fullmatch(r"[0-9a-f]{64}", nonce) is None:
        raise ValueError("nonce must be exactly 64 lowercase hexadecimal characters")
    if not isinstance(identity["version"], str) or re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", identity["version"]) is None:
        raise ValueError("version must be a known numeric release version")
    strings = [text(identity[name], capacity, name) for name, capacity in
               (("nonce", 65), ("version", 32), ("build", 64), ("module", 256))]
    # Input snapshot fields are validated, not copied as approval. The helper
    # obtains a fresh daemon snapshot; only the exact original identity travels.
    return FRAME.pack(0x544C4946, 1, FRAME.size, MODES[command], 0, 0, 0, 0,
                      bytes(32), pid, sec, usec, base, 1, 1, model, 0,
                      *strings, *([0] * 8), bytes(192))


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON field: {key}")
        result[key] = value
    return result


def invalid_constant(value):
    raise ValueError(f"invalid JSON constant: {value}")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=MODES)
    parser.add_argument("input", nargs="?", default="-", help="INSPECT JSON file, or - for stdin")
    args = parser.parse_args()
    try:
        if args.input == "-":
            data = sys.stdin.buffer.read(8193)
        else:
            with open(args.input, "rb") as source:
                data = source.read(8193)
        if len(data) > 8192:
            raise ValueError("INSPECT JSON exceeds the 8192-byte input limit")
        report = json.loads(data.decode("utf-8"), object_pairs_hook=unique_object,
                            parse_constant=invalid_constant)
        frame = serialize_inspect(report, args.command)
    except (OSError, UnicodeError, ValueError) as error:
        parser.error(str(error))
    sys.stdout.buffer.write(frame)


if __name__ == "__main__":
    main()
