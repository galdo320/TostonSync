#!/usr/bin/env python3
"""Resolve local PS5 deploy targets for Makefile recipes."""

from __future__ import annotations

import argparse
import json
import shlex
import sys
from pathlib import Path


DEFAULT_PAYLOAD = 9021
DEFAULT_WEB = 1993
DEFAULT_FTP = 2121


def load_targets(path: Path) -> dict:
    if not path.exists():
        return {"default": None, "targets": {}}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        raise SystemExit(f"target config is invalid: {path}: {exc}") from exc
    if not isinstance(data, dict) or not isinstance(data.get("targets", {}), dict):
        raise SystemExit(f"target config is invalid: {path}")
    return data


def pick(data: dict, target: str, host: str, payload: int, web: int, ftp: int) -> dict:
    targets = data.get("targets", {})
    if host:
        return {
            "key": target or "manual",
            "name": target or "Manual PS5",
            "host": host,
            "payload_port": payload,
            "web_port": web,
            "ftp_port": ftp,
            "manual": True,
        }
    if target:
        if target not in targets:
            known = ", ".join(sorted(targets)) or "(none)"
            raise SystemExit(f"Unknown TARGET={target}. Known targets: {known}")
        item = dict(targets[target])
        item["key"] = target
        item.setdefault("name", target)
        item.setdefault("payload_port", payload)
        item.setdefault("web_port", web)
        item.setdefault("ftp_port", ftp)
        return item
    default = data.get("default")
    if len(targets) > 1 and not default:
        print("Multiple PS5 targets configured. Choose one:", file=sys.stderr)
        for key in sorted(targets):
            print(f"  gmake daemon-run TARGET={key}", file=sys.stderr)
        print("or override directly: gmake daemon-run PS5_HOST=<PS5_IP>", file=sys.stderr)
        raise SystemExit(2)
    if default:
        return pick(data, str(default), "", payload, web, ftp)
    if len(targets) == 1:
        return pick(data, next(iter(targets)), "", payload, web, ftp)
    print("No PS5 target selected.", file=sys.stderr)
    print("Use PS5_HOST=<PS5_IP> or create .tostonsync-targets.json.", file=sys.stderr)
    raise SystemExit(2)


def shell_env(item: dict) -> str:
    fields = {
        "PS5_TARGET_KEY": item.get("key", ""),
        "PS5_TARGET_NAME": item.get("name", ""),
        "PS5_TARGET_HOST": item.get("host", ""),
        "PS5_TARGET_PAYLOAD_PORT": str(item.get("payload_port", DEFAULT_PAYLOAD)),
        "PS5_TARGET_WEB_PORT": str(item.get("web_port", DEFAULT_WEB)),
        "PS5_TARGET_FTP_PORT": str(item.get("ftp_port", DEFAULT_FTP)),
    }
    return "\n".join(f"{k}={shlex.quote(v)}; export {k}" for k, v in fields.items())


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("command", choices=("list", "info", "env"))
    parser.add_argument("--file", default=".tostonsync-targets.json")
    parser.add_argument("--target", default="")
    parser.add_argument("--host", default="")
    parser.add_argument("--payload-port", type=int, default=DEFAULT_PAYLOAD)
    parser.add_argument("--web-port", type=int, default=DEFAULT_WEB)
    parser.add_argument("--ftp-port", type=int, default=DEFAULT_FTP)
    args = parser.parse_args()

    data = load_targets(Path(args.file))
    if args.command == "list":
        targets = data.get("targets", {})
        if not targets:
            print("No PS5 target profiles configured.")
            print("Use PS5_HOST=<ip> or create .tostonsync-targets.json.")
            return 0
        for key in sorted(targets):
            item = targets[key]
            print(f"{key}: {item.get('name', key)} — {item.get('host')}:{item.get('payload_port', DEFAULT_PAYLOAD)}")
        return 0

    item = pick(data, args.target, args.host, args.payload_port, args.web_port, args.ftp_port)
    if args.command == "env":
        print(shell_env(item))
    else:
        host = item.get("host", "")
        print(f"Target console: {item.get('name', item.get('key', 'PS5'))}")
        print(f"Host: {host}")
        print(f"Payload port: {item.get('payload_port', DEFAULT_PAYLOAD)}")
        print(f"Web UI: http://{host}:{item.get('web_port', DEFAULT_WEB)}/")
        print("Note: this address may change if your router assigns a new IP.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
