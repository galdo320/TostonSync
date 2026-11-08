#!/usr/bin/env python3
"""Install/check the pinned upstream payload runtime; never contacts a console."""
import argparse
import hashlib
from pathlib import Path
import stat
import subprocess
import tempfile
import zipfile

ROOT = Path(__file__).resolve().parents[1]
SDK_VERSION = "0.43"
SDK_DIR = ROOT / "build" / "sdk-v0.43" / "ps5-payload-sdk"
SDK_URL = "https://github.com/ps5-payload-dev/sdk/releases/download/v0.43/ps5-payload-sdk.zip"
# Published GitHub release asset digest, verified before extracting any member.
SDK_SHA256 = "a9cc9929f21b2b2c5d5b309f3bab4997067c45281c0622cf4838b1aecba66fcb"
# CRT from that archive: includes upstream firmware 13.60 dispatch, stack
# alignment and optional payloadout support. Do not alias firmware offsets.
CRT_SHA256 = "e13ce68fcd8525df4b480a37b6239827e30998284781f4dd0cf37ec06717371a"


def digest(path):
    with path.open("rb") as file:
        return hashlib.file_digest(file, "sha256").hexdigest() if hasattr(hashlib, "file_digest") else hashlib.sha256(file.read()).hexdigest()


def check(sdk):
    crt = sdk / "target" / "lib" / "crt1.o"
    if not crt.is_file() or digest(crt) != CRT_SHA256:
        raise ValueError("unsupported/unverified payload CRT; run gmake sdk-setup (pinned SDK v0.43 with firmware 13.60 support)")
    if not (sdk / "bin" / "prospero-clang").is_file():
        raise ValueError("SDK compiler wrapper missing")
    print(f"Payload runtime OK: SDK v{SDK_VERSION}, verified CRT with 13.60 dispatch")


def install(archive=None):
    SDK_DIR.parent.parent.mkdir(parents=True, exist_ok=True)
    if SDK_DIR.exists():
        check(SDK_DIR)
        return
    # No overwrite of an existing SDK or /opt. Download is explicit, not part
    # of compilation, packaging, checks or deployment.
    with tempfile.TemporaryDirectory(prefix="sdk-setup-", dir=SDK_DIR.parent.parent) as tmp:
        temporary = Path(tmp)
        if archive is None:
            archive = temporary / "sdk.zip"
            subprocess.run(["curl", "--fail", "--location", "--show-error",
                            "--connect-timeout", "10", "--max-time", "120",
                            "--output", str(archive), SDK_URL], check=True)
        if digest(archive) != SDK_SHA256:
            raise ValueError("SDK archive checksum mismatch; nothing installed")
        with zipfile.ZipFile(archive) as bundle:
            for member in bundle.infolist():
                path = Path(member.filename)
                mode = member.external_attr >> 16
                if (path.is_absolute() or ".." in path.parts or
                        not path.parts or path.parts[0] != "ps5-payload-sdk" or
                        stat.S_ISLNK(mode)):
                    raise ValueError("unsafe SDK archive member; nothing installed")
            bundle.extractall(temporary)
            for member in bundle.infolist():
                mode = member.external_attr >> 16
                if mode & 0o111:
                    (temporary / member.filename).chmod(mode & 0o777)
        extracted = temporary / "ps5-payload-sdk"
        check(extracted)
        SDK_DIR.parent.mkdir(parents=True, exist_ok=True)
        # Directory rename fails if another setup already installed a nonempty
        # SDK; shutil.move would instead nest/mutate the existing installation.
        extracted.rename(SDK_DIR)
    print(f"Installed locally: {SDK_DIR}")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("check", "install"))
    parser.add_argument("--sdk", type=Path, default=SDK_DIR)
    parser.add_argument("--archive", type=Path)
    args = parser.parse_args()
    try:
        install(args.archive) if args.command == "install" else check(args.sdk)
    except (OSError, ValueError, zipfile.BadZipFile, subprocess.CalledProcessError) as error:
        parser.exit(1, f"payload-sdk: {error}\n")


if __name__ == "__main__":
    main()
