#!/usr/bin/env python3
"""Build and scan the allowlisted public TostónSync repository/release."""

from __future__ import annotations

import hashlib
import json
import os
import stat
import re
import shutil
import sys
import tempfile
import zipfile
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent))
from private_key_scan import private_patterns, contains_private_material


ROOT = Path.cwd()
DIST = ROOT / "dist" / "github"
PUBLIC = DIST / "TostonSync"
SUPPORT_URL = "https://ko-fi.com/galdo"
SUPPORT_QR = "assets/support/tostonsync-kofi-qr.png"

ROOT_FILES = ('Makefile', 'config.ini.example', 'autoload.txt.example', 'README.md', 'LICENSE', 'THIRD_PARTY_NOTICES.md', 'CREDITS.md', 'CHANGELOG.md', 'BUILD.md', 'QUICKSTART_MAC.md', 'Start TostónSync.command', 'SECURITY.md')
TREES = ()
TOOLS = ('embed_text.py', 'ps5_target.py', 'public_release.py', 'payload_sdk.py', 'lifecycle_helper.c', 'lifecycle_identity.py', 'check_syscall_registers.py', 'private_key_scan.py', 'release_sign.c', 'sign_release.py', 'start-tostonsync.command', 'public_source.json', 'test_public.py')
PUBLIC_DOCS = ('GOOGLE_DRIVE_CERTIFICATES.md', 'PUBLIC_METADATA_TLS.md', 'RELEASE_UPDATES_TLS.md', 'MONOCYPHER_LICENSE.md', 'SUPPORT.md', 'SAVE_COMPATIBILITY.md', 'LIFECYCLE.md', 'CERTIFICATE-TERMS.md', 'SDK-SOURCES.json', 'SDK-LICENSES.md', 'CATALOG.md')
SKIP_SUFFIXES = (".elf", ".zip", ".log", ".bak", ".tmp", ".pyc", ".o")
PRIVATE_CAPTURE_PROBE_FILES = {"check_paired_capture_probe.py"}

GITIGNORE = """/build/
/bin/
*.elf
*.zip
*.log
.DS_Store
__MACOSX/
__pycache__/
*.pyc
config.ini
/data/
certtest/
cacert*.pem
tokens.json
gdrive_tokens.json
history.json
.tostonsync-targets.json
*.bak
*.tmp
*.zip.tmp
!certs/google-we2-wr2.pem
!certs/public-metadata-roots.pem
"""

# Non-ELF members; the delivery names are derived from the current version.
ZIP_MEMBERS = {
    "README.md", "LICENSE", "THIRD_PARTY_NOTICES.md", "CREDITS.md", "CHANGELOG.md",
    "config.ini.example", "certs/google-we2-wr2.pem", "certs/public-metadata-roots.pem", "certs/release-roots.pem",
    "docs/RELEASE_UPDATES_TLS.md", "docs/MONOCYPHER_LICENSE.md",
    "docs/GOOGLE_DRIVE_CERTIFICATES.md",
    "docs/PUBLIC_METADATA_TLS.md",
    "docs/SUPPORT.md",
    "docs/SAVE_COMPATIBILITY.md",
    "docs/LIFECYCLE.md", "tools/lifecycle_identity.py",
    SUPPORT_QR,
    "dashboard/README.md",
    "dashboard/TOST10001/eboot.bin",
    "dashboard/TOST10001/sce_sys/param.json",
    "dashboard/TOST10001/sce_sys/param.json.system",
    "dashboard/TOST10001/sce_sys/icon0.png",
}


def version() -> str:
    text = (ROOT / "src" / "version.h").read_text(encoding="utf-8")
    match = re.search(r'TOSTONSYNC_VERSION\s+"([0-9.]+)"', text)
    if not match:
        raise SystemExit("public-package: cannot read src/version.h")
    return match.group(1)


def elf_name(kind: str, release_version: str | None = None) -> str:
    role = {"daemon": "", "launcher": " Launcher", "installer": " Installer",
            "inspect": " Lifecycle Inspect", "stop": " Lifecycle Stop",
            "verify": " Lifecycle Verify"}[kind]
    return f"TostonSync{role} v{release_version or version()}.elf"


def export_elf(kind: str) -> Path:
    source = ROOT / {
        "daemon": "bin/tostonsync.elf",
        "launcher": "app/eboot.elf",
        "installer": "build/dashboard/install_dashboard.elf",
        "inspect": "bin/lifecycle-inspect.elf",
        "stop": "bin/lifecycle-stop.elf",
        "verify": "bin/lifecycle-verify.elf",
    }[kind]
    target = (ROOT / "build/dashboard" if kind == "installer" else ROOT / "bin") / elf_name(kind)
    copy_file(source, target)
    return target



def export_release_elf() -> Path:
    target = ROOT / "bin" / f"TostonSync-v{version()}.elf"
    copy_file(ROOT / "bin" / "tostonsync.elf", target)
    return target

def zip_members(release_version: str | None = None) -> set[str]:
    return ZIP_MEMBERS | {
        "Start TostónSync.command", "SHA256SUMS",
        elf_name("daemon", release_version),
        "dashboard/" + elf_name("installer", release_version),
        elf_name("inspect", release_version),
        elf_name("stop", release_version),
        elf_name("verify", release_version),
    }


def is_copyable(path: Path) -> bool:
    return (path.is_file() and not path.name.startswith("._") and
            path.name != ".DS_Store" and path.name not in PRIVATE_CAPTURE_PROBE_FILES and "__pycache__" not in path.parts and
            not path.name.endswith(SKIP_SUFFIXES))


def copy_file(source: Path, target: Path) -> None:
    target.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(source, target)


def public_source_files() -> dict[str, str | None]:
    manifest = json.loads((ROOT / "tools/public_source.json").read_text())
    if not isinstance(manifest, dict) or manifest.get("schema") != 1 or not isinstance(manifest.get("files"), dict):
        raise ValueError("invalid public source allowlist")
    files = manifest["files"]
    for target, source in files.items():
        for name in (target, source):
            if name is None and target == ".gitignore":
                continue
            if (not isinstance(name, str) or not name or "\\" in name or
                    Path(name).is_absolute() or any(p in ("", ".", "..") for p in name.split("/"))):
                raise ValueError("unsafe public source path")
            if any(p in {"evidence", "build", "bin", "_ref", ".git", "tmp", "dist"} for p in Path(name).parts):
                raise ValueError("private directory in public allowlist")
            if Path(name).name in {"HANDOFF.md", "AGENTS.md", "DIARIO_DEBUG.md", "RECUPERAR_SAVE_CORRUPTO.md"}:
                raise ValueError("private document in public allowlist")
            if name.endswith(SKIP_SUFFIXES):
                raise ValueError("generated artifact in public source allowlist")
    return files


def package_source() -> None:
    # A new output directory is required; never erase a previous export.
    files = public_source_files()
    if DIST.exists():
        raise FileExistsError("public export already exists; preserve it and use a fresh stage")
    for target, source in files.items():
        if source is not None:
            p = ROOT / source
            if p.is_symlink() or not p.is_file():
                raise ValueError("public source must be a regular file: " + source)
            for parent in p.parents:
                if parent == ROOT: break
                if parent.is_symlink(): raise ValueError("linked public source parent")
    PUBLIC.mkdir(parents=True)
    for target, source in files.items():
        if source is None:
            (PUBLIC / target).write_text(GITIGNORE, encoding="utf-8")
            (PUBLIC / target).chmod(0o644)
        else:
            copy_file(ROOT / source, PUBLIC / target)
    verify_public_source(PUBLIC)


def verify_public_source(public: Path) -> None:
    expected = public_source_files()
    actual = set()
    directories = {str(parent) for name in expected for parent in Path(name).parents if str(parent) != "."}
    for p in public.rglob("*"):
        name = p.relative_to(public).as_posix()
        mode = p.lstat().st_mode
        if stat.S_ISDIR(mode):
            if name not in directories:
                raise ValueError("unlisted public directory: " + name)
        elif stat.S_ISREG(mode):
            actual.add(name)
        else:
            raise ValueError("unsupported public entry type: " + name)
    if actual != set(expected):
        raise ValueError("public source inventory differs")
    for target, source in expected.items():
        p = public / target
        data = GITIGNORE.encode() if source is None else (ROOT / source).read_bytes()
        if p.is_symlink() or not stat.S_ISREG(p.lstat().st_mode) or p.read_bytes() != data:
            raise ValueError("public source bytes differ: " + target)
        mode = 0o644 if source is None else stat.S_IMODE((ROOT / source).stat().st_mode)
        if stat.S_IMODE(p.stat().st_mode) != mode:
            raise ValueError("public source mode differs: " + target)


def private_identifier_findings(paths, denylist: Path) -> list[str]:
    info = denylist.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o777 != 0o600:
        raise ValueError("private identifier list permissions are unsafe")
    rules = json.loads(denylist.read_text())
    if not isinstance(rules, dict):
        raise ValueError("invalid private identifier rules")
    patterns = rules.get("patterns")
    contexts = rules.get("allowed_public_context", [])
    if not isinstance(patterns, list) or not patterns or any(not isinstance(x, str) or not x for x in patterns):
        raise ValueError("empty or invalid private identifier list")
    if not isinstance(contexts, list) or any(not isinstance(x, str) or not x for x in contexts):
        raise ValueError("invalid public context list")
    findings = []
    for path in paths:
        data = path.read_bytes()
        for text in contexts:
            data = data.replace(text.encode(), b"")
        if any(value.encode().lower() in data.lower() for value in patterns):
            findings.append(str(path))
    return findings


def package_zip(release_zip: Path, source_root: Path | None = None) -> None:
    source_root = source_root or PUBLIC
    sources = {
        "Start TostónSync.command": source_root / "Start TostónSync.command",
        elf_name("daemon"): export_elf("daemon"),
        elf_name("inspect"): export_elf("inspect"),
        elf_name("stop"): export_elf("stop"),
        elf_name("verify"): export_elf("verify"),
        "certs/release-roots.pem": source_root / "certs/release-roots.pem",
        "docs/RELEASE_UPDATES_TLS.md": source_root / "docs/RELEASE_UPDATES_TLS.md",
        "docs/MONOCYPHER_LICENSE.md": source_root / "docs/MONOCYPHER_LICENSE.md",
        "README.md": source_root / "README.md",
        "LICENSE": source_root / "LICENSE",
        "THIRD_PARTY_NOTICES.md": source_root / "THIRD_PARTY_NOTICES.md",
        "CREDITS.md": source_root / "CREDITS.md",
        "CHANGELOG.md": source_root / "CHANGELOG.md",
        "config.ini.example": source_root / "config.ini.example",
        "certs/google-we2-wr2.pem": source_root / "certs" / "google-we2-wr2.pem",
        "certs/public-metadata-roots.pem": source_root / "certs" / "public-metadata-roots.pem",
        "docs/GOOGLE_DRIVE_CERTIFICATES.md":
            source_root / "docs" / "GOOGLE_DRIVE_CERTIFICATES.md",
        "docs/PUBLIC_METADATA_TLS.md": source_root / "docs" / "PUBLIC_METADATA_TLS.md",
        "docs/SUPPORT.md": source_root / "docs" / "SUPPORT.md",
        "docs/SAVE_COMPATIBILITY.md": source_root / "docs" / "SAVE_COMPATIBILITY.md",
        "docs/LIFECYCLE.md": source_root / "docs" / "LIFECYCLE.md",
        "tools/lifecycle_identity.py": source_root / "tools" / "lifecycle_identity.py",
        SUPPORT_QR: source_root / SUPPORT_QR,
        "dashboard/README.md": source_root / "dashboard" / "README.md",
        "dashboard/TOST10001/eboot.bin":
            ROOT / "build" / "dashboard" / "TOST10001" / "eboot.bin",
        "dashboard/TOST10001/sce_sys/param.json":
            source_root / "dashboard" / "TOST10001" / "sce_sys" / "param.json",
        "dashboard/TOST10001/sce_sys/param.json.system":
            source_root / "dashboard" / "TOST10001" / "sce_sys" / "param.json.system",
        "dashboard/TOST10001/sce_sys/icon0.png":
            ROOT / "assets" / "tostonsync_icon_512.png",
        "dashboard/" + elf_name("installer"): export_elf("installer"),
    }
    with zipfile.ZipFile(release_zip, "w", zipfile.ZIP_DEFLATED) as archive:
        for name, source in sources.items():
            if name == "Start TostónSync.command":
                info = zipfile.ZipInfo.from_file(source, name)
                info.external_attr = (0o100755 << 16)
                info.compress_type = zipfile.ZIP_DEFLATED
                archive.writestr(info, source.read_bytes())
            else:
                archive.write(source, name)
        daemon = elf_name("daemon")
        checksum = hashlib.sha256(archive.read(daemon)).hexdigest()
        archive.writestr("SHA256SUMS", f"{checksum}  {daemon}\n")
    with zipfile.ZipFile(release_zip) as archive:
        if archive.testzip() is not None:
            raise SystemExit(f"release archive integrity check failed: {release_zip}")


def scan_tree(root: Path) -> list[str]:
    errors: list[str] = []
    signing_patterns = private_patterns()
    forbidden_parts = {
        "__MACOSX", "certtest", "tokens.json", "gdrive_tokens.json",
        "cacert-backup.pem", ".DS_Store", "config.ini",
        "build", "bin", ".git", ".tostonsync-targets.json",
        ".tostonsync-signing", "primary.secret", "backup.secret",
    }
    private_markers = (
        ("gal" + "do").encode(), ("private-user@" + "example.invalid").encode(),
        ("fox" + "ed").encode(), ("i" + "cloud").encode(),
        ("203.0.113." + "254").encode(),
        ("203.0.113." + "253").encode(),
        ("sof" + "rito").encode(),
        ("-----BEGIN " + "PRIVATE" + " KEY-----").encode(),
    )
    token_value = re.compile(
        rb"(?i)(?:refresh_token|access_token)[\"']?\s*[=:]\s*[\"']?"
        rb"[A-Za-z0-9._\-/]{20,}"
    )
    secret_line = re.compile(r"(?im)^\s*client_secret\s*=\s*(?P<value>\S.*)$")
    secret_quoted = re.compile(
        r'''(?i)(?P<key_quote>["'])client_secret(?P=key_quote)\s*:\s*(?P<quote>["'])(?P<value>.*?)(?P=quote)'''
    )
    default_secret = re.compile(
        r'GDRIVE_DEFAULT_CLIENT_(?:ID|SECRET)\s+"([^\"]+)"'
    )
    for path in root.rglob("*"):
        rel = path.relative_to(root)
        if path.name.startswith("._") or path.suffix.lower() == ".zip":
            errors.append(f"forbidden path: {rel}")
            continue
        if any(part in forbidden_parts for part in rel.parts):
            errors.append(f"forbidden path: {rel}")
            continue
        if not path.is_file():
            continue
        data = path.read_bytes()
        if contains_private_material(data, signing_patterns):
            errors.append(f"private signing material in {rel}")
        clean = data.replace(SUPPORT_URL.encode(), b"")
        clean = clean.replace(b"galdo320/TostonSync", b"")
        clean = clean.replace(b"Made by Galdo", b"")
        clean = clean.replace(b"Creado por Galdo", b"")
        lower = clean.lower()
        for marker in private_markers:
            if marker.lower() in lower:
                errors.append(f"forbidden text in {rel}: {marker.decode()}")
        if token_value.search(clean):
            errors.append(f"possible OAuth token value in {rel}")
        for found in re.finditer(re.escape(SUPPORT_URL.encode()), data):
            suffix = data[found.end():found.end() + 1]
            if suffix and suffix not in b"\x00'\"< >\r\n)":
                errors.append(f"data appended to support URL in {rel}")
        forbidden_support = (
            b"ko-fi_" + b"api", b"kofi_" + b"api",
            b"ko-fi-" + b"token", b"kofi_" + b"token",
            b"ko-fi_" + b"webhook", b"kofi_" + b"webhook",
            b"webhook_" + b"secret",
        )
        if any(marker in lower for marker in forbidden_support):
            errors.append(f"Ko-fi API token or webhook marker in {rel}")
        try:
            text = data.decode("utf-8")
        except UnicodeDecodeError:
            continue
        for pattern in (secret_line, secret_quoted):
            for match in pattern.finditer(text):
                value = match.group("value").strip().strip('"\'')
                if value and value != "PASTE_YOUR_CLIENT_SECRET_HERE":
                    errors.append(f"real client_secret assignment in {rel}")
        if default_secret.search(text):
            errors.append(f"embedded OAuth credential in {rel}")
    return errors


def scan(public: Path, release_zip: Path) -> None:
    if not public.is_dir() or not release_zip.is_file():
        raise SystemExit("public-scan: run gmake public-package first")
    errors = scan_tree(public)
    with zipfile.ZipFile(release_zip) as archive:
        members = archive.namelist()
        names = set(members)
        allowed = zip_members()
        if names != allowed or len(members) != len(names):
            errors.append(f"release ZIP members differ: {sorted(names ^ allowed)}")
        else:
            with tempfile.TemporaryDirectory(prefix="tostonsync-public-scan-") as tmp:
                archive.extractall(tmp)
                errors.extend(f"release ZIP: {item}" for item in scan_tree(Path(tmp)))
    if errors:
        raise SystemExit("public-scan failed:\n- " + "\n- ".join(errors))
    print("public-scan: PASS")


def digest(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def print_tree() -> None:
    print(f"{PUBLIC.name}/")
    for path in sorted(PUBLIC.rglob("*"), key=lambda item: item.as_posix()):
        rel = path.relative_to(PUBLIC)
        indent = "  " * (len(rel.parts) - 1)
        print(f"{indent}{rel.name}{'/' if path.is_dir() else ''}")


def main() -> None:
    release_zip = DIST / f"TostonSync-v{version()}.zip"
    command = sys.argv[1] if len(sys.argv) > 1 else "package"
    if command == "package":
        package_source()
        package_zip(release_zip)
        scan(PUBLIC, release_zip)
        print_tree()
        print(f"SHA-256 ELF: {digest(ROOT / 'bin' / 'tostonsync.elf')}")
        print(f"SHA-256 ZIP: {digest(release_zip)}")
        print(f"Public source: {PUBLIC}")
        print(f"Release ZIP: {release_zip}")
    elif command == "scan":
        scan(PUBLIC, release_zip)
    elif command == "release":
        if tuple(map(int, version().split('.'))) >= (0, 5, 266):
            elf = export_release_elf()
            print(f"Release ELF: {elf}")
            print(f"SHA-256 ELF: {digest(elf)}")
        else:
            release_zip = ROOT / "bin" / f"TostonSync-v{version()}.zip"
            package_zip(release_zip, ROOT)
            print(f"Release archive: {release_zip}")
            print(f"SHA-256 ZIP: {digest(release_zip)}")
    elif command == "elf" and len(sys.argv) == 3 and sys.argv[2] in {"daemon", "launcher", "installer", "inspect", "stop", "verify"}:
        print(f"ELF: {export_elf(sys.argv[2])}")
    else:
        raise SystemExit("usage: public_release.py [package|release|scan|elf daemon|elf launcher|elf installer]")


if __name__ == "__main__":
    main()
