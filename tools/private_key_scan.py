#!/usr/bin/env python3
"""Detect actual local signing secrets without printing their bytes or fingerprints."""
import base64
import io
import os
from pathlib import Path
import stat
import zipfile

def private_patterns(directory: Path | None = None) -> tuple[bytes, ...]:
    directory = directory or Path.home() / '.tostonsync-signing'
    if not directory.exists():
        return ()
    st=directory.lstat()
    if not stat.S_ISDIR(st.st_mode) or st.st_uid!=os.getuid() or st.st_mode&0o777!=0o700:
        raise ValueError('signing directory permissions are unsafe')
    patterns=[]
    # Either key may be moved offline. If present, inspect only the known owned file.
    for role in ('primary','backup'):
        path=directory/(role+'.secret')
        if not path.exists():continue
        fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW)
        try:
            st=os.fstat(fd)
            if not stat.S_ISREG(st.st_mode) or st.st_uid!=os.getuid() or st.st_nlink!=1 or st.st_mode&0o777!=0o600 or st.st_size!=64:
                raise ValueError('signing key permissions or length are unsafe')
            data=os.read(fd,65)
            if len(data)!=64:raise ValueError('could not inspect signing key')
        finally:os.close(fd)
        for secret in (data,data[:32]):
            patterns.extend((secret,secret.hex().encode(),secret.hex().upper().encode(),base64.b64encode(secret)))
    return tuple(patterns)

def contains_private_material(data: bytes, patterns: tuple[bytes,...]) -> bool:
    return any(value in data for value in patterns)

def scan_paths(paths, directory: Path | None = None) -> list[str]:
    patterns=private_patterns(directory)
    found=[]
    for value in paths:
        path=Path(value)
        if path.stat().st_size>16*1024*1024:
            raise ValueError('privacy scan input exceeds the release size limit')
        with path.open('rb') as source:raw=source.read(16*1024*1024+1)
        if len(raw)>16*1024*1024:raise ValueError('privacy scan input exceeds the release size limit')
        leaked=contains_private_material(raw,patterns)
        if path.suffix.lower()=='.zip' or zipfile.is_zipfile(io.BytesIO(raw)):
            with zipfile.ZipFile(io.BytesIO(raw)) as archive:
                members=archive.infolist();names=[item.filename for item in members]
                if not members or len(members)>256 or len(set(names))!=len(names):
                    raise ValueError('privacy scan ZIP member inventory is invalid')
                if sum(item.file_size for item in members)>64*1024*1024:
                    raise ValueError('privacy scan ZIP exceeds the expanded size limit')
                for item in members:
                    name=item.orig_filename;mode=item.external_attr>>16
                    if (not name or '\x00' in name or '\\' in name or name.startswith('/') or
                            any(part in ('.','..','') for part in name.rstrip('/').split('/')) or
                            stat.S_IFMT(mode) not in (0,stat.S_IFREG,stat.S_IFDIR) or
                            item.flag_bits&1 or item.compress_type not in (zipfile.ZIP_STORED,zipfile.ZIP_DEFLATED) or
                            item.file_size>16*1024*1024):
                        raise ValueError('privacy scan ZIP member is unsafe or too large')
                    with archive.open(item) as source:data=source.read(16*1024*1024+1)
                    if len(data)>16*1024*1024 or len(data)!=item.file_size or zipfile.is_zipfile(io.BytesIO(data)):
                        raise ValueError('privacy scan ZIP member is incomplete or contains a nested archive')
                    leaked|=contains_private_material(data,patterns)
                    leaked|=any(part in ('.tostonsync-signing','primary.secret','backup.secret') for part in name.split('/'))
        if leaked:found.append(str(path))
    return found
