#!/usr/bin/env python3
"""Prepare, verify and publish signed ELF releases; retain historical ZIP verification."""
from __future__ import annotations
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
import zipfile
from private_key_scan import scan_paths
ROOT=Path(__file__).resolve().parents[1]
REPO='galdo320/TostonSync-dev'
PRIVATE_REPO_ID='R_kgDOVM1Sqw'
PUBLIC_REPO='galdo320/TostonSync'
MAX=16*1024*1024

def digest(p):return hashlib.sha256(Path(p).read_bytes()).hexdigest()
def run(args,**kw):return subprocess.run([str(a) for a in args],check=True,**kw)
def signer(directory):
    out=directory/'release-sign'
    run(['cc','-std=c11','-D_DEFAULT_SOURCE','-Isrc','-Wall','-Wextra','-Werror','tools/release_sign.c','src/third_party/monocypher/monocypher.c','src/third_party/monocypher/monocypher-ed25519.c','-o',out],cwd=ROOT)
    return out

def embedded_keys():
    text=(ROOT/'src/release_keys.c').read_text()
    values=re.findall(r'0x([0-9a-f]{2})',text)
    if len(values)!=64:raise ValueError('embedded key inventory invalid')
    return (bytes.fromhex(''.join(values[:32])),bytes.fromhex(''.join(values[32:])))

def manifest_object(raw):
    def unique(pairs):
        out={}
        for key,value in pairs:
            if key in out:raise ValueError('manifest contains a duplicate key')
            out[key]=value
        return out
    def constant(_):raise ValueError('manifest contains a non-JSON number')
    obj=json.loads(raw.decode('utf-8'),object_pairs_hook=unique,parse_constant=constant)
    if type(obj) is dict and type(obj.get('schema')) is int and obj['schema']==3:return manifest_elf_fields(obj)
    required={'schema','version','build','min_version','asset','asset_size','asset_sha256','elf','size','sha256'}
    if type(obj) is dict and obj.get('schema')==2:required.add('notes_sha256')
    if type(obj) is not dict or set(obj)!=required or type(obj['schema']) is not int or obj['schema'] not in (1,2):
        raise ValueError('manifest schema invalid')
    for key in ('version','min_version'):
        value=obj[key]
        if type(value) is not str or len(value)>31 or not re.fullmatch(r'(0|[1-9][0-9]{0,5})\.(0|[1-9][0-9]{0,5})\.(0|[1-9][0-9]{0,5})',value):
            raise ValueError('manifest version invalid')
    if tuple(map(int,obj['min_version'].split('.')))>tuple(map(int,obj['version'].split('.'))):
        raise ValueError('minimum version exceeds release')
    if type(obj['build']) is not str or not 1<=len(obj['build'])<=63 or any(not 32<=ord(c)<=126 for c in obj['build']):
        raise ValueError('manifest build invalid')
    for key,minimum in (('size',64),('asset_size',22)):
        if type(obj[key]) is not int or not minimum<=obj[key]<=MAX:raise ValueError('manifest size invalid')
    for key in ('sha256','asset_sha256') + (('notes_sha256',) if obj['schema']==2 else ()):
        if type(obj[key]) is not str or not re.fullmatch(r'[0-9a-f]{64}',obj[key]):raise ValueError('manifest hash invalid')
    if obj['asset']!=f"TostonSync-v{obj['version']}-public.zip" or obj['elf']!=f"TostonSync v{obj['version']}.elf":
        raise ValueError('manifest asset name invalid')
    return obj

def verify(manifest,signature,archive):
    if not 0<manifest.stat().st_size<=4096 or signature.stat().st_size!=64:raise ValueError('invalid manifest or signature length')
    raw=manifest.read_bytes();signed=signature.read_bytes()
    if not 0<len(raw)<=4096 or len(signed)!=64:raise ValueError('invalid manifest or signature length')
    with tempfile.TemporaryDirectory(prefix='toston-sign-verify-') as tmp:
        d=Path(tmp);tool=signer(d);valid=False
        frozen_manifest=d/'manifest';frozen_signature=d/'signature'
        frozen_manifest.write_bytes(raw);frozen_signature.write_bytes(signed)
        for i,key in enumerate(embedded_keys()):
            p=d/f'public-{i}';p.write_bytes(key)
            result=subprocess.run([str(tool),'verify',str(p),str(frozen_manifest),str(frozen_signature)],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
            valid|=result.returncode==0
        if not valid:raise ValueError('signature does not match an embedded public key')
    obj=manifest_object(raw)
    if obj['schema'] not in (1,2):raise ValueError('ZIP verification requires historical schema 1 or 2')
    if archive.name!=obj['asset'] or not 22<=archive.stat().st_size<=MAX or archive.stat().st_size!=obj['asset_size'] or digest(archive)!=obj['asset_sha256']:raise ValueError('ZIP size/hash differs from signed manifest')
    if scan_paths([manifest,signature,archive]):raise ValueError('private signing material detected; publication refused')
    with zipfile.ZipFile(archive) as z:
        if z.comment:raise ValueError('release ZIP comments are unsupported')
        names=z.namelist()
        if len(names)!=len(set(names)) or obj['elf'] not in names or z.getinfo(obj['elf']).file_size!=obj['size'] or not 64<=obj['size']<=MAX:raise ValueError('ELF member invalid')
        payload=z.read(obj['elf'])
        if hashlib.sha256(payload).hexdigest()!=obj['sha256']:raise ValueError('ELF hash differs from signed manifest')
        marker=re.findall(rb'TOSTONSYNC_UPDATE_V1\|version=([0-9.]+)\|build=([^|\x00]+)\|END\x00',payload)
        if marker!=[(obj['version'].encode(),obj['build'].encode())]:raise ValueError('ELF marker differs from signed manifest')
    return obj

def prepare(args):
    version=re.search(r'TOSTONSYNC_VERSION "([0-9.]+)"',(ROOT/'src/version.h').read_text()).group(1)
    if not re.fullmatch(r'(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)',args.min_version):raise ValueError('minimum version invalid')
    if tuple(map(int,args.min_version.split('.')))>tuple(map(int,version.split('.'))):raise ValueError('minimum version exceeds release')
    archive=args.zip.resolve();elf=args.elf.resolve()
    if not 64<=elf.stat().st_size<=MAX or not 22<=archive.stat().st_size<=MAX:raise ValueError('B1 size cap exceeded')
    if scan_paths([elf,archive]):raise ValueError('private signing material detected; preparation refused')
    data=elf.read_bytes()
    if archive.name!=f'TostonSync-v{version}-public.zip':raise ValueError('unexpected archive name')
    marker=re.findall(rb'TOSTONSYNC_UPDATE_V1\|version=([0-9.]+)\|build=([^|\x00]+)\|END\x00',data)
    if len(marker)!=1 or marker[0][0].decode()!=version:raise ValueError('ELF version marker differs from source')
    name=f'TostonSync v{version}.elf'
    with zipfile.ZipFile(archive) as z:
        if z.namelist().count(name)!=1 or z.getinfo(name).file_size!=len(data) or z.read(name)!=data:raise ValueError('ZIP and sealed ELF differ')
    obj={'schema':1,'version':version,'build':marker[0][1].decode('ascii'),'min_version':args.min_version,'asset':archive.name,'asset_size':archive.stat().st_size,'asset_sha256':digest(archive),'elf':name,'size':len(data),'sha256':digest(elf)}
    notes=args.notes.read_bytes()
    notes.decode('utf-8')
    if len(notes)>4096 or b'\0' in notes:raise ValueError('release notes exceed the signed display contract')
    if scan_paths([args.notes]):raise ValueError('private signing material detected in notes')
    args.out.mkdir(mode=0o700,parents=True,exist_ok=False)
    manifest=args.out/'update-manifest.json';signature=args.out/'update-manifest.sig'
    with manifest.open('xb') as f:f.write((json.dumps(obj,sort_keys=True,separators=(',',':'))+'\n').encode());f.flush();os.fsync(f.fileno())
    v2=args.out/'update-manifest-v2.json';sig2=args.out/'update-manifest-v2.sig'
    with v2.open('xb') as f:
        f.write((json.dumps(obj|{'schema':2,'notes_sha256':hashlib.sha256(notes).hexdigest()},sort_keys=True,separators=(',',':'))+'\n').encode());f.flush();os.fsync(f.fileno())
    with tempfile.TemporaryDirectory(prefix='toston-sign-') as tmp:
        tool=signer(Path(tmp))
        for m,sig in ((manifest,signature),(v2,sig2)):
            run([tool,'sign',Path.home()/'.tostonsync-signing'/f'{args.key}.secret',m,sig])
    verify(manifest,signature,archive);verify(v2,sig2,archive)
    print(json.dumps({'result':'PASS_SIGNED_LOCAL','version':version,'elf_size':len(data),'elf_sha256':obj['sha256'],'zip_sha256':obj['asset_sha256']}))

def private_repo():
    data=json.loads(subprocess.check_output(['gh','repo','view',REPO,'--json','id,nameWithOwner,visibility']))
    if data.get('visibility')!='PRIVATE':raise ValueError('repository is not PRIVATE')
    if data.get('id')!=PRIVATE_REPO_ID or data.get('nameWithOwner')!=REPO:
        raise ValueError('private repository identity differs')

def source_binding(tag,commit):
    if not re.fullmatch(r'[0-9a-f]{40}',commit):raise ValueError('source commit must be an exact full commit ID')
    def git(*args):return subprocess.check_output(['git',*args],cwd=ROOT,text=True).strip()
    if git('status','--porcelain','--untracked-files=all'):raise ValueError('publication requires a clean source tree')
    if git('rev-parse','HEAD')!=commit:raise ValueError('HEAD differs from the sealed source commit')
    ref='refs/tags/'+tag
    if git('cat-file','-t',ref)!='tag':raise ValueError('release requires an annotated tag')
    if git('rev-parse',ref+'^{commit}')!=commit:raise ValueError('local tag differs from the sealed source commit')
    remote=git('ls-remote','https://github.com/'+REPO+'.git',ref,ref+'^{}')
    refs={}
    for row in remote.splitlines():
        fields=row.split()
        if len(fields)!=2 or fields[1] in refs:raise ValueError('remote tag response invalid')
        refs[fields[1]]=fields[0]
    if set(refs)!={ref,ref+'^{}'} or refs[ref]!=git('rev-parse',ref) or refs[ref+'^{}']!=commit:
        raise ValueError('remote annotated tag differs from the sealed source commit')
    for name in ('src/release_keys.c','src/version.h'):
        expected=subprocess.check_output(['git','show',commit+':'+name],cwd=ROOT)
        if expected!=(ROOT/name).read_bytes():raise ValueError('signing source differs from the sealed source commit')
    if re.search(r'TOSTONSYNC_VERSION "([0-9.]+)"',(ROOT/'src/version.h').read_text()).group(1)!=tag[1:]:
        raise ValueError('tag version differs from the sealed source')

def publish(args):
    private_repo();obj=verify(args.manifest,args.signature,args.zip);tag='v'+obj['version']
    if args.manifest.name!='update-manifest.json' or args.signature.name!='update-manifest.sig':raise ValueError('asset names invalid')
    v2=args.manifest.with_name('update-manifest-v2.json');sig2=args.signature.with_name('update-manifest-v2.sig')
    new=verify(v2,sig2,args.zip)
    if new!={**obj,'schema':2,'notes_sha256':digest(args.notes)}:raise ValueError('dual manifest or signed notes mismatch')
    if scan_paths([args.notes]):raise ValueError('private signing material detected in notes')
    source_binding(tag,args.source_commit)
    if subprocess.run(['gh','release','view',tag,'--repo',REPO],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL).returncode==0:raise ValueError('release already exists; no overwrite')
    run(['gh','release','create',tag,'--repo',REPO,'--verify-tag','--title',f'TostónSync {tag}','--notes-file',args.notes,args.zip,args.manifest,args.signature,v2,sig2])
    args.download.mkdir(mode=0o700,parents=True,exist_ok=False)
    run(['gh','release','download',tag,'--repo',REPO,'--dir',args.download,'--pattern',obj['asset'],'--pattern','update-manifest.json','--pattern','update-manifest.sig','--pattern','update-manifest-v2.json','--pattern','update-manifest-v2.sig'])
    for original in (args.zip,args.manifest,args.signature,v2,sig2):
        received=args.download/original.name
        if received.read_bytes()!=original.read_bytes():raise ValueError('download differs from signed local asset')
    verify(args.download/'update-manifest.json',args.download/'update-manifest.sig',args.download/obj['asset'])
    verify(args.download/v2.name,args.download/sig2.name,args.download/obj['asset'])
    published=json.loads(subprocess.check_output(['gh','release','view',tag,'--repo',REPO,'--json','body']))
    if type(published.get('body')) is not str or hashlib.sha256(published['body'].encode('utf-8')).hexdigest()!=new['notes_sha256']:
        raise ValueError('published release notes differ from the signed body')
    private_repo();source_binding(tag,args.source_commit)
    print(json.dumps({'result':'PASS_PUBLISHED_AND_VERIFIED','source_commit':args.source_commit,'url':f'https://github.com/{REPO}/releases/tag/{tag}','elf_size':obj['size'],'elf_sha256':obj['sha256']}))


ELF_RELEASE_MIN=(0,5,266)
ELF_MANIFEST_FIELDS={'schema','version','build','min_version','asset','asset_size','asset_sha256','notes_sha256'}

def version_tuple(value):
    if type(value) is not str or len(value)>31 or not re.fullmatch(r'(0|[1-9][0-9]{0,5})\.(0|[1-9][0-9]{0,5})\.(0|[1-9][0-9]{0,5})',value):
        raise ValueError('manifest version invalid')
    return tuple(map(int,value.split('.')))

def manifest_elf_fields(obj):
    if type(obj) is not dict or type(obj.get('schema')) is not int or obj['schema']!=3:raise ValueError('ELF manifest schema invalid')
    # Additive signed fields are compatible; new required semantics raise min_version.
    if not ELF_MANIFEST_FIELDS<=set(obj):raise ValueError('ELF manifest fields missing')
    current=version_tuple(obj['version']);minimum=version_tuple(obj['min_version'])
    if not ELF_RELEASE_MIN<=minimum<=current:raise ValueError('ELF minimum version invalid')
    if type(obj['build']) is not str or not 1<=len(obj['build'])<=63 or any(not 32<=ord(c)<=126 for c in obj['build']):
        raise ValueError('manifest build invalid')
    if type(obj['asset_size']) is not int or not 64<=obj['asset_size']<=MAX:raise ValueError('manifest size invalid')
    for key in ('asset_sha256','notes_sha256'):
        if type(obj[key]) is not str or not re.fullmatch(r'[0-9a-f]{64}',obj[key]):raise ValueError('manifest hash invalid')
    if obj['asset']!=f"TostonSync-v{obj['version']}.elf":raise ValueError('manifest asset name invalid')
    return obj

def verify_elf(manifest,signature,elf):
    if not manifest.is_file() or not signature.is_file() or not elf.is_file():raise ValueError('ELF release asset missing')
    if not 0<manifest.stat().st_size<=4096 or signature.stat().st_size!=64 or not 64<=elf.stat().st_size<=MAX:
        raise ValueError('invalid ELF, manifest or signature length')
    raw=manifest.read_bytes();signed=signature.read_bytes();payload=elf.read_bytes()
    if not 0<len(raw)<=4096 or len(signed)!=64 or not 64<=len(payload)<=MAX:raise ValueError('invalid ELF, manifest or signature length')
    with tempfile.TemporaryDirectory(prefix='toston-elf-verify-') as tmp:
        d=Path(tmp);tool=signer(d);valid=False
        frozen_manifest=d/'manifest';frozen_signature=d/'signature'
        frozen_manifest.write_bytes(raw);frozen_signature.write_bytes(signed)
        for i,key in enumerate(embedded_keys()):
            public=d/f'public-{i}';public.write_bytes(key)
            result=subprocess.run([str(tool),'verify',str(public),str(frozen_manifest),str(frozen_signature)],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
            valid|=result.returncode==0
        if not valid:raise ValueError('signature does not match an embedded public key')
    obj=manifest_object(raw)
    if obj['schema']!=3:raise ValueError('direct ELF verification requires schema 3')
    if elf.name!=obj['asset'] or len(payload)!=obj['asset_size'] or hashlib.sha256(payload).hexdigest()!=obj['asset_sha256']:
        raise ValueError('ELF size/hash differs from signed manifest')
    marker=re.findall(rb'TOSTONSYNC_UPDATE_V1\|version=([0-9.]+)\|build=([^|\x00]+)\|END\x00',payload)
    if not payload.startswith(b'\x7fELF') or marker!=[(obj['version'].encode(),obj['build'].encode())]:raise ValueError('ELF marker differs from signed manifest')
    if scan_paths([manifest,signature,elf]):raise ValueError('private signing material detected; publication refused')
    return obj

def release_notes(path,version):
    notes=path.read_bytes();text=notes.decode('utf-8')
    if len(notes)>4096 or b'\0' in notes:raise ValueError('release notes exceed the signed display contract')
    for name in ('LICENSE','THIRD_PARTY_NOTICES.md','README.md'):
        pattern=r'https://github\.com/'+re.escape(PUBLIC_REPO)+r'/blob/(?:main|v'+re.escape(version)+r'|[0-9a-f]{40})/'+re.escape(name)+r'(?=[)#?\s]|$)'
        if not re.search(pattern,text):raise ValueError('release notes missing repository link: '+name)
    if scan_paths([path]):raise ValueError('private signing material detected in notes')
    return notes

def prepare_elf(args):
    version=re.search(r'TOSTONSYNC_VERSION "([0-9.]+)"',(ROOT/'src/version.h').read_text()).group(1)
    elf=args.elf.resolve()
    if not elf.is_file() or not 64<=elf.stat().st_size<=MAX:raise ValueError('B1 size cap exceeded or ELF missing')
    if elf.name!=f'TostonSync-v{version}.elf':raise ValueError('unexpected ELF asset name')
    payload=elf.read_bytes()
    marker=re.findall(rb'TOSTONSYNC_UPDATE_V1\|version=([0-9.]+)\|build=([^|\x00]+)\|END\x00',payload)
    if not payload.startswith(b'\x7fELF') or len(marker)!=1 or marker[0][0].decode()!=version:raise ValueError('ELF version marker differs from source')
    notes=release_notes(args.notes,version)
    obj=manifest_elf_fields({'schema':3,'version':version,'build':marker[0][1].decode('ascii'),'min_version':args.min_version,
        'asset':elf.name,'asset_size':len(payload),'asset_sha256':hashlib.sha256(payload).hexdigest(),'notes_sha256':hashlib.sha256(notes).hexdigest()})
    if scan_paths([elf]):raise ValueError('private signing material detected; preparation refused')
    args.out.mkdir(mode=0o700,parents=True,exist_ok=False)
    manifest=args.out/'update-manifest.json';signature=args.out/'update-manifest.sig'
    with manifest.open('xb') as f:
        f.write((json.dumps(obj,sort_keys=True,separators=(',',':'))+'\n').encode());f.flush();os.fsync(f.fileno())
    with tempfile.TemporaryDirectory(prefix='toston-elf-sign-') as tmp:
        run([signer(Path(tmp)),'sign',Path.home()/'.tostonsync-signing'/f'{args.key}.secret',manifest,signature])
    verify_elf(manifest,signature,elf)
    print(json.dumps({'result':'PASS_SIGNED_LOCAL','schema':3,'version':version,'elf_size':obj['asset_size'],'elf_sha256':obj['asset_sha256']}))

def release_inventory(published,obj):
    if type(published) is not dict or type(published.get('body')) is not str or hashlib.sha256(published['body'].encode('utf-8')).hexdigest()!=obj['notes_sha256']:
        raise ValueError('published release notes differ from the signed body')
    assets=published.get('assets')
    expected={obj['asset']:obj['asset_size'],'update-manifest.json':None,'update-manifest.sig':64}
    if type(assets) is not list or len(assets)!=3:raise ValueError('release must contain exactly three assets; ZIPs are forbidden')
    sizes={}
    for asset in assets:
        if type(asset) is not dict or type(asset.get('name')) is not str or type(asset.get('size')) is not int or asset['name'] in sizes:
            raise ValueError('release asset inventory invalid')
        sizes[asset['name']]=asset['size']
    if set(sizes)!=set(expected) or any(size is not None and sizes[name]!=size for name,size in expected.items()):
        raise ValueError('release asset inventory differs from signed ELF release')
    return sizes

def publish_elf(args):
    private_repo();obj=verify_elf(args.manifest,args.signature,args.elf);tag='v'+obj['version']
    if args.manifest.name!='update-manifest.json' or args.signature.name!='update-manifest.sig':raise ValueError('asset names invalid')
    if hashlib.sha256(release_notes(args.notes,obj['version'])).hexdigest()!=obj['notes_sha256']:raise ValueError('signed notes mismatch')
    if args.download.exists():raise ValueError('download directory already exists; no overwrite')
    if subprocess.check_output(['git','branch','--show-current'],cwd=ROOT,text=True).strip()!='main':raise ValueError('publication requires main')
    source_binding(tag,args.source_commit)
    existing=subprocess.run(['gh','release','view',tag,'--repo',REPO],capture_output=True,text=True)
    if existing.returncode==0:raise ValueError('release already exists; no overwrite')
    if existing.returncode!=1 or not re.search(r'release not found|HTTP 404',existing.stderr or '',re.I):raise ValueError('release absence not established; no publication')
    run(['gh','release','create',tag,'--repo',REPO,'--verify-tag','--title',f'TostónSync {tag}','--notes-file',args.notes,args.elf,args.manifest,args.signature])
    args.download.mkdir(mode=0o700,parents=True,exist_ok=False)
    run(['gh','release','download',tag,'--repo',REPO,'--dir',args.download,'--pattern',obj['asset'],'--pattern','update-manifest.json','--pattern','update-manifest.sig'])
    for original in (args.elf,args.manifest,args.signature):
        if (args.download/original.name).read_bytes()!=original.read_bytes():raise ValueError('download differs from signed local asset')
    verify_elf(args.download/'update-manifest.json',args.download/'update-manifest.sig',args.download/obj['asset'])
    published=json.loads(subprocess.check_output(['gh','release','view',tag,'--repo',REPO,'--json','body,assets']))
    sizes=release_inventory(published,obj)
    if sizes['update-manifest.json']!=args.manifest.stat().st_size:raise ValueError('manifest asset size differs from signed local release')
    private_repo()
    if subprocess.check_output(['git','branch','--show-current'],cwd=ROOT,text=True).strip()!='main':raise ValueError('publication requires main')
    source_binding(tag,args.source_commit)
    print(json.dumps({'result':'PASS_PUBLISHED_AND_VERIFIED','schema':3,'source_commit':args.source_commit,'url':f'https://github.com/{REPO}/releases/tag/{tag}',
        'elf_size':obj['asset_size'],'elf_sha256':obj['asset_sha256'],'assets':sorted(sizes)}))

def main():
    p=argparse.ArgumentParser();sub=p.add_subparsers(dest='action',required=True)
    a=sub.add_parser('prepare');a.add_argument('--elf',type=Path,required=True);a.add_argument('--out',type=Path,required=True);a.add_argument('--min-version',default='0.5.266');a.add_argument('--key',choices=('primary','backup'),default='primary');a.add_argument('--notes',type=Path,required=True)
    a=sub.add_parser('verify');asset=a.add_mutually_exclusive_group(required=True);asset.add_argument('--elf',type=Path);asset.add_argument('--zip',type=Path,help='historical schema-1/2 ZIP verification only');a.add_argument('--manifest',type=Path,required=True);a.add_argument('--signature',type=Path,required=True)
    a=sub.add_parser('publish');a.add_argument('--elf',type=Path,required=True);a.add_argument('--manifest',type=Path,required=True);a.add_argument('--signature',type=Path,required=True);a.add_argument('--notes',type=Path,required=True);a.add_argument('--download',type=Path,required=True);a.add_argument('--source-commit',required=True)
    args=p.parse_args()
    if args.action=='prepare':prepare_elf(args)
    elif args.action=='publish':publish_elf(args)
    else:print(json.dumps({'result':'PASS_SIGNATURE_AND_ASSETS',**(verify_elf(args.manifest,args.signature,args.elf) if args.elf else verify(args.manifest,args.signature,args.zip))}))
if __name__=='__main__':main()
