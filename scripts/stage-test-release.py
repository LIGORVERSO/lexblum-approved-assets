#!/usr/bin/env python3
"""Extract only approved TESTES asset names into runner staging; reject zip tricks.
The source ZIP can include audit/readme files; none are published as assets.
"""
import json, pathlib, re, sys, zipfile, hashlib, stat

if len(sys.argv) != 2 or not re.fullmatch(r'requests/testes/[a-z0-9._-]+\.json', sys.argv[1]):
    raise SystemExit('STAGING_REQUEST_PATH_INVALID')
request = json.loads(pathlib.Path(sys.argv[1]).read_text())
tag = request.get('tag')
if not isinstance(tag, str) or not re.fullmatch(r'[a-z0-9][a-z0-9._-]{0,80}', tag) or pathlib.Path(sys.argv[1]).name != tag+'.json':
    raise SystemExit('STAGING_TAG_INVALID')
zip_path = pathlib.Path('bundles/testes') / (tag+'.zip')
out = pathlib.Path('staging/testes') / tag
items = request.get('assets', [])
if not isinstance(items,list) or not (3 <= len(items) <= 2000):
    raise SystemExit('STAGING_MANIFEST_INVALID')
expected = {}
for item in items:
    if not isinstance(item, dict): raise SystemExit('STAGING_ITEM_INVALID')
    name, size, digest = item.get('name'), item.get('size'), item.get('sha256')
    if not isinstance(name,str) or not re.fullmatch(r'(?:[a-f0-9]{64}|(?:oga-|sdc-)?catalog\.envelope)',name):
        raise SystemExit('STAGING_ASSET_NAME_INVALID')
    if not isinstance(size,int) or not 0 < size <= 90*1024*1024 or not isinstance(digest,str) or not re.fullmatch(r'[a-f0-9]{64}',digest) or name in expected:
        raise SystemExit('STAGING_ASSET_META_INVALID')
    expected[name] = (size,digest)

if not zip_path.is_file() or zip_path.stat().st_size > 150*1024*1024:
    raise SystemExit('STAGING_ZIP_SIZE_INVALID')
with zipfile.ZipFile(zip_path) as z:
    infos = z.infolist()
    if len(infos)>2200: raise SystemExit('STAGING_ZIP_ENTRIES_EXCESSIVE')
    members = {}
    for info in infos:
        name=info.filename
        if name.startswith('release-assets/') and not name.endswith('/'):
            base=name[len('release-assets/'):]
            if base not in expected or '/' in base or '\\' in base or base in members or (info.external_attr >> 16) & 0o170000 == stat.S_IFLNK:
                raise SystemExit('STAGING_UNEXPECTED_ASSET')
            members[base]=info
    if set(members) != set(expected): raise SystemExit('STAGING_ASSET_SET_MISMATCH')
    out.mkdir(parents=True,exist_ok=True)
    for name, info in members.items():
        size,digest=expected[name]
        if info.file_size != size: raise SystemExit('STAGING_DECLARED_SIZE_MISMATCH')
        result=bytearray()
        with z.open(info) as reader:
            for chunk in iter(lambda: reader.read(65536),b''):
                result.extend(chunk)
                if len(result)>size: raise SystemExit('STAGING_ZIP_BOMB')
        if len(result)!=size or hashlib.sha256(result).hexdigest()!=digest:
            raise SystemExit('STAGING_ASSET_HASH_MISMATCH')
        path=out/name
        if path.exists(): raise SystemExit('STAGING_DESTINATION_EXISTS')
        path.write_bytes(result)
print('STAGING_MT_ZIP_VALIDATED', tag, len(members))
