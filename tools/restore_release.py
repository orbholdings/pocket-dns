#!/usr/bin/env python3
"""Restore checksum-verified prebuilt files and assemble the public download ZIP."""
import gzip
import hashlib
import json
import os
from pathlib import Path
import shutil
import zipfile

ROOT = Path(__file__).resolve().parents[1]
SOURCE_FOLDERS = ['src', 'web', 'installer', 'partitions', 'data', 'blocklist-sources', 'third-party', 'tools', 'tests']
SOURCE_FILES = ['platformio.ini', 'requirements-build.txt', 'requirements-flash.txt', 'README.md', 'LICENSE', 'CHANGES.md', 'V2_SCOPE.md', 'VERIFICATION.md']

def relative(base, value):
    path = Path(value)
    if path.is_absolute() or '..' in path.parts:
        raise ValueError('Invalid release path')
    return base / path

def assemble(release):
    for name in ['README.md', 'START_HERE.txt', 'LICENSE', 'CHANGES.md', 'VERIFICATION.md']:
        shutil.copy2(ROOT / name, release / name)
    shutil.copy2(ROOT / 'tools' / 'flash.py', release / 'flash.py')
    shutil.copy2(ROOT / 'requirements-flash.txt', release / 'requirements-flash.txt')
    shutil.copytree(ROOT / 'third-party', release / 'third-party', dirs_exist_ok=True)
    source = release / 'source'
    source.mkdir(exist_ok=True)
    for name in SOURCE_FILES:
        shutil.copy2(ROOT / name, source / name)
    for folder in SOURCE_FOLDERS:
        for path in (ROOT / folder).rglob('*'):
            if not path.is_file() or any(x in ('node_modules', '__pycache__', 'vendor-deps') for x in path.parts):
                continue
            if path.suffix not in ('.cpp', '.h', '.html', '.js', '.cjs', '.py', '.json', '.csv', '.bin', '.txt', '.md'):
                continue
            target = source / path.relative_to(ROOT)
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(path, target)
    pack = release / 'Pocket_DNS_V2_Complete_Pack.zip'
    staging = pack.with_suffix('.zip.part')
    with zipfile.ZipFile(staging, 'w', zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
        for path in sorted(release.rglob('*')):
            if path.is_file() and path not in (pack, staging) and path.name != 'SHA256SUMS.txt' and not path.name.endswith('.part'):
                archive.write(path, Path('Pocket_DNS_V2') / path.relative_to(release))
    with staging.open('rb') as stream:
        os.fsync(stream.fileno())
    os.replace(staging, pack)
    with zipfile.ZipFile(pack) as archive:
        if archive.testzip() is not None:
            raise ValueError('Download ZIP failed its CRC check')
        for name in archive.namelist():
            if 'Signing_Key' in name or 'PRIVATE_Signing_Kit' in name:
                raise ValueError('Private signing material must not be published')
    (release / 'SHA256SUMS.txt').write_text(''.join(hashlib.sha256((release / name).read_bytes()).hexdigest() + '  ' + name + '\n' for name in ['Pocket_DNS_V2_Complete_Pack.zip', 'Pocket_DNS_USB_Installer.html']))
    print('Assembled', pack.name, pack.stat().st_size, 'bytes; ZIP CRC passed.')

def main():
    prebuilt = ROOT / 'prebuilt'
    release = ROOT / 'release'
    records = json.loads((prebuilt / 'checksums.json').read_text())
    verified = []
    for record in records['files']:
        data = gzip.decompress(relative(prebuilt, record['file']).read_bytes())
        if len(data) != record['bytes'] or hashlib.sha256(data).hexdigest() != record['sha256']:
            raise ValueError('Prebuilt checksum mismatch: ' + record['path'])
        verified.append((relative(release, record['path']), data))
    for path, data in verified:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
    manifest = json.loads((release / 'manifest.json').read_text())
    if manifest['version'] != records['version']:
        raise ValueError('Release version mismatch')
    from sign_update import verify
    for layout, board in manifest['boards'].items():
        factory = relative(release, board['factory']).read_bytes()
        if len(factory) != board['bytes'] or hashlib.sha256(factory).hexdigest() != board['sha256']:
            raise ValueError('Factory checksum mismatch: ' + layout)
        verify(relative(release, board['signed_update']).read_bytes(), release / 'update_public_key.pem', board['chip'], layout, board['partition_sha256'], min_version=manifest['version_code'])
    print('Verified all prebuilt checksums and four signed update packages.')
    assemble(release)

if __name__ == '__main__':
    main()
