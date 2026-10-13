#!/usr/bin/env python3
"""Record already built/signed release bytes for public, key-free distribution."""
from pathlib import Path
import gzip
import hashlib
import json

ROOT = Path(__file__).resolve().parents[1]
release = ROOT / 'release'
out = ROOT / 'prebuilt'
out.mkdir(exist_ok=True)
manifest = json.loads((release / 'manifest.json').read_text())
records = []
files = [release / 'manifest.json', release / 'update_public_key.pem', release / 'Pocket_DNS_USB_Installer.html']
files += sorted((release / 'firmware').rglob('*'))
for path in files:
    if not path.is_file():
        continue
    data = path.read_bytes()
    relative = path.relative_to(release)
    compressed = out / relative.with_name(relative.name + '.gz')
    compressed.parent.mkdir(parents=True, exist_ok=True)
    compressed.write_bytes(gzip.compress(data, compresslevel=9, mtime=0))
    records.append({'file': compressed.relative_to(out).as_posix(), 'path': relative.as_posix(), 'bytes': len(data), 'sha256': hashlib.sha256(data).hexdigest()})
(out / 'checksums.json').write_text(json.dumps({'version': manifest['version'], 'files': records}, indent=2) + '\n')
print('Prepared', len(records), 'verified release files for public distribution.')
