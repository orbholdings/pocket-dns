#!/usr/bin/env python3
from pathlib import Path
from build_blocklist import fnv,norm
root=Path(__file__).resolve().parents[1]
base=(root/'data/blocklist.bin').read_bytes();balanced={int.from_bytes(base[i:i+5],'little') for i in range(0,len(base),5)}
source=root/'blocklist-sources/hagezi-pro-mini.txt';domains={norm(s) for s in source.read_text().splitlines() if s.strip() and not s.startswith(('#','!'))}
hashes=sorted({fnv(d.encode()) for d in domains}-balanced);(root/'data/strict.bin').write_bytes(b''.join(h.to_bytes(5,'little') for h in hashes));print('Strict additions:',len(hashes))
