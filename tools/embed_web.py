from pathlib import Path
import gzip
root=Path(__file__).resolve().parents[1]
parts=['#pragma once\n#include <Arduino.h>\n']
for name in ['dashboard','setup']:
 data=gzip.compress((root/'web'/f'{name}.html').read_bytes(),compresslevel=9,mtime=0)
 parts.append(f'static const uint8_t {name.upper()}_GZ[] PROGMEM = {{\n')
 parts.extend(','.join(str(v) for v in data[i:i+24])+',\n' for i in range(0,len(data),24));parts.append('};\n')
(root/'src/page.h').write_text(''.join(parts))
