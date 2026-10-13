Import("env")
import hashlib
from pathlib import Path
root = Path(env.subst("$PROJECT_DIR"))
out = Path(env.subst("$BUILD_DIR")) / "generated"
out.mkdir(parents=True, exist_ok=True)
layout = env.subst("$PIOENV")
csv = root / env.GetProjectOption("board_build.partitions")
chip = "esp32s3" if "s3" in layout else "esp32"
(out / "build_info.h").write_text(
    '#pragma once\n#define PDNS_VERSION "2.0.1"\n#define PDNS_VERSION_CODE 20001\n'
    f'#define PDNS_CHIP "{chip}"\n#define PDNS_LAYOUT "{layout}"\n'
    f'#define PDNS_PARTITION_SHA256 "{hashlib.sha256(csv.read_bytes()).hexdigest()}"\n')
env.Append(CPPPATH=[str(out)])
