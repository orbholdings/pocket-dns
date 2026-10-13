#!/usr/bin/env python3
"""Run the existing shared-code tests and socket-engine integration tests."""
import os
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
build = ROOT / '.cache' / 'host-tests'
build.mkdir(parents=True, exist_ok=True)
includes = list((ROOT / '.cache' / 'test-deps').glob('ArduinoJson/src'))
includes += list((ROOT / '.pio' / 'libdeps').glob('*/ArduinoJson/src'))
if not includes:
    sys.exit('Install ArduinoJson 6.21.5: pio pkg install --global --storage-dir .cache/test-deps --library bblanchon/ArduinoJson@6.21.5')
flags = ['g++', '-std=c++11', '-g', '-O1', '-fsanitize=address,undefined', '-fno-omit-frame-pointer', '-fno-pie', '-no-pie', '-I' + str(ROOT / 'src'), '-I' + str(includes[0])]
environment = dict(os.environ, ASAN_OPTIONS='detect_leaks=0')
for name, extra in [('native_core', []), ('native_v2', []), ('storage_host', ['-I' + str(ROOT / 'tests' / 'mocks')]), ('engine_host', [str(ROOT / 'src' / 'dns_engine.cpp'), '-pthread'])]:
    binary = ROOT / 'tests' / 'engine_host' if name == 'engine_host' else build / name
    subprocess.run(flags + extra + [str(ROOT / 'tests' / (name + '.cpp')), '-o', str(binary)], check=True, cwd=ROOT)
    if name != 'engine_host':
        subprocess.run([str(binary)], check=True, cwd=ROOT, env=environment)
for script in ['tests/test_engine.py', 'tests/test_signed_update.py', 'tools/test_build_blocklist.py']:
    subprocess.run([sys.executable, script], check=True, cwd=ROOT, env=environment)
print('Host tests passed.')
