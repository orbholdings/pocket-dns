# Pocket DNS 2.0.1 verification — 13 October 2026

All four final builds completed successfully with PlatformIO 6.1.18, Espressif32 6.12.0 and Arduino ESP32 2.0.17. No PSRAM is enabled.

| Build | App binary bytes | Program bytes | Static RAM bytes | Factory bytes |
|---|---:|---:|---:|---:|
| esp32-4mb | 971,264 | 964,693 | 110,360 | 4,194,304 |
| esp32s3-4mb | 927,360 | 926,993 | 110,472 | 4,194,304 |
| esp32s3-8mb | 927,360 | 926,993 | 110,472 | 8,388,608 |
| esp32s3-16mb | 927,360 | 926,993 | 110,472 | 16,777,216 |

Static RAM figures exclude runtime heap allocations, including the bounded DNS engine, Wi-Fi stack and temporary JSON buffers. Hardware heap headroom/throughput still needs measurement. The engine uses fixed buffers to bound query memory; hardware heap headroom still needs measurement.

Checks completed:

- Shared C++ protocol/cache/config tests: query bounds/compression-cycle rejection, positive TTL expiry, NXDOMAIN SOA minimum/remaining TTL, request ID/case restoration, option-specific requests excluded from shared cache, schema validation, rule suffix boundaries and CRC32.
- 50,000 deterministic malformed packet cases under AddressSanitizer and UndefinedBehaviorSanitizer. LeakSanitizer is disabled because this host blocks its process inspection.
- Eight integration tests of the actual C++ socket engine: blocked answers, expiry/cache reuse, backup timeout/malformed response failover, spoofed transaction ID rejection, six out-of-order concurrent requests, TCP client framing + oversized UDP truncation/upstream TCP fallback, cookie requests not cached and queue overload/recovery. Result: all pass.
- Actual A/B storage class with a simulated filesystem: interrupted writes at 43 offsets, latest-copy CRC corruption, recovery of the prior copy and same-object validation after save. Address/undefined-behaviour checks pass.
- Signed-package verification tests: valid package, wrong chip/layout/partition hash, older version, corrupted/truncated/extra payload, altered manifest and untrusted signing key. All pass. Firmware crypto uses Espressif's mbedTLS ECDSA-P256/SHA-256; the host signature tests use Python cryptography. Physical OTA crypto/rollback still needs a board test.
- Chrome Headless 132 real-browser tests: admin sign-in, pause/resume, activity quick-allow, device profile save, settings/history toggle, HA token/YAML/revoke, signed multipart upload form, Wi-Fi settings, desktop/mobile layout without horizontal overflow and JavaScript error checks.
- Installer opened directly from file://: secure context and Web Serial exposed; vendored SDK/QR scripts load; all four embedded gzip images decompress to correct length/SHA-256; chip/capacity selection accepts supported builds and rejects C3; simulated serial flash uses address 0x0, 4,194,304 bytes, full erase and a matching flash MD5; credential capture and QR display pass. No actual USB board was flashed here.
- Factory packaging checks: correct chip ID/header/DIO frequency, partition checksum and bounds, application slot fit, exact bootloader/partition/metadata/app0/app1/filesystem bytes in complete images, sorted unique 40-bit blocklist hashes, filesystem extraction matches both lists and each signed update verifies against the embedded public key.
- OTA metadata: application slot 0 is selected with sequence 3, the backup slot 1 has sequence 2, both are VALID and CRCs follow ESP-IDF's esp_rom_crc32_le(UINT32_MAX, seq, 4). Both slots contain the same initial V2 image. The packaged SDK has rollback enabled and the application supplies a strong delayed-confirmation override.

The release includes full source, manifests and data licence/source snapshots. Public artifacts exclude private signing keys and compiled Wi-Fi/admin passwords.

The final closed ZIP is tested for CRC/inventory. Public Git objects are compared with the prepared source and compressed firmware, and the release assembler rechecks decompressed SHA-256 values and all four signed update packages before publication.

Not tested here: real CP2104/native USB timing, actual setup AP/2.4 GHz Wi-Fi, router DHCP/IPv6 settings, hardware sustained throughput, physical interrupted flash/power cycles and automatic/manual rollback on silicon. Test these on Simon's WROOM-32 before selling or configuring an entire network.

V2.0.1 adds the optional Square support link. The host test runner and browser tests are portable for GitHub Actions. Source is at https://github.com/orbholdings/pocket-dns. No private signing key is committed.
