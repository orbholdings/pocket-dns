# Pocket DNS 2.0.1

A small, open-source DNS ad blocker for ESP32-WROOM-32 and ESP32-S3. It runs on internal RAM and regular SPI flash, without PSRAM.

[Download the installer and firmware](https://github.com/orbholdings/pocket-dns/releases) · [Buy me a coffee](https://square.link/u/kAddgU4q)

Support is entirely optional. The Square page opens only when you choose the link; the dashboard and installer load no payment widgets or external scripts.

## Start with the USB installer

1. Extract the ZIP completely. Do not open files inside Windows' ZIP preview.
2. Open `Pocket_DNS_USB_Installer.html` in desktop Chrome or Edge.
3. Connect the board with a USB **data** cable. Close serial monitors and other flashers.
4. Click **Connect & detect board** and select the CP210x / Silicon Labs COM port for the WROOM-32. The installer detects the chip and flash capacity and selects its complete factory image.
5. Tick the factory-install acknowledgement, then click **Install complete firmware**. This replaces old firmware, Wi-Fi credentials and settings.
6. The installer verifies the written flash and reads the device's setup Wi-Fi name/password. Scan the QR or join that Wi-Fi, then open **http://192.168.4.1**.
7. Enter your home **2.4 GHz** Wi-Fi credentials and choose an admin password of 8–64 characters.
8. Reconnect your computer/phone to your normal Wi-Fi. Open the IP shown by the wizard, or `http://pocketdns.local/dashboard` if your device supports mDNS.
9. Reserve Pocket DNS's IP address in your router, and advertise it as the **LAN / DHCP DNS server**. Reconnect clients or renew their DHCP leases.

If the setup credentials do not appear, press RESET once and click **Read setup credentials**. If USB reconnects on an S3, select the newly available port. There is no universal setup password: each board generates its own and stores it in NVS. The setup password is available over the physical USB serial connection. The admin password is set by the customer.

### The earlier flashing problem

A complete `factory.bin` is written at **0x0**. An application-only binary belongs at an application partition offset. The installer chooses the complete image and address for you. On WROOM-32, the complete image is exactly **4,194,304 bytes** and contains the bootloader at 0x1000.

### Supported builds

| Board family | Detected flash | Build selected | Factory image | Application slots | Filesystem |
|---|---:|---|---:|---:|---:|
| Classic ESP32 / ESP-WROOM-32 | At least 4 MB | esp32-4mb | 4 MB | 2 × 0x150000 | 0x150000 |
| ESP32-S3 | 4 MB | esp32s3-4mb | 4 MB | 2 × 0x150000 | 0x150000 |
| ESP32-S3 | 8 MB | esp32s3-8mb | 8 MB | 2 × 0x180000 | 0x4f0000 |
| ESP32-S3 | At least 16 MB | esp32s3-16mb | 16 MB | 2 × 0x180000 | 0xcf0000 |

These builds target regular quad/SPI flash. Octal-flash modules need a different build. ESP32-C3, C6, S2 and other families are not included; do not flash another family's image. An S3 with PSRAM can still use the appropriate regular-flash build, but this firmware does not enable PSRAM. Boards with unusual pin assignments, LEDs or boot circuits need hardware-specific checking.

Classic uses DIO / 40 MHz. S3 uses DIO / 80 MHz. A classic board with more than 4 MB uses the 4 MB layout. The 4 MB build cannot store a raw 500,000-entry list alongside dual OTA slots; the larger S3 builds have more filesystem space. This release ships **123,390 Balanced entries plus 17,454 Strict additions** on every board.

## Features implemented

- Six concurrent DNS requests, bounded queues and overload recovery.
- UDP DNS plus three concurrent TCP client connections; up to two upstream TCP fallback connections. Responses up to 4,096 bytes and queries up to 1,024 bytes. Larger replies fail over or return SERVFAIL rather than being forwarded as damaged packets.
- TTL-aware positive and negative caching, 12 answers up to 1,024 bytes each. Larger valid answers are forwarded without caching. NXDOMAIN/NODATA caching honours SOA minimum TTL, and cached SOA TTLs decrease correctly. ECS/cookie/option-specific requests are not shared between clients. RD/CD/AD/DO settings are separated.
- Primary/backup resolvers with source, transaction ID and question validation. Defaults: Quad9 9.9.9.9 and 149.112.112.112. Local filtering remains active during failover.
- Balanced, Strict and Bypass device profiles; 32 persistent names/profiles; 64 active client counters. MAC identity is preferred when the neighbour table supplies it, otherwise the IP is used. MACs are not authentication credentials.
- Allow/block rules including subdomains, 200 per list within an 8 KB shared domain pool. Allow rules take priority. Rule/profile changes invalidate pending queries and the device answer cache.
- Last 48 queries with domain, reason, source IP, query type, elapsed time and transport. One-click allow. History can be disabled and cleared; it lives in RAM and is not written per query.
- Responsive local dashboard, timed pause/resume, system health, diagnostics and router setup guidance.
- Wi-Fi setup/recovery AP with a unique per-unit password generated after enabling the radio entropy source, nonblocking reconnect attempts, a customer-set admin password, salted PBKDF2-HMAC-SHA256 storage and bounded login attempts. Cookies are HttpOnly/SameSite Strict. Browser mutations require a custom request header.
- CRC-checked A/B settings snapshots; the last valid copy survives an interrupted write. JSON backup/restore includes settings, rules and profiles and excludes passwords, Wi-Fi credentials and HA tokens.
- ECDSA P-256 signed `.pdu` updates with board/layout/partition/version/size checks, streaming SHA-256 verification and inactive-slot writes. Raw `.bin` uploads are rejected by the V2 dashboard. Equal-version reinstalls are allowed; older version codes are rejected.
- Delayed OTA confirmation after 15 seconds of application startup checks. Startup failures after 45 seconds, or crashes/resets before confirmation, allow rollback. Factory images seed **both** application slots and valid OTA metadata so a recovery image is available from the first install.
- Local Home Assistant REST sensors and a filtering switch. A separate revocable bearer token permits `/api/status` and `/api/blocking` only. The dashboard generates ready-to-merge YAML.
- Self-contained browser USB installer with embedded images, chip/capacity selection, SHA-256 checks before flashing, flash MD5 verification, credential capture and Wi-Fi QR.

## Daily use and limitations

The DNS service listens on IPv4. It filters A and AAAA queries sent to that IPv4 address. Configure IPv6 DNS in your router too, or clients may bypass it. Public secondary DNS servers, VPNs, browser secure DNS and hardcoded DNS can bypass a local sinkhole. DNS blocking cannot remove ads served from the same domain as wanted content, including many video ads.

Bypass forwards to the selected upstream resolver; that resolver may have its own security filtering. “Disable DNS” rejects DNS from a device and is not a network firewall or internet-disconnect control. Clients can retain previous answers until their TTL expires after you change a rule. Query stats/history reset on reboot. Router DNS proxying can make every query appear to come from the router; advertise Pocket DNS directly through DHCP for individual profiles.

Dashboard and HA endpoints use local HTTP. Keep them on your trusted LAN and do not forward them to the internet. The small board uses bounded buffers and a single web request handler; large uploads or slow web clients can reduce DNS responsiveness. Hardware throughput and memory headroom must be measured on the actual board.

### Recovery

- During normal operation, hold **BOOT (GPIO0)** for **8 seconds** to clear Wi-Fi, passwords, HA token, settings and custom rules. Built-in blocklists remain. Release the button and use **Read setup credentials** after it restarts.
- Do not hold BOOT while applying power unless you intend to enter the ROM flash loader.
- **Firmware → Restore previous firmware** requires the other slot to contain a valid image. Rolling back firmware does not restore an older settings snapshot.
- After a signed update, wait about 30 seconds and reload the dashboard. The firmware must pass its startup checks before another OTA update.
- If both images or the filesystem are damaged, use the full USB factory installer again. This resets settings.

### Python fallback (Windows)

Install Python 3, then from the extracted pack:

```text
py -3 -m pip install -r requirements-flash.txt
py -3 flash.py --port COM5
```

Use your actual COM port. The script detects chip/flash size and checks the selected complete image. It asks for `INSTALL` before replacing the existing installation. To read credentials again:

```text
py -3 flash.py --port COM5 --read-setup
```

If there is no COM port, check the data cable and install the Silicon Labs CP210x VCP driver for your WROOM-32 board. On boards without automatic boot control, hold BOOT while pressing/releasing RESET to enter the flash loader.

## Build from source and maintain updates

The repository root contains firmware, dashboard/setup pages, partition tables, snapshot data, tooling and tests. The release ZIP also includes a `source/` copy. Dependencies are pinned in PlatformIO and the npm lockfile. Set `PLATFORMIO_SETTING_ENABLE_TELEMETRY=false` before running PlatformIO.

```text
python -m pip install -r requirements-build.txt
npm ci --prefix tools/vendor
python tools/embed_web.py
pio run -e esp32-4mb -e esp32s3-4mb -e esp32s3-8mb -e esp32s3-16mb
python tools/package_release.py --key /private/path/Pocket_DNS_Update_Signing_Key.pem
```

The separate private signing kit contains the key matching this firmware's embedded public key. **Do not include it in customer downloads or public repositories.** Keep a backup; losing it means existing devices cannot accept your future signed updates. The signer accepts a private key path explicitly. Private keys are not compiled into firmware or included in this public build pack.

For a future release, change `PDNS_VERSION` and `PDNS_VERSION_CODE` in `tools/pio_metadata.py` ; packaging reads these from each build. Alternatively use `tools/sign_update.py` with the same values. The partition SHA is generated from the exact selected CSV. A layout change requires a USB factory install. A manual firmware update does not replace built-in blocklist data. Refreshing built-in data currently requires a new factory image; automatic internet list downloads are not implemented.

`tools/build_blocklist.py` rebuilds Balanced hashes from the supplied source snapshots. Strict contains Pro Mini hashes that are not already in Balanced; `tools/build_strict.py` reproduces that difference. Blocklists are sorted little-endian 40-bit FNV-1a hashes. This saves RAM but can have rare hash collisions; it is not an exact full-domain database.

## Verification and next hardware test

See [VERIFICATION.md](VERIFICATION.md) for compiled sizes and checks. Protocol/cache/settings tests run the actual shared C++ code with AddressSanitizer and UndefinedBehaviorSanitizer; integration tests run the actual socket engine against simulated UDP/TCP upstreams. Real-browser tests exercise the dashboard and file-origin installer with simulated Web Serial. The complete ZIP and saved installer are separately read back and checked after saving.

**No ESP32 is physically attached to this build environment.** First install on your WROOM-32, confirm the setup AP appears, join home Wi-Fi, run dashboard diagnostics, then test DNS from a PC before changing your whole router. Keep this as a test build until USB, Wi-Fi, sustained query load and power-cycle/OTA rollback have been tested on real hardware.

## Sources and licensing

Firmware derives from MIT-licensed `M-Abozaid/esp32-c3-adblock` at commit `238ef7b27097e8597f39e9a5ce07a958488572a2`; its LICENSE and upstream attribution are retained. Blocklist data has separate terms, including HaGeZi GPL-3.0. Source snapshots, source URLs, notices and licences accompany the binaries. Preserve them when distributing devices or downloadable firmware. Additional library notices are in `third-party/`.

Primary technical references: [ESP-IDF OTA](https://docs.espressif.com/projects/esp-idf/en/v4.4.8/esp32/api-reference/system/ota.html), [DNS TCP RFC 7766](https://www.rfc-editor.org/rfc/rfc7766.html), [negative caching RFC 2308](https://www.rfc-editor.org/rfc/rfc2308.html), [Web Serial](https://developer.chrome.com/docs/capabilities/serial), [Home Assistant REST](https://www.home-assistant.io/integrations/rest/) and [REST switch](https://www.home-assistant.io/integrations/switch.rest/).

## Repository layout and automated checks

- `src/`, `web/`, `installer/`: firmware and local interfaces. `src/page.h` is generated by `python tools/embed_web.py`.
- `partitions/`, `data/`, `blocklist-sources/`, `third-party/`: flash layouts, reproducible blocklist snapshots, source attribution and licences.
- `tools/`, `tests/`: build, flash, signing, packaging and host tests.
- `prebuilt/`: gzip-compressed complete factory images and signed updates for this release. `python tools/restore_release.py` verifies and restores them into `release/` and makes the complete download ZIP.
- `.github/workflows/`: host tests, four-board builds and publication of verified prebuilt downloads.

Run host tests with `python tools/run_tests.py`. For browser tests install Playwright and Chromium, then run `node tests/test_ui.cjs`; `CHROME_EXECUTABLE_PATH` optionally selects an existing Chromium binary. Browser tests use simulated USB and do not prove real flashing or hardware operation.

The public repository contains the **public verification key only**. Your private signing kit stays offline. For a fork that needs its own trusted updates, generate an ECDSA P-256 key pair and replace `src/update_public_key.h` with your public key before building. Keep the matching private key outside the checkout. Devices need a factory install to change their trusted key.
