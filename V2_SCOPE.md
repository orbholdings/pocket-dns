# Pocket DNS V2 implementation scope

User authorised all proposed improvements on 12 October 2026.

- Concurrent bounded UDP DNS and TCP DNS (clients and upstream fallback).
- TTL-aware positive/negative answer cache; malformed response protection.
- Backup upstream resolver with local filtering retained.
- Balanced / Strict / Bypass device profiles and persistent friendly names.
- Bounded recent-query history with reasons and quick allow rules.
- Nonblocking Wi-Fi provisioning and diagnostics with router setup guidance.
- Per-device setup credentials and customer-set/changeable admin password.
- Atomic settings and rules backup/restore.
- Signed board/layout/version-checked update packages, startup health checks and rollback.
- Local Home Assistant status and filtering control using a separate revocable token.
- Offline guided browser installer that detects the chip/capacity, chooses the complete image and displays setup credentials.
- Classic ESP32 4 MB first; ESP32-S3 4/8/16 MB compiled variants where practical.

Resource limits: no PSRAM, bounded sockets/requests/cache/history. Never persist every query. No WAN admin exposure, subscription or cloud account. Physical USB/network testing still requires the user's board.

SDK finding: Arduino 2.0.17's packaged ESP32 and S3 SDKs have CONFIG_BOOTLOADER_APP_ROLLBACK_ENABLE enabled. Override verifyRollbackLater() to postpone Arduino's automatic confirmation; confirm only after application startup health checks.

Package files must be written to staging paths, closed/fsynced and renamed atomically. Use prepared Library uploads and verify materialised saved copies because the earlier direct upload produced an incomplete ZIP.
