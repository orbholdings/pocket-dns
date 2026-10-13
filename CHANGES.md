# Pocket DNS 2.0.1

Adds an optional Buy me a coffee link to the dashboard and USB installer, public GitHub source, installation documentation and build/test automation.

# Pocket DNS V2

Replaces the blocking V1 resolver with concurrent UDP/TCP forwarding, answer caching and backup failover. Adds real Strict profile data, per-device profiles, a responsive dashboard, bounded query history, diagnostics, per-device credentials, customer-set admin passwords, A/B settings and JSON backups, restricted Home Assistant tokens, signed updates with delayed confirmation/rollback, and an embedded browser installer selecting complete images at 0x0.

Builds target classic ESP32 4 MB and ESP32-S3 4/8/16 MB, with no PSRAM. All resource limits, inherited upstream code/data licences, tests and actual hardware-test limitations are documented in README.md.

Final setup adjustment: start Wi-Fi in station mode before generating per-device setup credentials, and disable Wi-Fi sleep after mode changes.
