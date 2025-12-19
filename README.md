# Security Advisories Index

[Marlink Cyber](https://marlink.com/solutions/cyber-security/) identifies and responsibly discloses vulnerabilities in leading enterprise and open source software to strengthen global cybersecurity.
This index lists such security vulnerabilities discovered by [Marlink Cyber](https://marlink.com/solutions/cyber-security/).
Each entry links to its detailed advisory markdown file.

---

## Advisories

| Advisory ID | Product | Title | CVE or Reference |
|--------------|----------|----------|-----|
| MCSAID-2025-009 | [RUCKUS Network Director (RND)](https://support.ruckuswireless.com/products/156-ruckus-network-director-rnd) | Critical Security Bypass Vulnerability Leading to Remote Code Execution and Shell Access in RUCKUS Network Director (RND) | *(Pending)* [1](https://support.ruckuswireless.com/security_bulletins/334) |
| [MCSAID-2025-008](./advisories/MCSAID-2025-008-proxychains-ng-stack-buffer-overflow-proxy_from_string.md) | [proxychains-ng](https://github.com/rofl0r/proxychains-ng) | [Stack Buffer Overflow in proxy_from_string() leads to arbitrary code execution and/or crash](./advisories/MCSAID-2025-008-proxychains-ng-stack-buffer-overflow-proxy_from_string.md) | [CVE-2025-34451](https://www.cve.org/CVERecord?id=CVE-2025-34451) |
| MCSAID-2025-007 | [FreePBX](https://www.freepbx.org/) | Reserved | *(Pending)* |
| [MCSAID-2025-006](./advisories/MCSAID-2025-006-freepbx-os-command-injection.md) | [FreePBX](https://www.freepbx.org/) | [FreePBX Endpoint Manager command injection via Network Scanning feature](./advisories/MCSAID-2025-006-freepbx-os-command-injection.md) | [CVE-2025-59051](https://www.cve.org/CVERecord?id=CVE-2025-59051) |
| [MCSAID-2025-005](./advisories/MCSAID-2025-005-freepbx-reflected-xss-asterisk-http-status.md) | [FreePBX](https://www.freepbx.org/) | [FreePBX core module vulnerable to reflected cross-site scripting via Asterisk HTTP Status page](./advisories/MCSAID-2025-005-freepbx-reflected-xss-asterisk-http-status.md) | [CVE-2025-59429](https://www.cve.org/CVERecord?id=CVE-2025-59429) |
| [MCSAID-2025-004](./advisories/MCSAID-2025-004-rtl_433-rfraw-parse-overflow.md) | [rtl_433](https://github.com/merbanan/rtl_433) | [Stack-based Buffer Overflow in `parse_rfraw()` leads to arbitrary code execution and/or crash](./advisories/MCSAID-2025-004-rtl_433-rfraw-parse-overflow.md) | [CVE-2025-34450](https://www.cve.org/CVERecord?id=CVE-2025-34450) |
| [MCSAID-2025-003](./advisories/MCSAID-2025-003-scrcpy-global-buffer-overflow.md) | [scrcpy](https://github.com/Genymobile/scrcpy) | [Buffer Overflow in sc_read32be function triggered by sc_device_msg_deserialize](./advisories/MCSAID-2025-003-scrcpy-global-buffer-overflow.md) | [CVE-2025-34449](https://www.cve.org/CVERecord?id=CVE-2025-34449) |
| [MCSAID-2025-002](./advisories/MCSAID-2025-002-radare2-nullptr-deref-bin_dyldcache.md) | [radare2](https://github.com/radareorg/radare2) | [NULL Pointer Dereference in `load()` (bin_dyldcache.c) leads to DoS](./advisories/MCSAID-2025-002-radare2-nullptr-deref-bin_dyldcache.md) | [CVE-2025-63744](https://www.cve.org/CVERecord?id=CVE-2025-63744) |
| [MCSAID-2025-001](./advisories/MCSAID-2025-001-radare2-nullptr-deref-bin_ne.md) | [radare2](https://github.com/radareorg/radare2) | [NULL Pointer Dereference in `info()` (bin_ne.c) leads to DoS](./advisories/MCSAID-2025-001-radare2-nullptr-deref-bin_ne.md) | [CVE-2025-63745](https://www.cve.org/CVERecord?id=CVE-2025-63745) |

---

## Notes

- **CVE IDs** will be updated when assigned by MITRE or the respective CNA.
- Contributions of verified fixes and reproduction details are welcome.

## Vulnerability Disclosure Policy

Check out our [Vulnerability Disclosure Policy](./VULNERABILITY-DISCLOSURE-POLICY.md).

