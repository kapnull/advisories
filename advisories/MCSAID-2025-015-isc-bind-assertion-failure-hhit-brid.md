# ISC BIND: Assertion Failure in HHIT/BRID leads to Denial of Service

- **Advisory ID:** MCSAID-2025-015
- **CVE ID:** [https://www.cve.org/CVERecord?id=CVE-2025-13878](CVE-2025-13878)
- **Reported:** 2025-11-01
- **Published:** 2026-01-21
- **Severity:** High (CVSS 7.5)
- **Vulnerability type:** Denial of Service (DoS), Service crash
- **Current state:** Fix/Patch released by vendor
- **Exploitation:** Easy, not seen in the wild
- **Software:** [ISC BIND](https://www.isc.org/bind/)
- **CWE:** [CWE-617: Reachable Assertion](https://cwe.mitre.org/data/definitions/617.html)
- **Discovered by:** Vlatko Kosturjak of Marlink Cyber

---

## Summary

Two malformed DNS resource record types - **HHIT** (type 67) and **BRID** (type 68) - trigger an assertion in BIND’s `dns_rdata_towire()` when the RDATA length is less than three octets. The assertion aborts the `named` daemon, causing an immediate denial‑of‑service (DoS) condition.

The flaw is exploitable remotely in both forwarding and recursive modes; the attacker only needs to cause the server to process a crafted DNS message containing an undersized HHIT or BRID RR.

---

## Affected Versions

| BIND Version | Status |
|---------------|--------|
| 9.18.43 and earlier (9.18.40‑9.18.43, 9.18.40‑S1‑9.18.43‑S1) | Vulnerable |
| 9.20.17 and earlier (9.20.13‑9.20.17, 9.20.13‑S1‑9.20.17‑S1) | Vulnerable |
| 9.21.16 and earlier (9.21.12‑9.21.16) | Vulnerable |
| 9.18.44 and later (including 9.18.44‑S1) | Fixed |
| 9.20.18 and later (including 9.20.18‑S1) | Fixed |
| 9.21.17 and later | Fixed |

---

## Impact

The identified flaw allows a remote attacker to cause a denial‑of‑service (DoS) condition by crashing the BIND service. This disruption can have significant operational impact, as DNS resolution is a critical dependency for most Internet and enterprise services.

---

## Exploitation

Exploitation is easy: an attacker only needs to trigger the server to process a DNS message containing an undersized HHIT or BRID RR. Current analysis indicates that arbitrary code execution is not feasible; the impact is limited to service interruption resulting from the crash.

---

## Details

The assertion originates from the `REQUIRE(rdata->length >= 3)` guard in the `towire_hhit()` and `towire_brid()` functions within `lib/dns/rdata/generic/`. When the length is 2 or less, the guard triggers an abort, terminating `named`. The problem is triggered by any malformed RR in either recursive or forwarding mode.

The flaw is part of the IETF DRIP Entity Tags implementation in ISC BIND.

---

## Indicators

**On host:**

- Crashing of BIND/DNS service

- Assert failures of BIND
  - `rdata/generic/brid_68.c:87: REQUIRE(rdata->length >= 3) failed`
  - `rdata/generic/hhit_67.c:87: REQUIRE(rdata->length >= 3) failed`

**On network:**

- DNS resource record types HHIT (type 67) and BRID (type 68) with RDATA length less than three octets.

---

## Recommendations

If you are running affected versions of ISC BIND, upgrade to the following fixed versions:

- 9.18.44 (also 9.18.44‑S1)
- 9.20.18 (also 9.20.18‑S1)
- 9.21.17

---

## Timeline

- 2025‑11‑01 – Vulnerability reported to ISC official security contact
- 2025‑11‑01 – ISC confirmed receipt of the report
- 2025‑11‑04 – Vulnerability acknowledged by ISC
- 2025‑12‑02 – CVE‑2025‑13878 reserved
- 2026‑01‑21 – Public disclosure and official fix released

---

## References

- IETF DRIP Entity Tags specification: [draft-ietf-drip-registries-33](https://datatracker.ietf.org/doc/html/draft-ietf-drip-registries-33)
- BIND 9 Software Vulnerability Matrix: [ISC Knowledge Base AA-00913](https://kb.isc.org/docs/aa-00913)
- Marlink Cyber Security Advisory: [MCSAID-2025-015](https://github.com/marlinkcyber/advisories/blob/main/advisories/MCSAID-2025-015-isc-bind-assertion-failure-hhit-brid.md)
- ISC BIND BRID / HHIT implementation plan: [bind9 issue #5444](https://gitlab.isc.org/isc-projects/bind9/-/issues/5444)
- Software: [ISC BIND](https://www.isc.org/bind/)

