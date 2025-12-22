# Dire Wolf: Stack-based Buffer Overflow in KISS Frame Processing (src/kiss_frame.c)

- **Advisory ID:** MCSAID-2025-010
- **CVE ID:** TBD
- **Product:** [Dire Wolf](https://github.com/wb2osz/direwolf)
- **Reported:** 2025-11-04
- **Published:** 2025-11-16
- **Fixed:** commit [694c95485b21c1c22bc4682703771dec4d7a374b](https://github.com/wb2osz/direwolf/commit/694c95485b21c1c22bc4682703771dec4d7a374b)
- **Severity:** High (Memory corruption / crash)
- **CWE:** [CWE-121: Stack-based Buffer Overflow](https://cwe.mitre.org/data/definitions/121.html)
- **Discovered by:** Vlatko Kosturjak of Marlink Cyber

---

## Summary

A stack-based buffer overflow vulnerability exists in Dire Wolf in the function `kiss_rec_byte()` (file `src/kiss_frame.c`). The vulnerability occurs when processing KISS frames that reach `MAX_KISS_LEN`. The function writes a terminating FEND byte beyond the allocated buffer, and the subsequent call to `kiss_unwrap()` overreads the stack array, causing memory corruption. This can lead to crashes (Denial of Service) and potentially further control over execution.

---

## Affected Versions

| Version                                       | Status                    |
| --------------------------------------------- | ------------------------- |
| 1.8 (latest release at time of reporting)     | Vulnerable |
| Git master prior to commit `694c954`          | Vulnerable |
| Including and after commit `694c95485b21c1c…` | Patched  |

---

## Technical Details

In the `kiss_rec_byte()` function, during the `KS_COLLECTING` state, non-FEND bytes are accumulated up to the `MAX_KISS_LEN` limit. The original code performed the following check at line 485:

```c
/* original logic — insufficient boundary check */
if (kf->kiss_len < MAX_KISS_LEN)
```

This check does not reserve space for the final FEND terminator byte that must be appended to complete the KISS frame. When a KISS frame reaches exactly `MAX_KISS_LEN`, the code attempts to write the terminating FEND byte beyond the allocated buffer boundary, causing a stack buffer overflow.

The subsequent call to `kiss_unwrap()` at line 322 then reads from this corrupted stack memory, leading to:
- Process abort when running with AddressSanitizer
- Stack corruption of adjacent variables without sanitizers
- Potential control-flow corruption or daemon destabilization

Malicious KISS TCP clients can exploit this by sending crafted binary payloads to the KISS port (typically port 7002).

The upstream patch modifies the boundary check to reserve space for the final byte:

```c
/* patched logic */
if (kf->kiss_len < MAX_KISS_LEN - 1)
```

By reducing the collection limit by one byte, there is adequate room for appending the terminating FEND byte without overflowing the buffer. The fix is available in commit `694c95485b21c1c22bc4682703771dec4d7a374b`.

AddressSanitizer detection output shows:
```
stack-buffer-overflow at offset 2171 on the 'unwrapped' variable
```

---

## Proof / Test

Repro steps and PoC are described in the issue thread.

Platform: Ubuntu 24.04.3
Configuration: KISSPORT 7002 0

Test method:
1. Configure Dire Wolf with KISS TCP port enabled
2. Send crafted binary payload via netcat to trigger the overflow
3. AddressSanitizer detects stack-buffer-overflow in `kiss_unwrap()`

```sh
# With AddressSanitizer enabled
# Process aborts with stack-buffer-overflow detection
```

---

## Impact

* **Primary impact:** Denial of Service (crash) due to stack memory corruption.
* **Secondary impact:** Potential memory corruption that may be leveraged for control-flow corruption or daemon destabilization (depends on compiler, mitigations, and calling context).
* **Attack Vector:** Network (malicious KISS TCP clients can send crafted payloads to KISS port).
* **Privileges Required:** None (unauthenticated access to KISS TCP port).
* **User Interaction:** None (the parsing happens automatically when KISS frames are received).
* **Suggested CVSS v3.1 Base Score (example):** 7.5 (High) — e.g. `AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H` (adjust as appropriate for your environment).

---

## Fix / Mitigation

**Upgrading / Applying the Fix**

1. **Upgrade** to a version including commit `694c95485b21c1c22bc4682703771dec4d7a374b` or later. The commit implements the corrected boundary check preventing buffer overflow.

2. If you maintain a packaged distribution and cannot immediately upgrade, **backport** the patch by applying the single-line change in `src/kiss_frame.c` at line 485:

```diff
- if (kf->kiss_len < MAX_KISS_LEN)
+ if (kf->kiss_len < MAX_KISS_LEN - 1)
```

Then rebuild/install.

3. As a temporary workaround, restrict access to the KISS TCP port to trusted clients only, or disable KISS TCP functionality if not required.

---

## References

* [Stack Buffer Overflow in KISS Frame Processing · Issue #617](https://github.com/wb2osz/direwolf/issues/617)
* Commit fixing the issue: [`694c95485b21c1c22bc4682703771dec4d7a374b` — "Issue 617 - Buffer overflow in KISS code"](https://github.com/wb2osz/direwolf/commit/694c95485b21c1c22bc4682703771dec4d7a374b)
* Product: [Dire Wolf](https://github.com/wb2osz/direwolf)

