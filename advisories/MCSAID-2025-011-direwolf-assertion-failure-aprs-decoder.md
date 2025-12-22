# Dire Wolf: Assertion Failure in APRS MIC-E Decoder Leads to Denial of Service (src/decode_aprs.c)

- **Advisory ID:** MCSAID-2025-011
- **CVE ID:** TBD
- **Product:** [Dire Wolf](https://github.com/wb2osz/direwolf)
- **Reported:** 2025-11-04
- **Published:** 2025-11-07
- **Fixed:** commit [3658a878920803bbb69a4567579dcc4d6cb80a92](https://github.com/wb2osz/direwolf/commit/3658a878920803bbb69a4567579dcc4d6cb80a92)
- **Severity:** Medium (Denial of Service / crash)
- **CWE:** [CWE-617: Reachable Assertion](https://cwe.mitre.org/data/definitions/617.html)
- **Discovered by:** Vlatko Kosturjak of Marlink Cyber

---

## Summary

A denial-of-service vulnerability exists in Dire Wolf in the function `aprs_mic_e()` (file `src/decode_aprs.c`). When processing a specially crafted AX.25 frame containing a MIC-E message with an empty comment field, the code triggers an unhandled assertion that immediately terminates the process. Any unauthenticated APRS frame reaching Dire Wolf components can exploit this parser vulnerability to achieve remote denial of service.

---

## Affected Versions

| Version                                       | Status                    |
| --------------------------------------------- | ------------------------- |
| 1.8 (latest release at time of reporting)     | Vulnerable |
| Git master prior to commit `3658a87`          | Vulnerable |
| Including and after commit `3658a878920803b…` | Patched  |

---

## Technical Details

In the `aprs_mic_e()` function at line 1672 of `src/decode_aprs.c`, the code contains an assertion to validate that the MIC-E comment field is not empty:

```c
/* original vulnerable code */
assert(strlen(mcomment) > 0);
```

The vulnerability occurs when:
1. A malformed AX.25 frame is received and decoded as a MIC-E message
2. The message contains an empty comment field (or a nul character near the end of the packet)
3. The `strlen(mcomment)` call returns 0
4. The assertion fails, causing immediate process termination

According to the developer, "the contrived test case...contained a nul character near the end of the packet which should not happen with APRS." This malformed input caused `strlen()` to return a shorter length than the actual byte count, triggering the assertion failure.

The upstream patch replaces the assertion with a defensive check:

```c
/* patched logic */
if (strlen(mcomment) < 1) {
  strlcpy(A->g_mfr, "UNKNOWN vendor/model", sizeof(A->g_mfr));
  return;
}
```

This defensive programming approach gracefully handles malformed packets by setting a default vendor/model string and returning early, instead of crashing the entire process. The fix is available in commit `3658a878920803bbb69a4567579dcc4d6cb80a92`.

---

## Proof / Test

Repro steps and PoC are described in the issue thread.

Platform: Ubuntu 24.04.3

**Hex payload:**
```
27 27 27 27 27 27 27 27 10 00 27 27 27 27 27 27...
```

**Base64 encoding:**
```
JycnJycnJycQACcnJycnJycnJycnJycnJ56mpqaukohEAyInnqampq6SiEQDIkVniQA=
```

**Test method:**
```sh
# Pipe the crafted payload to decode_aprs
echo "JycnJycnJycQACcnJycnJycnJycnJycnJ56mpqaukohEAyInnqampq6SiEQDIkVniQA=" | base64 -d | build/src/decode_aprs

# Expected output on vulnerable version:
# decode_aprs: ...decode_aprs.c:1672: aprs_mic_e: Assertion `strlen(mcomment) > 0' failed.
# Aborted (core dumped)
```

---

## Impact

* **Primary impact:** Denial of Service (immediate process crash).
* **Attack Vector:** Network (any unauthenticated APRS frame reaching Dire Wolf components).
* **Privileges Required:** None (unauthenticated access to APRS decoder).
* **User Interaction:** None (the parsing happens automatically when APRS frames are received).
* **Scope:** Unchanged (the vulnerability affects only the Dire Wolf process itself).
* **Suggested CVSS v3.1 Base Score (example):** 7.5 (High) — e.g. `AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H`.

---

## Fix / Mitigation

**Upgrading / Applying the Fix**

1. **Upgrade** to a version including commit `3658a878920803bbb69a4567579dcc4d6cb80a92` or later. The commit replaces the assertion with a defensive check that handles malformed packets gracefully.

2. If you maintain a packaged distribution and cannot immediately upgrade, **backport** the patch by applying the change in `src/decode_aprs.c` at line 1669:

```diff
- assert(strlen(mcomment) > 0);
+ if (strlen(mcomment) < 1) {
+   strlcpy(A->g_mfr, "UNKNOWN vendor/model", sizeof(A->g_mfr));
+   return;
+ }
```

Then rebuild/install.

3. As a temporary workaround, implement input validation or filtering to reject malformed AX.25/APRS frames before they reach the decoder, if possible in your deployment environment.

---

## References

* [Crafted AX.25 frame can crash the process - Denial of Service · Issue #618](https://github.com/wb2osz/direwolf/issues/618)
* Commit fixing the issue: [`3658a878920803bbb69a4567579dcc4d6cb80a92` — "Issue 618 - Crash on hand crafted packet"](https://github.com/wb2osz/direwolf/commit/3658a878920803bbb69a4567579dcc4d6cb80a92)
* Product: [Dire Wolf](https://github.com/wb2osz/direwolf)

