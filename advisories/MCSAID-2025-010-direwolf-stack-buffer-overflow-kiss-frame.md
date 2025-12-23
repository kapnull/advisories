# Dire Wolf: Stack-based Buffer Overflow in KISS Frame Processing (src/kiss_frame.c)

- **Advisory ID:** MCSAID-2025-010
- **CVE ID:** [CVE-2025-34457](https://www.cve.org/CVERecord?id=CVE-2025-34457)
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
| 1.8.1 (latest release at time of reporting)   | Vulnerable |
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

Full Asan Output:
```
==3579451==ERROR: AddressSanitizer: stack-buffer-overflow on address 0x70f7d5c9787b at pc 0x5ef775f12465 bp 0x70f7d74671d0 sp 0x70f7d74671c0
WRITE of size 1 at 0x70f7d5c9787b thread T17
 #0 0x5ef775f12464 in kiss_unwrap /htp/direwolf/direwolf/src/kiss_frame.c:322
 #1 0x5ef775f14081 in kiss_rec_byte /htp/direwolf/direwolf/src/kiss_frame.c:467
 #2 0x5ef775f160d1 in kissnet_listen_thread /htp/direwolf/direwolf/src/kissnet.c:983
 #3 0x70f7ee65ea41 in asan_thread_start ../../../../src/libsanitizer/asan/asan_interceptors.cpp:234
 #4 0x70f7ed69caa3 in start_thread nptl/pthread_create.c:447
 #5 0x70f7ed729c6b in clone3 ../sysdeps/unix/sysv/linux/x86_64/clone3.S:78

Address 0x70f7d5c9787b is located in stack of thread T17 at offset 2171 in frame
 #0 0x5ef775f139df in kiss_rec_byte /htp/direwolf/direwolf/src/kiss_frame.c:388

 This frame has 1 object(s):
  [48, 2171) 'unwrapped' (line 446) <== Memory access at offset 2171 overflows this variable

SUMMARY: AddressSanitizer: stack-buffer-overflow /htp/direwolf/direwolf/src/kiss_frame.c:322 in kiss_unwrap
```

Full Asan Output of 1.8.1:

```
KISS frame should end with FEND.
KISS frame should not have FEND in the middle.
=================================================================
==714631==ERROR: AddressSanitizer: stack-buffer-overflow on address 0x707054b6487b at pc 0x60ae137e2525 bp 0x7070558631d0 sp 0x7070558631c0
WRITE of size 1 at 0x707054b6487b thread T17
    #0 0x60ae137e2524 in kiss_unwrap /htp/direwolf/direwolf-1.8.1/src/kiss_frame.c:322
    #1 0x60ae137e4141 in kiss_rec_byte /htp/direwolf/direwolf-1.8.1/src/kiss_frame.c:467
    #2 0x60ae137e6191 in kissnet_listen_thread /htp/direwolf/direwolf-1.8.1/src/kissnet.c:983
    #3 0x70706c85ea41 in asan_thread_start ../../../../src/libsanitizer/asan/asan_interceptors.cpp:234
    #4 0x70706b69caa3 in start_thread nptl/pthread_create.c:447
    #5 0x70706b729c6b in clone3 ../sysdeps/unix/sysv/linux/x86_64/clone3.S:78

Address 0x707054b6487b is located in stack of thread T17 at offset 2171 in frame
    #0 0x60ae137e3a9f in kiss_rec_byte /htp/direwolf/direwolf-1.8.1/src/kiss_frame.c:388

  This frame has 1 object(s):
    [48, 2171) 'unwrapped' (line 446) <== Memory access at offset 2171 overflows this variable
HINT: this may be a false positive if your program uses some custom stack unwind mechanism, swapcontext or vfork
      (longjmp and C++ exceptions *are* supported)
Thread T17 created by T0 here:
    #0 0x70706c8f51f9 in pthread_create ../../../../src/libsanitizer/asan/asan_interceptors.cpp:245
    #1 0x60ae137e733d in kissnet_init_one /htp/direwolf/direwolf-1.8.1/src/kissnet.c:354
    #2 0x60ae137e733d in kissnet_init /htp/direwolf/direwolf-1.8.1/src/kissnet.c:274
    #3 0x60ae1373b6be in main /htp/direwolf/direwolf-1.8.1/src/direwolf.c:1138
    #4 0x70706b62a1c9 in __libc_start_call_main ../sysdeps/nptl/libc_start_call_main.h:58
    #5 0x70706b62a28a in __libc_start_main_impl ../csu/libc-start.c:360
    #6 0x60ae13747094 in _start (/htp/direwolf/direwolf-1.8.1/build/src/direwolf+0x64094) (BuildId: c3192edd1a724baea713a0f1c5add7e4657d33c0)

SUMMARY: AddressSanitizer: stack-buffer-overflow /htp/direwolf/direwolf-1.8.1/src/kiss_frame.c:322 in kiss_unwrap
Shadow bytes around the buggy address:
  0x707054b64580: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x707054b64600: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x707054b64680: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x707054b64700: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x707054b64780: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
=>0x707054b64800: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00[03]
  0x707054b64880: f3 f3 f3 f3 f3 f3 f3 f3 f3 f3 f3 f3 f3 f3 f3 f3
  0x707054b64900: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x707054b64980: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x707054b64a00: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x707054b64a80: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
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

