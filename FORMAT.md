# SBC Archive Format (SBC Archiver 0.970) — Reverse-Engineered Notes

Status: living document. Everything is marked **[VERIFIED]** (byte-exact against
`unsbc.exe` output on the corpus), **[PARTIAL]** (works for some archives), or
**[HYPOTHESIS]** (observed/guessed, not proven).

Reference implementation: `sbc_proto.py` (Python) and `sbc.c` + `sbc_stage2.h`
(C). Disassembly addresses refer to `unsbc.exe` (image base `0x400000`).

---

## 1. Container layout

```
+--------------------------+  offset 0
| magic "SBC\x1eH" (5 B)   |
+--------------------------+
| header (range-coded)     |
+--------------------------+
| alignment / prefix       |
+--------------------------+
| payload header (RC)      |
+--------------------------+
| stored / coded data      |
+--------------------------+
| ... trailer ...          |
| 2 B stored checksum      |  at len-7 .. len-5  (big-endian)
| 5 B trailer / padding    |  at len-5 .. len
+--------------------------+  len
```

- Magic: `53 42 43 1E 48` = `"SBC\x1eH"` **[VERIFIED]**
- Footer: `data[len-7 : len-5]` big-endian is the stored checksum. `len-5..len`
  holds 5 trailing bytes (not fully characterised; contains flags/metadata).
  **[VERIFIED location, PARTIAL meaning]**

### Stored checksum

`stored = CRC16/ARC_raw(output) XOR 0xFFFF` where `CRC16/ARC_raw` is:
- poly `0xA001` (reflected 0x8005), init `0xFFFF`, **no** final xor.
- Equivalent to the usual CRC-16/ARC with final xor, but the "raw" value is
  stored after an extra inversion.

Verified byte-exact for pattern, records, image24 (m1/m2), biased, hello,
zeros, empty. **[VERIFIED]**

This checksum is the oracle used to select the compression level (see §7).

---

## 2. Range coder (RC)

The header and all size/name fields are coded with a binary range coder
(class `RC` in `sbc_proto.py`, `SbcRC` in `sbc.c`).

- State: `low`, `range`, `code`. Byte-oriented renormalisation.
- `decode_large(n)` / `decode_int(mx)` / `decode_int_maxbits(nbits)` are
  wrappers over the same core.
- `Extra` = adaptive symbol model (fenwick/bit-tree) with `nsyms`, `inc`,
  `cap_freq`, `cap_tot`, optional `boost0`.
- `SizeModel` = model over packed 32-bit values (zig-zag deltas against the
  previous size). Used for `dt` and `sz` per file.

Header parsing order **[VERIFIED across corpus]**:

```
crypto   : u(8)
csum     : u(8)
solid    : u(2)
fn_extra : Extra(nsyms=0x45, inc=1, caps 0x4000/0x4000)   # filename alphabet
fl_extra : Extra(nsyms=8,    inc=1, caps 0x200/0x400, boost0=0x20)
nfiles   : decode_int(0xFFFF0000) + 1
for each file:
    name symbols until symbol 0 (max 0x200), mapped through ALPHABET
    flag = fl_extra.decode_sym()
    dt   = size_model_0.decode()
    sz   = size_model_1.decode()
method   : u(0x3F)
extra3   : u(3)
```

After this, `rdr.pos` points at the payload prefix.

### Filename alphabet (0x45 symbols)

`0`, `-`, space, `/`, `.`, `~`, `0-9`, `a-z`, `A-Z`, `_` (exactly 0x45).
Index 0 terminates a name. **[VERIFIED]**

---

## 3. Payload start

```
payload_start = hdr_pos + delta          delta in 0..3 (2 most common)
```

It is **not** a fixed prefix and it is **not** derived from `extra3` (the old
`(hdr_pos & ~3) + 4` rule was an empirical hack that only fitted part of the
corpus). GDB on `unsbc.exe` shows the header range coder is followed by its
**flush**: `0x429920` (RC::flush) writes the four bytes of `low`, and the
decoder's renormalisation pulls a prefix of those bytes in while decoding the
last header symbol. The number of bytes pulled in depends on the coder state,
so the payload lands at `hdr_pos + delta` with `delta` = 2 or 3 for every
archive measured so far (0 and 1 also occur, e.g. `nested-m1` at 142 =
`hdr_pos + 2` and `eng-m2` at `hdr_pos + 1`).

Because the flush boundary is not recoverable from the decoded symbols alone,
the decoder resolves `delta` by **validation**: each candidate `extract3` is
decoded and the result is checked against the stored CRC16 (see §1). List of
verified values: `biased` 2, `code` 2, `hello` 2, `image` 3, `image24` 2,
`pattern` 2, `random` 2 (m2: 3), `records` 2, `zeros` 3, `eng` 2 (m2: 1),
`nested` 2. **[VERIFIED behaviourally; exact closed-form rule still OPEN]**

The same `+2` flush applies inside the payload section: when `e1 == 0` the
stored BWT block starts at `payload_header_rc_pos + 2` (verified on
`random-m1/m2/m3`), not at a 4-byte-aligned position.

---

## 4. Payload header

Read at `payload_start`, all through the same RC (re-initialised on the
bytestream at that position). This layout matches the currently passing
corpus profiles; it is not yet validated for all archive methods. The C reader
currently disagrees with the legacy payload-header fields on image/eng
(methods 7 and 41), even though the legacy extracts those archives correctly:

```
vlq      = read_vlq(reader)              # BWT block length (== stored L length)
primary  = rc.decode_large(vlq)          # BWT primary index
nbits    = rc.decode_int_maxbits(0x14)   # number of bits in the filter record stream
bits     = copy_bits(rc, nbits)          # MSB-first packed bits, 8 bits per rc.u(256)
flag3    = rc.u(3)
if flag3 == 2: extra16 = rc.u(0x10)
nsyms    = 20                            # in practice; see note
extra    = Extra(nsyms, inc=1, caps 0x4000/0x4000)
e1       = extra.decode_extra()
e2       = extra.decode_extra()
```

Notes:
- `nsyms` is derived from `window_size(method) = (method<<19)+0xFFFFF` via
  `size_to_nsyms()` in the disassembly, but for all observed archives the
  effective value is 20. The C port currently hardcodes 20 (matches corpus).
  **[PARTIAL]**
- `vlq == 0` means "empty / no coded block" for verified empty-archive cases. Do not assume a parsed zero is valid when header decoding has not been cross-checked for that method. **[VERIFIED for empty cases; partial across methods]**
- `flag3` semantics (see §6). Legacy GDB confirms image-m1/m2/m3 use `flag3=1` and eng-m1/m2/m3 use `flag3=0`; C currently misdecodes those header fields. **[PARTIAL]**
- `e1` is the number of bytes of the coded stream located at the **end** of the
  archive: `coded_start = len - 7 - e1`, `coded_len = (len-7) - coded_start`.
  **[VERIFIED]**
- `e2` is currently unused by the working paths. **[PARTIAL]**

### VLQ encoding (`read_vlq`)

Top two bits of first byte select length:

| prefix | bytes | value |
|--------|-------|-------|
| `00`   | 1     | `a` |
| `01`   | 2     | `((a^0x40)<<8) | b` |
| `10`   | 3     | `(((a^0x80)<<8|b)<<8) | c` |
| `11`   | 4     | `((((a^0xC0)<<8|b)<<8|c)<<8) | d` |

**[VERIFIED]**

---

## 5. BWT + primary

`L` is the BWT last column of length `vlq`; `primary` is the primary index.
Inverse BWT (`ibwt`):

```
count[byte], C[] cumulative starts
T[C[c]++] = i   for i in 0..n-1, c = L[i]
p = primary
for i in 0..n-1: p = T[p]; out[i] = L[p]
```

**[VERIFIED]** for all archives where `L` is recovered correctly.

### Primary and the rotation tie order (SOLVED)

The vendor's BWT is built by **a stable first-byte bucket pass followed by a
Bentley-McIlroy three-way quicksort** over the cyclic rotations (entry
`0x4225c0`, small path `0x421ac0` for `n < 0x8000`, two-byte bucket path
`0x421cc0` above it, sort core `0x423010`, `< 11` handler `0x424f90`, helper
`0x424da0`, histogram/prefix `0x445bd0`/`0x445d70`/`0x445cb0`).  `0x4225c0`
appends `min(n, 0x1000)` bytes of the input to the buffer and passes
`end = n + min(n, 0x1000) - 7` as the comparison limit.

`L` does not depend on the tie order (rotations that compare equal also share
their preceding byte), but **`primary` does**: it is the SA slot that rotation
0 ends up in, and the vendor's order is not the canonical one.  `sbc_enc.h`'s
`sbc_bwt` is a faithful port: `tools/bwt_probe_small.py` compares it against
the vendor on 36 periodic/random inputs (layers dumped from the vendor's own
archives) and reports **36 identical, 0 primary mismatches**, `reg04`
included.  **[VERIFIED]**

The rules a port has to reproduce, in the order they run:

1. **Bucket pass** (`0x421ac0`): count the first bytes, fill the SA in
   increasing index order per bucket (stable), skip buckets of size 1, and
   return at once -- leaving the SA untouched -- when one bucket holds all `n`
   rotations.  That is why all-equal input (`"a" x n`, `zeros`) gives 0.
2. **Skip rule**: before sorting a segment, walk it backwards comparing
   `s[a[i] - 1]` with `s[a[0] - 1]` (stopping at any `a[i] == 0`) and return if
   they all match -- the BWT column only depends on those bytes, so the order
   inside such a segment cannot change `L`.  This is why the vendor's SA is not
   a canonical rotation order: most buckets are left in insertion order even
   though their rotations differ (a `bytes(0..24) * 8` block decodes correctly
   with 30 out-of-order adjacent pairs).
3. **3-way partition** (`0x423010`): keys equal to the pivot are gathered at
   both ends (`eqL` from the left, `eqR` from the right) and `vecswap`ed to the
   middle.  Those swaps are not stable, so an equal class comes out permuted --
   that is the whole `reg04` effect.  The pivot is parked in `a[hi]` (the spare
   slot, i.e. the first slot of the *next* segment) and restored by the first
   loop-head swap.  The tail is
   `k1 = min(i - eqL, eqL - lo)`, `vecswap(lo, i - k1, k1)`,
   `k2 = min(hi - eqR - 1, eqR - j)`, `vecswap(i, hi - k2, k2)`, and then
   `less = i - eqL`, `eqsz = (eqL - lo) + (hi - eqR) - 1`,
   `greater = eqR - j` with `i - j == 1`.
4. **Pivot**: `median3(a[lo], a[mid], a[hi-1])` below 36 elements (0x423138),
   a ninther over the `n/8` offsets above it.  Ties use the vendor's own
   priority, not a plain median: **`a[lo]` wins when it ties `a[mid]`**, then
   `a[hi-1]` wins when it ties either; only three distinct keys take the
   ordinary median.  The chosen *slot* is swapped into `a[lo]`, so on a segment
   whose keys are all equal picking `mid` instead of `lo` permutes it and moves
   rotation 0 (e.g. `"ab" x 1500` comes out at 1499 instead of 0).
5. **Cutoff**: `< 11` elements go to the insertion handler, which compares the
   full byte range `[depth, min(end - a[i]) - 1)` and is stable.
6. **Equal-band hand-off**: the equal band recurses at `depth + 1` while the
   depth is below 6; from there it switches to the vendor's **4-byte-key
   path**, which partitions on the big-endian 32-bit word at the depth and
   advances its equal bands by **2** bytes (so the depth sequence is
   1..5, 6, 8, 10, ...).  The 0x2000-entry worklist at `0x462440` is LIFO
   scratch: it changes when segments are visited, never the result, so a
   recursive/iterative port is equivalent.
7. **Comparison index wrap**: the buffer only holds `n + min(n, 0x1000)`
   bytes, and the compare normalises an index that reaches the limit by
   subtracting `n` (`0x424e1d`: `cmp limit,%eax / jl / sub n`).  Without it the
   last few rotations compare against the zeros past the buffer and split a
   band the vendor keeps together -- that is what made `"ab"`/`"abc"` cycles
   and the 1500-byte `word` cycle disagree while 2000 and 3000 matched.

One **port-side** shortcut, not a vendor rule: a `p`-periodic block repeats its
keys every `p` bytes, so a band that survived to depth `p` is a set of
identical rotations and every deeper partition is an all-equal no-op (rule 3
leaves such a segment's order alone).  `sbc_bwt` returns at `depth >= p`, with
`p` the KMP period.  Without it an exactly periodic 1 MiB block runs one no-op
pass per byte; block content that is periodic *except* for a truncated tail is
not covered and still lands in that quadratic case, but the encoder's repeat
transform keeps such files away from the BWT.

Ground truth for all of this is `tools/bwt_sa_dump.py`: it runs `sbc.exe` under
`winedbg`, breaks at `0x4225c0`/`0x41fb23`, dumps the final SA and the exact
buffer that was sorted, and prints the bucket layout plus the rank of rotation
0 (n = 200, eight repeats: `rank(0) = 194`, the same number the 3000-byte
archive shows as primary 2990).  `_work/bwt_sort_model.py` is a line-by-line
Python mirror of the C port with the vendor `primary` of seven
self-contained inputs (all seven exact); `tools/bwt_vectors.py` keeps the
(input, `L`, primary) triples.

### Where `L` comes from

Two cases:

1. **`e1 == 0`** — `L` is stored verbatim right after the payload header:
   `lpos = rc_pos + 2` (the payload-header RC flush); `L = data[lpos : lpos+vlq]`.
   **[VERIFIED]** on random-m1/m2/m3, byte-exact against the corpus. The older
   `(rc_pos + 4) & ~3` rule was wrong: it only coincided for one of the three
   (rc_pos = 46) and shifted the block by one byte for the other two, which is
   exactly the "first ~6 bytes ok then diverge" symptom recorded earlier.

2. **`e1 != 0`** — `L` is entropy-coded in the tail region. The Python path
   uses `tools/stage2_test.py`'s stage1/stage2 PPM model; the C path uses
   `sbc_stage2.h` (`sbc_stage1`, `sbc_run_stage2`). Both recover code-m1's `L`
   byte-exactly against the saved vendor capture. Coverage for other archives
   remains partial; see `RE_report.md` §11.7. **[PARTIAL]**

---

## 6. `flag3` post-processing

Read immediately after the filter bit stream.

| `flag3` | meaning | handling |
|---------|---------|----------|
| 0 | no post-filter | identity **[VERIFIED]** |
| 1 | LZP expansion (`0x40a690` init / `0x40a7d0` core) | C `sbc_lzp_decode` **[VERIFIED byte-exact vs vendor on image24-m3]**; Python helper is not equivalent |
| 2 | LZP cascade: `extra16 + 1` marker passes, then the default pass | C `sbc_lzp2_decode` **[VERIFIED byte-exact on vendor-made `extra16=0` and `extra16=1` archives]** |

`flag3 == 1` is a real LZP decoder, not a constant/pad special case.
Parameters (from `0x40a690`): `mark1=2`, `mark2=0xC5`, `Lbase=15`,
`WINDOW=66`, `SKIP=66`, hash mask **`0x1FFFFF`** (2^21 entries, 8 MB table),
output capacity `+0x10000`.

`flag3 == 2` is the same LZP engine used as a cascade, not a different
filter.  The encoder always runs the default pass (2, 0xC5, 66, 66) first
(`0x41f290` -> `0x416ac0`); if that output is still above `2 MB`, it appends
marker passes while each one shrinks the buffer (`0x41f327`, helpers
`0x4167c0`/`0x416790`).  Extra pass `i` (0-based) uses marker
`(i - 0x5865) & 0xffff`, window `(i + 1) << 20`, and skip
`min(window, 0x400)`.  The record's `extra16` is **extra passes - 1**: one
marker pass stores 0, two store 1, and so on (the encoder writes
`(passes - 1) << 8 | 2`).  The decoder therefore applies the marker passes
in reverse order (`i = extra16` down to 0) and the default pass **last**
(`0x40ea90`).  `extra16 == 0` is consequently one marker pass plus the
default pass, not the default pass alone.

Both forms are verified byte-exactly against the vendor: `-m3` on a 3 MB
stream naturally reaches the cascade when the first LZP output is above
2 MB.  Relaxing the encoder's output-capacity check under gdb (the normal
check is `input - 0x1000`) made one extra pass succeed (`extra16=0`,
`_work/f32/ereal0-m3.sbc`) and two succeed (`extra16=1`,
`_work/f32/ereal1-m3.sbc`); `unsbc.exe` extracts both to the original bytes,
and our decoder matches.  The gdb helpers are
`_work/force_real_auto.gdb` / `force_real1.gdb`, and
`tools/cascade_test.py` replays both cascade samples, plus the `big3` /
`big-m3` no-sub archives.

The mask is the one thing that made large repetitive blocks fail: with
`0xFFFFF` every context whose `word ^ (word>>19)` has bit 20 set aliased onto
another slot, so the decode ran correctly for thousands of bytes and then
copied from the wrong source (3 MB uppercase `code.c` at `-m3` diverged at
LZP output byte 23336, which is only visible after the mode-6 stage).  The
vendor's two traces — a lookup that lands on `table[0x103087]` while our
`h4()` said `0x03087`, and the same table cell holding the copied offset —
pin the mask to 21 bits.
Input len is passed in the caller's `[ebp-0x14]`; the in/out length is
returned through arg4 (pointer). For image24-m3 the vendor reports
**outlen = 98304**, and C output is byte-identical to it (1489 non-zero
bytes, zeros after ~775). This verifies that sample's C implementation; it
does not establish correctness for every profile.

Confirmed by live legacy/GDB traces: image-m1/m2/m3 take `flag3=1` and
eng-m1/m2/m3 take `flag3=0`. The legacy extracts 65,536 bytes from each image
archive and 20,359 bytes from each eng archive. Current C parses disagree on
the flag field (image-m2/m3 and eng-* become `flag3=2`), so the payload header
parse is not yet aligned with the oracle for those profiles. Earlier Python
header readings claiming `flag3=2` were likewise invalid and are not evidence
of the legacy format. **[VERIFIED legacy branch selection; C profile mismatch unresolved]**

### Mode 4 (`0x406940`): a control-word flag set

`0x408dff` reads a 24-bit `ctrl` and calls
`0x406940(obj->[0x44], dst, src, flen, ctrl, x, y, z)`.  The record stores the
header word `header = vendor << 1 | dict`, so the function receives
`v = ctrl >> 1`.  Its body is a fixed pipeline (all of it implemented in
`sbc_apply_mode4`):

```
marker0, marker1 = v & 1 ? (derived from salt) : (0xFF, 0xFE)
work = map(src)                        if v & 0x02     0x4079d0
if v & 0x08:  0x408060 line pass, then the *appending* CR fold (0x406b68)
else:         the in-place/eating CR fold (0x407a50)   if v & 0x30
              else drop space after LF (v & 0x10) / CR (v & 0x20)   0x4079f0
expand 0x80..0xFD tokens, `marker1` escapes one literal   if v & 0x40
capital pass: `marker0` + byte -> byte ^ 0x20              if v & 0x04
```

| bit (v) | header bit | meaning |
|---|---|---|
| `0x01` | `0x02` | derive both markers from the salt in `v`'s bytes 1/2 |
| `0x02` | `0x04` | the `0x4079d0` 256-byte permutation (`SBC_MODE4_MAP`) |
| `0x04` | `0x08` | `0x406ed0` capital marker |
| `0x08` | `0x10` | `0x408060` prose-line reconstruction (needs `e2`) |
| `0x10` | `0x20` | drop the space after LF |
| `0x20` | `0x40` | drop the space after CR |
| `0x30` | `0x60` | both: the CR fold replaces the two drops |
| `0x40` | `0x80` | `0x406f20` token expansion |

Corpus values:

| archives | header ctrl | bits |
|---|---|---|
| code-m1/m2/m3, plain LF text | `0xAC` | `0x80|0x20|0x08|0x04` |
| eng-m1/m1-of/m1-on/m2/m3 | `0x8C` | `0x80|0x08|0x04` (no `0x20`) |
| a 3.2 MB code block (`-m1`) | `0xA4` | same as `0xAC` **without** `0x08` |
| CRLF text | `0xEC` | `0x80|0x40|0x20|0x08|0x04` |
| 200 kB ASCII with a NUL after every byte, and 200 kB of `a b c ... z ` | `0x0C` | `0x08|0x04`, **no `0x80`** |

What used to be described as "inert" and "refused" is in fact the general
word above, and every bit is now implemented:

* `0x04` is the map: `0x4079d0` calls `FUN_00407730`, which builds the 256-byte
table at `0x444020` from `0x43a3e0` (seed `0x5a`) and applies
`buf[i] = table[buf[i]]`.  `SBC_MODE4_MAP` is that table, byte for byte.
* `0x80` (the token bit, tested at `0x406a22`) selects the `0x406f20`
expansion.  When clear the record is the bare map (the two `0x0C` rows).
The vendor clears it when its token pass emitted nothing.
* `0x08` is the capital pass, not inert: `0xA4` records carry literal capitals
instead of the `0xFF` markers, and our encoder's tokenizer honours the bit.
* `0x10`/`0x20` write and drop the space after the LF/CR marker; `0x40`
selects CR (`0xEC` texts), and both together (`0x30`) fold CR/CRLF instead.
* `0x02`/`0x01` (the prologue and the map) are the low bits: the prologue
names the markers as `marker0 = (v >> 8) ^ 0xFF`, `marker1 = marker0 -
(v >> 16) - 1`, or the fixed `0xFF`/`0xFE` pair when bit 0 is clear.  The
expander's `marker1` escape copies the next byte verbatim, and `0x406ed0`
applies `marker0` + byte -> byte ^ 0x20 *after* the expansion.

The token table has **126** entries: `0x80..0xFD`, with `0xFD` = `wh`
(only the decompressor's jump table reaches it; the vendor's tokenizer never
emits it, which is why our encoder's matcher stops at `0xFC`).
`tools/m4_forge.py` packs one forged archive per branch (salted markers both
ways, escaped literals, no capital pass, no map, `0xFD`, prose+CRLF) and
requires both decoders to reproduce the source.

**Mode 6** (used for uppercase text, e.g. `code.c` uppercased: 300000 →
13398 filtered bytes, archive 2079 bytes) is now implemented as
`sbc_apply_mode6` and decodes byte-exactly.  `RECS` shows `mode=6 ctrl=000000`.
`0x406940` is now fully implemented: no flag combination is refused, and the
corpus shapes above are just the ones the vendor's chooser emits.

`SBC_MODE6_COPY=1` still lets the raw filtered stream through so `SBC_DUMP`
can save it for offline analysis.

Mode 6 is a **repeat-from-context** filter, not a dictionary: the filtered
stream is a mix of literals and `7B F0 <len>` codes.

```
code:  sel < 0x80        L = sel + 16
       sel in 0x80..0xBF L = (sel & 0x3F) + (b1 << 6) + 16
       sel >= 0xC0       L = (sel & 0x3F) + (b1 << 6) + (b2 << 14) + 16
```

A code copies `L` bytes from the position recorded for the **two-byte context**
( = the last two bytes of output so far) in a 65536-entry table.  Only
**literals** update that table (key `out[p-2..p-1]`, value `p`, for `p >= 2`),
copies do not — that is precisely what makes the encoder read an older,
literal-born source rather than the copy it just emitted, and it is why a naive
LZP replay with the `flag3` window/hash failed.  The literal `{` itself is
emitted unchanged (in the dump a literal `{` is followed by a space); only the
sequence `7B F0` introduces a code, which the 16-byte minimum length keeps
unambiguous for text.

Verified byte-exactly on `rep1` (110000 B), `line2` (96000 B) and uppercased
`code.c` (300000 B); `tools/text_variants.py` covers those three as a
regression test, now at both 300 kB and 3 MB (all five variants × three levels
pass at 3 MB, including the multi-record blocks where the block-wide table and
its absolute positions matter).

### Mode 6 — the vendor routine

Read off `unsbc.exe` **0x4083a0** (`f(obj, src, dst, len)`, called from the
record dispatcher `0x408a00` → `0x408bc4` with `obj->0x38`):

* the marker bytes are `obj->[0xc]` and `obj->[0xd]` (here `7B F0`) and the
  minimum length is `obj->[4]-1` (`17`; the three `sel` forms add 16 to it),
  so both are **parameters of the object**, not constants of the format;
* the table is a 65536-entry array of 32-bit **output positions**, indexed by
  the 16-bit context at the current output cursor (`*(dst-2) | *(dst-1)<<8`;
  the dump confirms only literals store, at the position of the literal);
* the table and its positions are **block-wide**, not record-wide: the vendor
  decodes record *k* of a block straight into `out + k*0x80000` of one
  contiguous buffer (call site `0x408bc4`) and never resets the table, so a
  record resolves contexts stored by the earlier ones.  The first two output
  bytes of every record are copied unconditionally and without a store
  (`0x4083ca`); only then does the loop start, so the store guard is
  record-local (`used >= 2`), not block-local;
* a copy is a plain forward byte loop with no length clamp, so an overlapping
  source expands like an LZ run;
* `7B F0 00` is an **escape**: it emits the two marker bytes literally and
  stores both positions in the table.  Implemented in `sbc_apply_mode6` and
  exercised end to end by the `marker` variant of `tools/text_variants.py`
  (uppercased text with `{`+`0xF0` pairs every 5 kB: the vendor emits the
  escape at offset 1418 of the filtered stream and all three levels decode
  byte-exactly).

The pair is a parameter of **that** object, not of the format: the 9 MB `-m2`
archive's second block also contains `03 C5` sequences, but they belong to the
second-stage filter (§8.1), whose own object uses `03 C5` at `+0x4028/+0x4029`.

### Dictionary-reference records

After the 3-bit mode the dispatcher reads one flag bit; when set, the record is
a **dictionary reference**: `getbits(bitlen(2048))` = 12-bit index, then a
25-bit byte count, then `memcpy(dst, pairs[index], count)` (`0x408aa8`).  The
pairs are the `(ptr,len)` of every record already produced in the block, kept
in a 2048-slot ring that the record loop wraps (`0x408f0d`); `bitlen(2048)` =
12 is where the index width comes from.  Such a record has no `sub` bit, and
after the copy it appends its own `flen` bytes from the filtered stream
(mode 5 literals): the output is `count + flen` bytes and the next record
starts `flen` bytes further in.  The 9 MB/`t3` cases have `flen = 0` and are
pure copies; `t4` block 1 is the general shape (`count=1500`, `flen=2500`:
copy the previous 1500-byte file, append the 2500 new bytes), which our
decoder got wrong (it ignored `flen` and stopped one block short) until the
two parts were added together.

Implemented in `sbc_parse_recs_*` (`dict`/`dref`/`dlen`) and `sbc_apply_recs`
(the ring is stored as offsets into the block buffer, so a realloc cannot
invalidate it).  The 9 MB `-m2` three-file set (identical 3 MB files) is the
first archive seen to use it: block 0 is one mode-6 record (3,000,000 bytes)
plus a dictionary reference of 145,727 bytes, for 3,145,727 bytes total — the
block spans the first file and part of the second, so its size is *not* the
current file's remaining length.

Block 1 of that archive is a single stored record (`flen=6693`, `mode=5`) with
`sub=1`, `idx=32`, `flag=0`; its expansion (2,854,273 bytes) needs the history
the vendor fed after block 0, see §8.1.  With the per-record feed in place the
archive decodes byte-exactly at `-m2` and `-m3`.

---

## 7. Filter record stream

`bits` (from `copy_bits`) is a bit-packed sequence, read MSB-first with
`getbits(buf, bitpos, n)` (first-read bit becomes result bit 0):

```
loop:
    flen = getbits(25)
    if flen == 0x1FFFFFF: end
    if consumed + flen > usize: end (bogus tail)
    coded = getbits(1)
    mode  = coded ? getbits(3) : 5
    dict  = coded ? getbits(1) : 0
    if dict:                    # dictionary reference to an earlier record
        dref = getbits(12)      # index in the block's record ring
        dlen = getbits(25)      # bytes replayed from its start
    if coded and mode == 4:
        ctrl = getbits(24)      # mode 4 control word (the dict bit is bit 0)
    if coded and mode == 7:
        m7 = getbits(12)        # predictor width
    if coded and mode in (0, 2):
        adv = getbits(1)        # mode 6 transform of the filter output (§7.1)
    if level >= 2:              # archives made by -m2/-m3
        sub = getbits(1)
        if sub:
            flag = getbits(1)
            idx = getbits(5)
    record(flen, coded, mode)
    consumed += flen
```

`flen` is the number of **input** bytes consumed by that filter. A filter may
expand (output length != flen).

### Modes

- **mode 5 / coded==0**: copy through (stored). **[VERIFIED]**
- **mode 0**: adaptive delta. Two variants:
  - **simple** (`0x424150`, `apply_mode0`): lag candidates `(2,3,4,6,8,13)`,
    weight table built from `cnt=(2,2,4,8,112)`, `vals=(15,7,3,1,**-64**)` —
    the init arrays are at `0x45e660`/`0x45e674`, and the last weight is -64,
    not -256: the deeper penalty decays four times slower, which decides when
    the state engages on noisy image data (`image7.raw` at byte 1742).
    Threshold `0x3E80`, passthrough if `n <= 0x23FF`, and the state machine
    gives up after a `0x4000`-byte trial window without a lag, which is what
    the encoder's `-m1` copy decision keys on (ENCODER.md 6.4). **[VERIFIED]**
  - **advanced** (`0x425200`): chunked delta coder with a context model and
    a lag pool. **SOLVED, byte-exact** (port in `sbc_m0adv.h`, both
    directions). The object is built by `FUN_00424fa0`:
    - `-m2`: `nmod=3, slots-after-give-up=3, first=768, min=8192, ext=1024,
      pool range=0, flag=0`
    - `-m3`: `nmod=10, slots-after-give-up=6, first=600, min=6719, ext=915,
      pool range=53 (lags 5..52), flag=1`

    Object fields: `+0x04`/`+0x08` the two scratch tables, `+0x38 nmod`,
    `+0x3c` slots kept after the copy give-up, `+0x40` first chunk, `+0x44`
    max chunk, `+0x48` chunk extension, `+0x4c` pool range, `+0x50` flag, and
    the array at `+0x58` (11 dwords, read by the getter `0x4552a0`).
    `P = max(pool range, 24)` (53 / 24): the first P bytes are copied verbatim
    and seed the contexts.

    **Slot byte counts (`+0x58`).** At every chunk end the apply adds the
    chunk's `limit` to `arr[active]` (`0x43cef8`), so `arr[s]` is how many
    bytes went through slot `s` — slot 2 is the fixed lag 3, one 24-bit pixel
    row. This is the array the mode-7 gate reads (`get(obj, 2) > n / 3`), see
    the mode-7 policy below and ENCODER.md 6.8. `sbc_m0_adaptive` keeps the
    same counts in `sbc_m0a_last_slot[]`.

    **Slots.** 0 = no predictor; 1..4 have the fixed lags 2,3,4,8; 5..10
    start with 10,16,20,12,6,24. With a pool range the slots 5..nmod are
    *reassigned at every chunk end* to the pool lags 5..range-1 whose sum of
    |original - value at distance k| over the chunk is smallest (the running
    lag and lag 8 are excluded; slot 5 keeps the running lag). That is how
    lags outside the fixed table (9, 18, 27, 33 ...) occur.

    **Contexts.** Every slot owns a 64 KiB table. Slot 0 indexes it with
    `(previous byte << 8) | byte`; slot i with `(previous delta << 8) | delta`
    where `delta = original - value at slot i's lag`. A cell is the age of
    that context: set to the current age on first sight, incremented while
    below `age + limit/2048`, and every such touch counts one score point for
    the slot. The age starts at 1, grows by 5 per selector call and wraps at
    0xFA, which clears the tables.

    **Selector** (`FUN_004248c0`, called at each 257-byte check that ends a
    chunk and at each chunk end):
    - copy slot active, or `limit < min/2` and no cut hint: measure every
      candidate against slot 0 with `thr = min(score[0]>>5, 12) + limit>>10`;
      the best slot wins if `thr + score[i] < score[0]` (running minimum);
      it is accepted unless a switch would drop a better predictor by less
      than 10 points.
    - otherwise: slot 0 wins when `score[0] < score[active]`, else the slot
      is kept.
    - the age wrap clears all tables (or, in the last branch, tables 0 and
      `active`).

    **Chunks.** `limit = first`; it grows by `ext` while the same slot is
    kept (capped at `min`) and resets to `first` on a switch. The 257-byte
    check cuts the chunk (`limit = pos - 2`: the chunk ends two bytes before
    the cut, not one) when the best slot is not the active one, or when no
    slot beats slot 0 by 9 points and the active slot is not 0. The shortened
    limit is what the selector reads (its short-chunk test and
    `limit >> 10` margin) and it is also the base the *next* chunk grows from
    (`limit += ext`), so an off-by-one here walks the whole chunk grid out of
    step.  A **third cut site** sits in the per-byte tail (0x425e9a, shared by
    the model and the direct path, after the slot-0 update and before the
    counter): past the first 128 bytes of a chunk it ends the chunk
    (`limit = pos - 1`, counter untouched, so a later cut may still fire in
    the same chunk) as soon as `score[active] > score[0] + min(pos >> 4, 0x20)`
    — the same test the chunk end hands the selector as its `d` flag.  The
    current byte is still processed, so the chunk leaves a short remainder:
    when it leaves exactly one byte, the selector gives it slot 0 and that
    byte is stored verbatim, which is why an image-like record's last residual
    byte equals its last data byte (`tail_repro`, RE_report §24). After 16 KiB
    of copy the pool is dropped and `nmod` falls back to `+0x3c` (6 / 3).

    **Direction.** Encoder: `residual = original - predictor`, decoder:
    `original = residual + predictor`; predictors are always taken from the
    original bytes. `sbc_m0_adaptive()` implements both (`enc` flag), and
    `sbc.c` uses it for `-m2`/`-m3` mode-0 records while
    `sbc_enc_filters.h` uses it for the encoder. Verified byte-identical in
    both instances: the `parity_random` set2 image at `-m3` (filter stream,
    payload 24634 and primary 24330 all match the vendor) and the set8 image
    at `-m2` (84300/84300 filter bytes, the archive byte-identical and the
    vendor's own archive decodes to the original files). The last mismatch
    was the chunk cut above: with `pos - 1` the grid slipped one byte after
    every cut and byte 70718 of the set8 image came out coded with slot 2
    instead of slot 0.  The third cut was the other half of the story: the
    `tail_repro` record's last byte is copy-coded through it, and with
    `sbc_m0adv.h` implementing all three the 469,838-byte case is
    byte-identical (155,004 B, `e1 = 719`), as are the corpus (`39/39`),
    `parity_random` (`18/18`, `24/24`), `multifile_parity` (`54/54`) and the
    decoder suite (`52/52`).
- **mode 7** (`0x429bd0`): **backward-adaptive predictor. SOLVED and
  byte-exact** on the corpus, on noisy images and on several widths.
  The record's 12-bit parameter is the row width: `W = 3*param` (image24
  stores 257 -> W=771; image7 stores 256 -> W=768). The first `W+3` bytes are
  one row: three literal bytes and then
  `out[i] = (src[i] + out[i-3]) & 0xFF`; a record of at most `W+3` bytes ends
  after that row, and `len <= 0x1f` or `param <= 1` is a plain copy
  (`0x429c0c`, `0x42a28d`).

  The rest is decoded byte by byte.  With `left=out[i-3]`, `up=out[i-W]` and
  `ul=out[i-W-3]`, there are four predictors:

  ```
  0: left          1: up
  2: left + up - ul (2-D gradient)
  3: MED(left, up, ul)             (JPEG-LS median: min/max/gradient)
  ```

  `out[i] = src[i] + predictor`; the state selects no predictor (0), `left`
  (1) or the selected predictor (2).  A selector picks the cheapest of the
  four predictors from four sliding sums of `abs(out - pred)` over a 192-byte
  window (ties keep the earlier predictor); the selector computed while
  decoding byte `i` is used for byte `i+1`.

  Four context models keep 16-bit histories of (a) `out`, (b) `out-left` and
  (c) the selected residual.  They index three 64 k saturating counters; the
  add/remove of contexts whose counter is below 8 feeds three accumulators,
  and every 256 bytes `0x42a1b0` re-evaluates the state and its threshold:
  raw residual, `left`, or the selected predictor.  The exact state machine
  is reproduced in `sbc_apply_mode7`.

  `image24` is a horizontal gradient with zero body residuals, so the old
  pure-gradient rule matched it by accident.  `packed_corpus/image7-m3.sbc`
  (image24 plus +-1 noise, 49 kB) exercises the predictor/state machine and is
  in the self-test; 256x64, 320x80 and 256x128 noise samples from the vendor
  also decode byte-exactly.

  **Which records get mode 7, and with what width.**  The choice is made in
  the mode-0 handler of the record coder (`FUN_004129b0`, case 0 at
  `0x412d8d`), right after the adaptive filter returned.  Three tests:
  the record is longer than `0x4000` bytes (the coded size is the record's
  own length), the level is `-m3` (`this+4 > 1`), and
  `get(filterobj, 2) > n / 3` — the getter `0x4552a0` returning `arr[2]`, the
  array at `obj+0x58` that holds **bytes coded per slot** (see §7, the -m3
  object).  Slot 2 is the fixed lag 3, i.e. one pixel row of a 24-bit image.
  If all three hold, `0x443e20` measures the row pitch: it scores 2400
  candidate lags (`3 * 100` .. `3 * 2499`) over the window `data+7500` with
  three phases (a geometric walk from the head, 767 positions from the middle
  every third byte, a geometric walk back from the end), keeps the 16 lowest
  scores, refines each over ten 6000-byte slices against its own lag and its
  2x/3x multiples, and returns the cheapest candidate (`lag / 3`) — or 0 when
  the best fails to beat 80 % of the worst refined score.  The record then
  carries that width as its 12-bit parameter.  Every term of the score is
  `|a - b|` through the identity table at `0x4827bf` (the bytes in front of it
  are 1, 2, 3... so negative differences cost the same), and the encode side
  is ported as `sbc_enc_m7_search` (`tools/m7_parity.py`).`
- **mode 4**: text compound filter (`ctrl=0xAC`), implemented in Python and C
  for the observed code-* variant. It consumes 24 bits after the 3-bit mode
  (`getbits(0x18)` at `0x408e0a`). The corrected code-* record list is one
  `(flen=39270, coded=1, mode=4, ctrl=0xAC)` record; the former mode-7
  `(flen=172)` was parser desynchronization. For this control word the
  transform maps each input byte through the vendor 256-byte substitution
  table, drops one padding space after mapped newlines, and expands tokens
  `0x80..0xFC` with a fixed word/letter-pair dictionary. This yields exactly
  45270 output bytes (`usize`, +6000). The `_work/ctrl` probes generalize
  the remaining control bits (below).

  The map table was dumped from the vendor routine at `0x40780c`; the token
  dictionary and newline-padding rule were checked against the vendor's
  `code.c` output. Python `apply_mode4` and C `sbc_apply_mode4` produce the
  expected file byte-for-byte for code-m1/m2/m3. **[VERIFIED for ctrl=0xAC]**

  **Code-* pipeline correction:** with the fixed 20-symbol payload Extra
  model, code-m1 has `e1=1720`, `e2=0`; Python's `L` is byte-exact against the
  vendor PPM destination at `0x427f90`, and inverse-BWT output matches the
  vendor filter input at `0x408e90` (39270 bytes). C matches the saved vendor
  captures too. **[VERIFIED Python/C stages and all final code-* outputs]**
  The bit7/bit3/bit2 structure is generalized through the `_work/ctrl`
  probes (the vendor's `ctrl>>1` bit map is in the next paragraph).

  **Ctrl samples and the prose stage (`0x408060`).**  `_work/ctrl/t01`
  (`ctrl=0xBC`), `t02` (`0xFC`), `t04` (`0xBC`) and `t06` (`0xDC`) are prose
  streams.  A vendor dump on `t01` shows `0x408060` turns the 223,621-byte
  filtered stream into 219,525 bytes before the token expander; the only
  changes are 3,199 space-to-LF rewrites and 4,096 dropped spaces after a line
  break, so the map and token table are correct.

  `0x408060` is a **line-break reconstruction pass**, and its model is now
  reversed.  The line-length code is the block's `e2` field: `e2` raw bytes
  follow the `e1` PPM tail, the first byte is an implicit `0`, and the range
  decoder reads them **backwards** (last four bytes are the initial code word,
  MSB first).  The model has 19 symbols, `freq=1`, `total=19`, increment 7,
  max frequency 768 and max total 8192; it halves every frequency when either
  cap is passed.  The range decoder keeps 32-bit `low/range/code`,
  `unit=range/total`, `value=(code-low)/unit`, then
  `low+=unit*cum`, `range=unit*freq`; it renormalises while the top byte is
  settled (xor <= 0xFFFFFF) or `range <= 0x3FFF`, pulling the preceding byte
  and shifting `code`, `range` and `low` left by 8; in the low-range case
  `range=(-low)&0x3FFF` first.  A space is decoded on the first space of a
  line (`edx=0x13`); symbol `0x12` means "do not break", otherwise the space
  is rewritten to LF/CR once `cnt >= min(edx+7,0x18)`, then `edx=0x13`,
  `cnt=0`.  A target byte drops the space after it.

  The vendor receives `ctrl>>1` in `0x406940`: the pass is header bit `0x10`,
  the CR target is header `0x40`, the CR/CRLF fold is header `0x60` and the
  LF/CR space drops are header `0x20`/`0x40`.  The standalone replay
  `_work/m4_line_model.py` and C reproduce `t01-stageA.bin` and all 15
  `_work/ctrl` outputs byte-for-byte; the hidden `e2` also has to be added to
  the block trailer offset (`next_pos` and the CRC).  **[VERIFIED: t01..t15,
  51/51 corpus, 15/15 text variants at 300 kB and 3 MB]**
- **mode 6** (repeat): `7B F0 <len>` copies `len+16` bytes from the last
  position recorded for the two-byte output context; forced marker escapes and
  the block-wide table are described in ENCODER.md §6.9. **[VERIFIED]**
- Other modes (1, 2, 3): not observed in any vendor archive.

### The `adv` bit

A mode-0 record whose `adv` bit is set does **not** carry the filter's output:
when the mode-0 filter accepts the record only weakly (`r = 1`: at least 4096
bytes coded with a lag, but no more than a tenth of the record at `-m1`
/eighth at `-m2`/`-m3`), `0x412af0` runs the mode-6 transform `0x411bb0` over
the filter's *own output*, with a fresh table and cap
`len - min(len>>7, 0x1000)`.  When the whole stream fits (`out <= cap - 6`) the
record stores that shorter stream, sets `adv = 1` and keeps `mode = 0`; when
it does not fit, the record stores the filter output with `adv = 0`.

`flen` is therefore the length of the *repeat* stream.  The decoder expands it
with the mode-6 decoder (`0x4083a0`, block-wide table and output buffer, exactly
like a mode-6 record) and then runs the mode-0 inverse over the whole expansion;
the record's output length is the expanded length, not `flen`.

Measured on a 120000-byte input (`512` random bytes, a 6000-byte `ab` run, a
1000-byte random block repeated): `-m1` writes `len=7628 mode=0 adv=1`, the
archive is 1854 bytes and both this decoder and the vendor's extract it back
byte-exactly.  The `adv` bit only appears at `-m1` in practice: the adaptive
filter's verdict also has a weak case on paper, but every `-m2`/`-m3` probe
(204-case battery included) comes out strong or refused.  **[VERIFIED at
-m1; -m2/-m3 implemented from the same code path, no vendor case yet]**

---

## 8. Compression levels (m1 / m2 / m3)

**The header does state the level**: it is `extra3`, the `u(3)` read right after
`method` (§2). Value `0`, `1`, `2` = `-m1`, `-m2`, `-m3`. **[VERIFIED]**
on all three 9 MB sets and on the whole `packed_corpus` (`image-m1/m2/m3`,
`nested-m1/m2/m3`, ... all follow the pattern).

Earlier sessions missed it because `extra3` was assumed to be a spare flag and
the level was brute-forced against the trailer checksum; that works but it is
slow and, more importantly, it made the second-stage filter unusable (its
variant depends on the level, see §8.1). `sbc.c` now reads the level from the
header and only falls back to trying the other two values.

What the level changes:

| level | mode-0 delta parameters | second-stage filter |
|-------|-------------------------|---------------------|
| m1    | `simple` (no options)   | no                  |
| m2    | `advanced 24,3,768`     | yes, variant 0      |
| m3    | `advanced 53,10,600`    | yes, variant 1      |

**[VERIFIED]**

---

## 8.1 Second-stage filter (`-m2` / `-m3`)

A record whose header carries the `sub` bit (§7) is filtered twice: the mode
filter produces its usual output, which a second, *stateful* filter then
expands. It is the only filter with state that survives across blocks, which is
why it stayed undecoded the longest: getting one block wrong corrupts every
following block of the archive.

Vendor code: `0x408980` (per-record wrapper), `0x4231a0` (configure), `0x423c60`
(expand), `0x423540` (feed history), `0x4238a0` (feed call at block end),
`0x4232c0` (table rebuild).

### Record bits

Appended to the mode-specific fields, for `-m2`/`-m3` archives only:

```
sub(1)
sub == 1: flag(1) idx(5)        # the same bits 0x408980 reads first
```

`idx` is a 5-bit field copied verbatim into `obj+0x4014`; the expander uses
`obj[0x4014] - 1` as the length base (traced: `idx=32` -> `obj[0x4014]=32` ->
base 31; `idx=4` -> base 3).  `flag` is *not* the level selector below — it is
the 4-byte alignment switch, always 0 in the corpus.

### The two variants

| variant | prologue | hash | table | ring |
|---------|----------|------|-------|------|
| 0 (`-m2`) | 3 bytes | 17 bits, `(d[-3]<<13) ^ (d[-2]<<8) ^ d[-1]` | 131072 slots | 1.5 MB |
| 1 (`-m3`) | 8 bytes | 21 bits, `(w4 ^ w4>>13) ^ ((w8 ^ w8>>15) << 11)` with `w4`/`w8` the little-endian dwords at `d-4`/`d-8` | 524288 slots | 24 MB |

**[VERIFIED]** Vectors: `_work/subfilter/in{1,2}.bin` -> `out{1,2}.bin` (m2,
2305 -> 2890273 and 2635 -> 3018000), `tools/sub_test.py`; m3: `len 216 ->
524288` and `len 3040 -> 2762546` captured the same way.

### Expansion

Markers are `03 C5` (fixed, whatever the record says). Output starts with the
prologue copied from the input; then, byte by byte:

```
literal c                    -> emit c
03 C5 00                     -> emit 03 C5, skip 3 input bytes (6 when the
                                alignment flag is set)
03 C5 L, L < 0x80            -> copy (L + base) *dwords* from the ring
03 C5 L, 0x80 <= L <= 0xBF   -> copy ((L & 0x3F) + base + next<<6) dwords
03 C5 L, L >= 0xC0           -> copy ((L & 0x3F) + base + next<<6 + next2<<14)
                                dwords
```

`base = idx - 1`. The copy source is `ring + table[hash of the output bytes just
emitted]`, read 4 bytes at a time and wrapping at the ring end; the vendor keeps
an 8-byte mirror of the ring start past the end so a read that straddles the
boundary sees the first bytes again.

### History

The history is fed **once per record output, in order**, and only after the
block's checksum accepted it.  The object keeps a list of `(ptr,len)` pairs
(ptrs at `+0x0`, lens at `+0x2000`, count at `+0x4000`): `0x408980` appends one
entry for every record it produces, and `0x4238a0` flushes the list at block end
through `0x423540`.  **Dictionary references are never registered**, so their
bytes do not reach the ring.  The 9 MB `-m2` set shows it: block 0 is
3,000,000 (mode 6) + 145,727 (dict reference) bytes, yet the ring fed after it
holds only the last 1.5 MB of the 3,000,000-byte mode-6 output (i.e. of the
first file) — feeding the whole 3,145,727-byte block instead rotates the ring
and makes block 1's expansion diverge at its 10th byte.

That distinction cost several wrong attempts.  The per-record hook `0x408f39`
is *not* the feed: it only runs for mode 1 and calls `0x4230a0`.  And feeding a
rejected (checksum-mismatched) attempt poisons the following block.

Per feed:

```
if len <= 0x7F: return
if len > ring_size: drop the oldest bytes, keep the last ring_size
copy at write position, wrapping
mirror ring[0..8] at ring[ring_size..]
if bytes_fed_total > 3 * ring_size: zero the table and rehash the whole ring
else: hash the newly written positions, starting at max(wp, prologue);
      a wrapped write is hashed in two runs ([start,size) then [prologue,wp))
```

### Verification

`unsbc`-identical output for: `set-m2.sbc` (9 MB, 3 blocks), `set-m2-b2`,
`set-m2-b5`, `set-m2-b10` (1/3/5 MB blocks), `one-a.txt-m2`, `one-c.txt-m2`,
`big-m2`, `set-m3.sbc` (9 MB, variant 1), `one-c.txt-m3`, and the three-file
3x3 MB set at `-m2` (block 1 = `idx 32`) and `-m3`. **[VERIFIED]**

The no-sub profile now decodes byte-exactly too: `_work/gtbig/big3-m3.sbc`
(and `big3-m3-hr.sbc`) is a single 3 MB block where **all** records have
`sub=0` (mode 6 + stage 2, `flag3=1`, `e1=5527`), and the 36 MB uppercase
`code.c` archives
(`big-m3.sbc` / `big-m3-hn.sbc`, block 0 no-sub, block 5 with a 25-one run
inside a length) also match with and without a checksum.  Their earlier
failure was in the filter-record parser, not in this history: the old
terminator search accepted a short two-record parse.  `sbc_parse_recs_greedy`
reads the records forward from bit 0 and stops at the real terminator, which
fixes the block.

---

## 9. Trailer

`data[-7:-5]` = stored checksum (big-endian).
`data[-5:]` = 5 bytes still partially unknown; they survive all current
decodes and are not consumed by the payload. Investigate if they encode level
or flags. **[OPEN]**

`coded_start = len - 7 - e1` ties the tail length to the header's `e1`.

---

## 10. Method byte (observed)

`window_size(method) = (method<<19)+0xFFFFF`, `nsyms = size_to_nsyms(...)`.

For **stored** archives the field tracks the block size the encoder picked:
`method = (block_size - 1 MB) / 512 kB`, and the payload's shared `Extra` model
uses `nsyms = bitlen(window_size(method))` (20..22).  The block size is the
smaller of `(N+1)*512 kB` (`-bN`, default `b5` = 3 MB) and a value derived from
the total input, `((total + 512 kB) / 512 kB + 1) * 512 kB` (the `+1` applies
even on an exact multiple).  Measured on random single-file archives from
400 kB to 5 MB, with and without `-bN`:

| total | -bN | block size | method |
|-------|-----|-----------|--------|
| 900 kB | 5 | 1.5 MB | 1 |
| 1.5 MB | 5 | 2 MB | 2 |
| 2.5 MB | 5 | 3 MB | 4 |
| 4 MB | 1 | 1 MB | 0 |
| 4 MB | 2 | 1.5 MB | 1 |
| 4 MB | 4 | 2.5 MB | 3 |
| 4 MB | 5 | 3 MB | 4 |
| 4 MB | 10 | 4.5 MB (total-derived) | 7 |

Compressed archives write **other** values there (67-byte text: 52; pattern:
56; records: 62; eng: 41 ...), i.e. the byte is a method/model selector whose
meaning for `e1 != 0` payloads is still **[OPEN]**.  The table below is only a
fingerprint of the corpus sources.

| source | method |
|--------|--------|
| pattern | 56 |
| records | 62 |
| image24 | 3 |
| image | 7 |
| biased | 22 |
| hello | 48 |
| empty | 16 |
| zeros | 28 |
| random | 6 |
| code | 2 |
| nested | 42 |
| mixed | 4 |
| eng | 41 |

**[VERIFIED per archive]**

---

## 11. Corpus

Sources in `corpus/`, packed archives in `packed_corpus/` (`-m1/-m2/-m3`).
Sizes:

| source | size |
|--------|------|
| pattern.bin | 192000 |
| records.bin | 240000 |
| image24.raw | 98304 |
| biased.bin | 120000 |
| zeros.bin | 200000 |
| hello.txt | 67 |
| code.c | 45270 |
| image.raw | 65536 |
| eng.txt | 20359 |
| mixed.bin | 35003 |
| random.bin | 120000 |
| empty.dat | 0 |

---

## 12. Reference: key disassembly addresses

- `parse_header` `0x403b00`; per-file loop `0x403dab-0x4044f9`.
- method read `0x4044f9`; extra3 `0x404515`; level `0x40451a`.
- payload filters walker `0x408e90`; `getbits` `0x40a040`; filter add `0x408a00`.
- mode 0 simple `0x424150`; mode 0 advanced `0x425200`; mode 4 `0x406940`
  (subs `0x407d20`, `0x408060`, `0x406ed0`).
- BWT `0x435df0` region; flag3 expand `0x40ea90`; `0x40a690`/`0x40a7d0`.
- Forward BWT `0x4225c0` (entry), `0x421ac0` (n < 0x8000), `0x421cc0`
  (n >= 0x8000, two-byte buckets), rotation sort `0x423010`, `< 11` handler
  `0x424f90`, insertion helper `0x424da0`, `0x445bd0`/`0x445d70`/`0x445cb0`
  (counts, histogram, prefix sums).  See §5 for the tie-order limitation.
- Stage-2 (sub) expansion `0x423c60`, object init `0x4231a0`; the record
  dispatcher `0x408a00` reads the repeat bit of a mode-0/2 record before the
  filter and expands the payload with the mode-6 decoder `0x4083a0` first.
- CRC: vtable `0x4429a8`; init `0x422ee0`; update `0x422ea0` -> `0x435df0`;
  getter `0x422e8c` (`xor eax,0xffff`); table built at `0x448a60`/`0x448a68`
  with poly `0xA001`.
- Vtables: `0x443198` (advanced), `0x4431b0` (simple mode 0).

---

## 13. Open format questions

1. ~~`e1 != 0` tail entropy model (`unique_fill` / PPM) is not fully correct
   for image/eng/nested/mixed.~~ **RESOLVED (2026-10-28): it was never the tail
   model.**  The reproduction below (`python3 tools/tail_repro.py`: the corpus
   files concatenated, doubled and cut to 469,838 B, packed `-m2`) is now
   **byte-identical** (155,004 B, third block `pos=154259`, `vlq=2716`,
   `primary=1946`, `flag3=1`, `e1=719` as the vendor writes it).  The block
   failed because its filter *record* differed in one byte: the mode-0
   adaptive filter has a **third cut site** (0x425e9a) that ends a chunk as
   soon as the running slot's score gets `min(pos >> 4, 32)` points ahead of
   the copy slot's, once past the first 128 bytes — leaving a one-byte chunk
   that the selector hands to slot 0, so the record's last byte is stored
   verbatim.  Our port only had the two counter-block cuts and filtered that
   byte with the running slot; the PPM/BWT layer then coded a stream of the
   same length, which is why it looked like a tail-entropy difference.  See
   `ENCODER.md` §6.8 and `RE_report.md` §24.  Code-m1/m2/m3 remain verified
   through the full mode-4 pipeline; their PPM/BWT stages are byte-exact (see
   §7).
2. ~~Generate a real `flag3 == 2, extra16 > 0` archive~~ **RESOLVED**: two
   vendor-made samples (`extra16=0` and `extra16=1`) are byte-exact; the
   decoder applies the marker passes in reverse order, then the default pass.
3. ~~`flag3 == 1` LZSS stops early~~ **RESOLVED: it does not; our LZP is
   byte-exact. The zeros after ~775 are genuine LZP output.**
4. ~~mode 4 for ctrl=0xAC and mode 7 exact semantics~~ **RESOLVED** (see §7):
   the code-* and prose variants decode byte-exactly, and mode 7 is the full
   backward-adaptive predictor.  The last encoder-reachable shape,
   `ctrl=0x0C` (vendor raw `0x006`), is the token-less record of item 10 and
   is implemented on both sides now (§6.14 of `ENCODER.md`).
5. ~~Mode-4 implicit line breaks (`0x408060`, prose ctrl samples)~~ **RESOLVED**
   in `RE_report.md` §21: the 19-symbol range-coded line-length model is
   ported (`sbc_mode4_lines`).
6. ~~Trailer 5 bytes~~ **SOLVED** (see §4): `VLQ(0)` followed by the 32-bit
   big-endian rolling hash.
7. ~~Why random (incompressible) uses `e1 == 0` but the stored block does not
   inverse-BWT correctly beyond a few bytes.~~ CLOSED: the stored block starts
   at `rc_pos + 2` (see §5).
8. ~~Mode-7 row width `W`~~ **SOLVED**: `W = 3*param` from the record's 12-bit
   field; a record shorter than `W+3` is one left-delta row (0x42a28d).
9. ~~Mode-0 **advanced** parameter selection is not universal.~~ **RESOLVED**
   by the port in `sbc_m0adv.h` (§7). The per-257-byte controller, the slot
   pool, the context-age tables, the chunk-cut offset and the two object
   parameter sets are reproduced; on the `parity_random` set2 image (42000 B,
   `-m3`) the filter stream, the 24634-byte payload and the primary all match
   the vendor, the set8 image (84300 B, `-m2`) matches all 84300 filter bytes
   and its archive is byte-identical, and the archives whose advanced records
   used to fail the block CRC (set2 `-m3`, set8 `-m2`/`-m3`) now decode and
   extract byte-exactly.
10. ~~The dense mode-4 `ctrl=0x0C` shape~~ **SOLVED**: `0x406940` skips its
    `0x407d20` token pass when the control word has no `0x80` bit, so such a
    record is the bare byte map (`inv[map][input]`, flen == the block size).
    The decoder accepts it (`sbc_apply_mode4` implements the whole
    control word and refuses no flag combination) and the encoder writes
    it — including the vendor's rule that the bit is *cleared* when the token
    pass emits no code, which is what turns the `a b c ...` prose into a
    `0x0C` record instead of `0x8C`.  Reproducers, both byte-identical at
    `-m1`/`-m2`/`-m3`: 200 kB of `a b c d ... z ` (150 B archives) and 200 kB
    of ASCII with a NUL after every byte (the `wide` case of
    `tools/m1_probe.py`, 167/168/168 B).  See ENCODER.md §6.14.

---

## 14. Verified vendor equivalence (session 2 and continued)

For code-m1/m2/m3, Python and C now both decode the single mode-4 record
(`ctrl=0xAC`) to `corpus/code.c` byte-exactly (45270 bytes). The C
implementation was checked by extracting each archive and comparing the
result with `cmp`; the Python full decoder was checked against the same
expected bytes. The mode-4 substitution table is captured from vendor
`0x40780c`; its token expansions and newline padding behavior produce the
vendor output.

---

## 14.1 Earlier verified vendor equivalence (session 2)

For `image24-m3.sbc` we compared our Python/C pipeline against the live
vendor decoder (`unsbc.exe` under Wine + gdb) byte-for-byte:

| stage | vendor location | result |
|-------|-----------------|--------|
| stage2 + inverse BWT (`raw`) | input of `0x40ea90` | **identical** (2518 B, 1391 non-zero) |
| LZP / flag3 output (`vout`) | output buffer of `0x40a7d0` (`0x015a0020`) | **identical** (98304 B, 1489 non-zero) |
| final image | `image24.raw` | **identical** after `sbc_apply_mode7` |

Header of `image24-m3.sbc`: `vlq=2518 prim=1869 nbits=68 e1=330 flag3=1
extra16=0 rcpos=48 len=387 usize=98304`; single filter record
`(flen=98304, coded=1, mode=7)`.

The image24-m3 verification closed this path: `sbc_apply_mode7(vout)` ==
`corpus/image24.raw` (98304/98304); it remains in the 24-case self-test.

### Mode-7 derivation (corrected)

The first derivation used image24 only.  Its LZP output `vout` is zero for
most of the body (`vout[i] == 0` from `i~775`), so **any** predictor that
reproduces a horizontal gradient matches that archive; the old `W=768`
gradient rule was an accidental fit, not the format.  The live function
`0x429bd0` shows the first row is `3 + 3*param` bytes (774 for image24,
param=257), and the body is `out = src + predictor` with the per-byte
selector and three-state machine described in §7.  Two direct oracle runs
prove it: a 2000-byte random residual stream and a 98304-byte noisy image,
both patched into the vendor function under gdb, match the C port byte for
byte; the real `image24`, `image7`, 256x64, 320x80 and 256x128 vendor
archives all decode exactly.

Note: Python `flag3_expand` remains an unverified stub for `flag3==1`; only
the C `sbc_lzp_decode` path has been compared byte-for-byte with the vendor.
Use the captured LZP output as the Python-side mode-7 input when testing that
path.

---

## 15. Tooling usage (for a fresh session)

All harnesses live in `/workspace/tools/` (copied from `/tmp/opencode`):
`text.asm` (full 4.2 MB disassembly), `m0adv.asm`, `ppm.asm`, `rdis.py`,
`auto.py`, `stage2_test.py`, `lzp_test.py`, `ml.sh`, `capture.sh`,
`wintrace.sh`, `gdbwrap/`, `trace.gdb`, plus oracle dumps.

Build / self-test the C decoder:

```bash
cd /workspace
gcc -O2 -Wall -Wextra -o sbc sbc.c -lm
./sbc                       # runs the 24-archive self-test
./sbc packed_corpus/x.sbc /tmp/outdir   # extract one archive
```

Vendor oracle (Wine, 32-bit prefix):

```bash
wineserver -k; sleep 1
WINEPREFIX=/root/.wine32 wine unsbc.exe x packed_corpus/image24-m3.sbc -t/tmp/opencode/oracle_x -y
```

Live tracing with gdb attached to winedbg (the wrapper strips `target remote`
and reuses the winedbg connection so breakpoints hit at image VAs):

```bash
cd /workspace
PATH=/workspace/tools/gdbwrap:$PATH WINEPREFIX=/root/.wine32 \
  winedbg --gdb unsbc.exe x packed_corpus/image24-m3.sbc -t/tmp/opencode/oracle_x -y
# then gdb reads commands from -x /tmp/opencode/trace.gdb (or the wrapper default)
```

Buffer capture inside gdb: use `dump binary memory FILE START (START+N)`
(the `x/16xb` + computed-end form fails with a syntax error). Example
breakpoint at the LZP call:

```gdb
break *0x40f9d1
commands
silent
set $outb=$edx
set $lenp=$ebp-0x14
continue
end
# on a second breakpoint just after the call:
#   printf "outlen=%u\n", *(unsigned int*)($lenp)
#   dump binary memory /tmp/opencode/lz_out.bin $outb ($outb+98304)
```

Note: in the callee `0x40ea90`, arg4 is `&caller_local`; the input length is
`*(arg4)` and the output length is written back to the same location.

PE VA -> file offset (base 0x400000): `.text` VA `0x1000` raw `0x400`;
`.rdata` VA `0x3a000` raw `0x37a00`; `.data` VA `0x39000` raw `0x37800`;
`.bss` VA `0x44000`; `.idata` VA `0x4e000` raw `0x40e00`.

Wine artefacts: prefix `/root/.wine32`; run `wineserver -k` before a fresh
trace. The C decoder currently contains temporary `SBC_DBG` fprintf
instrumentation (backup `/tmp/sbc.c.bak`) — remove before release.

## 16. Multi-block / multi-file payload (session 7)

The payload after the header (offset `hdr_pos`, see §5/§15.2) is not one
compressed stream but a **sequence of independent blocks**:

```
block := <vlq>                     # BWT length of this block (read_vlq)
         <RC stream>               # primary, nbits, bit-stream, flag3[, u16]
                                 #   then e1 = payload bytes, e2 = extra
         <payload>                 # e1 bytes (e1 == 0 -> stored, len = vlq)
         <u16 be CRC16 of output>  # trailer, NOT part of the next header
```

* Header fields 1:1 with §4, but the RC keeps running **across** blocks for one
  thing only: the `Extra` model. It is initialised once (first block) and the
  same `freq[]/total` state is reused by every following block, so `e1`/`e2`
  stay small. `nsyms` is 20 or 21 depending on the archive/level; try both.
* The 2-byte value after the payload is **CRC16/ARC (poly 0xA001, init 0xFFFF,
  xorout 0xFFFF) of the block's decoded output** (i.e. after BWT, filter
  records and `flag3`). This is what lets the decoder pick the ambiguous
  mode-0 variant (plain vs advanced) *per block* instead of per archive.
* With checksums on (`-hr`) there is also a 2-byte **integrity record before
  the payload**, and the archive header carries a digest; see §17.
* Normally a block fills exactly one file: blocks are concatenated until the
  file's declared size is reached, then the next file starts. Small files are
  one block, `image.raw` (192000 B) is 3 blocks. In "solid" archives a single
  block spans several files (see the last subsection).
* `flag3` is applied to the *whole block output* (LZP with the block's total
  output size as `usize`), not to each filter chunk.

Result: **51/51 corpus archives decode byte-exactly** (was 40/51) in ~1.3 s
total, and the 24 built-in self-tests pass.

### Solid archives (`*-of`, `*-os`, …): solved

Those pack **several files into one block**, so a block's output overflows the
running file. A block is now decoded against the sum of the *remaining* file
sizes (the `span` pass of `sbc_decode_stream`, only tried when the normal
per-file pass fails), and its output is copied across the file boundaries in
archive order, as many bytes as each declared size allows. The block needs **no
size field**: the LZP + filter chain ends on its own, which the block CRC
confirms.

The last bug was not in the block layout but in a guard: `sbc_run_stage2` had a
hard iteration cap of 200000. That is plenty for small blocks but too low for a
246853-byte block (block 1 of `nested-m3-os` needs ~300k iterations), so
`stage2` returned -1 and the whole stream was rejected. The cap is now
`200000 + 8*n` — still a guard against a desynced stream, but scaled to the
block size.

Measured block outputs (equal to the vendor's `status` at `[ebp-0x14]`):
703066 for `nested-m3-of` block 0, and 432868 + 372506 = 805374 for
`nested-m3-os`. No prefix sum of the file sizes matches those numbers, because
a block output is the concatenation of *post-filter* chunks, not of whole
files.

## 17. Checksums (`-hr`, the vendor's default)

The two 8-bit fields after the magic are the **integrity and verify checksum
types** (`hdr->crypto` / `hdr->csum` in `sbc_parse_header` is a misnomer):
`0/0` = `-hn`, `1/1` = `-hr` (CRC16), `2/2` = `-hc` (CRC32), and so on up to
`7/7` (SHA256); see 17.1 for the whole table.  `unsbc v` prints them as
`Checksums (integrity/verify): CRC16/CRC16`.

All CRC16 records below are CRC16/ARC (poly `A001`, init `FFFF`, xorout
`FFFF`), stored **big-endian**.

```
header_digest = CRC16 over  LE32(nfiles)
                           per file: name symbol indices (SBC_ALPHABET codes,
                                     no terminator), flag(1), LE32(dt),
                                     LE32(size), 00*4
   -> coded as two u(8) right after the file entries, before method/extra3
block:
   integrity (before payload) = CRC16 over LE32(primary), 00 00 (e1/e2),
                                ceil(nbits/8) record-bit bytes, payload bytes
   verify    (after payload)  = CRC16 of the decoded block output
```

The integrity record covers the block header fields *and* the stored stream, so
`unsbc` reports *Input data is corrupted!* when either is damaged; the verify
record failing gives *Block checksum verify failed!*.  For a stored block below
512 B the explicit copy record carries one extra zero filter bit at `-m2`/`-m3`
(56 bits instead of 55), which shifts `nbits` and the following bytes.

### 17.1 The other digest types

Same layout, same feed, only the width and the function change.  Verified
against `sbc.exe` (byte-identical archives for all of them) and against
`unsbc v`, which prints the matching `Checksums (integrity/verify): X/X` line:

| type | switch | algorithm | record |
|------|--------|-----------|--------|
| 2 | `-hc` | CRC32 IEEE, reflected poly `0xEDB88320`, init/xorout `0xFFFFFFFF` (zlib) | 4 |
| 3 | `-ha` | Adler32, `a=1,b=0`, mod 65521 (zlib) | 4 |
| 4 | `-hs` | Sum32, see below | 4 |
| 5 | `-hm` | MD5 (RFC 1321) | 16 |
| 6 | `-h1` | SHA-1 (FIPS 180-1) | 20 |
| 7 | `-h2` | SHA-256 (FIPS 180-2) | 32 |

The record width is `0 / 2 / 4 / 16 / 20 / 32` bytes for types `0 / 1 / >=2`
with 4 for 2..4, and the payload starts at `hdr_pos + width` (the header
digest of a `-hn` archive is empty, so the payload follows the range-coded
block header directly).  All records are big-endian.

**Sum32** (type 4) is the vendor's own toy checksum.  Update routine `0x4227b0`,
final `0x4229b0`, factory case at `0x401c3c` (24-byte object, vtable
`0x442b28`):

```
A = 1, B = 0, word = 0, cnt = 0, n = 0
for each byte b:                       # n counts every byte
    word = (b << 24) | (word >> 8)     # MSB first, i.e. LE32 of each 4 bytes
    if ++cnt == 4: B += A; A += word; cnt = 0
final:                               # pad the partial word with zero bytes,
    n = byte count before padding    # which shifts the held bytes down
    value = (A + B) ^ n
```

Measured: `abcd` → `64636267`, 4 zero bytes → `00000006`, 8 zero bytes →
`0000000b`, 64 zero bytes → `00000051`, `01..08` → `100d0a02`, 8 × `61` →
`2424242e`, `61 62 63` → `00030200`.  Each block's digests start from a fresh state, so `n` is the
block output length.
