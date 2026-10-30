# SBC encoder — reimplementation notes

Goal: a pure-C encoder that produces **bit-identical** archives to
`sbc.exe` 0.970 for every profile it supports.

Current state: for **stored blocks** (incompressible data) the encoder is
byte-identical to the vendor for all eight checksum types
(`-hn`/`-hr`/`-hc`/`-ha`/`-hs`/`-hm`/`-h1`/`-h2`; `-hr` is the default, as in
`sbc.exe`), for all three levels, on single- and multi-file archives,
multi-block ones included, with `-ad` **and** with the default adaptive split
(§4.3).  Validated by `tools/enc_matrix.py` (72/72 random multi-file sets of
1 B .. 1 kB per file, 1..3 levels x the eight `-h` types), `tools/enc_big.py`
(73/73 multi-block `-ad` archives up to 3.1 MB), `tools/csum_test.py` (all
eight digests, round-trip + corruption) and by the real `unsbc.exe`, which
verifies and extracts our archives.

Compressed blocks are written too (§6.5): filter -> LZP -> BWT -> stage2, the
record list, the store/compress decision and the stored-BWT fallback all match
the vendor.  `tools/block_archive_test.py` compares whole archive bodies for
the corpus cases whose blocks are single mode-0/mode-5 records and gets
**20/20 byte-identical** (compressed, stored and stored-BWT blocks), and the
real `unsbc.exe` tests and extracts those archives to the original bytes.

The **mode policy** is measured and implemented (§6.4, §6.5, §6.11) and is
the default (`SBC_POLICY=0` turns it off and writes stored blocks;
`SBC_COMP=<mode>` forces one mode): `-m1` filters when the simple filter's
state machine engages, `-m2` copies when the advanced filter's lag search
found no lag, `-m3` takes the cheaper of copy and mode 0, and text/repeat
blocks go to modes 4 and 6 (`tools/m1_probe.py`'s 204-case battery is clean at
all three levels, `-ad` included; §6.14).  The `-m2`/`-m3` **second stage** (`sub`) is implemented as well
(§6.12), `-m3` records follow the vendor's 512 kB window rule, and all block
structures are implemented (§6.13).  What is left is the per-unit *content
analysis* of `0x4132c0` on `-m3` blocks (§6.12): it only changes a record's
boundary when a 512 kB unit boundary starts with a format magic (`II`/`MM`
as TIFF, `BM`, ...) or when its statistical classifier fires.  One 36 MB
text probe hits it; every randomized suite is byte-identical without it.

The layer dumps also found and fixed two **decoder** gaps on large/common
texts, both validated by the block CRC rather than by inspection:

* `ctrl` bit `0x08` is an encoder-side parameter, not a mapping change (the
  same content gets `0xAC` at 2.2 MB and `0xA4` at 3.2 MB) — masking it off
  makes a 3.2 MB `-m1` archive decode and re-extract byte-exactly.  The
  encoder now reproduces it: the mode-4 chooser's bit `0x04` (= record
  `0x08`) is dropped for a segment of `0x2FF800` bytes or more.  Bisected at
  the default 3 MB block on two contents of different shapes, both flip
  exactly there (periodic lines: `0xAC` at `0x2FF7FF`, `0xA4` at `0x2FF800`;
  prose: `0x8C`/`0x84`); the chooser sees the whole record, not the 512 kB
  analysis window.  Other block sizes are untested;
* `ctrl` bit `0x40` is CRLF mode: the encoder keeps the CR and drops the LF,
  so the decoder emits `\r\n` per CR and the `0x20` space-merge keys on `\r`
  too.  `code.c` converted to CRLF (300 kB and 2.5 MB) now decodes exactly.

* **mode 6** (uppercase text; `code.c` uppercased: 300000 → 13398 filtered
  bytes) is a repeat-from-context filter: `7B F0 <len>` copies `len+16` bytes
  from the last position recorded for the two-byte output context, and only
  literals update that 64 k-entry table.  `sbc_apply_mode6` decodes it
  byte-exactly on `rep1`, `line2` and uppercased `code.c`; see FORMAT.md §6.

* **large repetitive blocks** decode now.  Two separate bugs behind the old
  "diverges at 558334 B" symptom: the `flag3` LZP hash mask is `0x1FFFFF`, not
  `0xFFFFF` (the wrong mask made large blocks copy from the wrong slot), and
  mode 6's table is block-wide with absolute positions that survive records
  (the vendor writes record *k* into `out + k*0x80000` of one buffer).  A 3 MB
  uppercased `code.c` decodes byte-exactly at all three levels, and so does
  the whole `tools/text_variants.py` suite at 3 MB.

* **dictionary-reference records** are implemented on both sides: a record can
  replay up to 2^25 bytes of an earlier record's output (12-bit ring index +
  25-bit count), which is how the 9 MB three-file `-m2` set codes its identical
  files and how `t3`/`t4` copy one file into the next.  The encoder detects the
  prefix (1024 bytes or more, against the block's earlier records), writes the
  tail only, and skips the filter and second stage for that record.

Both sides now also handle the **token-less mode-4 record** (`ctrl` without
`0x80`, e.g. `0x0C`): the vendor's `0x406940` skips the token expansion there
and the record is the bare byte map, which is what the vendor writes for text
whose words the table cannot match (§6.14).  Remaining decoder gaps: the
`0x406940` shapes carrying the low bits `0x01`/`0x02` and the mode-7 row width
for records shorter than `W`.  The
`flag3 == 2` LZP cascade is verified on vendor-made `extra16=0` and
`extra16=1` archives (`_work/f32/ereal0-m3.sbc`, `ereal1-m3.sbc`), and the
9 MB set's second-stage block (`sub=1`, `idx=32`) decodes byte-exactly.

---

## 1. CLI surface of the legacy encoder

`sbc.exe` (the extractor is `unsbc.exe`):

```
sbc c [-m123] [-b1..63] [-ad|-ab|-af] [-on|-of|-oa|-oz|-os|-ub]
      [-hn|-hr|-hc|-ha|-hs|-hm|-h1|-h2] [-c<alg> -s<pw>] archive files...
```

* `-m1/-m2/-m3` = level; `-bN` = block size `(N+1)*512 kB`, default `b5` (3 MB).
  Implemented: the effective block size is `min((N+1)*512 kB, size-derived)`
  where the size-derived value is `((total + 512 kB) / 512 kB + 1) * 512 kB`
  (`+1` even on an exact multiple), and `method = (bs - 1 MB) >> 19`.
* `-ad|-ab|-af`: `-ad` disables the adaptive reduction and is implemented
  exactly; `-ab`/`-af` (the default) need the vendor's analysis (see 4.3).
* `-o` block structure, as the vendor's own help spells it out:
  `on` normal (block per file), `of` partial-solid sorting by filename,
  `oa` partial-solid by analysis, `oz` partial-solid analysis+name (the
  default), `os` solid (force full blocks), plus `ub` uniform-block mode.
  None of these is implemented by our encoder yet; it always writes the
  `-on`-style layout that `-ad`/the default analysis produces.
* `-h*` integrity record: `hn` none, `hr` CRC16 (default), `hc` CRC32,
  `ha` Adler32, `hs` Sum32, `hm` MD5, `h1` SHA1, `h2` SHA256.
* `-c*` ciphers: `ca` AES, `cd` 3DES, `cb` Blowfish, `cs` Serpent, `cc`
  CAST-128, `ct` Twofish; `-s` password.

## 2. Header — DONE, bit-identical

Order (mirrors `sbc_parse_header`, implemented in `sbc_enc.h`):

```
"SBC" 1e 48
range-coded stream, 4 adaptive models created first (they read nothing):
  fn  nsyms 0x45 inc 1 capfreq 0x4000 captot 0x4000
  fl  nsyms 8    inc 1 capfreq 0x200  captot 0x400  boost0 0x20
  sm0 nsyms 0x20 inc 1 capfreq 0x4000 captot 0x4000
  sm1 nsyms 0x21 inc 1 capfreq 0x4000 captot 0x4000
crypto      u(8)
csum        u(8)                 1 = CRC16, 0 = none
solid       u(2)
nfiles-1    int(0xFFFF0000)
per file:   name (fn symbols, 0 terminator), flag (fl symbol),
            dt (sm0), size (sm1)
method      u(6)                 window bucket for stored payloads, see 2.3
extra3      u(3)                 compression level: 0/1/2 for -m1/-m2/-m3
flush: 4 bytes of `low`
```

Verified: for `-m1 -on -hn` with one file the first 20 bytes are identical to
the legacy archive, including the header flush length. Our decoder reads the
same values back.

### 2.1 `dt` = DOS packed date/time, **standard time** (no DST)

`dt = (date << 16) | time`,
`date = ((y-1980)<<9) | (m<<5) | d`, `time = (h<<11) | (min<<5) | (sec/2)`.

The clock is **standard time**, not local time: the vendor runs under Wine and
its DOS conversion ignores daylight saving, so in summer it stores one hour
less than `localtime()` reports. Measured with a 1000-byte file packed at
`2026-07-01 12:00` (headers differed by exactly an hour with `localtime()`) and
at `2026-01-05 12:00` (identical); the whole corpus has October mtimes, which
is why every corpus header used to differ from a fresh vendor run while the
bodies matched. `sbc_dos_datetime()` now re-reads the instant at `t - 3600`
when `tm_isdst` is set. Years < 1980 are clamped (mtime 0 produced
`0x00001005`, i.e. date 0).

### 2.2 File order in the header — SOLVED

The vendor sorts the entries by **descending size** (its "Sorting files..."
banner) with a **stable** sort: equal sizes keep their command-line order.
Verified with `aa=300 bb=100 cc=200 dd=200 ee=500 ff=100`, which the vendor
stores as `ee aa cc dd bb ff`.  Our encoder now does the same.

### 2.3 The `method` field (stored archives) — SOLVED

For stored payloads the byte is the **window bucket** of the block size the
vendor picked from the total input size.  `window_size(method) =
(method << 19) + 0xFFFFF`, and the header stores the index of the block size in
512 kB steps above 1 MB:

| total input | block size | method | nsyms |
|-------------|-----------|--------|-------|
| < 512 kB    | 1.0 MB    | 0      | 20    |
| < 1 MB      | 1.5 MB    | 1      | 21    |
| < 1.5 MB    | 2.0 MB    | 2      | 21    |
| < 2 MB      | 2.5 MB    | 3      | 22    |
| >= 2 MB     | 3.0 MB    | 4      | 22    |

Measured on 400/900/1100/1600/2100/2600/3100/4100 kB single-file archives
(method 0,1,2,3,4,4,4,4), all of which have byte-identical headers to ours.
So for stored blocks `method = (block_size - 1 MB) / 512 kB`, and the payload's
shared `Extra` model uses `nsyms = bitlen(window_size(method))` (20..22) —
that is what `SBC_ENC_NSYMS` used to hard-code as 20.  The decoder derives
`nsyms` from the same formula now, with 20/21 as fallbacks.

The same bucket applies to **compressed** archives: measured on `-m1` code
repetitions of 300 kB / 700 kB / 1.2 MB / 2.2 MB / 3.2 MB the vendor writes
methods 0 / 1 / 2 / 4 / 4, exactly the table above, and every archive of the
corpus follows it too (`nested`, 805374 B → method 1).  An earlier note in this
file claimed compressed blocks stored something else there (52/56/62); that was
a misreading of old probes and is now settled — the `method` byte is the
block-size window bucket in both cases, so the encoder already writes it
correctly for compressed payloads too.

## 3. Payload block — byte-identical (stored blocks)

```
block := <vlq>                     ; BWT length, plain VLQ (not range coded)
         <range-coded header>      ; primary, nbits, bits[], flag3, e1, e2
         <payload>                 ; e1 bytes, or vlq bytes when e1 == 0 (BWT L)
```
Blocks are written back to back with **no padding**: the payload starts right
after the range-coded header stream, and the next block right after the
payload — except for the 2-byte CRC16 records `-hr` puts around every payload
(one before, one after).  That is the `+2` the decoder applies at `data_pos`
and `next_pos`, and it must be skipped **only** when `hdr->csum != 0`; see §3.1.

Header fields, in order, all through the one RC stream:
`primary = large(vlq)`, `nbits = int_maxbits(0x14)`, `nbits` raw bits,
`flag3 = u(3)` (+ `u(0x10)` when flag3 == 2), then `e1` and `e2` through the
**shared adaptive `Extra` model** (created in the first block with `nsyms`
20 or 21, reused afterwards — exactly like the decoder).

`bits[]` is the filter-record list, LSB-first: `flen`(25) + `coded`(1)
[+ `mode`(3) [+ `ctrl`(24)]] [+ 1 option bit when coded] and a 25-bit
all-ones terminator.  There is **one record per file** in the block (a file
split by a block boundary contributes one record per fragment), so a block of
six files starts with six records, not one.  Each record is either
`flen, coded=0` (26 bits, files of **512 bytes or more**) or
`flen, coded=1, mode=5, 0, ...` (30 bits plus `level` extra option bits:
1 at `-m1`, 2 at `-m2`/`-m3`; used below 512 bytes).  At `-m3` the analysis
caps a record at `0x80000` bytes, so a longer file (or block) is written as
several records, each at most 512 kB (§4.3).

Laying the records out per file and sorting the header entries was the last
piece for multi-file archives: with both in place the archives are
byte-identical to the vendor's, e.g. 6 files (`300 100 200 200 500 100` B) and
9 files (`700 120 350 350 80 1000 512 511 3` B), for `-m1/-m2/-m3` x
`-hr`/`-hn`.

### 3.1 Payload start and checksums

`data_pos` is `rcpos` when the archive has no integrity record (`-hn`) and
`rcpos + w` when it has one, `w` being the digest width of `hdr->csum`
(2/4/16/20/32 for CRC16, the 32-bit digests, MD5, SHA1 and SHA256), with a
second copy of the record after the payload.  The decoder used to assume `+2`
unconditionally, which silently corrupted `-hn` archives, and later guessed the
payload start as `hdr_pos + {0..6}`; it now uses `hdr->csum` for both the width
and the start, keeping the old deltas only as fallbacks.  `next_pos` follows
the same rule.

## 4. Archive trailer — SOLVED

Every archive ends with `00` + a 32-bit **big-endian** value.  It is a rolling
hash of the archive's blocks, written by `0x41f1d0` from `obj+0x28` (the field
is seeded by `0x421330` and folded once per block in `0x41f920`):

```
seed   = (block_size - 1) + 0xFF80                     ; 0x421330 / ctor
per block (0x41fb6c..0x41fbc3):
    m = x ^ ((~x) >> 23)                               ; 32-bit, logical shr
    x = ror32(m, 25) + (block_len ^ nibrev(primary))
trailer: VLQ(0), then x big-endian
```

* `block_len` is the `vlq` of that very block (payload length: the raw size
  for stored blocks, the compressed size otherwise) and `primary` is its BWT
  index — so the low 16 bits *look* like `0x4000|size` on small archives, which
  is what made it look like a plain size field.
* `nibrev` is `0x445b80`, a nibble-wise bit reversal driven by the 16-byte table
  at `0x45ec00`; the vendor's table has a quirk (`table[0xD] = 0xD` instead of
  `0xB`) which is reproduced as-is.
* `block_size` is chosen from the total input size: `size + 0.5 MB` rounded up
  to 0.5 MB, clamped to [1 MB, 3 MB] (that is the `blocks: N MB` banner).  An
  **exact** multiple of 0.5 MB moves to the next bucket (`floor + 1`, not
  `ceil`): a 512 kB input uses a 1.5 MB block size, which the trailer hash
  proves (it differed for exactly `0x80000` before this fix).
* Several blocks/frames chain: the next block starts from the previous value
  (confirmed on a 4 MB file: seeds `0x0030ff7f`, then `0x387f408d`).

Consequence: our archives are no longer "identical except 5 bytes" — they are
identical, full stop, for everything the encoder produces today.

The decoder checks this value: patching any of the 5 trailing bytes makes
`unsbc t` report *Input data is corrupted!*.

### 4.1 Checksums (`-hr`, vendor default) — SOLVED

The two 8-bit header fields (`hdr->crypto` / `hdr->csum` in `sbc_parse_header`)
are **the integrity and verify checksum types**, not crypto/csum: the vendor
writes `1/1` for `-hr` and `2/2` for `-hc` (0/0 for `-hn`).  `sbc.exe` labels
them `Checksums (integrity/verify): CRC16/CRC16`.

With CRC16 on, three digests are produced (all CRC16/ARC, poly `0xA001`,
init `0xFFFF`, xorout `0xFFFF`, stored big-endian):

1. **Header digest** — CRC over `LE32(nfiles)`, then per file the *filename
   symbol indices* (same `SBC_ALPHABET` codes, no terminator), `flag` (1 byte),
   `LE32(dt)`, `LE32(size)` and 4 zero bytes.  It is range-coded as two `u(8)`
   values right **after the file entries and before `method`/`extra3`**, which
   is why a `-hr` header stream is 2 bytes longer than a `-hn` one.  Traced at
   `0x4072b6..0x4072ee` (Final -> `write_bits(rc, buf, 16)`), digest built by
   the checksum object `0x9d23a0`.
2. **Integrity record** (before the payload): CRC16 over `LE32(primary)`, two
   zero bytes (the `e1`/`e2` coding fields), the `ceil(nbits/8)` record-bit
   bytes, then the payload bytes.  It therefore covers the whole block header
   *and* the stored stream — corruption of either raises *Input data is
   corrupted!*.
3. **Verify record** (after the payload): CRC16 of the block's decoded output
   (= the raw input for a stored block), which is the record the decoder uses
to pick the ambiguous mode-0 filter variant.

Corrupting the post record gives *Block checksum verify failed!*, the pre
record or the payload gives *Input data is corrupted!*.

#### `-m2`/`-m3` record header

For stored blocks below 512 B the explicit copy record carries **one extra
zero filter-parameter bit at `-m2`/`-m3`** (55 bits at `-m1`, 56 at `-m2/-m3`),
so `nbits` and every following byte differ.  With that bit reproduced, the
`-m2/-m3` archives are byte-identical too.  Blocks >= 512 B use the compact
`coded = 0` record form, which is level-independent.

### 4.2 Multi-file archives — DONE

All files of a non-solid archive are packed into one **concatenated stream**,
cut into blocks as §4.3 describes, with one filter record per file fragment
per block (§3).  Together with the size-descending sort (§2.2) this reproduces
the vendor byte for byte.

### 4.3 Block splitting

Two regimes, both reproduced; the only thing still open is what the vendor
does *inside* a block it decides to compress (§6).

**`-ad` (no adaptive reduction) — SOLVED, byte-identical.**  Blocks are cut
independently of the content:

* one block holds at most `bs - 1` bytes (1 MB - 1, 1.5 MB - 1, 3 MB - 1, …);
* a block boundary is placed after a file only when **both** the file that
  ends and the one that follows are at least 1 kB; a small file is merged
  into its neighbour instead of sitting alone at a block edge.  Measured:
  `1023 + data` merges, `1024 + data` splits, `1000+1200` and `1000+1000`
  merge, `1024+1024` splits, `400000 + 100` gives one 400100-byte block while
  `400000 + 2000` gives 400000 + 2000, and with `-b1`
  `big(1.5 MB) + 500 B + big(1.5 MB)` gives `1048575, 451425, 451925`.

Verified by `tools/enc_big.py`: archives identical to `sbc.exe` for 0.9–3.1 MB
inputs, one and two files, `-b1`/`-b5`, `-m1`/`-m2`, `-hn`/`-hc`, including
blocks that straddle a file boundary (73/73 cases on the last run, no
failure).

**`-m3` filter records — SOLVED.**  The analysis caps every filter record at
`0x80000` bytes: a longer record is written as several records of at most
512 kB (524288 stays a single record, 524289 gives `524288 + 1`, a 600000-byte
block gives `524288 + 75712`, a 2 MB one four records).  `-m1`/`-m2` keep one
record for the whole block.  This was the 26-bit (`nbits` 77 vs 51) surplus of
the previous replay; with the cap, stored blocks now match byte for byte in
all three levels, single files and file sets alike.

**Default (`-af`/`-ab`, adaptive reduction) — SOLVED for stored payloads.**
The vendor's analysis (`sbc.exe` 0x407ae0) cuts the window at data-dependent
points: a 1 MB input is cut at ~530 kB (529 748, 530 755, 530 823, 530 252,
531 600 on different random files) and a 4 MB one into ~530 kB blocks.
`sbc_enc_split_next` replays the routine byte by byte — the 0x40000-entry
histogram of 16-bit contexts, the distinct counter and the score test
`(distinct >> 6) + 0x22` (`>> 7 + 0x36` below 64 kB) — and its file-boundary
rule now matches §4.3's `-ad` rule (a file only ends a block when it and the
next file are both ≥ 1 kB).  Byte-identical on incompressible inputs from
200 kB to 4 MB at `-m1`/`-m2`/`-m3`.  Compressible inputs still differ
because the payload itself is not reproduced yet (see §6), which also means
the split points of such blocks are untested.

## 5. Checksums — all eight `-h` types done

The header fields 1/2 hold the integrity/verify type, and the *same* object is
used for the header digest and for the two per-block records.  Only the digest
width changes: 2 bytes for CRC16, 4 for the 32-bit digests, 16/20/32 for
MD5/SHA1/SHA256 (all big-endian).  The record feed is unchanged (LE32(primary),
`e1`, `e2`, record bytes, payload).

| switch | type | algorithm | width | matrix |
|--------|------|-----------|-------|--------|
| `-hn` | 0 | none | 0 | identical |
| `-hr` | 1 | CRC16/ARC, poly `0xA001`, init/xorout `0xFFFF` | 2 | identical |
| `-hc` | 2 | CRC32 IEEE (zlib), reflected poly `0xEDB88320` | 4 | identical |
| `-ha` | 3 | Adler32 (zlib), mod 65521 | 4 | identical |
| `-hs` | 4 | Sum32 (vendor-specific, see 5.1) | 4 | identical |
| `-hm` | 5 | MD5 | 16 | identical |
| `-h1` | 6 | SHA1 | 20 | identical |
| `-h2` | 7 | SHA256 | 32 | identical |

All eight are byte-identical to the vendor on the matrix (multi-file, all
levels, 72/72 with seed 5) and the real `unsbc.exe` prints the matching
`Checksums (integrity/verify): …` line and reports *No media errors* on our
multi-block archives for every type.  MD5/SHA1/SHA256 come from `sbc_hash.h`
(streaming, shared by encoder and decoder).

Our decoder verifies all seven digest types now, and no longer falls back to
its lenient pass for archives whose digests it can verify — a corrupted `-hc`
or `-hm` archive is rejected instead of extracted silently.  Two decoder
changes were needed for the wide digests: the record width is derived from the
header type (`0/2/4/16/20/32`) and the payload starts at
`hdr_pos + width` (tried first, the old 0..6 delta guesses are kept as
fallbacks).

### 5.1 `-hs` (Sum32) — solved

The vendor routine is at `0x4227b0` (update) / `0x4229b0` (final) in
`unsbc.exe`; type 4 is dispatched from the factory at `0x401c3c`, which
allocates a 24-byte object and installs vtable `0x442b28`.  State: `A`, `B`,
a byte count `n` and a partial word.

```
A = 1, B = 0, word = 0, cnt = 0
for each byte b:
    word = (b << 24) | (word >> 8)      # MSB-first: ends up as LE32 of the 4 bytes
    if ++cnt == 4: B += A; A += word; cnt = 0
final: pad the partial word with zero bytes (4 - cnt),
       then value = (A + B) ^ n          # n counted before the padding
```

Checked against every measured record (`abcd` → `64636267`, 4 zero bytes →
`00000006`, 8 zero bytes → `0000000b`, 64 zero bytes → `00000051`, `01..08` →
`100d0a02`, …) and byte-identical on the matrix.

## 6. Roadmap

### 6.1 Layer dumps — the oracle for every stage

The decoder walks the encoder pipeline backwards, so **every intermediate
buffer it builds is the exact input of one encoder stage**.  With
`SBC_DUMP=<dir>` it writes them per block (`tools/layer_dump.py` drives it and
checks the invariants):

| file | encoder stage that produces it |
|------|-------------------------------|
| `00_payload.bin` | stage1/stage2 output, i.e. the bytes stored in the archive |
| `01_bwt.bin` | BWT string (= stage2 output, or the payload itself when `e1 == 0`) |
| `02_lzp.bin` | LZP output = input of the BWT |
| `03_filter.bin` | filter-chain output = input of the LZP |
| `04_block.bin` | decoded block = input of the filter chain |
| `hdr.txt`, `recs.txt` | block fields (with the record bits in hex), parsed records |
| `arc.txt` | archive header and file table |

Layers are numbered by the stage that produces them, so an encoder-side dump of
the same stage diffs byte for byte.  On the 52 corpus archives this gives **93
blocks, 55 of them compressed, 42 with LZP**; all cross-layer invariants hold
(`bwt == lzp` always, `filter == lzp` when `flag3 == 0`, `payload == e1` when
compressed, `payload == bwt` when stored).

Three facts the dumps settled immediately:

* `e1` is the **payload length** (never seen different from `00_payload.bin`),
  and `vlq` is the BWT length, i.e. the LZP output size — not the block size;
* `flag3` and `e1` are independent: `nested-m3` block 2 is **stored with LZP**
  (`flag3 = 1`, `e1 = 0`), so the LZP stage can be used by blocks that skip the
  PPM coder;
* a record's `flen` counts **filtered** bytes, so the records add up to the
  `03_filter` layer (mode 4 shrinks text 20359 → 15086 here), not to the block
  output.

`SBC_TRACE=1` goes one step further and logs the **decisions** the stream
carries, which are the vendor encoder's own choices (use it on small blocks):

* stage 1 seeds `M` anchors of the block (`S1 n=122 M=20`), each as a symbol
  picked from a move-to-front list of the 256 byte values plus a delta-coded
  position, and leaves `pos[0..M]` as the sorted anchor list;
* stage 2 fills the gaps: it emits runs of `prev = dst[pos[0]]`, then codes one
  distance per anchor (`S2 sym=… aidx=… t=… esi=…`) through the `A`/`B` models
  plus the raw bit channel, or escapes with `t == nsyms` when `prev` has no
  later occurrence.

So the mirror is not a PPM: it is a run/anchor coder.  It has **no freedom at
all** once the BWT string `S` is known (see §6.3): the anchors are the first
occurrence of every distinct byte value, so `M` is exactly the number of
distinct bytes of `S` (122 → 20, 134 → 36, 15086 → 45, 39270 → 39,
240000 → 256 -- the old "vendor searches over `M`" guess was wrong), and each
distance points at the *next* occurrence of `prev`.  The models themselves are
not unknowns: their tables are already in `sbc_tables.h`
(`SBC_APAR`/`SBC_ATAB`/`SBC_BTAB`/`SBC_T360`).

### 6.2 The coding layer — SOLVED (shadow encoder)

`SBC_PPMTEST=1` replays every value the decoder reads back through the range
encoder, in the same order: a shadow `SbcWRC` writes the same
`(total, start, freq)` into a second payload buffer, and the raw bit channel is
written into a byte array packed MSB-first and **reversed at the end** (the
reader starts at `len-1` and walks backwards), with the final partial byte
padded with zeros in the low bits.  The result must equal the bytes the
archive stores.

Measured: **55/55 compressed blocks** of the corpus, plus `-hn` archives (no
digest) and a 2.2 MB multi-block `-m1` archive — byte-identical, `rc` *and*
raw-bit section.  So the following are settled and need no further reversal:

* `sbc_model_decode_sym` ⇄ encoder (same pre-decode rescale, same post-update
  increments, same `cap_freq` rescale);
* the shared `Extra` model, the `A[20]`/`B[25]` model selection and the
  `map`/`c404` update in stage 2;
* the payload layout: range-coded stream from the front, bit stream from the
  back, 4-byte flush of the range coder;
* `SBC_NSYMS=<n>` pins the `Extra` width for probing archives whose `method`
  byte gives a wrong guess.

What was still missing at that point was only the **decisions**: how many
anchors `M`, which ones stage 1 sends, and which occurrence of `prev` each
stage-2 distance points at.  Those turned out to be fully determined by the
BWT string -- see §6.3.

A block whose decisions are replayed can already be rebuilt bit for bit, which
is what `tools/ppm_test.py` checks on every run.

### 6.3 The stage1/stage2 encoder — SOLVED

`SBC_TRACE=1` on the *decoder* is a log of the vendor's own choices, so the
policies can be read off directly.  Dumping the final stage2 output with
`SBC_DSTOUT=<dir>` (one file per compressed block) and re-deriving the
decisions from that string gives, for every block tried, **exactly the same
trace**; `tools/stage2_enc_proto.py` does the comparison:

| archive | n | M | stage1 entries | stage2 steps |
|---------|------|-----|----------------|--------------|
| code-m1 | 39270 | 39 | 39/39 | 7547/7547 |
| image24-m1 | 12234 | 256 | 256/256 | 2279/2279 |
| biased-m1 | 120000 | 14 | 14/14 | 100860/100860 |
| pattern-m1 | 279 | 36 | 36/36 | 66/66 |
| records-m1 | 240000 | 256 | 256/256 | 199272/199272 |
| zeros-m1 | 122 | 20 | 20/20 | 30/30 |
| eng-m1 | 15086 | 45 | 45/45 | 4731/4731 |

The rules (implemented in `sbc_enc_stage2.h`):

* **stage1.**  The anchors are the first occurrence of every distinct byte
  value of `S`, in increasing position order, so `M` = number of distinct
  bytes.  Each anchor ships its value as `sbc_wrc_u(0x100 - i, idx)`, `idx`
  being its rank in the decoder's remaining permutation (it swaps `pos[i]` and
  `pos[slot]` exactly like `sbc_stage1`), and its position as
  `delta = newpos - cum` through the `E` model (`inc 10`, `cap_freq 64`,
  `cap_tot 1024`, resized to `remain` or `logmap(remain-2)+3`), with the low
  `esi` bits on the raw channel.
* **stage2.**  Walk `S` left to right: `prev = S[pos[0]]`, fill up to the next
  known position, then insert the **next occurrence** of `prev` strictly after
  `pos[1]`.  The coded distance is a rank distance: `esi = T - pos[1] - K`,
  where `K` counts the known positions in `(pos[1], T)` -- i.e. it counts only
  the still-unknown output positions, which is why the decoder has to walk
  `pos` and subtract `gap-1` as it goes.  When `prev` has no later occurrence
  the step is an escape: `t = nsyms`, no `B` symbol, no bits, no `map`/`c404`
  update, and the decoder drops the consumed anchor.  Otherwise `t` is the
  bit-length bucket of `esi-2` (`t = esi` for 0/1, `t = 2` for 2/3, then
  `t = bitlen(esi-2)+1`), `B[t-2]` codes `(esi-2 - 1<<(t-2)) >> (t-5)` and the
  low `t-5` bits go on the raw channel (MSB first).  `nsyms` follows the same
  `sbc_reinit` threshold dance as the decoder.

With those rules the payload is reproduced **bit for bit**, not just the
decisions: `sbc_enc_stage2_payload()` in `sbc_enc_stage2.h` (range coder +
`A`/`B`/`E` models + reversed bit channel) gives `tools/stage2_payload_test.py`
**55/55 identical** compressed blocks of the corpus -- rc *and* raw-bit
sections, including `records-m1` (240000 B → 145202 B), `biased-m1` (120000 →
45795), `nested-m3-of` blk000 (393717 → 165658), `nested-m3-os` blk001
(246853 → 163385) and `image24-m1` (12234 → 2342).  `./sbc t2 S payload` is the
direct check.

### 6.4 Filter chain (encoder side) — transforms done, policy open

Record layout first, because it shapes the encoder: a record covers one *file
segment*, so ordinary archives have exactly one record per block, and the
multi-record blocks are the solid structures cutting at file boundaries
(`nested-m3-of` blk000 = `240000/0 | 120000/5 | 120000/5 | 192000/5 | 31066/5`).
`flen` is the **output** length of the filter (it matches `03_filter.bin`), so
the record consumes its source segment and produces `flen` filtered bytes.

The transforms are deterministic once the mode is known; only mode 4 carries
real choice (`ctrl`, 24 bits).  The mode-0 variant is not in the stream at all,
it comes from the level: `-m1` = simple (`0x424150`), `-m2` =
`(P=24, nmod=3, f40=768)`, `-m3` = `(P=53, nmod=10, f40=600)`.  Mode 7 stores
its width as a 12-bit parameter (`W = 3*param`: 257 for `image24`, 256 for
`image7`), mode 4 its 24-bit `ctrl` (`0xAC` for `code.c`, `0x8C` for
`eng.txt`).

Forward transforms, in `tools/filter_enc_proto.py`:

* **mode 0 simple** — the decoder's state machine only looks at the
  reconstructed bytes, so the forward pass is the same loop with `dst` known
  (`src[i] = dst[i] - dst[i-state]`).
* **mode 0 advanced** — the lag is derived from the *residual* stream the
  decoder is about to read (`sbc_adv_distinct` looks at `src`), so the forward
  pass iterates to the fixed point: choose a lag, derive the residuals, re-read
  the scores from them, repeat.  It converges in a couple of rounds.
* **mode 7** — predictor/selector state also depends only on the reconstructed
  bytes, so the same "run the decoder with `dst` known" rule applies: with
  `out = data[i]`, the residual is `data[i] - pred` where `pred` follows the
  state machine (0 / left / the selected predictor).  Implemented as
  `sbc_enc_mode7()` in `sbc_enc_filters.h`.

Verified: the 19 corpus blocks whose single record is mode 0 reproduce
`03_filter.bin` byte for byte (`image-m1/m2/m3`, `image24-m1/m2`, `zeros-m1`,
`pattern-m1/m2`, `records-m3`, the `nested` blocks), which covers both variants
and the fixed-point lag choice, and the 7 mode-7 blocks match too
(`image24-m3`, `image7-m3` and the five `nested` 98304-byte ones), each with the
vendor's own 12-bit width.  `./sbc t3 <param> data filtered` is the direct
check for mode 7.

What is still open is the **policy** — when the vendor uses a filter at all and
which one.  It is not a plain content rule: identical bytes get different modes
at different levels (zeros: mode 0 at `-m1`, copy at `-m2/-m3`; pattern: mode 0
at `-m1/-m2`, copy at `-m3`; records: copy at `-m1/-m2`, mode 0 at `-m3`;
`image24`: mode 0 at `-m1/-m2`, mode 7 at `-m3`).  Text goes to mode 4
(`code.c`, `eng.txt`) and the small/incompressible files to copy.

The first guess — "the analysis keeps the candidate with the smallest output"
— is **wrong**, and measurably so: `tools/mode_choice_costs.py` runs our own
pipeline once per candidate on every compressed single-record block and prints
the four stage sizes next to the mode the vendor actually wrote.  At `-m1`/
`-m2` the choice is not the cheapest candidate in 7 of 44 blocks (e.g.
`nested-m1` blk006, 120000 bytes of `records`: mode 0 at 45795 payload bytes
against copy at 35828, both with LZP inactive), so scoring cannot be what
drives `-m1`/`-m2` at all.

What does drive them, per level, is testable and largely reproduced:

* **`-m2` = "did the advanced filter do anything?".**  Run the level-1 filter
  and compare with the input: an identity result means its own lag test found
  no lag (`sbc_enc_adv_lag` returning 0), and the vendor then writes a copy
  record; otherwise it writes mode 0 with those bytes.  This explains **10 of
  10** `-m2` blocks, including the ones where copy would have been smaller
  (`pattern`: identity filter 272 LZP bytes vs copy 134, still mode 0).
* **`-m3` = cheapest candidate wins.**  With the level-2 parameters, the mode
  chosen is the one whose *final payload* is smallest among copy, mode 0
  (P=53) and mode 7 (with the record's own 12-bit width): **23 of 24** blocks.
  This is what flips `pattern`/`zeros` to copy at `-m3`, keeps `records` on
  mode 0 (3303 against 145202), and picks mode 7 for the image blocks (330
  against 518).  The single exception is `image7-m3`: mode 7 at 5625 bytes
  versus mode 0 at 5481 (2.6 %); its width search is a separate question (the
  record carries 256, while 341 would have given 5290).
* **`-m1` filters almost everything.**  9 of 10 blocks, and that includes the
  case where the simple filter is exactly the identity (`zeros`), so there is
  no lag gate at this level.  The exception is the record-like corpus data
  (`records`, whose blocks are copied), which must trip a compressibility
  pre-check that is not identified yet — note that entropy does not separate
  it from the image data the same level *does* filter.

**Update (measured later, wired in).**  The advanced filter itself has a
**minimum input size**, like the simple one's 0x2400 bail-out: bisected on
periodic data of periods 4, 10 and 16 (lowercase and uppercase), 11316 bytes
come out unchanged and 11317 get the residuals, and the cutoff does not depend
on the content.  Below it the filter returns the identity, which is what the
policy reads as "no filter".

* `-m2` is then a single rule: filters to the advanced output when it differs
  from the input, and otherwise (identity) takes the repeat record when the
  mode-6 transform applies, or copy.  That covers every probe: uppercase
  `code.c` (45270 B, identity filter, mode 6), zeros and true random data
  (identity, no mode-6 match, copy), periodic cycles/images/`pattern.bin`
  (changed, mode 0) and the small `pat` files (below the filter's minimum,
  hence copy; a 9000-byte 32-cycle is mode 6 instead).

  The gate is the filter's own **lag verdict** (`sbc_enc_adv_lag` returning
  0), not the output bytes: its controller can still change the stream when
  the lag search found nothing, and the vendor copies anyway.  `hi4` (200000
  B of `rnd & 0x0F`, shifted into the high nibble) is the case that separates
  the two: lag 0, first difference at byte 538, vendor copy record at all
  three levels — a byte comparison wrote mode 0 and 69 bytes more
  (`tools/m1_probe.py`, after the fix: 204/204).
* `-m3`: identity also gives the `m6/copy` branch (the 1500-byte image record
  of the t0 set stays copy although its mode-0 payload would be 326 bytes
  against 593).  Otherwise the **mode-7 gate runs first** (it sits inside the
  mode-0 handler, §6.8 item 3), then mode 6 when it applies, then the
  mode-0-versus-copy payload comparison.
* The copy-versus-payload choice also depends on `flag3`: the eight-byte
  margin only holds when the LZP pass found nothing.  With LZP active any
  saving keeps the payload (t5: vlq 435, payload 428, vendor writes the
  payload).

Synthetic probes (`tools/mode_probe.py`, which packs a repeating cycle with
`sbc.exe` under Wine and prints the record mode) show two more branches:

| cycle | `-m1` | `-m2` | `-m3` |
|-------|-------|-------|-------|
| `A`..`P`, 16 bytes | 0 | 0 | copy |
| `A`..`Z`,`A`..`F`, 32 bytes | 0 | 0 | **6** |
| same cycles built from raw bytes, 16 bytes | copy | 0 | copy |
| same cycles built from raw bytes, 32 bytes | **6** | 0 | **6** |

Two things follow.  A 16-byte cycle of printable ASCII and a 16-byte cycle of
raw bytes get *different* modes at `-m1` (0 versus copy) but the same at
`-m2`, so the byte values drive the level-1 decision and the level-2 gate is
structural, as above.  And a 32-byte cycle is mode 6 at both `-m1` and `-m3`
but mode 0 at `-m2`, which no single "cheapest" or "gate" rule explains — the
level-2 gate only looks at the delta filter, so a mode-6 candidate never
reaches it there.

The mode-6 appearance is structural, not a mis-read: its minimum match length
is 17, so a 16-byte cycle cannot use it and a 32-byte one can (the filtered
stream of the 200 kB input is 100 bytes).  Mode 4, mode 6 and the mode-7 width
search are all implemented now (§6.9, §6.10, §6.8 item 3).

The three rules above are wired into `sbc_enc_policy_mode()` (§6.5) and are
the default: the encoder picks the mode itself and all 20 corpus archives come
out byte-identical, as do the `parity_random`, `parity_fuzz`,
`multifile_parity` and `vendor_parity` suites.  What remains of the policy is
the `-m1` rule for record-like data.

### 6.5 The block writer — DONE (mode supplied, or picked by the policy)

`sbc_enc_block.h` now writes complete compressed blocks, not just the payload:
`sbc_enc_pipeline()` runs filter -> LZP -> BWT -> stage2 in one go,
`sbc_enc_comp_write()` emits the block header (VLQ, `primary`, record list,
`flag3`, `e1`/`e2`), the integrity record, the payload and the verify record,
and `sbc_enc_block_dispatch()` is installed as the archive writer's
`sbc_enc_emit_block()` hook.

Three details had to be measured, not guessed:

* **record form.**  A copy record of 512 bytes or more uses the compact
  `flen, coded=0` form (51 bits), *also* when the block is compressed; the
  explicit `coded=1, mode=5` form is only for blocks below 512 bytes.  Writing
  the explicit form cost 5 bits per block and shifted the whole payload by a
  byte.
* **store/compress decision.**  The margin depends on the mode.  A **copy**
  block needs to save **more than 8 bytes** over the BWT string
  (`e1 + 8 < vlq`): measured with the vendor on high-entropy inputs whose
  mode-5 payload we reproduce bit for bit, a 9-byte saving is compressed and
  an 8-byte one stored, and `hello.txt` (67 B, 1-byte saving) is stored.
  `SBC_ENC_MIN_GAIN` is that 8.  A **filtered** block (mode 0/4/6/7) needs
  **3 bytes**: the test is `payload + 3 <= vlq` (`SBC_ENC_FILT_GAIN`).  The
  mode-6 period-31 block stores 93 BWT bytes and writes its 89-byte payload,
  the 48-byte-cycle probe (vlq 115 against a 114-byte payload) stores the BWT,
  and the fuzz's `cycl25` is the boundary case the vendor keeps as a payload
  (vlq 68, payload 65) — so a saving of 3 is enough and one of 1 is not.
* **stored BWT.**  When the payload does not win but the filter+LZP+BWT string
  is already shorter than the block (`vlq < usize`), the vendor stores that
  string with `e1 = 0` instead of falling back to the raw block
  (`mixed-m2` blk000: 35003 -> 2983, no `-m2` payload coding).  Only when
  `vlq == usize` is the raw stored block written.

Validation: `tools/block_archive_test.py` supplies the mode of every corpus
archive whose blocks are all single mode-0/mode-5 records and compares the
whole archive body from the first block on -- **20/20 byte-identical**, across
`-m1/-m2/-m3`, compressed (`zeros`, `pattern`, `image*`, `biased`, `records`)
and stored (`hello`, `random`, `mixed` including its stored-BWT block).  The
`records` pairs are 240 kB in one block, so they also cover a payload three
orders of magnitude larger than `hello.txt`'s 67 bytes; `mixed-m2` is the one
multi-block case (a stored-BWT block followed by a raw one), and its body is
compared as a whole.  The
pipeline itself still passes `tools/block_pipeline_test.py` (37/37 blocks,
four stages each) and `tools/stage2_payload_test.py` (55/55).

On top of the byte comparison, the vendor's own extractor accepts these
archives: `unsbc.exe t` reports *No media errors were detected* for
`zeros-m3`, `pattern-m2`, `image24-m1`, `image-m1` and `mixed-m2`, and
`unsbc.exe x` extracts each of them to the exact input bytes (both CRC16
records verify).

The **mode policy** (§6.4) is implemented on top of that as
`sbc_enc_policy_mode()`: `-m1` filters, `-m2` copies when the advanced filter
is the identity, `-m3` takes the cheaper of copy and mode 0 on the final
payload.  It is opt-in (`SBC_POLICY=1`) while modes 4/6 and the `-m1`
exception are missing, and it already **closes the loop on binary data**:
`python3 tools/block_archive_test.py --policy` lets the encoder choose every
mode itself and still gets **20 of 20** corpus archives byte-identical; the
old `records.bin` miss (we filtered a block the vendor copies, one byte
longer) is gone.
The vendor's own `unsbc.exe t` reports *No media errors were detected* on the
archives that switch produces (`zeros-m3`, `pattern-m3`, `image24-m2`,
`biased-m2`), so the mode it picks is not just plausible but accepted by the
decoder that wrote the format.

`SBC_COMP=<mode>` still forces a single mode for the tests, and without either
switch the encoder writes stored blocks, which keeps every stored-block
archive byte-identical.

### 6.6 Remaining work

1. Implement the compressed payload, in this order:
   1. ~~**stage1/stage2 encoder**~~ **DONE** (§6.3);
   2. ~~**LZP**~~ **DONE** (`flag3` 1, validated against `02_lzp.bin`);
   3. ~~**forward analysis + filter chain** (mode 0/4/7 records)~~ **DONE**
      (§6.4, §6.9, §6.10): the mode-0 transforms, mode 4 (line code), mode 6
      (repeat) and mode 7 with the vendor's own width estimator, plus the
      level rules.  What is left is only the `-m1` rule for record-like data
      (§6.4) and the periodic-block BWT tie of §6.8 item 1;
   4. ~~the block-level choice between stored and compressed payloads~~
      **DONE** (§6.5).
   The splitter (§4.3) and the `-m3` record cap are done, and the mode policy
   covers binary blocks (§6.4): the encoder chooses the filter itself and
   20/20 corpus archives are byte-identical.  The unidentified `-m1` rule for
   record-like data is the last piece of the policy.
2. Structures and ciphers.  `-on/-of/-oa/-oz/-os/-ub` are all implemented
   (§6.13); of the ciphers (`-ca/-cd/-cb/-cs/-cc/-ct`) **AES is done and
   verified both ways** (§6.15); the other five block primitives remain.
3. (done) Checksums: all eight types, see §5.
4. (done) `-bN` and `-ad`: block size, `method` and the per-file block
   boundaries are reproduced; `tools/enc_big.py` compares multi-block archives
   against the vendor (32/32).
5. Keep everything green:
   * `python3 tools/layer_dump.py` — dumps every stage of every corpus archive
     and checks the cross-layer invariants (93 blocks, 0 failure);
   * `python3 tools/ppm_test.py` — shadow encoder vs the stored payload of
     every compressed block (55/55 identical);
   * `python3 tools/stage2_payload_test.py` — rebuilds every compressed payload
     from its BWT string and compares (55/55 identical, §6.3);
   * `python3 tools/stage2_enc_proto.py S.bin TRACE` — decision parity of the
     stage1/stage2 rules against `SBC_TRACE=1`;
   * `python3 tools/filter_enc_proto.py` — forward mode-0 filters against
     `03_filter.bin` (19/19 blocks, §6.4);
   * `./sbc t3 <param> data filtered` — forward mode 7 against `03_filter.bin`
     (7/7 blocks, §6.4);
   * `python3 tools/block_pipeline_test.py` — the four pipeline stages against
     the layer dumps (37/37 blocks, §6.5);
   * `python3 tools/block_archive_test.py` — whole compressed archive bodies
     against the vendor with the mode supplied (20/20, §6.5);
   * `python3 tools/block_archive_test.py --policy` — same comparison with the
     encoder choosing the mode itself (20/20, §6.5);
   * `python3 tools/mode_choice_costs.py` — every candidate filter's stage
     sizes against the mode the vendor chose, the counter-evidence to the
     "cheapest wins" guess at `-m1`/`-m2` (§6.4);
   * `python3 tools/mode_probe.py --ascii --periods 2,4,8,16,32` — the vendor's
     mode for synthetic repeating cycles, the mode-6/period-17 evidence
     (§6.4; needs Wine, ~6 s per case);
   * `python3 tools/text_variants.py` — LF/CRLF/uppercase `code.c` plus an
     uppercase variant carrying literal `{`+`0xF0` pairs, packed by the vendor
     at all three levels and decoded by ours (15/15; the uppercase cases
     exercise filter mode 6 and the marker variant its `7B F0 00` escape);
   * `python3 tools/enc_matrix.py --vendor` — small multi-file sets, all levels
     x the eight `-h` types (48/48 with `--sets 2` on seed 1; longer runs are
     slow because every case starts a fresh Wine process);
   * `python3 tools/enc_big.py` — large multi-block archives with `-ad`
     (73/73 with `--sets 4`, no failure);
   * `python3 tools/csum_test.py` — all eight digests, round-trip plus a
     corrupted payload byte per type (32 cases, no wine needed);
   * `python3 tools/verify_all.py` — 52/52 corpus archives;
   * `python3 tools/crypt_parity.py` — every `-c*` cipher both ways (vendor
     archive through our decoder, ours through the real `unsbc.exe`); 24/24
     over `hello.txt`/`code.c`/`mixed.bin`/`image24.raw` at `-m3` (§6.15);
   * `./sbc` with no arguments — the built-in self-test now starts with a
     crypto KAT (AES-128, Blowfish, CAST-128, DES, 3DES, Serpent, Twofish),
     then the 25 corpus cases;
   * `python3 tools/parity_random.py` — generated file sets against the vendor,
     byte for byte (the strict oracle; see §6.8 for what still differs);
   * `python3 tools/mode6_parity.py` — cycle and uppercase-text archives at all
     three levels, the mode-6 transform and policy (27/27);
   * `python3 tools/m1_probe.py` — the hunting battery of §6.14: 68 synthetic
     inputs (cycles, ramps, counter/record/sparse data, NUL-interleaved ASCII
     `wide`, `a b c ... z ` `abc`, the corpus files) x three levels against
     the vendor, now **204/204**, `--ad` included;
   * `python3 tools/bwt_probe_small.py` — the forward-BWT tie check of
     FORMAT §5 (small repetitive inputs, our primitive vs the vendor's):
     36 identical, 0 primary mismatches — the regression check for the
     `reg04` class;
   * `python3 tools/m7_parity.py --levels 3` — single files against the vendor,
     the photographic records and their width (`--ad` for the raw filter);
     the corpus images and nine synthetic widths (64..385 px) are identical,
     with the width the vendor's own estimator returns (100 px -> 100,
     128 -> 128, 64 -> 128, image24 -> 257, image7 -> 256);
   * every tool that starts `sbc.exe` goes through `tools/vendor_run.py`,
     which deletes the target archive first (the vendor otherwise asks
     `Overwrite <archive>? (Y/N)` and waits forever), redirects stdin to
     `/dev/null` and applies a timeout.

---

## 6.7 Multi-file blocks and the mode-4 gate — SOLVED

**A block is not a file.**  The vendor filters each file of a block on its own
(one record per file, each with its own mode and `ctrl`) and only then
concatenates the filtered files into the single string that LZP, the BWT and
stage2 see.  `sbc_enc_pipeline_segs()` filters per segment and
`sbc_enc_comp_write()` writes the per-file record list; before that the
dispatcher fell back to the stored path whenever a block held more than one
file, which made every small multi-file archive two to ten times larger than
the vendor's (`zero0.dat` 1082 B + `records1.dat` 389 B: vendor 147 B, ours
1542 B — now byte-identical).

The mode-4 gate is **600 bytes**, not the `0x23FF` the text heuristics assumed:
prefixes of `eng.txt` and `code.c` get a copy record at 599 bytes and a mode-4
record at 600, at all three levels, and the boundary does not depend on the
content (`abcdefghij` repeats stay copy at 902 B because no dictionary token
matches them at all).  The policy keeps the measured value in front of the
chooser (§6.14), so a 2026-byte prose block at `-m1` takes the vendor's branch
instead of copy and a 599-byte one still gets its copy record.

## 6.8 Randomized parity: the suites, and what is left

`tools/parity_fuzz.py` packs generated single files at all three levels and
`tools/multifile_parity.py` does the same for two-to-six file sets; each one
attributes a mismatch to the file order, the block layout or the payload.
Both are byte-for-byte comparisons against `sbc.exe` run under Wine.
Current state (2026-10-28, after the BWT port of item 1): **75/75** fuzz
cases, **18/18** `tools/parity_random.py --sets 6` and **24/24** with
`--sets 8`, **39/39** `tools/vendor_parity.py` corpus archives, **108/108** on
`tools/multifile_parity.py`, **52/52** corpus archives through the decoder
(`tools/verify_all.py`), `mode6_parity` 27/27, `m7_parity` 0 failures,
`m0_adaptive_test` 10/10, `ppm_test` 55/55, `enc_matrix` 144/144,
`enc_big` 64/64 and `tools/tail_repro.py` identical.  Nothing in the
randomized suites differs any more; what is left is only the list below.

1. **BWT primary on exactly periodic blocks -- SOLVED.**  The vendor's
   sorter is ported in `sbc_enc.h` (`sbc_bwt`), see FORMAT §5: the bucket
   pass, the "all elements share the preceding byte" skip, the
   Bentley-McIlroy partition (pivot parked in `a[hi]`, `k1`/`k2` vecswaps),
   the 11-element insertion cutoff, the switch to the 4-byte-key path and the
   three details that only show up on periodic input: the pivot's tie
   priority (`a[lo]` wins over `a[mid]`, 0x423138), the 4-byte path's **2**-byte
   step (recompute it when the band changes path, otherwise the depth climbs
   one byte at a time and splits at the last odd depth), and the comparison
   index wrap at the limit (0x424e1d).  `reg04` at `-m1/-m2/-m3` is
   byte-identical, `primary` 2990 included, and `tools/bwt_probe_small.py` --
   the vendor's own BWT layer fed back through our sorter -- is **36/36** with
   no primary mismatch (before the three details it missed `ab`/`abc` cycles
   at 2000/3000 B and the 1500-byte `word` cycle).  The old stable doubling
   sort always picked the class start (2880 instead of 2990 at 120 repeats).
   It is also faster than the doubling sort it replaced: `./sbc t6` (BWT
   only) on a 1 MiB block takes 0.15 s instead of 0.84 s on random data and
   0.02 s instead of 0.12 s on text.  One shape is slower than the old sort
   and has to be known: a block that is periodic *except* for a truncated
   tail keeps its equal band alive to depth n (the periodic shortcut cannot
   apply), so a 1 MiB one takes ~2 min in `t6`.  Real files of that shape
   never reach the BWT -- the repeat transform catches them first (a 1 MiB
   cycle with one changed byte packs in 0.03 s to a 137-byte archive) -- and
   no archive suite hits it.  Ground truth while doing it:
   `tools/bwt_sa_dump.py` (the vendor's final SA, dumped under `winedbg`),
   `tools/bwt_probe_small.py` and the Python mirror in
   `_work/bwt_sort_model.py` (7/7 vendor primaries).

2. **File and block order.**  *Solved*: the order is the name-length pre-sort
   of §6.13.4 followed by the structure's own sorter (descending size for
   `-on`/`-os`, the extension hash for `-of`, the analysis pass for
   `-oa`/`-oz`), so the earlier "content-dependent" reading was the analysis
   sorter's metric, not the file name.  Seed 77 is 180/180 across all six
   structures and all three levels (§6.13.5); the last `-on` miss
   (`t3 -m2`, a 300-byte prose block the vendor codes to 19 bytes) was the
   filtered-block margin: the eight-byte copy margin only applies when the
   filter left the stream at full length, so a 24-byte BWT with a 19-byte
   payload is now written (`payload + 3 <= bwtlen`).
3. **Photographic records: policy (the `-m2` tie is solved).**  The adaptive
   mode-0 filter is **ported and exact** (`sbc_m0adv.h`, FORMAT §7), in both
   instances and both directions: on the set2 `-m3` image the forced mode-0
   run produces the vendor's filter stream, payload (24634) and primary
   (24330) byte for byte, on the set8 image at `-m2` all 84300 filter bytes
   match and the archive is byte-identical (`n2.sbc` == `vm2.sbc`), and the
   vendor's advanced-record archives now decode and extract byte-exactly
   (set2 `-m3`, set8 `-m2`/`-m3`).

   * *Policy — SOLVED; it is the slot byte counts, not a lag test.*  The
     mode-0 handler of the record coder (`FUN_004129b0`, case 0 = 0x412d8d)
     runs the adaptive filter and then, before anything else, asks the filter
     object for `get(obj, 2)` (vtable[2] = the getter 0x4552a0, i.e. the
     dword at `obj+0x60`) and compares it with `n / 3` (0x412df0).  That
     field is `arr[2]` of the object's array at `+0x58`, and the array holds
     **bytes coded per slot** (0x43cef8: every chunk end adds its limit to
     `arr[active]`) — so the test asks whether the analysis spent a third of
     the record on slot 2, the fixed lag **3**, i.e. on one 24-bit pixel row.
     When it did, and the record is longer than 0x4000 bytes (the coded size
     is the record's own length) at `-m3` (the handler tests `this+4 > 1`),
     the estimator 0x443e20 names the row width and a result above 1 replaces
     mode 0 by mode 7 right there (0x412e25) — mode 7 is not part of any cost
     comparison, and mode 6 is only reached when this gate says no.
     `sbc_m0_adaptive` now accumulates the per-slot counts
     (`sbc_m0a_last_slot`), and they are **exact**: image24 `arr =
     255,0,97980`, image7 `255,0,48766`, `image.raw` `255,65132,0`, the
     set2 image `255,0,12079` — the four numbers the vendor's own object
     prints at that breakpoint.  With the gate in place image24 and image7
     are byte-identical at `-m3` (widths 257 and 256), the set2 image keeps
     its mode-0 record (`12079 <= 42000/3`) and the set8 image its copy
     record, and both sets are identical at `-m2` and `-m3`
     (`tools/m7_parity.py` is the single-file check).
   * *The old `-m2` tie — solved, and it was not a scoring rule.*  At a
     257-byte cut the vendor rewrites the chunk limit to `pos - 2`, not
     `pos - 1`: the chunk ends two bytes before the cut.  That limit is what
     the selector reads (short-chunk test and `limit >> 10` margin) **and**
     the value the next chunk's `limit += ext` starts from, so with `pos - 1`
     the whole chunk grid slipped one byte after every cut.  Byte 70718 of
     the set8 image then fell at the end of a slot-2 chunk where the vendor
     starts a slot-0 chunk (the 249/240 scores agreed: our selector picked
     slot 2 too, the boundary was the difference).  With `pos - 2`     the grid
     stays aligned, every slot choice follows, and the stream matches
     byte for byte; the vendor's `-m2` archive now decodes through our block
     CRC and extracts to the original four files.
   * *The record's last byte — solved: there is a third cut site.*  Besides
     the two cuts inside the 257-byte counter block, `FUN_00425200` cuts from
     the per-byte tail at 0x425e9a (reached by the model path **and** by the
     direct path through `0x42643e: jmp 0x425e48`):

     ```
     if (counter > 0xFFFFF)  return;      /* a cut already happened */
     if (pos <= 0x7F)        return;      /* not before half a chunk */
     add = min(pos >> 4, 0x20);
     if (score[active] <= score[0] + add) return;
     limit = pos - 1;                     /* cut, counter untouched */
     ```

     It fires when the running slot's score is `min(pos >> 4, 32)` points
     **ahead** of the copy slot's — the same test the chunk end passes to the
     selector as its `d` flag — and it keeps the counter, so the counter-block
     cuts can still fire afterwards in the same chunk.  The current byte is
     processed, so the chunk ends on a short remainder: in the set8-style
     tail the final chunk is 130 bytes, the cut lands at `pos = 128` (limit
     `127`) and the remaining **one** byte becomes a slot-0 chunk, which is
     why the vendor's residual keeps the record's last data byte verbatim
     (`... 02 ff 43` against our old `... 02 ff ff`).  Without it the chunk
     grid is identical, the accumulators match, and only that byte differs —
     the failure `tools/tail_repro.py` was filed under (FORMAT §13.1) as a
     PPM tail problem.  With the cut in place the tool reports byte-identical
     archives (155,004 B, `e1 = 719`) and the block decodes and extracts.

## 6.9 Mode 6 (repeat) forward transform — SOLVED

`sbc_enc_mode6()` is the mirror of the decoder, and its output is byte-exact
against the vendor's `03_filter` layer on both a period-31 cycle
(100836 B -> 93 B) and uppercased `code.c` (45270 B -> 13378 B); the block
built from it matches the vendor's `vlq`/`primary`/`e1` exactly.  Everything
below was read off `sbc.exe` 0x411bb0 (constructor 0x411ae0/0x411b50: markers
`0x7B`/`0xF0`, minimum length `0x11`, cap `0x40000F`):

* two bytes go out literally and **without** a table store; after that every
  literal records its own position under the two-byte context in front of it
  and a copy uses the position recorded for the last two output bytes;
* a candidate must agree on the first nine bytes (three word compares); the
  copy length is capped at `min(distance, remaining) - 1`, so it never reaches
  its own source, and is used from 17 bytes up;
* **lazy step**: when the position one byte further on has a longer match, the
  byte is literal and the look-ahead match is taken — the test is
  `len + 1 < len2`.  This is what turns the 100 kB cycle into a doublng run of
  copies (30, 61, 123, 247, ... bytes) instead of one long copy;
* length code `v = L - 16`: one byte while `v <= 0x7F`, two while
  `v <= 0x2FFF`, three above it (the 2-byte form covers up to `0x3FFF`, so the
  emitter's own ceiling is what decides);
* a literal `7B F0` pair becomes `7B F0 00`, only when a byte follows it.

**Policy.**  The vendor runs the filter only above 4 kB (`n > 0x1000`: 4096
bytes get a copy record, 4097 a mode-6 one) and keeps it only when it more than
halves the block: uppercase text lands at 30 %, cycles at 0.05 %, while the
image blocks — 75 % after mode 6 — keep their own mode.  Where it then wins
depends on the level: at `-m1` it is the fallback when the simple filter's own
state machine gives up (a 32-byte cycle at 4200 B or more; when that filter
engages, as it does for a 20-byte cycle, mode 0 wins) and at `-m2`/`-m3` it is
simply taken whenever it applies — the vendor writes it for uppercased
`code.c` at `-m3` even though the copy payload is 226 bytes smaller (1770
against 1996), so it is not part of the `-m3` cost comparison.  `set3`
(4 files, a 100 kB period-31 block) is byte-identical at all three levels, the
12-file cycle probe is identical at all levels, and the corpus stays 39/39 and
20/20.  `tools/mode6_parity.py` (27/27) is the repeatable check.

## 6.10 Mode 4 line code: the 19-symbol coder — SOLVED

`_work/m4_line_encode.py` is the mirror of `0x408060` and
`tools/m4_line_parity.py` checks it.  The decoder pulls its bytes from the
**end** of `e2`: the last four bytes are the initial code word (MSB first,
descending addresses) and every renormalisation pulls the preceding byte.  So
the encoder emits its bytes in pull order and reverses the buffer; the flush is
the four bytes of the final `low`, and the guard byte the vendor stores in
front of the stream falls out of that same flush — there is no separate
convention to guess.  Model: 19 symbols, every frequency 1, increment 7,
halving rescale at `freq > 768` or `total > 8192`.  Fed the vendor's own symbol
sequence the encoder returns `e2` byte for byte on all six real blocks we have
(`set6`/`set9` v1..v3), flush included.

**Symbol rule** (what the vendor emits at each fetch): a symbol is fetched at
the first space after a break, and its value is `min(k, 24) - 7` for the next
line that folds; a folded line turns its line break into a *marker space*, so
the flat line has `k + 1` spaces and `thr = k` fires on the last of them.
Lines with fewer than seven spaces stay literal — the symbol stays armed and
they cannot fire, since `thr >= 7` — and a literal break only resets `cnt`
(the fetch is not re-armed).  The last line never folds: it takes `0x12`
("fire, write nothing"), which is also the escape a line longer than 24 spaces
needs.

**Harness.**  `SBC_LINEDUMP=<dir> ./sbc <archive> <out>` dumps, for every block
that runs the prose pass, the pass's input (`NNN_in.bin`), the vendor's `e2`
(`NNN_e2.bin`) and its target byte (`NNN_tag.txt`).
`python3 tools/m4_line_parity.py <dir>` replays that input, replans the
symbols and compares the re-encoded bytes; **6/6 real blocks identical**.
`tools/m4_line_samples.py` generates prose geometries (lines of 0..6, 0..14
and 0..28 spaces, CRLF, missing trailing newline, tail lines with 7 or 20
spaces), packs them with `sbc.exe` and runs the same check: **18 identical,
126 different**, and every mismatch is the *last* symbol only — the vendor
folds where the planner writes `0x12` or the other way round, which shows up
as one or two extra renormalisation bytes at the end and nothing else.  The
plan up to that point, the model and the flush are right.

The tail symbol and the sampled mismatches were closed later — see §6.11.

The corpus is unaffected (`tools/verify_all.py`: 52/52).

## 6.11 Mode 4 line model: fold before tokenize — SOLVED

Three ordering/edge rules finished the line-model branch; with them the fuzz's
`crlf` and `big` samples became byte-identical at all three levels (they were
the last two non-periodic failures):

1. **The fold runs before the tokenizer.**  The vendor feeds the folded stream
   (marker spaces, placeholders and all) to the tokenizer, so the "the last
   four bytes are never tokenized" rule measures the *folded* length.  A
   folded CRLF break is one byte (`SP`) instead of two, which shifts that
   window by one and is why `...dog the\r\n` keeps `the` literal when the line
   folds but tokenizes it when it does not.  `sbc_enc_m4_tokenize()` is now a
   separate pass that runs on the fold output; the plain (no line code) path
   runs it on the raw bytes as before.
2. **A literal LF break carries a placeholder space only where a word can
   follow.**  Measured on `big.bin` heads with custom tails: the space is
   written when the next byte is a letter (a capital included — the `0xFF`
   marker comes *after* it) or a space, and not for a digit, a tab,
   punctuation, an empty line or the end of the block (`from\n`, `from\n3`,
   `from\n\t`, `from\n\n` all carry none).  That is why `big` was one byte
   long: we wrote the placeholder after the final break.
3. **A literal CR break is always `CR SP`** — that space *is* the CRLF's LF,
   turned into the byte the expander drops later — even at the end of the
   block.  Verified with digit/tab/capital/punctuation/blank-line tails on a
   CRLF file: all 43 breaks of `crlf.bin` carry it, and so does the last one.

`tools/parity_fuzz.py --count 18` → 51 identical, 3 different (the three
`reg04` levels, §6.8 item 1).

The same session fixed the **-m1 mode choice** as well: at `-m1` the simple
filter's state decides first (mode 0 when it engaged, even though the repeat
filter could shrink the block further: a 10240-byte cycle of `0..255` gets
mode 0/e1 341 while the vendor does not use mode 6 that would store 0), and
mode 6 is only the fallback when the state machine gave up (regular `word`
lines, `state == 0`, get mode 6 exactly as the vendor does).  The old order
tried mode 6 first, which wrote mode 6 for the 256-byte cycle.

## 6.12 The `-m3` second stage (`sub`) — SOLVED both ways

At `-m2`/`-m3` the vendor runs one more compressor over the record *before*
its filter: the record's raw bytes become a literal/copy stream, the filter
runs on that stream, and the decoder reverses the order (filter, then expand).
A 36 MB text set at `-m3` shows what the stage is worth: 61 of its 67 records
carry `sub`, and a 512 kB text chunk that mode 6 would store in 13 kB becomes
**216 bytes**.

The format (decoder side, `sbc_sub_*` in `sbc.c`, verified bit-exactly):

* a record gains `sub(1) flag(1) idx(5)`; `idx` is the *length base* the copies
  are measured in (`lbase = idx`, minimum match `lbase` words = `lbase * 4`
  bytes), and `flag` is the 4-byte alignment pad; the record's mode bits stay;
* the stream starts with a 3-byte (level 1) or 8-byte (level 2) prologue and
  is a sequence of literals and `03 C5 <L>` copies of 4-byte words taken from
  a rolling ring (1.5 MB at `-m2`, 24 MB at `-m3`); the 17-bit (21-bit) hash
  of the 3 (8) bytes before the cursor indexes the table;
* `L` is one byte up to `0x7F`, two up to `0x2FFF` (`0x80 | (L & 0x3F)`, then
  `L >> 6`) and three above (`0xC0 | (L & 0x3F)`, low byte, high byte);
* a literal `03` followed by `C5` is written `03 C5 00` (plus three pad bytes
  when the record is aligned);
* the history is fed **once per block**, with each record's output, and only
  after the block is accepted; records of 128 bytes or less never reach it.

The encoder side is now implemented too (`sbc_enc_sub.h`, a transcription of
0x43a380 with the caller 0x4129b0 for the parameters), and it is byte-exact
against the vendor's own records: `./sbc subtest DIR` reproduces all 61 `sub`
records of the 36 MB `-m3` text set, including the last (a 40139-byte tail) and
the 24 MB ring they run on.  The parameters it needed:

* the length base comes from the mode the record is about to get: **4** for
  modes 0/2/6, **9** for text (mode 4), **32** for gradient (mode 7) and for
  copy records longer than 4 kB, **4 with the alignment bit** for mode 1; the
  record stores `lbase - 1` in its 5-bit field;
* the caller gives the compressor `min(len, cap) - 12` output bytes, with
  `cap = len - min(len/20, 4096)` (0x4129b0: `uVar3 = 0x1000`, and below
  `0x14014` bytes `uVar3 = len / 0x14`); when the stream does not fit the
  record is stored unfiltered.  (An early transcription read the divisor as
  4/5 instead of 1/20, which refused every stage whose stream was longer than
  a fifth of the record -- the `-ub` 2400-byte merged record of 6.13.6 is the
  case that exposed it: the vendor takes the stage with a 908-byte stream.)
* a stream of 512 bytes or less turns the record into a **copy record**
  (`mode = 5`, the filter is skipped: 0x412be8) — that is why every `sub`
  record of the text set reads `mode=5 sub=1 idx=4`;
* the stage starts **disabled** (0x43a060): only the first successful feed
  clears 0x4020, so the first block of an archive never carries `sub`
  records (200 kB of zeros stays a stored record at every level);
* the compressed stream is then filtered with the record's mode, and the
  filter's own parameters (`ctrl` for mode 4, `m7` for mode 7) are taken from
  the stream, not from the raw bytes.

The one structural rule that came with it: at `-m3` a record is **one 512 kB
window** of the block (`-m1`/`-m2` keep a whole file in one record: a 3 MB
file is six records at `-m3` and one at `-m2`), which is also the slot size
mode 6 addresses its block-wide table with.  The measured exception is the
window analysis picking the text filter (mode 4): that record runs to the end
of the file part in the block (3 MB of `code.c` becomes one 2.7 MB mode-4
record, while images, random data and uppercase text are cut six ways).

Validated: `tools/vendor_parity.py --multi` 42/42, `tools/parity_fuzz.py`
51/54 (the three `reg04` cases, §6.8), `tools/mode6_parity.py` 27/27, and
whole archives byte-identical on a 3 MB text (`-m3`, 5603 B), a 5 MB
periodic text (`-m3`: the first block is a 3,145,727-byte mode-4 record with
`sub=0`, the second a 2,097,153-byte one with `sub=1 idx=9`), a 36 MB text
(`-m3`; blocks 0..3 and 5..11 identical, block 4 differs — see below), two
prose blocks of 2 MB and 3,143,680 B at `-m1` (the ctrl `0x08` boundary) and
3 MB of random data with `-ad`.

Still open around it:

* the **window analysis** is ours (measured policy) rather than the vendor's
  content detector, so a record whose analysis the vendor calls copy can be
  filtered by us: in `big.txt` block 4 the vendor's unit 2 is a `mode=5`
  window that absorbs the rest of the block into one 2 MB record, while our
  policy says mode 6 and cuts six records — block 4 is the only differing
  block of that 36 MB archive.  The same gap makes a synthetic 3 MB gradient
  compress with mode 6 where the vendor writes six identity mode-0 records.
* `tools/parity_random.py --sets 6` set 2 (`-m2`/`-m3`) still differs: that
  vendor archive is one our *decoder* cannot read yet (it is the `sub=1
  idx=32` block of §1), so neither side can be compared record by record.
* `tools/multifile_parity.py` keeps 7 differing cases out of 24, none of them
  `sub`: two are the small-block mode-0/copy choice at `-m2`/`-m3` and three
  are block splitting (§6.13).

## 6.13 Block structures (`-on/-of/-oa/-oz/-os/-ub`) — all implemented

The vendor's own help gives the semantics.  `-on`, `-of`, `-oa`, `-oz`, `-os`
and `-ub` are all implemented, and `-oz` is the default (the vendor's own
progress line says `blocks: 1.0 MB/analysis+name`):

| switch | meaning                                                        |
|--------|----------------------------------------------------------------|
| `-on`  | normal: block per file                                          |
| `-of`  | partial-solid: sort by filename (extension, then name)          |
| `-oa`  | partial-solid: analysis                                         |
| `-oz`  | partial-solid: analysis+name (the default)                      |
| `-os`  | solid: force full blocks                                        |
| `-ub`  | uniform-block: `-oz` order and boundaries, one record per block |

### 6.13.1 `-oa` / `-oz`: the analysis sorter — SOLVED

`-oa` and `-oz` are the same function (`FUN_0040a9d0`), with a `by_name` flag:
`-oz` (the default) also feeds `FUN_004094c0`'s extension hash into the
similarity metric, `-oa` leaves that field zero.  The record layout is:

| offset | field                                                     |
|--------|-----------------------------------------------------------|
| +0x200 | distinct byte count (a **byte**, wraps at 256)             |
| +0x201 | analysis key (average similarity to the window)            |
| +0x205 | file size                                                  |
| +0x209 | name pointer                                               |
| +0x20d | extension hash (`-oz` only)                                |
| +0x211 | group flag: 1 = block start, 0 = follower, 2 = emitted     |

**Sampling.**  Each file is read in 64 kB chunks, at most 256 kB.  On the
first chunk, if `bytes_read - 1 > 1023` the 64K-context histogram and the
byte histogram are cleared, the first byte is seeded (`bh[b] = 1`) and the
scan starts at byte 1.  Files of 1024 bytes or less therefore inherit the
previous file's histograms; that is why a small file can have `distinct = 0`
after a random file.  The signature is `freq[v] = min(255, bh[v] / scale)`
with `scale = (min(size, 256K) >> 12) + 1`, and `pred[v]` the most frequent
predecessor of `v` (ties keep the highest predecessor).

**Similarity (`FUN_0040a620`).**  The important subtlety: the
`|distinct(a) - distinct(b)| > 17` and `size <= 1023` tests do **not** return
0.  They jump past the content loop with `score = 0` and still run the hash
test at the end, so two files with the same extension score 13 even when
their contents are unrelated.  Full metric:

```
score = popcount over v of (pred_a[v]==pred_b[v] && freq_a[v] && freq_b[v])
if distinct_a + distinct_b < 250:
    score = (|distinct_a - distinct_b| > 13) ? score >> 1 : score + 3
if score > 128:
    score = (score - 64) + (score >> 3)
    ok = score < 200
if ok and (hash_a or hash_b):
    if hash_a == hash_b: return score + 13
    if score > 13: score -= 5
return score
```

**Ordering.**  Insertion into the working array is descending by size, ties
after equals.  The array is then processed in windows of 1500 files: each
record's key is the truncated average of the metrics `> 27` to the window,
the window is sorted ascending by key with the vendor's Shell sort (gap table
at `0x457280`: 1, 3, 7, 21, 48, 112, 336, 861, ...), then groups grow:

* the group start is the window record with the highest key and a size above
  8191 (no candidate leaves the current position in place);
* the best remaining match (`metric > 27`, first wins on ties) is rotated to
  the next slot and becomes a follower; files of 1023 bytes or less always
  join the current group;
* the window is refreshed every `n / 40` groups or when the window is down to
  374 entries and more than that many files remain.

A second pass emits group 0, then repeatedly picks the remaining group start
with the highest metric to `order[0]` (fallback: the first remaining start).
This is why a 300-byte random file ends up *inside* the text group in the t4
set: it is small enough to be pulled in, then the whole group is emitted as a
unit.  Our `sbc_enc_pss.h` is a direct transcription; it matches the vendor's
order on all six fixed sets (`t0`..`t5`) for **both** `-oa` and `-oz`, and
on a probe set where only the extension hash can decide between two
identical-size zero files.

**Blocks.**  Each group is one solid stream: the splitter must not cut at the
file boundaries inside it (`sbc_enc_emit_adaptive(..., merge_files = 1)`), so
the vendor emits `{text, rnd, text}` as a single 5200-byte block and
`{prose, prose}` as a single 5500-byte block.  The header's file table is the
same order.

### 6.13.2 Dictionary-reference records — SOLVED

A block keeps the `(offset,len)` of every record it has produced, and a record
whose first bytes equal the *start* of an earlier record is written as a
reference: `flen(25) coded=1 mode=5 dict=1 dref(12) dlen(25)`, then only the
tail after the match goes to the filter stage.  The vendor's three measured
shapes are all reproduced (`t3`, `t4`, 9 MB `-m2` set): a whole 1500-byte file
copied by a later one (`flen=0`, `dlen=1500`), a 1500-byte file followed by
2500 new bytes (`flen=2500`, `dlen=1500`), and a 145727-byte prefix of a 3 MB
record.  Rules measured on those sets:

* the match is taken against the block's earlier records only, from their
  start, and the longest one wins; a prefix of 1024 bytes or more is enough;
* the record always becomes a copy record (mode 5), whatever mode it would
  otherwise have had, and it never gets a second-stage stream;
* at `-m2`/`-m3` the dict record still carries one clear second-stage bit
  after `dlen` (the decoder ignores it, but `t3` at `-m2` is 124 bits against
  123 without it);
* the copied prefix is *not* part of the block's filtered stream: the payload
  holds the tails only, and the block's reconstructed length is larger than
  its filtered length;
* dict records are not registered in the second-stage history (the 9 MB `-m2`
  set showed this first).

With that, the `t3` (`{9000, 1500}` image pair) and `t4` (`text/rnd/prose`)
sets are byte-identical at `-m1`, `-m2` and `-m3`.

### 6.13.3 `-of`: extension groups — implemented

`-of` is not the analysis sorter: it keeps the **name-length order** below
inside one extension and stable-sorts the file list by extension.  The header
follows that order and every extension run is one partial-solid group, so a
block never spans two extensions.

**Key.**  The extension key is the vendor's rolling hash (`FUN_00409c10`),
not a string compare: the characters after the last dot of the last path
component (case-folded, the **last four** only) are packed into a word so the
extension reads as a big-endian field at the top, and the word is complemented.
`""` (no dot, a leading dot, a one-character name, a trailing dot) is
`0xffffffff` and sorts first.  Because the key is a hash, `abcx` and
`abcdef` group together (both hash as `bcx` / `cdef`), and the *order* is
ascending by that word, which is not always a plain string compare: `ab` hashes
`0x6162_0000` and `b` hashes `0x6200_0000`, so `ab < b`.  Measured on three
probe sets (`noext` < `hi.bin` < `mm.TXT`, two `.txt` files swap when their
arguments do, one extension per block) and on the seed-77 set: 30/30 archives
(`-of`, all three levels) are byte-identical.

**Dictionary tails keep their mode.**  A record that replays a prefix and then
has a tail does not have to be a copy record: the vendor filters the tail with
the normal policy and writes the record as `flen coded mode=4 dict=1
dref dlen ctrl(24)`, i.e. the tail's own mode bits follow the two dictionary
fields (before those bits the record list still reads exactly like the `t4`
shapes).  Seed-77 `t8 -of -m1` is that case: a 9000-byte text whose first
1500 bytes are the previous file comes out `flen=5779 mode=4 dict=1 dref=0
dlen=1500 ctrl=0x56`.  Both the decoder and the encoder handle it now, and the
archive is byte-identical at `-m1`, `-m2` and `-m3`.

`-on` was also fixed while here: it used to keep the default `-oz` reordering
while forcing one file per block.  It now selects the plain descending-size
order, as the vendor does.

### 6.13.4 The file-table order: a name-length sort — SOLVED

The vendor reorders the file list **before** it picks the structure
(`FUN_00408e00`, called from the compression driver ahead of the structure
switch).  The key is `strlen(name)` -- the argument exactly as typed, so
`sub/b.dat` counts nine characters -- and the sort is a Shell sort with the
gap sequence `gap = n*10/13`, where a gap of 9 or 10 becomes 11, followed by
one plain insertion pass; every comparison is strict, so equal lengths keep
their command-line order.  For `n == 2` a single compare-and-swap does it.

The structure sorter then runs on *that* array, so every tie it leaves alone
(`-of`'s same-extension files, `-on`'s same-size files, `-oz`'s equal metrics)
comes out in name-length order, not the argv order.  That is the whole of the
seed-77 gap: `0_text.dat` (10), `1_zero.dat` (10), `2_rnd.dat` (9) and
`3_zero.dat` (10) are emitted as `2_rnd, 0_text, 1_zero, 3_zero`, and a set
whose names are all the same length keeps the command line.

`-os` is implemented as well (solid: the splitter may cut inside a file, the
header is the archive-wide remaining-size convention), so all five structures
now run.

### 6.13.6 `-ub`: uniform blocks — SOLVED

`-ub` is a modifier of `-oz`, not a separate sorter: the file order (analysis
+name), the partial-solid groups and the block boundaries are `-oz`'s, and the
only difference is the **record list** -- every block becomes a single record
covering all of its files.  Measured on the seed-77 sets: the 5-file `t3` set
is five per-file records at `-oz` (`len=3082/900/300/300/300`) and one
`len=1614 mode=6` record at `-ub`; `t0`'s `[1500 zero][900 text]` block is two
records at `-oz` and one 2400-byte record at `-ub`, which then takes the
`-m2` second stage (908 bytes, `sub=1 idx=9`) exactly as the vendor does.
A single large file is unaffected (`-ub` and `-oz` give byte-identical 3.2 MB
archives, the splitter's content cuts included), and the header's file table
is the `-oz` order.

The implementation is a `uniform` flag through `sbc_enc_archive_ex`/
`sbc_enc_emit_adaptive`: the block's segment list is replaced by `{blen}` just
before the block is emitted, and the CLI accepts `-ub` as `struct_mode = 5`
(the `-oz` analysis path plus that flag).  Verified **30/30** on
`multifile_parity --struct ub --count 10 --levels 1,2,3` (seed 21) and on the
six seed-77 sets at all three levels (18/18).

Remaining: a 300-byte prose file at `-m2`/`-m3` (`-on`, seed-77 `t3`) comes
out as a 19-byte payload block from the vendor and as a stored block from us
(the small-block mode/copy choice at the second stage, §6.12).

### 6.13.5 Verification status

* The CLI's default structure is now `-oz`, like the vendor's (its progress
  line reads `blocks: 1.0 MB/analysis+name`); before, only the explicit
  `-oz` reordered anything.
* `multifile_parity --count 6 --levels 1,2,3 --struct default,oz,oa` (seed
  21): **54/54 identical**, after the `-m2`/`-m3` size gate and the
  `flag3` payload rule above.
* Seed 77 (`--count 10`, 10 trials, **all six structures**): **180/180**
  identical (`default,on,of,oa,oz,os` at `-m1/-m2/-m3`).  The name-length
  pre-sort (§6.13.4) closed every order mismatch, the mode-4 dict tails
  (§6.13.3) closed `t8 -of`, and the filtered-block margin closed the last
  `-on` miss (`t3 -m2`, 300-byte prose: 19-byte payload against a 24-byte BWT,
  now written instead of stored; smoke check
  `multifile_parity --count 4 --seed 77 --struct on --levels 2` -> 4/4).
* Fixed sets: `t3` and `t4` byte-identical at all three levels, `-oa` and
  `-oz`; `-m2`/`-m3` included.
* `-of` probes: all three sets byte-identical (extension hash, grouping and
  dict records included).
* Local regressions after the adaptive mode-0 port (`sbc_m0adv.h`):
  `verify_all` 52 OK/0 FAIL, `block_archive_test` 20/20,
  `block_pipeline_test` 37 ok/0 bad, `csum_test` 0 failures,
  `parity_fuzz --count 12 --levels 1,2,3` 36/36, `parity_random --sets 3`
  8/9 (only set2 `-m3`, §6.8 item 3: policy picks mode 7 where the vendor
  writes mode 0).  The filter itself is covered by `./sbc t0 <file>`
  (`tools/m0_adaptive_test.py`: both instances, encoder+decoder round trip,
  10/10 corpus samples).  The vendor archives that used to fail on their advanced
  mode-0 records now decode and match: `/tmp/pr6/set2/o.sbc` (4 files, image
  CRC ok), set2 `-m3`, set8 `-m3` and set8 `-m2` (all four files).  The last
  `-m2` miss was the cut offset of §6.8 item 3 (`pos - 2`).
* Mode-7 gate (§6.8 item 3): with the per-slot counts in place the four
  vendor probes match exactly (`arr[2]` 97980 / 48766 / 0 / 12079), the
  corpus images are byte-identical at `-m3` (image24 387 B, image7 5683 B,
  widths 257 and 256) and so are the two image sets that used to miss:
  set2 `-m2`/`-m3` (25996/26267 B) and set8 `-m2`/`-m3` (139993/133590 B).
  `parity_random --sets 3` is 9/9 and `--sets 10` **30/30** (it was 28/30,
  the two misses being exactly those sets), `parity_fuzz` 36/36,
  `multifile_parity` 108/108, `mode6_parity` 27/27, `text_variants` 15/15,
  `enc_big` 64/64, `vendor_parity --files *image*` 12/12, `layer_dump`
  0 invariant failures (55 compressed blocks), `ppm_test` 55/55,
  `stage2_payload_test` 55/55, `verify_all` 52 OK, `block_archive_test`
  20/20 with and without `--policy`, and the built-in `./sbc` suite 25/25
  (a mode-7 archive written by us decodes and extracts byte-exactly through
  our own decoder and through the vendor's).


## 6.14 The token-less mode-4 record and the `-m2` lag gate — SOLVED

Two policy/decoder gaps closed by the `tools/m1_probe.py` battery, both
against the vendor's own unreproducible cases; after them the battery is
**204/204** (68 inputs × 3 levels).  The last three — the `ascii_mixed` input
(100 kB of an ascii-16 cycle followed by 100 kB of random data), which the
vendor takes as mode 0 at `-m1` and as a copy record at `-m2`/`-m3` while we
picked the other way round once `-ad` kept the whole 200 kB in one block —
are **solved too**: the filter's own verdict now mirrors the vendor's, i.e.
the verdict is the pair (`coded`, `strong?`) that the vendor's own state
machine returns and not a size heuristic of ours.

* Simple variant (`sbc_enc_mode0_simple`, `0x43acb0`'s verdict): with `coded`
  <= `0x1000` bytes of output the filter refuses (`r = 0`); above it `r = 2`
  when `coded > n/10` and `r = 1` otherwise.  At `-m1` any `r != 0` means the
  record is mode 0 (`r = 1` additionally arms the repeat stage, below) and
  only `r = 0` falls through to mode 6/copy.
* Adaptive variants (`-m2`/`-m3`, `0x43c490`'s verdict): refuse when the size
  test trips, when the copy slot's score sum is not beaten by more than 1/64
  (`t6c < t70 + (t70 >> 6)`), or when fewer than `min(n/128, 3072)` bytes were
  coded with a real lag; otherwise mode 0.  `-m3` adds the two scratch-table
  counts to the same decision.

The `-ad` battery is 204/204 with those rules, as is `tools/enc_matrix.py`
(144/144), `tools/enc_big.py` (64/64) and `tools/parity_random.py` (30/30).
The one input class `tools/parity_fuzz.py` used to miss (`reg04`, all three
levels) was never a filter rule: it was the BWT primary tie order of
FORMAT §5, now reproduced by the ported sorter (§6.8 item 1).

### The weak accept's repeat stage (`adv`) — SOLVED

When the mode-0 filter returns a **weak** accept (`r = 1`) the vendor does not
stop there: `0x412af0`'s tail runs the repeat transform `0x411bb0` over the
*filter's output* (cap `len - min(len>>7, 0x1000)`, a fresh table --
`FUN_00411bb0` starts with `memset(table, 0, 0x40000)`) and, when the whole
input is consumed and the output fits (`<= cap - 6`), it overwrites the
record's stream with it and sets the record's **`adv`** bit.  A weak accept
whose repeat transform does not fit stays mode 0 with `adv = 0`, and the
strong (`r = 2`) and refused (`r = 0`) cases never reach the stage (the
refusal runs the same transform over the source, which is the mode-6
candidate the policy already has).

The decoder mirrors this in `0x408a00`: for a mode-0/2 record it reads the
`adv` bit after the dict fields and *before* the filter step and, when set,
expands the recorded stream with the mode-6 decoder `0x4083a0` first, then
applies the mode-0 inverse to the whole expansion -- so a record's output
length is the expanded length, not its `flen`.  Our decoder does exactly that
(`sbc_apply_recs`: block-wide mode-6 table and output buffer, then
`sbc_mode0_inv`), and the encoder runs the stage in `sbc_enc_pipeline_plan`
when `sbc_enc_m0_verdict == 1` and `fl > 0x1000`, writing the bit through
`b->advs[]`.

**First vendor case found** (the `advweak` input of `tools/m1_probe.py`: 512
random bytes, a 6000-byte `ab` run, a 1000-byte random block repeated to
120000): at `-m1` the vendor writes `len=7628 mode=0 adv=1` and an 1854-byte
archive; ours is byte-identical, and both this decoder and the vendor's
extract it back to the original bytes.  At `-m2`/`-m3` the same input is
refused by the adaptive filter and becomes a mode-6 record on both sides.
The adaptive filter's weak verdict is reachable on paper but no probe found
it: its score margin (`t6c >= t70 + t70/64`) fails on every synthetic shape
tried (cycles with period 20..52, periodic-plus-jitter, random tails), and
the stage itself is level-independent, so the `-m1` case covers the code
path.  The 204-case `m1_probe` battery has no other `adv` record.

### The token bit (`ctrl` 0x80) describes the record

`0x406940`'s bit `0x80` (vendor `0x40`, tested at `0x406a22`) selects the
`0x407d20` **token expansion**; the other passes (the map, `0x408060`'s line
model, the `0x4079f0` space drops, the `0x406b68` CRLF fold) are driven by
their own bits.  The vendor also writes records **without** `0x80`:

| case | `ctrl` | `e2` | flen | stored stream |
|---|---|---|---|---|
| `wide`, 200 kB ASCII with a NUL after every byte | `0x0C` | 0 | 200000 | inverse map of the input, byte for byte |
| `abc`, 200 kB of `a b c ... z ` | `0x0C` | 0 | 200000 | same |

Both were read off the vendor's archive with `SBC_DBG2=1` and the stored
bytes were confirmed against the map table (the `03_filter` layer equals
`inv[SBC_MODE4_MAP][input]`), and both decode with the block CRC — so the
decoder's rule is: with `0x80` clear, translate and stop, no expansion.  The
`0x80` bit is not part of the base shape: the base is header `0x04` (the
`0x4079d0` permutation), and `sbc_apply_mode4` now implements the entire
`0x406940` word instead of accepting only the shapes the chooser emits (the
salted markers of header `0x02`, the capital pass of header `0x08`, the two
fold forms and the `0xFD` token are in FORMAT.md §Mode 4 and
`tools/m4_forge.py`).

The encoder reproduces it: `sbc_enc_mode4` writes the bare inverse map when
the bit is clear, and — this is the second half — **drops the bit when its
token pass emitted nothing**.  The chooser's word (`0x40cb80`, transcribed
in `sbc_enc_m4_ctrl`) sets the token bit from a letter-density test, but the
vendor's `abc` record shows `0x0C`: the table holds words and letter pairs,
and text with a space between every letter matches none of them.  So the bit
is the token pass's **own yield** (`sbc_enc_m4_units`, token codes plus the
`0xFF` capital markers, counted where they are written), and the record's
`ctrl` is the filter's effective word, not the chooser's.  Every observation
fits: `abc` 0 units → `0x0C`; `eng.txt`/`code.c` (dense English) → `0x8C`/
`0xAC`; `wide` is already cleared by the density test (`sumc` counts its
100000 NULs) and by having no units either.

With both halves in place `wide` and `abc` are byte-identical to the vendor
at `-m1`, `-m2` and `-m3` (167/168/168 and 150/150/150 bytes), and the
vendor's `wide` archive decodes and extracts byte-exactly through our
decoder — before, the `0x0C` record made the decoder give up on the block
(`st=-1`, no candidate passed the CRC).

### The `-m2` gate is the lag verdict

`-m2`'s "did the advanced filter do anything?" is decided by the lag search
(`sbc_enc_adv_lag`), not by comparing the filter's output with its input: the
level-1 object's controller keeps coding when no lag was found, and the
vendor still writes the copy record.  `hi4` is the case: `200000` bytes of
`rnd & 0x0F` shifted into the high nibble, lag 0, first output byte that
differs from the input at offset 538 — the vendor's `-m2` archive is a copy
record (102354 B, the same size as its `-m1`/`-m3` ones), a byte test wrote
mode 0 and 69 bytes more.  The fix is the `||` in the `-m2` branch of
`sbc_enc_policy_mode`: no lag *or* an unchanged stream takes the
`mode 6`/copy branch.

### What the policy asks now, and what `m1_probe` covers

The battery's `wide` case is the one the `m1_probe` probe set was built for:
the 0x0C record reached the encoder first (the old policy never even ran the
chooser on it, because the printable-ASCII gate rejected the NULs) and only
then the decoder.  The policy now takes the **chooser's word** as the text
test — `sbc_enc_is_text`'s printable/lowercase heuristic plus its 5 % size
gate are gone, since the vendor keeps the record the chooser asked for even
when it does not shrink at all (that is what a `0x0C` record is) — and
`biased.bin`/`pattern.bin`/`mixed.bin` still come out right because the
chooser itself returns 0 for them.  `abc` is the same shape with an even
smaller probe: the token bit's honesty rule above.  The one measured rule
that has to stay in front of the chooser is the 600-byte gate of §6.7:
taken away, a 599-byte `eng.txt`/`code.c` prefix becomes a mode-4 record our
chooser is happy with while the vendor writes copy (checked at 599/600/1500
bytes on both files, all three levels, all identical after the gate was put
back).

## 6.15 Archive encryption (`-c*`) — all six ciphers done

`sbc_crypto.h` implements the vendor's `-c` container, the 8192-round KDF,
the `check_byte` and the CBC wrapper once; the cipher id in the magic
(`'H' + id`) selects the block primitive and the key length:

| letter | id | cipher | key | status |
|---|---|---|---|---|
| `-ca` | 1 | AES/Rijndael | 32 | **DONE** |
| `-cb` | 2 | Blowfish | 32 | **DONE** |
| `-cc` | 3 | CAST-128 | 16 | **DONE** |
| `-cd` | 4 | triple-DES | 24 | **DONE** |
| `-cs` | 5 | Serpent | 32 | **DONE** |
| `-ct` | 6 | Twofish | 32 | **DONE** |

Encryption cannot be byte-identical to the vendor (16 random salt bytes), so
the oracle is interoperability: a vendor archive must decode/extract through
our CLI (with `SBC_PASS`), and our archive must extract through `unsbc.exe`.
`tools/crypt_parity.py` runs both directions for every cipher; the matrix is
**24/24** (six ciphers x `hello.txt`, `code.c`, `mixed.bin`, `image24.raw`, all
`-m3`, passphrase with a space), and a two-file `-m2` archive was checked the
same way for Serpent and Twofish (vendor -> our decoder, ours -> `unsbc.exe`).
A wrong passphrase gives `-3`.

Two details the parity run settled:

* **Serpent is TNEPRES.**  The key schedule at `0x430320` copies the passphrase
  into its 0x230-byte buffer *backwards* (`mov dl,[ebx-1]; dec ebx`) and the
  reference round function is the standard one, so the cipher is Serpent with
  key and block bytes reversed.  Wrapping the standard primitive in a 32-byte
  key reversal plus a 16-byte block reversal reproduces the vendor byte for
  byte (check byte included).  The stock algorithm does **not** match.
* **Twofish is the reference algorithm** (`q0`/`q1` are the ones at `0x58160`);
  the plain RFC 5926 key schedule and round function need no reversal.

Serpent and Twofish live in `sbc_cipher_extra.h` on top of the public-domain
LibTomCrypt sources (`sbc_cipher_serpent_impl.h`, `sbc_cipher_twofish_impl.h`).
`sbc_crypto_selftest()` (`sbc_crypto.h`) pins one published ECB vector per
primitive — AES-128 FIPS-197, Blowfish, CAST-128 RFC 2144, DES (and 3DES with
the DES key three times), the LibTomCrypt Serpent vector fed through the
TNEPRES reversal, and the LibTomCrypt Twofish vector — and the no-argument
self-test runs it first, so a broken primitive fails without Wine.

Vendor CLI note: the passphrase switch is `-np<pass>`, **not** `-s<pass>`
(`-s` exists but then reads the secret from the console, and appending
characters to it is rejected: `Unexpected character 's' in switch`).  Our
encoder accepts both `-s<pw>` and `-np<pw>`.

Table leads in `sbc.exe` (raw file offsets): Twofish q0 at `0x58160`
(`a9 67 b3 e8 ...`), CAST-128 S-boxes at `0x59360` (`30 fb 40 d4 ...`),
Blowfish S-boxes at `0x5b360` (`d1 31 0b a6 ...`), DES PC-1 at `0x5cbc8`.
Serpent's S-boxes are computed (bitsliced), not stored as a byte table; the
vendor's `0x430320` key schedule is the lead that identifies TNEPRES.
