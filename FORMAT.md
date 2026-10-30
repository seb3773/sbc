# SBC Archive Format Specification (SBC Archiver 0.970)

This document provides a complete technical specification of the archive container, encoding models, compression algorithms, and cryptographic transforms used in **Super Byte Compact (SBC) Archiver version 0.970** (2000–2008 by Sami Runsas).

All structures, constants, and algorithms documented here have been reverse-engineered from the original x86 binaries (`sbc.exe` and `unsbc.exe`, image base `0x400000`) and verified with 100% bit-exact parity against the complete reference corpus.

---

## 1. Container Architecture & Overall Layout

An SBC archive consists of four main sections:

```
+------------------------------------+  Offset 0
| Magic Identifier "SBC\x1eH" (5 B)  |
+------------------------------------+
| Archive Header (Range-Coded)       |  Metadata, settings, and file table
+------------------------------------+
| Block Stream (Sequential Blocks)   |  One or more compressed data blocks
|   - Block 0                        |
|   - Block 1 ...                    |
+------------------------------------+
| Archive Trailer                    |  VLQ(0) + 32-bit rolling hash
+------------------------------------+  End of file
```

1. **Magic Identifier (5 bytes)**: `53 42 43 1E 48` (`"SBC\x1eH"`).
2. **Archive Header**: Encoded via the primary Binary Range Coder. Contains cipher configuration, checksum types, solid flags, file directory entries, method byte, and compression level.
3. **Block Stream**: Sequence of independent compression blocks. In non-solid mode, each file occupies one or more blocks. In solid mode (`-of`, `-os`, etc.), multiple files are packed into single blocks.
4. **Archive Trailer**: A single `0x00` byte (`VLQ(0)`) indicating the end of the block stream, followed by a 4-byte big-endian rolling hash.

---

## 2. Archive Header

Immediately following the 5-byte magic, the file stream is processed by a Binary Range Coder (RC):

```python
crypto   : u(8)                          # Cipher ID (0 = None, 1..6 = Ciphers)
csum     : u(8)                          # Checksum type (0 = None, 1 = CRC16, 2..7 = Digests)
solid    : u(2)                          # Solid mode flags
fn_extra : Extra(nsyms=0x45, inc=1, ...) # Filename alphabet model
fl_extra : Extra(nsyms=8, inc=1, ...)    # File flag model
nfiles   : decode_int(0xFFFF0000) + 1    # Number of files in archive

for file in range(nfiles):
    name : SBC_ALPHABET symbols until 0  # Filename string
    flag : fl_extra.decode_sym()         # File attribute flag
    dt   : size_model_0.decode()         # MS-DOS Date/Time (LE32: date<<16 | time)
    sz   : size_model_1.decode()         # Uncompressed file size in bytes

if csum != 0:
    header_digest : u(8) * digest_width  # Big-endian digest of header fields

method   : u(0x3F)                       # Method / Window selector
extra3   : u(3)                          # Compression level: 0 = M1, 1 = M2, 2 = M3
```

### 2.1 Filename Alphabet (`SBC_ALPHABET`)

Filenames are restricted to a 69-symbol (0x45) character set:

| Index | Character | Index | Character | Index | Character |
|---|---|---|---|---|---|
| `0x00` | NUL (terminator) | `0x06`..`0x0F` | `'0'` .. `'9'` | `0x2A`..`0x43` | `'A'` .. `'Z'` |
| `0x01` | `'-'` | `0x10`..`0x29` | `'a'` .. `'z'` | `0x44` | `'_'` |
| `0x02` | `' '` (space) | `0x03` | `'/'` | `0x04` | `'.'` |
| `0x05` | `'~'` | | | | |

*Note: DOS backslashes (`\`) are normalized to forward slashes (`/`) or mapped to relative paths.*

### 2.2 Header Digest

When checksums are enabled (`csum != 0`), a digest covers the header fields:
`CRC16( LE32(nfiles) + per_file[ name_symbols + flag(1) + LE32(dt) + LE32(sz) + 00*4 ] )`.
The digest is coded as big-endian bytes right after the file list and before `method`/`extra3`.

### 2.3 Method Byte & Compression Level

- `extra3` encodes the compression level: `0` = `-m1` (Fast), `1` = `-m2` (Normal), `2` = `-m3` (Maximum).
- `method` defines the reference block buffer size:
  $$\text{window\_size} = (\text{method} \ll 19) + \text{0xFFFFF}$$
  The range coder's payload symbol model uses:
  $$\text{nsyms} = \text{bitlen}(\text{window\_size})$$ (typically 20 to 22).

---

## 3. Binary Range Coder (RC)

All variable-length fields, header records, and block control structures use a byte-renormalizing Binary Range Coder (`SbcRC`).

### 3.1 State and Primitives

- **State variables**: `low` (32-bit), `range` (32-bit), `code` (32-bit).
- **Renormalization**: When `range <= 0x00FFFFFF`, `range` and `low` are shifted left by 8 bits, and the next input byte is shifted into `code`.
- **Primitives**:
  - `rc_get(total)`: Returns normalized scaled code `(code - low) / (range / total)`.
  - `rc_decode(cum, freq)`: Updates interval `low += cum * (range / total)` and `range = freq * (range / total)`.
  - `decode_large(bound)`: Decodes an integer in `[0, bound - 1]`.
  - `decode_int_maxbits(nbits)`: Reads variable-width integers up to `nbits`.

### 3.2 Adaptive Models

1. **`Extra` Symbol Model**: Cumulative frequency table with adaptive scaling (`total` cap, frequency caps, and periodic halving).
2. **`SizeModel`**: Difference model for file sizes and timestamps using zigzag delta encoding against previous entries.

---

## 4. Block Stream & Multi-Block Layout

The payload following the header consists of one or more sequential compression blocks:

```
+-----------------------------------------+
| Block Length VLQ (1..4 bytes)           |  BWT block length (decompressed L length)
+-----------------------------------------+
| Range-Coded Block Header                |
|   - Primary Index (decode_large(vlq))   |  BWT rotation index
|   - nbits (decode_int_maxbits(20))      |  Filter record bitstream length
|   - Bitstream (copy_bits(nbits))        |  MSB-first filter control bits
|   - flag3 (u(3))                        |  Post-processing transform
|   - [extra16 (u(16))]                   |  Only present if flag3 == 2
|   - e1 (extra.decode_extra())           |  Entropy payload length
|   - e2 (extra.decode_extra())           |  Mode-4 line model stream length
+-----------------------------------------+
| Integrity Checksum (optional)           |  Digest over block header + stream
+-----------------------------------------+
| Payload Data                            |
|   - If e1 == 0: Stored BWT stream       |  Raw uncompressed bytes (rc_pos + 2)
|   - If e1 != 0: Entropy-coded stream    |  Stage-2 PPM entropy encoded
+-----------------------------------------+
| Verify Checksum (CRC16/ARC or digest)   |  Digest over decoded block output
+-----------------------------------------+
```

### 4.1 Variable-Length Quantity (VLQ)

The block length is read directly from the byte stream:

| Prefix Bits | Total Bytes | Value Formula |
|---|---|---|
| `00xxxxxx` | 1 byte | `b0` |
| `01xxxxxx` | 2 bytes | `((b0 ^ 0x40) << 8) \| b1` |
| `10xxxxxx` | 3 bytes | `(((b0 ^ 0x80) << 16) \| (b1 << 8) \| b2` |
| `11xxxxxx` | 4 bytes | `(((b0 ^ 0xC0) << 24) \| (b1 << 16) \| (b2 << 8) \| b3` |

*A value of `vlq == 0` signifies the end of the block stream.*

### 4.2 Stream Boundaries & RC Flush

The Range Coder state is flushed with 4 bytes at the end of the header and before raw payload chunks. When `e1 == 0` (uncompressed BWT block), the raw stream begins at `rc_pos + 2` relative to the block header range coder state.

---

## 5. Burrows-Wheeler Transform (BWT) & Sorter Rules

Each block undergoes an inverse Burrows-Wheeler Transform to recover the pre-filtered stream from column $L$:

```c
void sbc_ibwt(const uint8_t *L, size_t n, uint32_t primary, uint8_t *out) {
    uint32_t count[256] = {0}, C[256], i, p = primary;
    for (i = 0; i < n; i++) count[L[i]]++;
    C[0] = 0;
    for (i = 1; i < 256; i++) C[i] = C[i-1] + count[i-1];
    uint32_t *T = malloc(n * sizeof(uint32_t));
    for (i = 0; i < n; i++) T[C[L[i]]++] = i;
    for (i = 0; i < n; i++) {
        p = T[p];
        out[i] = L[p];
    }
    free(T);
}
```

### 5.1 Cyclic Rotation Tie-Breaking Rules

The BWT output $L$ is invariant to rotation ties, but the **`primary` index** depends strictly on the vendor sorter's internal permutation order:

1. **Bucket Pass**: Stable distribution by initial byte.
2. **Context Skip Rule**: Prior to sorting a sub-segment, if all preceding characters `s[a[i] - 1]` match, the segment is skipped (leaves equal rotations in insertion order).
3. **Bentley-McIlroy 3-Way Quicksort**: Partitions equal keys to both ends (`eqL`, `eqR`) and swaps them to the middle using unstable vector swaps (`vecswap`).
4. **Pivot Selection**: `median3(a[lo], a[mid], a[hi-1])` with tie preference `a[lo] == a[mid] -> a[lo]`.
5. **Insertion Sort Cutoff**: Sub-problems of size $< 11$ are sorted with a stable insertion sort comparing up to `depth + min(end - a[i]) - 1`.
6. **Equal Band Multi-Byte Hand-off**: Sub-problems at depth $\ge 6$ partition using 32-bit big-endian words and advance depth by 2 bytes per step.
7. **Comparison Index Normalization**: Comparison indices past the buffer boundary (`n + min(n, 0x1000)`) wrap by subtracting `n`.

---

## 6. Payload Entropy Models (Stage 2)

When `e1 != 0`, the BWT column $L$ is compressed with a secondary entropy coder:

1. **Stage 1 (Bit-plane / Alphabet Reduction)**: Decomposes bytes into symbol classes and escape codes.
2. **Stage 2 (PPM Adaptive Modeler)**: High-order context-adaptive arithmetic model decoding the payload stream.
3. **Second-Stage History Filter (`sub == 1`)**:
   In `-m2` and `-m3` archives, a stateful dictionary filter with cross-block history operates on the decoded records:
   - **Variant 0 (`-m2`)**: 17-bit hash `(d[-3]<<13) ^ (d[-2]<<8) ^ d[-1]`, 128K table slots, 1.5 MB history ring.
   - **Variant 1 (`-m3`)**: 21-bit hash on two 32-bit words `(w4 ^ w4>>13) ^ ((w8 ^ w8>>15) << 11)`, 512K table slots, 24 MB history ring.
   - **Escape marker**: `03 C5`. Replaces matched phrases with references to the history ring.

---

## 7. Filter Record Stream & Transform Modes

The bitstream `bits` unpacked from the block header defines a sequence of variable-length filter records:

```python
while True:
    flen = getbits(25)
    if flen == 0x1FFFFFF or (consumed + flen > usize):
        break
    coded = getbits(1)
    mode  = getbits(3) if coded else 5
    dict  = getbits(1) if coded else 0
    if dict:
        dref = getbits(12)      # Ring reference index
        dlen = getbits(25)      # Replayed phrase length
    if coded and mode == 4:
        ctrl = getbits(24)      # Mode 4 control word
    if coded and mode == 7:
        m7   = getbits(12)      # Image predictor row width
    if coded and mode in (0, 2):
        adv  = getbits(1)       # Mode 6 composite flag
    if level >= 2:
        sub  = getbits(1)       # Second-stage filter flag
        if sub:
            flag = getbits(1)   # Alignment flag
            idx  = getbits(5)   # Copy base index
    apply_record(flen, coded, mode, ...)
    consumed += flen
```

### 7.1 Mode 0: Adaptive Delta

- **Simple Delta (`-m1`)**: Fixed lag candidates `(2, 3, 4, 6, 8, 13)`. State machine switches active lag based on error scores over a 16 KB trial window.
- **Advanced Adaptive Delta (`-m2`, `-m3`)**:
  - Context model tracking byte-deltas per slot with 64 KB age tables.
  - Slot pool dynamically reallocated at chunk boundaries based on minimum absolute difference sums.
  - Three distinct chunk cut triggers:
    1. Running error threshold comparison against slot 0.
    2. Context age saturation wrap (resets aging counters).
    3. Per-byte third cut (VA `0x425e9a`) when active slot score leads slot 0 by $\min(\text{pos} \gg 4, 32)$.

### 7.2 Mode 4: Text Compound Filter

Designed for source code and prose text files (`ctrl` parameter):

1. **Byte Substitution**: 256-byte mapping table (VA `0x40780c`).
2. **Line-Break Model (`0x408060`)**: When enabled via control bits, reconstructs LF/CR line endings using a 19-symbol reverse range coder reading backward from the block's `e2` bytes.
3. **Token Dictionary Expansion**: Expands token bytes `0x80..0xFC` into English keywords, C identifiers, and common character pairs.
4. **Whitespace Packing**: Reconstructs indented space blocks and trailing newline padding.

### 7.3 Mode 5: Literal Passthrough

Copies `flen` bytes verbatim from the stream without transformation.

### 7.4 Mode 6: Context-2 Repeat Transform

Repeat-match filter with two-byte context indexing:
- Matches are encoded as `7B F0 <len>` escape sequences.
- Copies `len + 16` bytes from the last seen occurrence of the active 16-bit prefix.

### 7.5 Mode 7: 2D Adaptive Spatial Predictor

Applied to 24-bit and high-depth raster images (`image24`, `image7`):
- **Pitch**: Row width $W = 3 \times \text{param}$ (e.g. param = 256 $\rightarrow W = 768$).
- **First row**: Decoded via horizontal delta: `out[i] = src[i] + out[i - 3]`.
- **Subsequent rows**: Evaluates four candidate 2D predictors for each pixel channel:
  - Predictor 0 (Left): $P_0 = \text{out}[i - 3]$
  - Predictor 1 (Up): $P_1 = \text{out}[i - W]$
  - Predictor 2 (2D Gradient): $P_2 = \text{out}[i - 3] + \text{out}[i - W] - \text{out}[i - W - 3]$
  - Predictor 3 (JPEG-LS Median):
    $$P_3 = \begin{cases} \min(P_0, P_1) & \text{if } P_{ul} \ge \max(P_0, P_1) \\ \max(P_0, P_1) & \text{if } P_{ul} \le \min(P_0, P_1) \\ P_2 & \text{otherwise} \end{cases}$$
- **Adaptive Selection**: 192-byte sliding accumulator chooses the optimal predictor minimizing $\sum | \text{out} - \text{pred} |$.

### 7.6 The `adv` Flag

When `adv == 1` on a Mode 0 or Mode 2 record, the filter output was weakly compressible and was pre-transformed with Mode 6 (repeat coder). The decoder expands with the Mode 6 decoder first, then applies inverse Mode 0/2.

---

## 8. Post-Processing Transforms (`flag3`)

Applied across the entire decoded block output after all filter records are assembled:

| `flag3` | Transform Type | Mechanism |
|---|---|---|
| `0` | **None** | Identity (stream is used directly). |
| `1` | **Single LZP** | LZP decompressor (`0x40a7d0`): `mark1=0x02`, `mark2=0xC5`, `window=66`, `skip=66`, hash mask `0x1FFFFF` (2M 32-bit entries, 8 MB table). |
| `2` | **LZP Cascade** | Multi-pass cascade: executes `extra16 + 1` marker passes in reverse order, followed by the default pass (`mark1=0x02`, `mark2=0xC5`) last. |

---

## 9. Checksums & Cryptography

### 9.1 Checksum Algorithms

| ID | Switch | Algorithm | Digest Size | Specification |
|---|---|---|---|---|
| `0` | `-hn` | None | 0 bytes | Disabled |
| `1` | `-hr` | CRC16/ARC | 2 bytes | Reflected poly `0xA001`, init `0xFFFF`, xorout `0xFFFF`, Big-Endian |
| `2` | `-hc` | CRC32 | 4 bytes | IEEE 802.3 poly `0xEDB88320`, init `0xFFFFFFFF`, xorout `0xFFFFFFFF` |
| `3` | `-ha` | Adler-32 | 4 bytes | Modulo 65521 ($s_1 = 1, s_2 = 0$) |
| `4` | `-hs` | Sum32 | 4 bytes | Proprietary 32-bit additive toy checksum (see below) |
| `5` | `-hm` | MD5 | 16 bytes | RFC 1321 |
| `6` | `-h1` | SHA-1 | 20 bytes | FIPS PUB 180-1 |
| `7` | `-h2` | SHA-256 | 32 bytes | FIPS PUB 180-2 |

#### Sum32 Algorithm

```c
uint32_t sbc_sum32(const uint8_t *data, size_t len) {
    uint32_t A = 1, B = 0, word = 0;
    size_t cnt = 0, i;
    for (i = 0; i < len; i++) {
        word = ((uint32_t)data[i] << 24) | (word >> 8);
        if (++cnt == 4) {
            B += A;
            A += word;
            cnt = 0;
        }
    }
    return (A + B) ^ (uint32_t)len;
}
```

### 9.2 Symmetric Encryption Ciphers

When `crypto != 0`, block payloads are encrypted with symmetric ciphers:

| ID | Switch | Cipher | Key Size | Block Size | Mode |
|---|---|---|---|---|---|
| `1` | `-ca` | AES / Rijndael | 128 / 256 bits | 16 bytes | CBC |
| `2` | `-cb` | Blowfish | 128 bits | 8 bytes | CBC |
| `3` | `-cc` | CAST-128 | 128 bits | 8 bytes | CBC |
| `4` | `-cd` | Triple-DES (3DES) | 168 bits (3 keys) | 8 bytes | CBC |
| `5` | `-cs` | Serpent | 256 bits | 16 bytes | CBC |
| `6` | `-ct` | Twofish | 256 bits | 16 bytes | CBC |

Key derivation expands the user passphrase using SHA-256 and salted key whitening.

---

## 10. Key Disassembly Reference Addresses

For cross-referencing and verification against `sbc.exe` / `unsbc.exe` (PE image base `0x400000`):

| Component / Function | VA in Binary | Description |
|---|---|---|
| `RC::init` / `RC::decode` | `0x4296e0` / `0x429760` | Binary range coder engine |
| `RC::decode_large` | `0x4297d0` | Large integer range decoder |
| `Header::parse` | `0x403b00` | Archive header parser & file table unpacker |
| `BWT::sort` | `0x4225c0` | Bentley-McIlroy 3-way quicksort rotation engine |
| `BWT::ibwt` | `0x435df0` | Inverse BWT linear reconstruction |
| `LZP::decode` | `0x40a7d0` | Primary LZP stream expander (`flag3 == 1`) |
| `LZP::cascade` | `0x40ea90` | Multi-pass LZP cascade expander (`flag3 == 2`) |
| `Mode0::simple` | `0x424150` | Fast adaptive delta decoder |
| `Mode0::advanced` | `0x425200` | Multi-context adaptive delta engine |
| `Mode4::apply` | `0x406940` | Text compound filter pipeline |
| `Mode4::subst_table` | `0x40780c` | 256-byte character substitution table |
| `Mode4::line_model` | `0x408060` | Backward 19-symbol line-break reconstructor |
| `Mode6::repeat` | `0x4083a0` | Context-2 phrase repeat decoder |
| `Mode7::predict` | `0x429bd0` | 2D adaptive spatial predictor |
| `Stage2::sub_expand` | `0x423c60` | Stateful history dictionary expander (`-m2`/`-m3`) |
| `CRC16::table` | `0x448a60` | Reflected polynomial `0xA001` CRC table |
