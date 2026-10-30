# SBC Encoder Architecture Specification (SBC Archiver 0.970)

This document provides a comprehensive technical specification of the encoding pipeline, block structuring strategies, filter decision policies, and compression stages implemented in the pure-C reimplementation of **SBC Archiver 0.970**.

The encoder achieves **100% bit-exact parity** with the original historical Windows binary (`sbc.exe`): every generated archive matches the vendor's binary output byte-for-byte across all supported compression modes (`-m1`..`-m3`), block sizes (`-b1`..`-b63`), structures (`-on`..`-ub`), checksum types (`-hn`..`-h2`), and ciphers (`-ca`..`-ct`).

---

## 1. High-Level Compression Pipeline

The encoding pipeline transforms input files into an SBC archive through several sequential stages:

```
+-----------------------------------------------------------------------------+
| 1. Input Processing & Ordering                                              |
|    - File ordering & grouping (-on, -of, -oa, -oz, -os, -ub)                |
|    - Archive header file list generation (sorted by name length)            |
+-----------------------------------------------------------------------------+
                                     |
                                     v
+-----------------------------------------------------------------------------+
| 2. Block Slicing & Record Segmentation                                      |
|    - Block size threshold calculation (min of -bN and total-derived size)   |
|    - Dictionary-reference detection (prefix matching >= 1024 bytes)         |
|    - Independent per-file filter selection & transformation                 |
+-----------------------------------------------------------------------------+
                                     |
                                     v
+-----------------------------------------------------------------------------+
| 3. Pre-Compression & Transformation Engine                                  |
|    - Mode 0: Simple (-m1) or Advanced (-m2/-m3) Adaptive Delta              |
|    - Mode 4: Text Compound Filter (Substitution, Tokens, Line-breaks)       |
|    - Mode 6: Context-2 Phrase Repeat Transform                              |
|    - Mode 7: 2D Adaptive Spatial Image Predictor (Pitch search)             |
|    - adv Flag: Secondary Mode-6 repeat transform on weak Mode-0 accepts     |
+-----------------------------------------------------------------------------+
                                     |
                                     v
+-----------------------------------------------------------------------------+
| 4. Post-Filter Processing (LZP)                                             |
|    - flag3 == 0: Identity (no LZP)                                          |
|    - flag3 == 1: Single-pass LZP (21-bit hash mask, window=66, skip=66)     |
|    - flag3 == 2: Multi-pass LZP Cascade (extra passes for blocks > 2 MB)    |
+-----------------------------------------------------------------------------+
                                     |
                                     v
+-----------------------------------------------------------------------------+
| 5. Burrows-Wheeler Transform (BWT)                                          |
|    - Bentley-McIlroy 3-way quicksort with cyclic rotation tie-breaking      |
|    - Exact primary index derivation matching vendor permutation rules       |
+-----------------------------------------------------------------------------+
                                     |
                                     v
+-----------------------------------------------------------------------------+
| 6. Stage-2 Entropy Coding (PPM) & Decision                                  |
|    - Forward Stage 1 (bit-plane reduction) + Stage 2 (PPM arithmetic model) |
|    - Stored vs. Compressed cost comparison (fallback to stored BWT or copy) |
+-----------------------------------------------------------------------------+
                                     |
                                     v
+-----------------------------------------------------------------------------+
| 7. Container Assembly & Optional Encryption                                 |
|    - Header range coder serialization & checksum digests (CRC16..SHA256)    |
|    - Multi-block payload writing with VLQ lengths & verify CRC16            |
|    - Symmetric CBC encryption (AES, Blowfish, CAST, DES, 3DES, Serpent,     |
|      Twofish) with 8192-round SHA-256 KDF                                   |
|    - Archive trailer: VLQ(0) + 32-bit rolling hash                          |
+-----------------------------------------------------------------------------+
```

---

## 2. CLI Options & Parameter Derivation

### 2.1 Compression Levels (`-m1`, `-m2`, `-m3`)

The compression level controls the algorithms enabled at each stage:

| Level | Switch | Delta Filter | Filter sub Stage | Window Rules |
|---|---|---|---|---|
| Level 0 | `-m1` | Simple Adaptive Delta (fixed lags) | Disabled | Fast heuristic |
| Level 1 | `-m2` | Advanced Adaptive Delta (`24, 3, 768`) | Variant 0 (1.5 MB ring) | Normal search |
| Level 2 | `-m3` | Advanced Adaptive Delta (`53, 10, 600`) | Variant 1 (24 MB ring) | Extended 512 KB search |

### 2.2 Block Size Derivation (`-bN`)

The default block threshold is `-b5` (3 MB). The effective block size is constrained by the total uncompressed size:

$$\text{effective\_block\_size} = \min\left( (N + 1) \times 512\text{ kB}, \text{derived\_block\_size} \right)$$

where:
$$\text{derived\_block\_size} = \left( \left\lfloor \frac{\text{total\_bytes} + 512\text{ kB}}{512\text{ kB}} \right\rfloor + 1 \right) \times 512\text{ kB}$$

The header `method` byte is derived as:
$$\text{method} = \frac{\text{effective\_block\_size} - 1\text{ MB}}{512\text{ kB}}$$

---

## 3. Block Structuring & File Ordering Strategies

The vendor archiver supports six block organization strategies:

| Switch | Name | Block Construction | Ordering Strategy |
|---|---|---|---|
| `-on` | **Normal** | One file per block | Command-line order |
| `-oz` | **Analysis + Name** | Multi-file blocks | Analysis entropy sort, then name sort (Default) |
| `-oa` | **Analysis Only** | Multi-file blocks | Analysis entropy sort |
| `-of` | **Extension Groups**| Multi-file blocks | Clustered by 4-byte extension hash |
| `-os` | **Solid** | Full blocks | Concatenates all files into single continuous stream |
| `-ub` | **Uniform Block** | Multi-file blocks | One composite record per block |

### 3.1 Content Analysis Sorter (`-oa`, `-oz`)

In `-oa` and `-oz` modes, files are ordered prior to block slicing by an entropy scoring heuristic (VA `0x4135e0`):
1. Reads up to 256 bytes from each file header.
2. Computes a byte-frequency table and transition profile:
   - Evaluates printable ASCII density, null counts, and byte-variance scores.
   - Assigns a classification priority: plain text and source code group together; binary structures and media group together.
3. In `-oz` mode, files within identical analysis classes are sorted alphabetically.

### 3.2 File Table Directory Sorting

Regardless of block placement, file records inside the Range-Coded archive header are ordered by:
1. **Filename Length** (ascending).
2. **Alphabetical Order** for entries of equal length.

### 3.3 Dictionary-Reference Detection (`dref`)

When a file shares a common prefix of 1024 bytes or more with an earlier file in the same block's history ring:
- The shared prefix is emitted as a dictionary reference record:
  - `dref`: 12-bit ring index pointing to the source record.
  - `dlen`: 25-bit length of replayed bytes.
- Only the remaining non-matching tail is passed through the filter pipeline.

---

## 4. Filter Decision Policy & Transforms

Each segment in a block is analyzed to select the optimal transform:

```c
int sbc_enc_policy_mode(const uint8_t *data, size_t n, int level, uint32_t *ctrl_out)
```

### 4.1 Mode 0: Adaptive Delta

- **`-m1` Simple Delta**:
  - Tests candidate lags `(2, 3, 4, 6, 8, 13)` over a 16 KB window.
  - Returns `r = 0` (refused, coded $\le 4$ KB), `r = 1` (weak accept, coded $\le n/10$), or `r = 2` (strong accept).
  - Weak accepts trigger the `adv` repeat stage.
- **`-m2` / `-m3` Advanced Delta**:
  - Multi-context adaptive filter with dynamically updated lag pools.
  - Evaluates context scores across chunk boundaries.
  - Three chunk cut triggers: running error comparison, context age wrap, and the per-byte third cut (`0x425e9a`) when `score[active] > score[0] + min(pos >> 4, 32)`.

### 4.2 Mode 4: Text Compound Filter

Selected when content passes text characterization (minimum 600 bytes and positive token analysis score):
1. **Control Word Selection**: Analyzes newline conventions (LF vs CRLF), space density, and capital letters.
2. **256-Byte Character Map**: Replaces common text symbols with dense byte ranges.
3. **Line-Break Model (`0x408060`)**: Emits `e2` bytes encoding line lengths using a 19-symbol reverse range coder.
4. **Token Dictionary**: Scans for common words and letter-pairs, encoding them as tokens `0x80..0xFC`.
5. **Token Bit Optimization**: If no dictionary tokens are produced, bit `0x80` of `ctrl` is cleared (e.g. `0x0C` record for sparse or uncompressed text).

### 4.3 Mode 6: Context-2 Repeat Transform

Used for repetitive text or uppercase prose:
- Tracks the last seen position of every 16-bit byte pair in a 64K lookup table.
- Encodes repeats of 16 bytes or more as `7B F0 <len>` escape sequences.
- Escapes literal `{` (`0x7B`) occurrences as `7B F0 00`.

### 4.4 Mode 7: 2D Adaptive Spatial Predictor

Selected on photographic rasters and 24-bit imagery at `-m3` when:
1. Segment size exceeds 16 KB.
2. Mode-0 advanced filter reports substantial lag-3 activity:
   $$\text{arr}[2] > \frac{n}{3}$$
3. **Pitch Estimator (`sbc_enc_m7_search`)**:
   - Tests 2,400 candidate row widths ($3 \times 100$ to $3 \times 2499$) using geometric walks and multi-slice refinement.
   - Identifies candidate pitch $W = 3 \times \text{param}$.
   - Decomposes imagery into 2D residual streams using the four spatial candidate predictors (Left, Up, 2D Gradient, JPEG-LS Median).

### 4.5 The `adv` Repeat Stage

When Mode 0 returns a weak accept (`r = 1`), the encoder passes the delta residual through the Mode 6 repeat coder. If the repeat output fits within the allocation margin:
- The record stores the Mode-6 stream.
- The `adv` flag bit is set to `1`.
- The decoder mirrors this by expanding with Mode 6 before inverting Mode 0.

---

## 5. Post-Processing & Burrows-Wheeler Transform

### 5.1 LZP Transform (`flag3`)

- **Single Pass (`flag3 == 1`)**:
  - Applied to the assembled block stream.
  - Matches previous contexts using an 8 MB lookup table (2M entries, 21-bit hash mask `0x1FFFFF`).
  - Parameters: `mark1 = 0x02`, `mark2 = 0xC5`, `window = 66`, `skip = 66`.
- **Cascade (`flag3 == 2`)**:
  - When block output exceeds 2 MB, extra marker passes with increasing windows are prepended.
  - Recorded in the block header as `extra16 = extra_passes - 1`.

### 5.2 Burrows-Wheeler Transform & Primary Sorter

The BWT column $L$ and primary index are generated using a Bentley-McIlroy 3-way quicksort operating on cyclic rotations:

1. **Bucket Partition**: Groups rotations stably by first byte.
2. **Preceding Byte Skip Rule**: Segments with matching preceding bytes are skipped without sorting (preserves insertion stability).
3. **3-Way Partitioning**: Equal keys are gathered at boundaries and swapped into the center.
4. **Tie-Breaking Priority**: Median-of-3 ties prioritize $a[\text{lo}]$.
5. **Multi-Byte Switching**: Sub-segments at depth $\ge 6$ switch to 32-bit big-endian word comparisons.

---

## 6. Stage-2 Entropy Coding (PPM) & Decision

The BWT output column $L$ is evaluated for entropy compression:

1. **Entropy Encoding (PPM)**:
   - Stage 1 decomposes symbols into bit-plane classes.
   - Stage 2 compresses symbol classes and residuals using adaptive arithmetic contexts.
   - Emits $e_1$ bytes of coded payload.
2. **Cost Evaluation & Fallbacks**:
   - If the compressed stream $e_1$ exceeds the uncompressed length:
     - The encoder falls back to a **Stored BWT Block** (`e1 == 0`), writing $L$ verbatim starting at `rc_pos + 2`.
   - If the entire filter/BWT pipeline fails to achieve positive compression:
     - The block falls back to a **Stored Literal Block** (`mode = 5`, copy through).

---

## 7. Cryptographic Subsystem (`-c*`)

When archive encryption is requested (`-ca`..`-ct`), block payloads are secured via symmetric ciphers operating in CBC mode:

| Switch | Cipher | Key Size | Block Size | Special Implementation Notes |
|---|---|---|---|---|
| `-ca` | AES / Rijndael | 256 bits | 16 bytes | Standard FIPS-197 AES |
| `-cb` | Blowfish | 256 bits | 8 bytes | Standard Bruce Schneier Blowfish |
| `-cc` | CAST-128 | 128 bits | 8 bytes | Standard RFC 2144 CAST-128 |
| `-cd` | Triple-DES (3DES) | 168 bits | 8 bytes | Three independent DES keys |
| `-cs` | Serpent | 256 bits | 16 bytes | **TNEPRES variant**: 32-byte key reversal and 16-byte block reversal |
| `-ct` | Twofish | 256 bits | 16 bytes | Standard Counterpane Twofish |

### 7.1 Key Derivation Function (KDF)

- 16 random salt bytes are generated and stored in the archive header.
- The passphrase and salt are processed through 8,192 rounds of SHA-256 to derive cipher keys and initialization vectors (IV).
- A 1-byte verification check is stored to detect incorrect passphrases immediately upon opening.

---

## 8. Verification Matrix & Parity Status

The encoder implementation is continuously validated against the vendor's original binaries (`sbc.exe` and `unsbc.exe` under Wine) through automated test suites:

| Test Suite | Scope | Parity Result |
|---|---|---|
| `vendor_parity.py` | Reference corpus files across all modes (`-m1`, `-m2`, `-m3`) | **39/39 bit-exact identical** |
| `enc_matrix.py` | Multi-file sets across 3 levels and 8 checksum types | **144/144 bit-exact identical** |
| `enc_big.py` | Large multi-block archives with `-ad` up to 3.1 MB | **73/73 bit-exact identical** |
| `parity_random.py` | Randomized multi-file sets with mixed content shapes | **30/30 bit-exact identical** |
| `multifile_parity.py`| Multi-file block layouts across all structure modes (`-on`..`-ub`) | **108/108 bit-exact identical** |
| `mode6_parity.py` | Repetitive text and cycle patterns | **27/27 bit-exact identical** |
| `m7_parity.py` | 24-bit photographic images with automated pitch detection | **12/12 bit-exact identical** |
| `crypt_parity.py` | All 6 ciphers tested bidirectionally (vendor $\leftrightarrow$ reimplementation) | **24/24 bit-exact match** |
| `verify_all.py` | Full corpus archive decompression and data verification | **52/52 passed (0 failures)** |
