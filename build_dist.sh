#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "${SCRIPT_DIR}"

VERSION="0.970.2"
DEB_VERSION="0.970.2-1"
DIST_DIR="${SCRIPT_DIR}/dist"
STAGE_DIR="${SCRIPT_DIR}/build/dist_stage"

TAR_NAME="sbc-v${VERSION}-linux-x86_64.tar.gz"
ZIP_NAME="sbc-v${VERSION}-windows-x86_64.zip"
DEB_NAME="sbc_${DEB_VERSION}_amd64.deb"

echo "=========================================================="
echo "  Building SBC Archiver ${VERSION} Distribution Packages"
echo "=========================================================="

mkdir -p "${DIST_DIR}"
rm -rf "${STAGE_DIR}"
mkdir -p "${STAGE_DIR}"

echo "=== Building Debian Package ==="
chmod +x ./build_deb.sh
./build_deb.sh

echo "=== Building Windows 64-bit Binary ==="
make win64

echo "=== Packaging Linux Tarball (${TAR_NAME}) ==="
mkdir -p "${STAGE_DIR}/linux"
cp -f "${SCRIPT_DIR}/build/linux/sbc" "${STAGE_DIR}/linux/sbc"
strip -s "${STAGE_DIR}/linux/sbc" || true
chmod 755 "${STAGE_DIR}/linux/sbc"
cp -f "${SCRIPT_DIR}/README.md" "${STAGE_DIR}/linux/"
cp -f "${SCRIPT_DIR}/FORMAT.md" "${STAGE_DIR}/linux/"
cp -f "${SCRIPT_DIR}/ENCODER.md" "${STAGE_DIR}/linux/"

tar -czf "${DIST_DIR}/${TAR_NAME}" -C "${STAGE_DIR}/linux" sbc README.md FORMAT.md ENCODER.md

echo "=== Packaging Windows Zip (${ZIP_NAME}) ==="
mkdir -p "${STAGE_DIR}/windows"
cp -f "${SCRIPT_DIR}/build/win64/sbc.exe" "${STAGE_DIR}/windows/sbc.exe"
x86_64-w64-mingw32-strip -s "${STAGE_DIR}/windows/sbc.exe" || true
chmod 755 "${STAGE_DIR}/windows/sbc.exe"
cp -f "${SCRIPT_DIR}/README.md" "${STAGE_DIR}/windows/"
cp -f "${SCRIPT_DIR}/FORMAT.md" "${STAGE_DIR}/windows/"
cp -f "${SCRIPT_DIR}/ENCODER.md" "${STAGE_DIR}/windows/"

(cd "${STAGE_DIR}/windows" && zip -9 "${DIST_DIR}/${ZIP_NAME}" sbc.exe README.md FORMAT.md ENCODER.md)

rm -rf "${STAGE_DIR}"

echo "=== Computing SHA-256 Checksums ==="
cd "${DIST_DIR}"
sha256sum "${TAR_NAME}" "${ZIP_NAME}" "${DEB_NAME}" > sha256sums.txt
cat sha256sums.txt

echo "=== Generating Release Notes ==="
cat << EOF > "${DIST_DIR}/release_notes.md"
## SBC Archiver ${VERSION}

Performance and optimization release further accelerating compression and checksum processing across all profiles (-m1, -m2, -m3) while maintaining 100% bit-exact compatibility with the original 32-bit DOS reference archiver.

### Performance Improvements
- **Fast Checksums (Slice-by-8 & Adler32)**: Table-driven reflected CRC16 and CRC32 processing 8 bytes per iteration, with deferred modulo reduction for Adler32 (benefiting both encoder and decoder).
- **Stage 2 Range Coder Acceleration**: Backward occurrence array (\`nxt[]\`) replacing per-symbol cursor lookups with linear memory access; SSE2-vectorized rank scanning (8 integers per step); byte-buffered bit accumulation.
- **Mode 0 Adaptive Filter Optimizations**:
  - SSE2 vectorization for lag-weight scoring in -m3 and delta/context computation in batch mode.
  - Branchless context-table updates (\`sbc_m0a_hit\`) eliminating branch mispredictions.
  - Table-by-table batch processing (\`sbc_m0a_batch0\`) when copy slot is active, maximizing cache locality.
- **Speedup Results**: ~ 1.15x to 1.50x faster encoding on text, structured records, and binaries.

### Release Assets
- \`${TAR_NAME}\` : Standalone 64-bit Linux binary (\`sbc\`) + documentation
- \`${ZIP_NAME}\` : Standalone 64-bit Windows static binary (\`sbc.exe\`) + documentation
- \`${DEB_NAME}\` : Debian / Ubuntu installer package (amd64)

### SHA-256 Checksums
\`\`\`
$(cat "${DIST_DIR}/sha256sums.txt")
\`\`\`
EOF

echo ""
echo "=== Distribution Assets Summary ==="
ls -lh "${DIST_DIR}"
echo "=========================================================="
echo "Distribution packaging completed successfully!"
