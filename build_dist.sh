#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "${SCRIPT_DIR}"

VERSION="0.970.1"
DEB_VERSION="0.970.1-1"
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

Maintenance and performance release bringing significant compression speedups to the pure C reimplementation of historical SBC Archiver 0.970, while strictly preserving 100% bit-exact parity with the original 32-bit DOS reference archiver.

### Performance Improvements
- **Transform & Policy Caching**: Caches Mode 0, Mode 4, and Mode 6 filtered buffers and linecodes during policy evaluation, eliminating duplicate filtering runs during pipeline execution.
- **BWT Reuse on Stored Fallback**: Direct reuse of the pipeline BWT array without re-sorting when a block falls back to stored mode (major speedup on high-entropy / incompressible streams).
- **Fast Stage 2 Encoding**: Replaced per-step linear \`memchr\` lookups with symbol occurrence index arrays (\`occ\`) and monotonic forward cursors; added early abort when payload cannot beat raw length.
- **Memory Pooling & Zero-Copy**: Reused scratch buffers and 64 KiB slot tables in Mode 0 (reducing memory allocations to a single memset per block); direct residual writes into destination buffers.
- **64-bit SWAR & Vector Intrinsics**: 8-byte multi-byte loads (\`sbc_ld64\`), \`__builtin_bswap32\`, and \`__builtin_ctzll\` in BWT, LZP, and sub-compressor inner loops.
- **Speedup Results**: ~ 1.30x to 1.53x faster encoding on code, binary, and high-entropy data.

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
