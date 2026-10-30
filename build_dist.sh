#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "${SCRIPT_DIR}"

VERSION="0.970"
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
## SBC Archiver 0.970

Pure freestanding C reimplementation of historical SBC Archiver 0.970 (Sami Runne, 2000–2002).

• **100% Bit-Exact Compatibility**: Bit-exact decompression and re-compression matching original 32-bit reference archives across all compression modes (M1 LZP+Huffman, M2 BWT+RLE+Huffman, M3 BWT+LZP+RLE+Huffman, M0 Store, M4-M7 transforms).
• **Ciphers & Checksums**: Full support for 6 encryption algorithms (AES-128, Blowfish, CAST-128, DES, 3DES, Serpent, Twofish) and 8 checksum formats (CRC16, CRC32, Adler32, Sum32, MD5, SHA-1, SHA-256).
• **Modern Cross-Platform CLI**: Standalone native Linux and static Windows 64-bit binaries, Unix path conversion (\`-u\`), bare listing (\`-1\`), path traversal and Zip-Slip protection.

### Release Assets

• \`${TAR_NAME}\` : Pre-built standalone 64-bit Linux binary (\`sbc\`) + documentation
• \`${ZIP_NAME}\` : Pre-built standalone 64-bit Windows static binary (\`sbc.exe\`) + documentation
• \`${DEB_NAME}\` : Debian / Ubuntu installer package (amd64)

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
