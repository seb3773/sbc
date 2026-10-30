#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PKG_DIR="${SCRIPT_DIR}/build/pkg_root"
VERSION="0.970.1-1"
ARCH="amd64"
DEB_NAME="sbc_${VERSION}_${ARCH}.deb"

echo "=== Building SBC Archiver 0.970 from source ==="
cd "${SCRIPT_DIR}"
make clean
make -j"$(nproc)" all

echo "=== Running test suite before packaging ==="
make test

echo "=== Packaging DEB ==="
rm -rf "${PKG_DIR}"
mkdir -p "${PKG_DIR}/usr/bin"
mkdir -p "${PKG_DIR}/usr/share/doc/sbc"
mkdir -p "${PKG_DIR}/DEBIAN"

# Install binary
if [ -f "${SCRIPT_DIR}/build/linux/sbc" ]; then
    cp -f "${SCRIPT_DIR}/build/linux/sbc" "${PKG_DIR}/usr/bin/sbc"
else
    cp -L -f "${SCRIPT_DIR}/sbc" "${PKG_DIR}/usr/bin/sbc"
fi
strip -s "${PKG_DIR}/usr/bin/sbc" || true
chmod 755 "${PKG_DIR}/usr/bin/sbc"

# Documentation
if [ -f "${SCRIPT_DIR}/README.md" ]; then
    cp "${SCRIPT_DIR}/README.md" "${PKG_DIR}/usr/share/doc/sbc/"
fi
if [ -f "${SCRIPT_DIR}/FORMAT.md" ]; then
    cp "${SCRIPT_DIR}/FORMAT.md" "${PKG_DIR}/usr/share/doc/sbc/"
fi
if [ -f "${SCRIPT_DIR}/ENCODER.md" ]; then
    cp "${SCRIPT_DIR}/ENCODER.md" "${PKG_DIR}/usr/share/doc/sbc/"
fi

# DEBIAN/control
cat << 'CTRL_EOF' > "${PKG_DIR}/DEBIAN/control"
Package: sbc
Version: 0.970.1-1
Section: utils
Priority: optional
Architecture: amd64
Maintainer: seb3773 <https://github.com/seb3773/sbc>
Depends: libc6 (>= 2.15)
Provides: sbc
Description: Pure C reimplementation of historical SBC 0.970 Archiver
 Complete, standalone freestanding C tool combining both compressor and
 decompressor into a single binary (sbc), achieving 100% bidirectional
 bit-exact compatibility with the original 32-bit archiver (SBC.EXE).
 Features:
  - 8 compression modes: M0 (Store), M1 (Fast LZP+Huffman), M2 (Normal BWT+RLE+Huffman), M3 (Max BWT+LZP+RLE+Huffman), M4-M7 (Advanced transforms)
  - 6 encryption algorithms: AES-128, Blowfish, CAST-128, DES, 3DES, Serpent, Twofish
  - 8 checksum formats: CRC16, CRC32, Adler32, Sum32, MD5, SHA-1, SHA-256
  - Selective extraction with wildcard pattern filtering
  - DOS and Unix table formatting, bare listing (-1), unix paths (-u)
  - Zip-Slip and path traversal security guards
  - Historical digital preservation & software interoperability (EU 2009/24/EC)
CTRL_EOF

# Build DEB
mkdir -p "${SCRIPT_DIR}/dist"
dpkg-deb --build --root-owner-group "${PKG_DIR}" "${SCRIPT_DIR}/dist/${DEB_NAME}"
cp -f "${SCRIPT_DIR}/dist/${DEB_NAME}" "${SCRIPT_DIR}/${DEB_NAME}"
echo "Package created: ${SCRIPT_DIR}/dist/${DEB_NAME} (and ${SCRIPT_DIR}/${DEB_NAME})"

# Clean temp packaging dir
rm -rf "${PKG_DIR}"

echo ""
echo "=== Package Information ==="
dpkg-deb -I "${SCRIPT_DIR}/dist/${DEB_NAME}"
echo ""
echo "=== Package Contents ==="
dpkg-deb -c "${SCRIPT_DIR}/dist/${DEB_NAME}"

echo ""
echo "=== SBC packaging finished successfully ==="
