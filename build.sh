#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

MODE="release"
TARGET_PLATFORM="linux"
MAKE_ARGS=()

for arg in "$@"; do
    case "$arg" in
        win64|win|windows|--win64)
            TARGET_PLATFORM="win64"
            ;;
        linux|--linux)
            TARGET_PLATFORM="linux"
            ;;
        all|all-platforms|--all)
            TARGET_PLATFORM="all-platforms"
            ;;
        debug|-DEBUG|--debug|DEBUG=1)
            MODE="debug"
            ;;
        clean)
            make clean
            exit 0
            ;;
        test)
            make test
            exit 0
            ;;
        deb)
            make deb
            exit 0
            ;;
        dist)
            make dist
            exit 0
            ;;
        help|-h|--help)
            make help
            exit 0
            ;;
        *)
            MAKE_ARGS+=("$arg")
            ;;
    esac
done

echo "=========================================================="
if [ "$MODE" = "debug" ]; then
    echo "  Building SBC Archiver 0.970 (DEBUG mode: $TARGET_PLATFORM)"
else
    echo "  Building SBC Archiver 0.970 (Target: $TARGET_PLATFORM)"
fi
echo "=========================================================="

if [ "$MODE" = "debug" ]; then
    make debug
else
    make clean >/dev/null 2>&1 || true
    make -j"$(nproc)" "$TARGET_PLATFORM" "${MAKE_ARGS[@]}"
fi

echo ""
echo "=== Summary of Generated Binaries ==="
if [ -f "$SCRIPT_DIR/build/linux/sbc" ]; then
    ls -lh "$SCRIPT_DIR/build/linux/sbc"
fi
if [ -f "$SCRIPT_DIR/build/win64/sbc.exe" ]; then
    ls -lh "$SCRIPT_DIR/build/win64/sbc.exe"
fi
echo "Done."
