#!/usr/bin/env bash
# Build SPScomm.exe with the MSYS2 MinGW-w64 toolchain.
# Run this from an MSYS2 "MinGW64" shell, or plain bash with /mingw64/bin on PATH.
set -euo pipefail

export PATH="/mingw64/bin:$PATH"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BUILD_DIR="$SCRIPT_DIR/build"

cmake -S "$SCRIPT_DIR" -B "$BUILD_DIR" -G Ninja -DCMAKE_BUILD_TYPE=Release
cmake --build "$BUILD_DIR"

echo
echo "Built: $BUILD_DIR/SPScomm.exe"

# cp program.txt into the same dir as the .exe file
mv program.txt ./build/.
