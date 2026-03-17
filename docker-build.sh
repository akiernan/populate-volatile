#!/bin/sh
# SPDX-License-Identifier: GPL-2.0-only
#
# Build and test populate-volatile inside a Linux Docker container.
# Run from the populate-volatile/ directory.
#
# Usage:
#   ./docker-build.sh            # gcc + glibc
#   ./docker-build.sh musl       # gcc + musl
#   ./docker-build.sh clang      # clang + glibc
#   ./docker-build.sh all        # all three

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

run_glibc() {
    echo "=== Building and testing (gcc + glibc) ==="
    docker build --target test --tag pv-test-glibc .
    docker run --rm pv-test-glibc
}

run_musl() {
    echo "=== Building and testing (gcc + musl) ==="
    docker build --target test-musl --tag pv-test-musl .
    docker run --rm pv-test-musl
}

run_clang() {
    echo "=== Building and testing (clang + glibc) ==="
    docker build --target test-clang --tag pv-test-clang .
    docker run --rm pv-test-clang
}

case "${1:-glibc}" in
    glibc) run_glibc ;;
    musl)  run_musl ;;
    clang) run_clang ;;
    all)   run_glibc; run_musl; run_clang ;;
    *)
        echo "usage: $0 [glibc|musl|clang|all]" >&2
        exit 1
        ;;
esac
