#!/bin/sh
# SPDX-License-Identifier: GPL-2.0-only
# Test file creation: empty, copy-from-source, skip-if-exists, mode.

PV_BIN=${1:?usage: test_files.sh <populate-volatile>}
SCRIPT_DIR=$(dirname "$0")
. "$SCRIPT_DIR/helpers.sh"

setup

# --- empty file creation ---
write_cfg "01_files" \
    "d root root 0755 /var/run none" \
    "f root root 0644 /var/run/utmp none" \
    "f root root 0600 /var/run/secret none"

run_pv

assert_file "var/run/utmp"   644
assert_file "var/run/secret" 600

# File must be empty
_size=$(stat -c '%s' "$ROOTDIR/var/run/utmp")
[ "$_size" = "0" ] || die "utmp should be empty, got size $_size"

# --- copy content from source ---
mkdir -p "$ROOTDIR/src"
printf 'hello world' > "$ROOTDIR/src/data.txt"

write_cfg "02_copy" \
    "d root root 0755 /dst none" \
    "f root root 0644 /dst/copy.txt /src/data.txt"

run_pv

assert_file   "dst/copy.txt" 644
assert_content "dst/copy.txt" "hello world"

# --- skip if target already exists ---
printf 'original' > "$ROOTDIR/dst/existing.txt"

write_cfg "03_skip" \
    "f root root 0644 /dst/existing.txt none"

run_pv

assert_content "dst/existing.txt" "original"

echo "PASS: files"
