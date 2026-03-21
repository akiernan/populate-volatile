#!/bin/sh
# SPDX-License-Identifier: GPL-2.0-only
# Test directory-to-symlink migration: contents are copied to the link target,
# the original directory is removed, and a symlink is created in its place.

PV_BIN=${1:?usage: test_migration.sh <populate-volatile>}
SCRIPT_DIR=$(dirname "$0")
. "$SCRIPT_DIR/helpers.sh"

setup

# --- basic migration ---
# /var/log is a directory with files; after apply it must be a symlink
# to /var/volatile/log and its contents must appear there.
mkdir -p "$ROOTDIR/var/log"
printf 'log entry 1\n' > "$ROOTDIR/var/log/messages"
printf 'auth log\n'    > "$ROOTDIR/var/log/auth.log"
mkdir -p "$ROOTDIR/var/volatile/log"

write_cfg "01_migrate" \
    "l root root 0755 /var/log /var/volatile/log"

run_pv

assert_symlink "var/log" "/var/volatile/log"
assert_file    "var/volatile/log/messages"
assert_content "var/volatile/log/messages" "log entry 1"
assert_file    "var/volatile/log/auth.log"

# --- empty directory: migrates cleanly with no content to copy ---
mkdir -p "$ROOTDIR/var/empty_dir"
mkdir -p "$ROOTDIR/var/volatile/empty_dir"

write_cfg "02_empty" \
    "l root root 0755 /var/empty_dir /var/volatile/empty_dir"

run_pv

assert_symlink "var/empty_dir" "/var/volatile/empty_dir"

echo "PASS: migration"
