#!/bin/sh
# SPDX-License-Identifier: GPL-2.0-only
# Test the reported scenario: link before object creation.
#
# Configuration:
# l root root 0777 /var/test /tmp/testfile
# f root root 0644 /var/test none
#
# Expected behavior:
# 1. /var/test is created as a symlink to /tmp/testfile.
# 2. When /var/test (file) is to be created, the utility follows the symlink
#    at /var/test and creates /tmp/testfile instead.

PV_BIN=${1:?usage: test_follow_symlink.sh <populate-volatile>}
SCRIPT_DIR=$(dirname "$0")
. "$SCRIPT_DIR/helpers.sh"

setup

# We need /tmp to exist in ROOTDIR because we're using it as a link target
mkdir -p "$ROOTDIR/tmp"
mkdir -p "$ROOTDIR/var"

write_cfg "follow_symlink" \
    "l root root 0777 /var/test /tmp/testfile" \
    "f root root 0644 /var/test none"

run_pv

# 1. /var/test should be a symlink to /tmp/testfile
assert_symlink "var/test" "/tmp/testfile"

# 2. /tmp/testfile should be a regular file created due to the symlink resolution
assert_file "tmp/testfile" 644

# --- directory case ---
write_cfg "follow_symlink_dir" \
    "l root root 0777 /var/testdir /tmp/realdir" \
    "d root root 0755 /var/testdir none"

run_pv

# 1. /var/testdir should be a symlink to /tmp/realdir
assert_symlink "var/testdir" "/tmp/realdir"

# 2. /tmp/realdir should be a directory created due to the symlink resolution
assert_dir "tmp/realdir" 755

echo "PASS: follow_symlink"
