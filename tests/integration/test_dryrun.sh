#!/bin/sh
# SPDX-License-Identifier: GPL-2.0-only
# Test that -n (dry-run) makes no filesystem changes.

PV_BIN=${1:?usage: test_dryrun.sh <populate-volatile>}
SCRIPT_DIR=$(dirname "$0")
. "$SCRIPT_DIR/helpers.sh"

setup

write_cfg "01_dryrun" \
    "d root root 0755 /should_not_appear none" \
    "f root root 0644 /also_not_appear   none" \
    "l root root 0755 /link_not_appear   /some/target"

# Run in dry-run mode
"$PV_BIN" -n -r "$ROOTDIR" -C "$CFGDIR"

assert_absent "should_not_appear"
assert_absent "also_not_appear"
assert_absent "link_not_appear"

# Confirm the same config does create things in normal mode
"$PV_BIN" -r "$ROOTDIR" -C "$CFGDIR"

assert_dir     "should_not_appear"
assert_file    "also_not_appear"
assert_symlink "link_not_appear" "/some/target"

echo "PASS: dryrun"
