#!/bin/sh
# SPDX-License-Identifier: GPL-2.0-only
# Test config file discovery: hidden files and subdirectories in the
# config directory are ignored, and their presence does not disturb
# processing of regular config files.

PV_BIN=${1:?usage: test_discover.sh <populate-volatile>}
SCRIPT_DIR=$(dirname "$0")
. "$SCRIPT_DIR/helpers.sh"

setup

write_cfg "01_real" \
    "d root root 0755 /from_real none"

# Hidden files are skipped
write_cfg ".hidden" \
    "d root root 0755 /from_hidden none"

# Subdirectories are skipped; discovery is not recursive
mkdir "$CFGDIR/subdir"
printf '%s\n' "d root root 0755 /from_subdir none" > "$CFGDIR/subdir/cfg"

run_pv

assert_dir    "from_real" 755
assert_absent "from_hidden"
assert_absent "from_subdir"

echo "PASS: discover"
