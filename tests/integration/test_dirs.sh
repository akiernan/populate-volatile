#!/bin/sh
# SPDX-License-Identifier: GPL-2.0-only
# Test directory creation: flat, nested, deep, mode, skip-if-exists.

PV_BIN=${1:?usage: test_dirs.sh <populate-volatile>}
SCRIPT_DIR=$(dirname "$0")
. "$SCRIPT_DIR/helpers.sh"

setup

# --- flat directory with mode ---
write_cfg "01_dirs" \
    "d root root 0755 /var/run none" \
    "d root root 0700 /var/run/lock none"

run_pv

assert_dir "var/run"      755
assert_dir "var/run/lock" 700

# --- deep directory (intermediate components created automatically) ---
write_cfg "02_deep" \
    "d root root 0750 /a/b/c/d none"

run_pv

assert_dir "a/b/c/d" 750

# --- existing directory: mode is preserved (skip-if-exists) ---
mkdir -p "$ROOTDIR/prexist"
chmod 700 "$ROOTDIR/prexist"

write_cfg "03_existing" \
    "d root root 0755 /prexist none"

run_pv

assert_dir "prexist" 700   # original mode, not overwritten

echo "PASS: dirs"
