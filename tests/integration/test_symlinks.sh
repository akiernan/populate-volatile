#!/bin/sh
# SPDX-License-Identifier: GPL-2.0-only
# Test symlink creation, no-op on correct link, and correction of wrong link.

PV_BIN=${1:?usage: test_symlinks.sh <populate-volatile>}
SCRIPT_DIR=$(dirname "$0")
. "$SCRIPT_DIR/helpers.sh"

setup

mkdir -p "$ROOTDIR/var"

# --- create new symlinks ---
write_cfg "01_create" \
    "l root root 0755 /var/lock /var/volatile/lock" \
    "l root root 0755 /var/run  /var/volatile/run"

run_pv

assert_symlink "var/lock" "/var/volatile/lock"
assert_symlink "var/run"  "/var/volatile/run"

# --- correct existing symlink pointing at wrong target ---
mkdir -p "$ROOTDIR/var2"
ln -s /wrong/target "$ROOTDIR/var2/link"

write_cfg "02_correct" \
    "l root root 0755 /var2/link /correct/target"

run_pv

assert_symlink "var2/link" "/correct/target"

# --- no-op when symlink already correct ---
write_cfg "03_noop" \
    "l root root 0755 /var/lock /var/volatile/lock"

run_pv

assert_symlink "var/lock" "/var/volatile/lock"

# --- symlink whose parent directory does not yet exist is created ---
write_cfg "04_mkparent" \
    "l root root 0755 /new/nested/link /some/target"

run_pv

assert_symlink "new/nested/link" "/some/target"

echo "PASS: symlinks"
