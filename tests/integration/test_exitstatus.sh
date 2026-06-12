#!/bin/sh
# SPDX-License-Identifier: GPL-2.0-only
# Test exit status aggregation: runtime failures yield a non-zero exit,
# rootfs-mode failures and skipped entries do not.
#
# The runtime-mode cases use -r / with entries chosen so nothing on the
# host is ever created or modified.

PV_BIN=${1:?usage: test_exitstatus.sh <populate-volatile>}
SCRIPT_DIR=$(dirname "$0")
. "$SCRIPT_DIR/helpers.sh"

setup

# --- runtime mode: a failing entry must produce a non-zero exit ---
# /proc/pv_no_such_dir cannot exist, so the create fails harmlessly.
write_cfg "01_fail" \
    "f root root 0644 /proc/pv_no_such_dir/file none"

if "$PV_BIN" -r / -C "$CFGDIR" 2>/dev/null; then
    die "expected non-zero exit for failing entry at runtime"
fi

# --- rootfs mode: the same failure is suppressed ---
run_pv 2>/dev/null || die "rootfs mode must exit zero on entry failure"

# --- runtime mode: entries skipped for unknown users are not failures ---
rm -f "$CFGDIR/01_fail"
write_cfg "02_skip" \
    "d pv_no_such_user pv_no_such_group 0755 /tmp none"

"$PV_BIN" -r / -C "$CFGDIR" 2>/dev/null \
    || die "skipped entries must not fail the run"

# --- runtime mode: already-satisfied entries exit zero ---
write_cfg "03_exists" \
    "d root root 0755 /tmp none"

"$PV_BIN" -r / -C "$CFGDIR" 2>/dev/null \
    || die "existing target must exit zero"

echo "PASS: exitstatus"
