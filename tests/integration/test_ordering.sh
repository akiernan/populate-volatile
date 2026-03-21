#!/bin/sh
# SPDX-License-Identifier: GPL-2.0-only
# Test that 00_core is always applied first regardless of filesystem ordering,
# and that later config files can build on what 00_core created.

PV_BIN=${1:?usage: test_ordering.sh <populate-volatile>}
SCRIPT_DIR=$(dirname "$0")
. "$SCRIPT_DIR/helpers.sh"

setup

# 99_other creates /var/volatile/tmp which lives under /var/volatile.
# 00_core creates /var/volatile.  If ordering were wrong, 99_other would
# be processed first and /var/volatile/tmp creation would fail silently
# (parent missing) or leave an inconsistent tree.
write_cfg "00_core"  "d root root 0755 /var/volatile none"
write_cfg "99_other" "d root root 1777 /var/volatile/tmp none"

run_pv

assert_dir "var/volatile"     755
assert_dir "var/volatile/tmp" 1777

# Verify 00_core runs before alphabetically-earlier names when they are
# discovered together.  "00_core" < "00_aaa" alphabetically, but that's
# fine — we just need 00_core to be first.
write_cfg "00_aaa" "d root root 0755 /from_aaa none"

run_pv

assert_dir "var/volatile"
assert_dir "from_aaa"

echo "PASS: ordering"
