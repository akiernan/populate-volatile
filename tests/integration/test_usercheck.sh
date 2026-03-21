#!/bin/sh
# SPDX-License-Identifier: GPL-2.0-only
# Test that entries whose user or group does not exist on the host are
# skipped, while entries with valid credentials are applied.

PV_BIN=${1:?usage: test_usercheck.sh <populate-volatile>}
SCRIPT_DIR=$(dirname "$0")
. "$SCRIPT_DIR/helpers.sh"

setup

write_cfg "01_usercheck" \
    "d root root                          0755 /should_exist      none" \
    "d this_user_will_never_exist_xyzzy root 0755 /bad_user         none" \
    "d root this_group_will_never_exist_xyzzy 0755 /bad_group        none"

run_pv

assert_dir    "should_exist"
assert_absent "bad_user"
assert_absent "bad_group"

echo "PASS: usercheck"
