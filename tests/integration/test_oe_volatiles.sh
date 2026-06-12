#!/bin/sh
# SPDX-License-Identifier: GPL-2.0-only
# Apply the entries of the real oe-core initscripts "volatiles" config
# (installed on target as 00_core) verbatim.  Its defining feature is
# intra-file dependency chains: directories and files created through
# symlinks set up by earlier entries in the same file.

PV_BIN=${1:?usage: test_oe_volatiles.sh <populate-volatile>}
SCRIPT_DIR=$(dirname "$0")
. "$SCRIPT_DIR/helpers.sh"

setup

# Preconditions normally provided by base-files in the image:
# /var/log is a relative symlink into volatile storage, and a shipped
# regular /etc/resolv.conf that the l entry must replace.
mkdir -p "$ROOTDIR/var" "$ROOTDIR/etc"
ln -s volatile/log "$ROOTDIR/var/log"
echo "nameserver 127.0.0.1" > "$ROOTDIR/etc/resolv.conf"

write_cfg "00_core" \
    "# This configuration file lists filesystem objects that should get verified" \
    "" \
    "d root root 1777 /run/lock none" \
    "d root root 0755 /var/volatile/log none" \
    "d root root 1777 /var/volatile/tmp none" \
    "l root root 1777 /var/lock /run/lock" \
    "l root root 0755 /var/run /run" \
    "l root root 1777 /var/tmp /var/volatile/tmp" \
    "l root root 1777 /tmp /var/tmp" \
    "d root root 0755 /var/lock/subsys none" \
    "f root root 0664 /var/log/wtmp none" \
    "f root root 0664 /var/run/utmp none" \
    "l root root 0644 /etc/resolv.conf /var/run/resolv.conf" \
    "f root root 0644 /var/run/resolv.conf none"

run_pv

# Plain directories (sticky bits included)
assert_dir "run/lock"          1777
assert_dir "var/volatile/log"  755
assert_dir "var/volatile/tmp"  1777

# Symlinks, including the two-hop /tmp -> /var/tmp -> /var/volatile/tmp
assert_symlink "var/lock" "/run/lock"
assert_symlink "var/run"  "/run"
assert_symlink "var/tmp"  "/var/volatile/tmp"
assert_symlink "tmp"      "/var/tmp"

# Directory created through the /var/lock symlink set up earlier in the
# same file: must land at run/lock/subsys inside the root tree.
assert_dir "run/lock/subsys" 755

# Files created through symlinked intermediates: /var/log (pre-existing,
# relative) and /var/run (created above, absolute).
assert_file "var/volatile/log/wtmp" 664
assert_file "run/utmp"              664

# The shipped regular /etc/resolv.conf is replaced by the symlink, and
# the f entry then materialises the target through /var/run.
assert_symlink "etc/resolv.conf" "/var/run/resolv.conf"
assert_file    "run/resolv.conf" 644

# Second run must be idempotent: everything already exists or matches.
run_pv

assert_symlink "etc/resolv.conf" "/var/run/resolv.conf"
assert_dir     "run/lock"        1777
assert_file    "run/utmp"        664

echo "PASS: oe_volatiles"
