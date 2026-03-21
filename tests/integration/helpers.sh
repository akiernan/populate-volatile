#!/bin/sh
# SPDX-License-Identifier: GPL-2.0-only
#
# Shared helpers for populate-volatile integration tests.
#
# Each test script sources this file after setting PV_BIN to the path of
# the populate-volatile binary (passed as $1 by meson).
#
# Usage pattern in a test script:
#   PV_BIN=${1:?}
#   SCRIPT_DIR=$(dirname "$0")
#   . "$SCRIPT_DIR/helpers.sh"
#   setup
#   write_cfg "01_foo" "d root root 0755 /var/run none"
#   run_pv
#   assert_dir "var/run" 755
#
# Note: stat -c '%a' is a GNU coreutils extension; these tests are
# Linux-only and rely on the GNU coreutils stat(1).

_TMPBASE=
ROOTDIR=
CFGDIR=

_cleanup() {
    [ -n "$_TMPBASE" ] && rm -rf "$_TMPBASE"
}

die() {
    printf 'FAIL: %s\n' "$*" >&2
    exit 1
}

# setup -- create temp rootdir and cfgdir, register cleanup on exit.
setup() {
    _TMPBASE=$(mktemp -d /tmp/pv_integ_XXXXXX) || die "mktemp failed"
    ROOTDIR="$_TMPBASE/root"
    CFGDIR="$_TMPBASE/cfg"
    mkdir -p "$ROOTDIR" "$CFGDIR"
    trap _cleanup EXIT
}

# run_pv [extra args] -- invoke populate-volatile in rootfs mode.
run_pv() {
    "$PV_BIN" -r "$ROOTDIR" -C "$CFGDIR" "$@"
}

# write_cfg NAME LINE... -- write a config file into $CFGDIR.
write_cfg() {
    _name=$1; shift
    printf '%s\n' "$@" > "$CFGDIR/$_name"
}

# assert_dir RELPATH [MODE] -- verify a directory exists.
assert_dir() {
    _path="$ROOTDIR/$1"
    [ -d "$_path" ] || die "expected directory: $1"
    if [ -n "${2:-}" ]; then
        _got=$(stat -c '%a' "$_path")
        [ "$_got" = "$2" ] || die "wrong mode on $1: got $_got, want $2"
    fi
}

# assert_file RELPATH [MODE] -- verify a regular file exists.
assert_file() {
    _path="$ROOTDIR/$1"
    [ -f "$_path" ] || die "expected file: $1"
    if [ -n "${2:-}" ]; then
        _got=$(stat -c '%a' "$_path")
        [ "$_got" = "$2" ] || die "wrong mode on $1: got $_got, want $2"
    fi
}

# assert_symlink RELPATH TARGET -- verify a symlink with the given target.
assert_symlink() {
    _path="$ROOTDIR/$1"
    [ -L "$_path" ] || die "expected symlink: $1"
    _got=$(readlink "$_path")
    [ "$_got" = "$2" ] || die "wrong symlink target for $1: got '$_got', want '$2'"
}

# assert_absent RELPATH -- verify a path does not exist (not even as a symlink).
assert_absent() {
    _path="$ROOTDIR/$1"
    { [ ! -e "$_path" ] && [ ! -L "$_path" ]; } || die "expected absent: $1"
}

# assert_content RELPATH TEXT -- verify a file's contents.
assert_content() {
    _path="$ROOTDIR/$1"
    _got=$(cat "$_path")
    [ "$_got" = "$2" ] || die "wrong content in $1: got '$_got', want '$2'"
}
