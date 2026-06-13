# Outstanding review findings

From a code review on 2026-06-12. All bugs, security hardening items
and cleanups identified in that review have been fixed in individual
commits (see the git history from "main: Fix dead DT_UNKNOWN fallback
in discover_cfgfiles" onwards). What remains is below.

## Test gaps

- `discover_cfgfiles` `DT_UNKNOWN` fallback - the regular-file
  filter is integration-tested, but the stat fallback cannot be
  exercised on tmpfs/ext4; would need extraction from main.c for a
  unit test.
- The runtime statx detection ladder in `pv_is_mounted`
  (ENOSYS/EINVAL/EPERM, clear `stx_attributes_mask` bit) cannot be
  exercised on a modern kernel; the mountinfo fallback itself is
  covered directly via `pv_is_mounted_mountinfo`.

## Verification

- `./docker-build.sh all` (glibc, musl, clang) passed 2026-06-12:
  14 OK + 1 skip each (bind_mount needs CAP_SYS_ADMIN, absent in
  unprivileged containers; covered locally via `unshare -rm`).

## Accepted deviations from upstream populate-volatile.sh

Audited against the upstream script on 2026-06-12.  An `l` entry
over an existing regular file now matches upstream's `ln -sf`
(replace); everything below is a deliberate divergence.

- **Per-entry requirement skipping**: upstream skips an entire
  config file when any user/group in it is undefined; we skip only
  the offending entries, so valid entries in the same file still
  apply.
- **Exit status**: upstream effectively always exits 0; we exit 1 on
  runtime failures (see downstream notes).  The oe-core wrapper
  must propagate the status.
- **Rootfs-mode diagnostics**: upstream redirects all build-time
  output to /dev/null; we still warn() on suppressed errors, so
  do_rootfs logs show what was skipped.  Considered a feature -
  upstream's silence hid real bugs (see next item).
- **Build-time copy sources**: upstream `cp`s `f`-entry sources from
  the *host* path during rootfs construction; we resolve them inside
  the staging tree.  Likewise absolute symlink components: upstream
  follows them onto the host (errors suppressed); we confine
  resolution to the staging tree.
- **Mountpoint detection**: upstream string-compares raw
  /proc/mounts (no \NNN unescaping, no canonicalisation); we use
  statx(STATX_ATTR_MOUNT_ROOT) with a realpath+mountinfo fallback.
- **Bind mounts**: upstream stacks a duplicate mount per run; ours
  skip when the destination is already bind-mounted from the intended
  source (same st_dev/st_ino), but still stack when a *different*
  source is mounted there, so the requested source always ends up
  visible as upstream guarantees.
- **Directory migration**: upstream's `cp -a $d/* $d/.[!.]*` misses
  dotfiles beginning with two dots; `cp -a src/.` does not.
- **Parse strictness**: modes must be octal (upstream accepted
  anything chmod does, including symbolic); fields beyond LTARGET
  are ignored (upstream folded them into LTARGET); tab-separated
  entries are requirement-checked properly (upstream's `cut -d " "`
  silently bypassed the check for them).
- **Cache / `update` / `clearcache`**: not implemented.  The cache
  only existed to amortise the script's slow requirement checker;
  the oe-core wrapper drops all arguments, so `update` callers get
  a normal (fast) populate pass.
- **`VERBOSE` and the ld.so.cache symlink** are handled by the
  oe-core wrapper (initscripts populate-volatile.sh), not the
  binary.
- **Symlink chains**: both resolve an `f`/`d` name one level, but
  for a result that is still a symlink upstream's `-e` test follows
  the remaining chain while our AT_SYMLINK_NOFOLLOW check reports
  "exists, skipping".

## Downstream notes for the next release

- populate-volatile now exits 1 at runtime when entries fail
  (rootfs mode still always exits 0); sysvinit integrations will see
  the new status.
- cp(1) is no longer found via PATH; packagers whose target layout
  lacks /bin/cp should pass `-Dcp_path=` (see meson_options.txt).
