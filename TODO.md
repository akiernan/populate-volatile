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

## Downstream notes for the next release

- populate-volatile now exits 1 at runtime when entries fail
  (rootfs mode still always exits 0); sysvinit integrations will see
  the new status.
- cp(1) is no longer found via PATH; packagers whose target layout
  lacks /bin/cp should pass `-Dcp_path=` (see meson_options.txt).
