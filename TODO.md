# Outstanding review findings

From a code review on 2026-06-12. Already fixed in separate commits:
dead `DT_UNKNOWN` fallback in `discover_cfgfiles`, missing `ERANGE`
retry / duplicated pw-gr lookup code, bind-mount idempotency and
fatality. Everything below is still open, roughly in priority order
within each section.

## Bugs

- **`main()` always exits `EXIT_SUCCESS`** (`src/main.c`):
  `apply_cb` discards `pv_apply_entry`'s return and nothing
  aggregates failures, so init scripts / do_rootfs cannot detect
  runtime failures. Decide on an exit-status contract and aggregate.
  Relatedly the doc comment on `process_cfgfile` claims it returns 1
  on requirement failure; it always returns 0.

## Security hardening

- **`..` escapes the rootfd tree in rootfs mode** (`lib/path.c`):
  `pv_resolve_path` treats `..` as an ordinary component and
  `pv_readlink_abs` deliberately emits `a/../b` paths for the kernel
  to resolve. `rootfd` is not a chroot, so a `..` chain in a config
  NAME or a staged symlink target (`../../../etc`) resolves above
  the staging directory and writes to the **host** during do_rootfs.
  Mitigate: reject `..` after resolution, or use
  `openat2(RESOLVE_BENEATH)` with a lexical fallback.
- **`exec_cp_a` uses `execlp`** (`lib/ops.c`): PATH lookup in a
  root-at-boot process. Use an absolute `/bin/cp` or a fixed PATH.
- **`pv_is_mounted` compares literal strings** (`lib/path.c`):
  mountinfo records the canonical mount point, so a path reaching
  the mountpoint through a symlinked component yields a false
  negative and `pv_link_file` will attempt to migrate (rmtree) a
  live mountpoint. Normalise before comparing, or document.

## Cleanups / redundant abstractions

- **`entry_list_t` is unnecessary** (`src/main.c`):
  `process_cfgfile` collects every entry into a growable array only
  to check + apply them one at a time - a streaming callback does
  the same with less code. Would delete `entry_list_t`,
  `entry_list_push`, `entry_list_free`, `collect_cb`, and the array
  form of `pv_check_requirements` (only ever called with
  `nentries == 1`). Each `pv_entry_t` is ~8.5 KB, so the array is
  also needlessly heavy.
- **Repeated idioms in `lib/ops.c`**: the
  `ctx->rootfs_mode ? 0 : -1` pattern (~8 sites); the
  "fstatat exists -> skip" preamble duplicated between
  `pv_create_file` and `pv_mkdir`; the
  `ltarget[0]=='/' ? +1 : ltarget` strip appears twice.
- **Stale errno check** (`lib/ops.c`, `pv_link_file` parent mkdir):
  testing `errno != EEXIST` after `pv_mkdirtree` fails is
  meaningless - it already swallows EEXIST internally and errno may
  be stale from its cleanup calls.
- **Error-handling contract**: ops return -1, `apply_cb` ignores it,
  bind mount used to exit (fixed). Pick one contract and follow it
  through to the exit code (see exit-status bug above).

## Test gaps

- `..` traversal behaviour in `pv_resolve_path`/`pv_readlink_abs` -
  pin down whatever the hardening above decides.
- `discover_cfgfiles` - no unit test (the dead-code bug would have
  been caught); only indirectly covered by the ordering integration
  test.
- Mounted-directory migration skip (`pv_link_file` case 3) - can sit
  in the privileged suite next to `test_bind_mount` (note: the suite
  runs unprivileged via `unshare -rm`).

## Housekeeping

- Untracked `Unity/` directory at the repo root: full upstream Unity
  checkout left over from the 2.6.1 vendoring; the vendored copy is
  the three files in `tests/unity/`. Delete or gitignore before it
  is committed by accident (it also includes files beyond what the
  licensing note covers).
- Pre-existing `-Wformat-truncation` warnings in `tests/test_ops.c`
  and `tests/test_bind_mount.c` (snprintf of `tmpbase` + suffix into
  `PATH_MAX`).
