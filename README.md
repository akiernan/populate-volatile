# populate-volatile

Replaces the `populate-volatile.sh` shell script used in OpenEmbedded-Core.

Reads declarative config files from `/etc/default/volatiles/` and creates the
described files, directories, symlinks, and bind-mounts on a tmpfs/ramfs at boot,
or stages them into a rootfs image at build time.

## Config file format

Each line (space-separated) describes one filesystem object:

```
TYPE  USER  GROUP  MODE  NAME  LTARGET
```

| Field | Values |
|---|---|
| TYPE | `f` file, `d` directory, `l` symlink, `b` bind-mount |
| USER / GROUP | owner name |
| MODE | octal permission bits, e.g. `0755` |
| NAME | absolute destination path (no rootdir prefix) |
| LTARGET | source path for `f`/`b`, link target for `l`; `none` → empty |

## Usage

```
populate-volatile [-v] [-n] [-r <rootdir>] [-C <cfgdir>] [<cfgfile> ...]

  -r <rootdir>   Root prefix (default: /). When set, rootfs-build mode is
                 assumed: non-fatal errors are suppressed.
  -C <cfgdir>    Config directory (default: <rootdir>/etc/default/volatiles).
  -v             Verbose output.
  -n             Dry-run (implies -v).
  <cfgfile>...   Process only these files (relative to cfgdir).
```

## Building

Requires meson + ninja and a C99 compiler with glibc or musl. Use the provided Docker wrapper for a reproducible build:

```sh
./docker-build.sh           # glibc build + tests (Ubuntu 24.04)
./docker-build.sh musl      # musl build + tests
./docker-build.sh all       # both
```

Native Linux build:

```sh
meson setup build
meson compile -C build
meson test -C build --print-errorlogs
```

## License

This project is licensed under the **GNU General Public License v2.0 only**
(`LICENSE.txt`).

The Unity test framework vendored in `tests/unity/` is a separate work and is
licensed under the **MIT license** — see the copyright header in
`tests/unity/unity.h`. Unity is used only for building the test suite and is
not linked into the installed binary.
