# Outstanding review findings

From a code review on 2026-06-12. Already fixed in separate commits:
dead `DT_UNKNOWN` fallback in `discover_cfgfiles`, missing `ERANGE`
retry / duplicated pw-gr lookup code, bind-mount idempotency and
fatality. Everything below is still open, roughly in priority order
within each section.

## Bugs

(none outstanding)

## Security hardening

(none outstanding)

## Cleanups / redundant abstractions


## Test gaps

- `discover_cfgfiles` `DT_UNKNOWN` fallback - the regular-file
  filter is now integration-tested, but the stat fallback cannot be
  exercised on tmpfs/ext4; would need extraction from main.c for a
  unit test.

## Housekeeping

- Untracked `Unity/` directory at the repo root: full upstream Unity
  checkout left over from the 2.6.1 vendoring; the vendored copy is
  the three files in `tests/unity/`. Delete or gitignore before it
  is committed by accident (it also includes files beyond what the
  licensing note covers).
