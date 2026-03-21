# SPDX-License-Identifier: GPL-2.0-only
project('populate-volatile', 'c',
  version : '1.0.0',
  license : 'GPL-2.0-only',
  license_files : 'LICENSE.txt',
  meson_version : '>=1.1.0',
  default_options : [
    'c_std=c99',
    'warning_level=2',
  ],
)

cc = meson.get_compiler('c')

# --------------------------------------------------------------------------
# Required headers
# --------------------------------------------------------------------------

if not cc.has_header('err.h')
  error('err.h not found — glibc or musl required')
endif

# --------------------------------------------------------------------------
# Compiler flags
# --------------------------------------------------------------------------

# _DEFAULT_SOURCE (glibc) / musl ignores feature-test macros so all of the
# below is visible regardless:
#   DT_DIR, DT_UNKNOWN  — dirent d_type constants
#   O_NOFOLLOW          — fcntl open flag
#   mkdtemp             — stdlib temp dir creation (tests)
#   strtok_r            — POSIX reentrant tokeniser
posix_args = ['-D_DEFAULT_SOURCE']

# Promote a useful set of warnings.  -Wno-unused-parameter keeps the build
# clean in test stubs that don't use all Unity-injected parameters.
extra_warnings = cc.get_supported_arguments([
  '-Wshadow',
  '-Wstrict-prototypes',
  '-Wmissing-prototypes',
  '-Wno-unused-parameter',
])

common_args = posix_args + extra_warnings

# --------------------------------------------------------------------------
# Library: libpv (static)
# --------------------------------------------------------------------------

libpv_inc = include_directories('include')

libpv = static_library('pv',
  sources : [
    'lib/config.c',
    'lib/ops.c',
    'lib/validate.c',
    'lib/path.c',
  ],
  include_directories : libpv_inc,
  c_args : common_args,
)

libpv_dep = declare_dependency(
  link_with           : libpv,
  include_directories : libpv_inc,
)

# --------------------------------------------------------------------------
# Executable: populate-volatile
# --------------------------------------------------------------------------

executable('populate-volatile',
  sources     : ['src/main.c'],
  dependencies: libpv_dep,
  c_args      : common_args,
  install     : true,
  install_dir : get_option('sbindir'),
)

# --------------------------------------------------------------------------
# Tests (Unity, vendored in tests/unity/)
# --------------------------------------------------------------------------

unity_inc = include_directories('tests/unity')
unity_src = files('tests/unity/unity.c')

foreach t : ['config', 'path', 'validate', 'ops']
  test(t,
    executable('test_' + t,
      sources : ['tests/test_' + t + '.c'] + unity_src,
      dependencies        : libpv_dep,
      include_directories : unity_inc,
      c_args              : common_args,
    ),
    timeout : 30,
  )
endforeach

# bind_mount requires CAP_SYS_ADMIN; the binary exits 77 (meson SKIP) when
# the capability is absent so unprivileged CI runs still pass.
test('bind_mount',
  executable('test_bind_mount',
    sources             : ['tests/test_bind_mount.c'] + unity_src,
    dependencies        : libpv_dep,
    include_directories : unity_inc,
    c_args              : common_args,
  ),
  timeout : 30,
)

summary({
  'description' : 'Set up volatile directories from declarative config at boot or rootfs build time',
  'install dir' : get_option('sbindir'),
}, section : 'populate-volatile')
