# SPDX-License-Identifier: GPL-2.0-only
#
# Build and test populate-volatile in a Linux container.
# All compilation and test execution happens inside this glibc-based Ubuntu environment.
#
# Targets:
#   test        gcc  + glibc
#   test-musl   gcc  + musl
#   test-clang  clang + glibc
#
# Usage (from the populate-volatile/ directory):
#   docker build --target test --tag pv-test .
#   docker run --rm pv-test

# --------------------------------------------------------------------------
# Base: common build dependencies
# --------------------------------------------------------------------------
FROM ubuntu:24.04 AS base

ENV DEBIAN_FRONTEND=noninteractive TZ=UTC

RUN apt-get update && apt-get install -y --no-install-recommends \
        gcc \
        libc6-dev \
        meson \
        ninja-build \
        pkg-config \
        ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# --------------------------------------------------------------------------
# build-glibc: gcc + glibc
# --------------------------------------------------------------------------
FROM base AS build-glibc

WORKDIR /src
COPY . .

RUN meson setup build --wipe \
        -Dc_std=c99 \
        -Dwarning_level=2 \
    && meson compile -C build

# --------------------------------------------------------------------------
# test: run the Unity test suite (gcc + glibc)
#
# Tests that exercise mount()/bind-mount (pv_bind_mount) require
# CAP_SYS_ADMIN; those are integration tests outside the Unity suite.
# The Unity tests work without elevated privileges.
# --------------------------------------------------------------------------
FROM build-glibc AS test

CMD ["meson", "test", "-C", "build", "--print-errorlogs"]

# --------------------------------------------------------------------------
# build-musl: gcc + musl via musl-tools cross-wrapper
# --------------------------------------------------------------------------
FROM base AS build-musl

RUN apt-get update && apt-get install -y --no-install-recommends \
        musl-tools \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /src
COPY . .

# musl-gcc is a wrapper that points at the musl libc headers and runtime.
RUN CC=musl-gcc meson setup build-musl --wipe \
        -Dc_std=c99 \
        -Dwarning_level=2 \
    && meson compile -C build-musl

# --------------------------------------------------------------------------
# test-musl: run tests (gcc + musl)
# --------------------------------------------------------------------------
FROM build-musl AS test-musl

CMD ["meson", "test", "-C", "build-musl", "--print-errorlogs"]

# --------------------------------------------------------------------------
# build-clang: clang + glibc
# --------------------------------------------------------------------------
FROM base AS build-clang

RUN apt-get update && apt-get install -y --no-install-recommends \
        clang \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /src
COPY . .

RUN CC=clang meson setup build-clang --wipe \
        -Dc_std=c99 \
        -Dwarning_level=2 \
    && meson compile -C build-clang

# --------------------------------------------------------------------------
# test-clang: run tests (clang + glibc)
# --------------------------------------------------------------------------
FROM build-clang AS test-clang

CMD ["meson", "test", "-C", "build-clang", "--print-errorlogs"]
