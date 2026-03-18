/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef PV_TRACE_H
#define PV_TRACE_H

#include <stdio.h>

/*
 * pv_trace is set to 1 when -T is passed on the command line.
 * TRACE() checks it inline so there is zero overhead when disabled.
 */
extern int pv_trace;

/*
 * Emit a trace line to stderr (unbuffered) when pv_trace is non-zero.
 *
 * stderr is used deliberately: it is not buffered by the C library, so
 * trace lines appear immediately even when stdout is block-buffered
 * (e.g. when captured by systemd or another init system).  This is why
 * warn/warnx errors appeared before the verbose stdout lines in the
 * captured output — trace messages will do the same.
 *
 * Format: "[trace] function_name: user-supplied message\n"
 */
#define TRACE(fmt, ...) \
    do { \
        if (pv_trace) \
            fprintf(stderr, "[trace] %s: " fmt "\n", \
                    __func__, ##__VA_ARGS__); \
    } while (0)

#endif /* PV_TRACE_H */
