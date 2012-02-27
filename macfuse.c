/*
 * MacFUSE libosxfuse_i32/libosxfuse_i64 adapter
 *
 * Copyright (c) 2011-2012 Benjamin Fleischer
 */

#include <stdbool.h>

#include "macfuse.h"

extern void osxfuse_enable_macfuse_mode(bool);
extern const char *osxfuse_version(void);

__attribute__((constructor)) static void libmacfuse_constructor(void);

static void libmacfuse_constructor(void) {
    osxfuse_enable_macfuse_mode(true);
}

const char *macfuse_version(void) {
    return osxfuse_version();
}
