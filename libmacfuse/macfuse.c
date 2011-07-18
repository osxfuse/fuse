//
//  macfuse.c
//  libmacfuse
//
//  Created by Benjamin Fleischer on 2011-06-30.
//  Copyright 2011 OSXFUSE Project. All rights reserved.
//

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
