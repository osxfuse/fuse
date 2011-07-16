//
//  macfuse.c
//  libmacfuse
//
//  Created by Benjamin Fleischer on 2011-06-30.
//  Copyright 2011 OSXFUSE Project. All rights reserved.
//

#include <stdbool.h>

#include "macfuse.h"

__attribute__((constructor)) static void lib_constructor(void); 

const char *macfuse_version(void) {
	return MACFUSE_VERSION;
}

static void lib_constructor(void) {
	osxfuse_enable_macfuse_mode(true);
}
