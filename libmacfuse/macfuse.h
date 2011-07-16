//
//  macfuse.h
//  libmacfuse
//
//  Created by Benjamin Fleischer on 2011-06-30.
//  Copyright 2011 OSXFUSE Project. All rights reserved.
//

#include <stdbool.h>

#define MACFUSE_VERSION "2.1.5"

const char *macfuse_version(void);

// Enable or disable the MacFUSE compatibility mode
void osxfuse_enable_macfuse_mode(bool);