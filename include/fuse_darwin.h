/*
 * Copyright (c) 2006-2008 Amit Singh/Google Inc.
 * Copyright (c) 2011-2012 Benjamin Fleischer
 */

#ifdef __APPLE__

#ifndef _FUSE_DARWIN_H_
#define _FUSE_DARWIN_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>

/* Versioning */

const char *osxfuse_version(void);
long fuse_os_version_major_np(void);

/* Advanced */

struct fuse_fs;

int fuse_device_fd_np(const char *mountpoint);
const char *fuse_mountpoint_for_fs_np(struct fuse_fs *fs);

#ifdef __cplusplus
}
#endif

#endif /* _FUSE_DARWIN_H_ */

#endif /* __APPLE__ */
