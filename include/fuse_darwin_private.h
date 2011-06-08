/*
 * Copyright (C) 2006-2008 Google. All Rights Reserved.
 * Amit Singh <singh@>
 */

#if (__FreeBSD__ >= 10)

#ifndef _FUSE_DARWIN_PRIVATE_H_
#define _FUSE_DARWIN_PRIVATE_H_

#ifdef __cplusplus
extern "C" {
#endif

#include "fuse_lowlevel.h"
#include "fuse_darwin.h"

#include <fuse_param.h>
#include <fuse_ioctl.h>
#include <fuse_version.h>
#include <pthread.h>
#include <strhash.h>

#ifdef __cplusplus
}
#endif

fuse_ino_t fuse_lookup_inode_internal_np(const char *mountpoint,
                                         const char *path);

int fuse_resize_node_internal_np(const char *mountpoint, const char *path,
                                 off_t newsize);

void fuse_exit_handler_internal_np(void);

int fuse_remove_signal_handlers_internal_np(void);

struct fuse *fuse_get_internal_np(const char *mountpoint);

void fuse_put_internal_np(struct fuse *fuse);

void fuse_set_fuse_internal_np(int fd, struct fuse *f);

void fuse_unset_fuse_internal_np(struct fuse *f);

/*
 * The mount_hash maps char* mountpoint -> struct mount_info. It is protected
 * by the mount_lock mutex, which is held across a mount operation.
 */
struct mount_info {
    int fd;            /* Valid when under mount_lock. */
    struct fuse *fuse; /* Non-NULL only if user fs created a struct fuse. */
};

extern pthread_mutex_t  mount_lock;
extern hash_table      *mount_hash;
extern int              mount_count; /* also the # of entries in mount_hash */
extern int              did_daemonize;

#endif /* _FUSE_DARWIN_PRIVATE_H_ */

#endif /* __FreeBSD__ >= 10 */
