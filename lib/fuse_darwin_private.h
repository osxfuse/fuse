/*
 * Copyright (c) 2006-2008 Amit Singh/Google Inc.
 * Copyright (c) 2011-2017 Benjamin Fleischer
 * Copyright (c) 2017 Dave MacLachlan/Google Inc.
 */

#ifdef __APPLE__

#ifndef _FUSE_DARWIN_PRIVATE_H_
#define _FUSE_DARWIN_PRIVATE_H_

#include "fuse_darwin.h"
#include "fuse_param.h"

#include <fuse_ioctl.h>

#include <dispatch/dispatch.h>

#include <DiskArbitration/DiskArbitration.h>

#ifdef _SYS_SEMAPHORE_H_
#error Caller must not include <semaphore.h>
#endif

/* Semaphores */
typedef dispatch_semaphore_t sem_t;

int fuse_sem_init(dispatch_semaphore_t *sem, int pshared, unsigned int value);
int fuse_sem_destroy(dispatch_semaphore_t *sem);
int fuse_sem_post(dispatch_semaphore_t *sem);
int fuse_sem_wait(dispatch_semaphore_t *sem);

#define sem_init(s, p, v)   fuse_sem_init(s, p, v)
#define sem_destroy(s)      fuse_sem_destroy(s)
#define sem_post(s)         fuse_sem_post(s)
#define sem_wait(s)         fuse_sem_wait(s)

/* lock operations for flock(2) */
#ifndef LOCK_SH
#  define LOCK_SH         0x01            /* shared file lock */
#  define LOCK_EX         0x02            /* exclusive file lock */
#  define LOCK_NB         0x04            /* don't block when locking */
#  define LOCK_UN         0x08            /* unlock file */
#endif /* !LOCK_SH */

/* Caller is responsable for freeing return value. */
char *fuse_resource_path(const char *path);

extern DASessionRef fuse_dasession;

#endif /* _FUSE_DARWIN_PRIVATE_H_ */

#endif /* __APPLE__ */
