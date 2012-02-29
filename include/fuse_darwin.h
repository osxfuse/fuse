/*
 * Copyright (C) 2006-2008 Google. All Rights Reserved.
 * Amit Singh <singh@>
 */

#ifdef __APPLE__

#ifndef _FUSE_DARWIN_H_
#define _FUSE_DARWIN_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <errno.h>
#include <stdint.h>
#include <sys/types.h>
#include <limits.h>
#include <pthread.h>
#include <time.h>

/* Semaphores */

struct __local_sem_t
{
    unsigned int    count;
    pthread_mutex_t count_lock;
    pthread_cond_t  count_cond;
};

typedef struct fuse_sem {
    int id;
    union {
        struct __local_sem_t local;
    } __data;
} fuse_sem_t;

#define FUSE_SEM_VALUE_MAX ((int32_t)32767)

int fuse_sem_init(fuse_sem_t *sem, int pshared, unsigned int value);
int fuse_sem_destroy(fuse_sem_t *sem);
int fuse_sem_getvalue(fuse_sem_t *sem, unsigned int *value);
int fuse_sem_post(fuse_sem_t *sem);
int fuse_sem_timedwait(fuse_sem_t *sem, const struct timespec *abs_timeout);
int fuse_sem_trywait(fuse_sem_t *sem);
int fuse_sem_wait(fuse_sem_t *sem);

#ifdef DARWIN_SEMAPHORE_COMPAT

/* Caller must not include <semaphore.h> */

typedef fuse_sem_t sem_t;

#define sem_init(s, p, v)   fuse_sem_init(s, p, v)
#define sem_destroy(s)      fuse_sem_destroy(s)
#define sem_getvalue(s, v)  fuse_sem_getvalue(s, v)
#define sem_post(s)         fuse_sem_post(s)
#define sem_timedwait(s, t) fuse_sem_timedwait(s, t)
#define sem_trywait(s)      fuse_sem_trywait(s)
#define sem_wait(s)         fuse_sem_wait(s)

#define SEM_VALUE_MAX       FUSE_SEM_VALUE_MAX

#endif /* DARWIN_SEMAPHORE_COMPAT */

/* Versioning */
const char *macfuse_version(void);
long        fuse_os_version_major_np(void);

/* Advanced */

struct fuse_fs;

int fuse_device_fd_np(const char *mountpoint);
const char *fuse_mountpoint_for_fs_np(struct fuse_fs *fs);
int fuse_knote_np(const char *mountpoint, const char *path, uint32_t note);
int fuse_purge_np(const char *mountpoint, const char *path, off_t *newsize);

#ifdef __cplusplus
}
#endif

#endif /* _FUSE_DARWIN_H_ */

#endif /* __APPLE__ */
