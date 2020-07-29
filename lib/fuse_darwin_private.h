/*
 * Copyright (c) 2006-2008 Amit Singh/Google Inc.
 * Copyright (c) 2011-2020 Benjamin Fleischer
 */

#ifdef __APPLE__

#ifndef _FUSE_DARWIN_PRIVATE_H_
#define _FUSE_DARWIN_PRIVATE_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <pthread.h>
#include <strhash.h>
#include <stdbool.h>
#include <stdint.h>
#include <sys/ioctl.h>
#include <time.h>

#include <DiskArbitration/DiskArbitration.h>

#ifdef __cplusplus
}
#endif

#ifndef FUSE_DEFAULT_USERKERNEL_BUFSIZE
#  define FUSE_DEFAULT_USERKERNEL_BUFSIZE 33554432
#endif

#ifndef OSXFUSE_NDEVICES
#  define OSXFUSE_NDEVICES 64
#endif

#ifndef OSXFUSE_DEVICE_BASENAME
#  define OSXFUSE_DEVICE_BASENAME "macfuse"
#endif

#ifndef OSXFUSE_MOUNT_PROG
#  define OSXFUSE_MOUNT_PROG "/Library/Filesystems/macfuse.fs/Contents/Resources/mount_macfuse"
#endif

#ifndef OSXFUSE_VOLUME_ICON
#  define OSXFUSE_VOLUME_ICON "/Library/Filesystems/macfuse.fs/Contents/Resources/Volume.icns"
#endif

// Mark the daemon as dead
#define FUSEDEVIOCSETDAEMONDEAD _IOW('F', 3,  u_int32_t)

/* Semaphores */

struct __local_sem_t {
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

/* lock operations for flock(2) */
#ifndef LOCK_SH
#  define LOCK_SH         0x01            /* shared file lock */
#  define LOCK_EX         0x02            /* exclusive file lock */
#  define LOCK_NB         0x04            /* don't block when locking */
#  define LOCK_UN         0x08            /* unlock file */
#endif /* !LOCK_SH */

const char *osxfuse_version(void);

char *fuse_resource_path(const char *path);

extern DASessionRef fuse_dasession;

#endif /* _FUSE_DARWIN_PRIVATE_H_ */

#endif /* __APPLE__ */
