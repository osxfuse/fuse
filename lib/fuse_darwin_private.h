/*
 * Copyright (c) 2006-2008 Amit Singh/Google Inc.
 * Copyright (c) 2011-2017 Benjamin Fleischer
 */

#ifdef __APPLE__

#ifndef _FUSE_DARWIN_PRIVATE_H_
#define _FUSE_DARWIN_PRIVATE_H_

#ifdef __cplusplus
extern "C" {
#endif

#include "fuse_darwin.h"

#include <fuse_param.h>
#include <fuse_ioctl.h>
#include <fuse_version.h>

#include <pthread.h>
#include <strhash.h>
#include <stdbool.h>
#include <stdint.h>
#include <time.h>
    
#ifdef __cplusplus
}
#endif

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

/* lock operations for flock(2) */
#ifndef LOCK_SH
#  define LOCK_SH         0x01            /* shared file lock */
#  define LOCK_EX         0x02            /* exclusive file lock */
#  define LOCK_NB         0x04            /* don't block when locking */
#  define LOCK_UN         0x08            /* unlock file */
#endif /* !LOCK_SH */

long fuse_os_version_major_np(void);

char *fuse_resource_path(const char *path);

fuse_ino_t fuse_lookup_inode_internal_np(const char *mountpoint,
                                         const char *path);

int fuse_knote_np(const char *mountpoint, const char *path, uint32_t note);

int fuse_purge_np(const char *mountpoint, const char *path, off_t *newsize);

int fuse_device_fd_np(const char *mountpoint);

struct fuse_fs;
const char *fuse_mountpoint_for_fs_np(struct fuse_fs *fs);

void fuse_exit_handler_internal_np(void);

int fuse_remove_signal_handlers_internal_np(void);

struct fuse *fuse_get_internal_np(const char *mountpoint);

void fuse_put_internal_np(struct fuse *fuse);

void fuse_set_fuse_internal_np(int fd, struct fuse *f);

void fuse_unset_fuse_internal_np(struct fuse *f);

#ifdef MACFUSE_MODE
void osxfuse_enable_macfuse_mode(bool arg);
bool osxfuse_is_macfuse_mode_enabled();
#endif

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

#endif /* __APPLE__ */
