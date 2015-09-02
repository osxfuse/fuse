/*
 * Copyright (c) 2006-2008 Amit Singh/Google Inc.
 * Copyright (c) 2012 Anatol Pomozov
 * Copyright (c) 2011-2015 Benjamin Fleischer
 */

#include "fuse_i.h"
#include "fuse_darwin_private.h"

#include <dlfcn.h>
#include <errno.h>
#include <libgen.h>
#include <mach-o/dyld.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/param.h>
#include <sys/types.h>
#include <unistd.h>

/*
 * Semaphore implementation based on:
 *
 * Copyright (C) 2000,02 Free Software Foundation, Inc.
 * This file is part of the GNU C Library.
 * Written by Ga<EB>l Le Mignot <address@hidden>
 *
 * The GNU C Library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Library General Public License as
 * published by the Free Software Foundation; either version 2 of the
 * License, or (at your option) any later version.
 *
 * The GNU C Library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Library General Public License for more details.
 *
 * You should have received a copy of the GNU Library General Public
 * License along with the GNU C Library; see the file COPYING.LIB.  If not,
 * write to the Free Software Foundation, Inc., 59 Temple Place - Suite 330,
 * Boston, MA 02111-1307, USA.
 */

#include <assert.h>

/* Semaphores */

#define __SEM_ID_NONE  0x0
#define __SEM_ID_LOCAL 0xcafef00d

/* http://www.opengroup.org/onlinepubs/007908799/xsh/sem_init.html */
int
fuse_sem_init(fuse_sem_t *sem, int pshared, unsigned int value)
{
	if (pshared) {
		errno = ENOSYS;
		return -1;
	}

	sem->id = __SEM_ID_NONE;

	if (pthread_cond_init(&sem->__data.local.count_cond, NULL)) {
		goto cond_init_fail;
	}

	if (pthread_mutex_init(&sem->__data.local.count_lock, NULL)) {
		goto mutex_init_fail;
	}

	sem->__data.local.count = value;
	sem->id = __SEM_ID_LOCAL;

	return 0;

mutex_init_fail:

	pthread_cond_destroy(&sem->__data.local.count_cond);

cond_init_fail:

	return -1;
}

/* http://www.opengroup.org/onlinepubs/007908799/xsh/sem_destroy.html */
int
fuse_sem_destroy(fuse_sem_t *sem)
{
	int res = 0;

	pthread_mutex_lock(&sem->__data.local.count_lock);

	sem->id = __SEM_ID_NONE;
	pthread_cond_broadcast(&sem->__data.local.count_cond);

	if (pthread_cond_destroy(&sem->__data.local.count_cond)) {
		res = -1;
	}

	pthread_mutex_unlock(&sem->__data.local.count_lock);

	if (pthread_mutex_destroy(&sem->__data.local.count_lock)) {
		res = -1;
	}

	return res;
}

int
fuse_sem_getvalue(fuse_sem_t *sem, unsigned int *sval)
{
	int res = 0;

	pthread_mutex_lock(&sem->__data.local.count_lock);

	if (sem->id != __SEM_ID_LOCAL) {
		res = -1;
		errno = EINVAL;
	} else {
		*sval = sem->__data.local.count;
	}

	pthread_mutex_unlock(&sem->__data.local.count_lock);

	return res;
}

/* http://www.opengroup.org/onlinepubs/007908799/xsh/sem_post.html */
int
fuse_sem_post(fuse_sem_t *sem)
{
	int res = 0;

	pthread_mutex_lock(&sem->__data.local.count_lock);

	if (sem->id != __SEM_ID_LOCAL) {
		res = -1;
		errno = EINVAL;
	} else if (sem->__data.local.count < FUSE_SEM_VALUE_MAX) {
		sem->__data.local.count++;
		if (sem->__data.local.count == 1) {
			pthread_cond_signal(&sem->__data.local.count_cond);
		}
	} else {
		errno = ERANGE;
		res = -1;
	}

	pthread_mutex_unlock(&sem->__data.local.count_lock);

	return res;
}

/* http://www.opengroup.org/onlinepubs/009695399/functions/sem_timedwait.html */
int
fuse_sem_timedwait(fuse_sem_t *sem, const struct timespec *abs_timeout)
{
	int res = 0;

	if (abs_timeout &&
	    (abs_timeout->tv_nsec < 0 || abs_timeout->tv_nsec >= 1000000000)) {
		errno = EINVAL;
		return -1;
	}

	pthread_cleanup_push((void(*)(void*))&pthread_mutex_unlock,
			     &sem->__data.local.count_lock);

	pthread_mutex_lock(&sem->__data.local.count_lock);

	if (sem->id != __SEM_ID_LOCAL) {
		errno = EINVAL;
		res = -1;
	} else {
		if (!sem->__data.local.count) {
			res = pthread_cond_timedwait(&sem->__data.local.count_cond,
						     &sem->__data.local.count_lock,
						     abs_timeout);
		}
		if (res) {
			assert(res == ETIMEDOUT);
			res = -1;
			errno = ETIMEDOUT;
		} else if (sem->id != __SEM_ID_LOCAL) {
			res = -1;
			errno = EINVAL;
		} else {
			sem->__data.local.count--;
		}
	}

	pthread_cleanup_pop(1);

	return res;
}

/* http://www.opengroup.org/onlinepubs/007908799/xsh/sem_trywait.html */
int
fuse_sem_trywait(fuse_sem_t *sem)
{
	int res = 0;

	pthread_mutex_lock(&sem->__data.local.count_lock);

	if (sem->id != __SEM_ID_LOCAL) {
		res = -1;
		errno = EINVAL;
	} else if (sem->__data.local.count) {
		sem->__data.local.count--;
	} else {
		res = -1;
		errno = EAGAIN;
	}

	pthread_mutex_unlock (&sem->__data.local.count_lock);

	return res;
}

/* http://www.opengroup.org/onlinepubs/007908799/xsh/sem_wait.html */
int
fuse_sem_wait(fuse_sem_t *sem)
{
	int res = 0;

	pthread_cleanup_push((void(*)(void*))&pthread_mutex_unlock,
			     &sem->__data.local.count_lock);

	pthread_mutex_lock(&sem->__data.local.count_lock);

	if (sem->id != __SEM_ID_LOCAL) {
		errno = EINVAL;
		res = -1;
	} else {
		if (!sem->__data.local.count) {
			pthread_cond_wait(&sem->__data.local.count_cond,
					  &sem->__data.local.count_lock);
			if (!sem->__data.local.count) {
				/* spurious wakeup, assume it is an interruption */
				res = -1;
				errno = EINTR;
				goto out;
			}
		}
		if (sem->id != __SEM_ID_LOCAL) {
			res = -1;
			errno = EINVAL;
		} else {
			sem->__data.local.count--;
		}
	}

out:
	pthread_cleanup_pop(1);

	return res;
}

/********************/

const char *
osxfuse_version(void)
{
	return OSXFUSE_VERSION;
}

/* Resource paths */

#define EXECUTABLE_PATH "@executable_path/"
#define LOADER_PATH "@loader_path/"

char *
fuse_resource_path(const char *path)
{
    char  base_path[MAXPATHLEN];
    char *relative_path = NULL;
    char *resource_path;

    if (strncmp(path, EXECUTABLE_PATH, sizeof(EXECUTABLE_PATH) - 1) == 0) {
        int      err = 0;
        uint32_t executable_path_len = MAXPATHLEN;

        /* Path relative to executable */
        err = _NSGetExecutablePath(base_path, &executable_path_len);
        if (err == -1) {
            return NULL;
        }

        relative_path = (char *)path + sizeof(EXECUTABLE_PATH) - 1;
    } else if (strncmp(path, LOADER_PATH, sizeof(LOADER_PATH) - 1) == 0) {
        Dl_info info;

        /* Path relative to loader */
        if (!dladdr(&fuse_resource_path, &info)) {
            return NULL;
        }
        strlcpy(base_path, info.dli_fname, sizeof(base_path));

        relative_path = (char *)path + sizeof(LOADER_PATH) - 1;
    }

    if (relative_path) {
        char  base_path_real[MAXPATHLEN];
        char *base_dir;

        if (!realpath(base_path, base_path_real)) {
            return NULL;
        }

        /* Parent directory of base path */
        base_dir = dirname(base_path_real);
        if (!base_dir) {
            return NULL;
        }

        /* Build resource path */
        asprintf(&resource_path, "%s/%s", base_dir, relative_path);
    } else {
        resource_path = malloc(strlen(path) + 1);
        if (!resource_path) {
            return NULL;
        }
        strcpy(resource_path, path);
    }

    return resource_path;
}

static int
schedule_umount(char* mountpoint, struct mount_info* mi, void* arg)
{
	int fd;
	pid_t pid;

	fd = mi->fd;
	pid = fork();
	if (pid == 0) { /* child */
		fcntl(fd, F_SETFD, 1); /* close-on-exec */
		execl("/sbin/umount", "/sbin/umount", mountpoint, NULL);
	} else {
		/* We do nothing in the parent. */
	}
	return 1;  /* Keep processing mountpoints. */
}

void
fuse_exit_handler_internal_np(void)
{
	pthread_mutex_lock(&mount_lock);
	hash_traverse(mount_hash, (int(*)())schedule_umount, NULL);
	pthread_mutex_unlock(&mount_lock);
}

int
fuse_remove_signal_handlers_internal_np(void)
{
	int res = 0;
	pthread_mutex_lock(&mount_lock);
	if (mount_count > 1) {
		/* Leave signal handlers up if we have > 1 mouned fs. */
		res = -1;
	}
	pthread_mutex_unlock(&mount_lock);
	return res;
}

static int
set_fuse_helper(char *mountpoint, struct mount_info *mi, struct mount_info *arg)
{
	if (mi->fd == arg->fd) {
		mi->fuse = arg->fuse;
		return 0;
	}
	return 1;
}

static int
unset_fuse_helper(char *mountpoint, struct mount_info *mi, struct fuse *f)
{
	if (mi->fuse == f) {
		mi->fuse = NULL;
		return 0;
	}
	return 1;
}

void
fuse_set_fuse_internal_np(int fd, struct fuse *f)
{
	struct mount_info mi;

	mi.fd = fd;
	mi.fuse = f;

	pthread_mutex_lock(&mount_lock);
	hash_traverse(mount_hash, (int(*)())set_fuse_helper, &mi);
	pthread_mutex_unlock(&mount_lock);
}

void
fuse_unset_fuse_internal_np(struct fuse *f)
{
	pthread_mutex_lock(&mount_lock);
	hash_traverse(mount_hash, (int(*)())unset_fuse_helper, f);
	pthread_mutex_unlock(&mount_lock);
}

int
fuse_device_fd_np(const char *mountpoint)
{
	int fd = -1;
	pthread_mutex_lock(&mount_lock);
	struct mount_info* mi =
        hash_search(mount_hash, (char *)mountpoint, NULL, NULL);
	if (mi != NULL) {
		fd = mi->fd;
	}
	pthread_mutex_unlock(&mount_lock);
	return fd;
}

/*
 * Note: fuse_purge_np is deprecated and will be removed in a future release.
 *
 * Use fuse_lowlevel_notify_inval_inode instead.
 */
int
fuse_purge_np(const char *mountpoint, const char *path, off_t *newsize)
{
	(void) newsize;
	
	struct fuse_avfi_ioctl avfi;
	fuse_ino_t ino = 0;
	struct fuse *f;
	struct fuse_chan *ch = NULL;

	if (!path) {
		return EINVAL;
	}

	ino = fuse_lookup_inode_internal_np(mountpoint, path);
	if (ino == 0) { /* invalid */
		return ENOENT;
	}

	f = fuse_get_internal_np(mountpoint);
	if (f) {
		struct fuse_session *se = fuse_get_session(f);
		ch = fuse_session_next_chan(se, NULL);
		fuse_put_internal_np(f);
	}
	if (!ch) {
		return ENXIO;
	}

	return fuse_lowlevel_notify_inval_inode(ch, ino, 0, 0);
}

/*
 * Note: fuse_knote_np is deprecated and will be removed in a future release.
 *
 * In Mac OS X 10.5 the file system implementation is responsible for posting
 * kqueue events. Starting with Mac OS X 10.6 the VFS layer takes over the job.
 */
int
fuse_knote_np(const char *mountpoint, const char *path, uint32_t note)
{
	struct fuse_avfi_ioctl avfi;
	fuse_ino_t ino = 0;
	int fd = -1;

	if (!path) {
		return EINVAL;
	}

	ino = fuse_lookup_inode_internal_np(mountpoint, path);
	if (ino == 0) { /* invalid */
		return ENOENT;
	}

	fd = fuse_device_fd_np(mountpoint);
	if (fd < 0) {
		return ENXIO;
	}

	avfi.inode = ino;
	avfi.cmd = FUSE_AVFI_KNOTE;
	avfi.ubc_flags = 0;
	avfi.note = note;
	avfi.size = 0;

	return ioctl(fd, FUSEDEVIOCALTERVNODEFORINODE, (void *)&avfi);
}

/********************/

#ifdef MACFUSE_MODE
static bool osxfuse_macfuse_mode = false;

void osxfuse_enable_macfuse_mode(bool arg) {
	osxfuse_macfuse_mode = arg;
}

bool osxfuse_is_macfuse_mode_enabled() {
	return osxfuse_macfuse_mode;
}
#endif

pthread_mutex_t mount_lock;
hash_table     *mount_hash;
int             mount_count;
int             did_daemonize;

static void fuse_lib_constructor(void) __attribute__((constructor));
static void fuse_lib_destructor(void)  __attribute__((destructor));

static void
fuse_lib_constructor(void)
{
	pthread_mutex_init(&mount_lock, NULL);
	mount_hash = hash_create(OSXFUSE_NDEVICES);
	mount_count = 0;
	did_daemonize = 0;
}

static void
mount_hash_purge_helper(char *key, void *value)
{
	free(key);
	free(value);
}

static void
fuse_lib_destructor(void)
{
	hash_purge(mount_hash, mount_hash_purge_helper);
	free(mount_hash);
	mount_hash = NULL;
	mount_count = 0;
}
