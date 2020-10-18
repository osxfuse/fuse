/*
 * Copyright (c) 2006-2008 Amit Singh/Google Inc.
 * Copyright (c) 2012 Anatol Pomozov
 * Copyright (c) 2011-2017 Benjamin Fleischer
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

#include <CoreFoundation/CoreFoundation.h>

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
	char base_path[MAXPATHLEN];
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
		strncpy(base_path, info.dli_fname, sizeof(base_path) - 1);
		base_path[sizeof(base_path) - 1] = '\0';

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

/********************/

DASessionRef fuse_dasession;

static void fuse_lib_constructor(void) __attribute__((constructor));
static void fuse_lib_destructor(void)  __attribute__((destructor));

static void
fuse_lib_constructor(void)
{
	fuse_dasession = DASessionCreate(NULL);
}

static void
fuse_lib_destructor(void)
{
	CFRelease(fuse_dasession);
	fuse_dasession = NULL;
}
