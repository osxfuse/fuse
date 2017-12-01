/*
 * Copyright (c) 2006-2008 Amit Singh/Google Inc.
 * Copyright (c) 2012 Anatol Pomozov
 * Copyright (c) 2011-2017 Benjamin Fleischer
 * Copyright (c) 2017 Dave MacLachlan/Google Inc.
*/

#include "fuse_i.h"
#include "fuse_darwin_private.h"

#include <dlfcn.h>
#include <errno.h>
#include <libgen.h>
#include <mach-o/dyld.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>


/* http://www.opengroup.org/onlinepubs/007908799/xsh/sem_init.html */
int
fuse_sem_init(dispatch_semaphore_t *sem, int pshared, unsigned int value)
{
	if (pshared) {
		errno = ENOSYS;
		return -1;
	}

  dispatch_semaphore_t local_sem = dispatch_semaphore_create(value);
  if (local_sem == NULL) {
    errno = ENOSPC;
    return -1;
  }
  *sem = local_sem;
	return 0;
}

/* http://www.opengroup.org/onlinepubs/007908799/xsh/sem_destroy.html */
int
fuse_sem_destroy(dispatch_semaphore_t *sem)
{
  dispatch_release(*sem);
  return 0;
}

/* http://www.opengroup.org/onlinepubs/007908799/xsh/sem_post.html */
int
fuse_sem_post(dispatch_semaphore_t *sem)
{
  dispatch_semaphore_signal(*sem);
	return 0;
}

/* http://www.opengroup.org/onlinepubs/007908799/xsh/sem_wait.html */
int
fuse_sem_wait(dispatch_semaphore_t *sem)
{
  if (dispatch_semaphore_wait(*sem, DISPATCH_TIME_FOREVER) != 0) {
    errno = EINTR;
    return -1;
  }
	return 0;
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
