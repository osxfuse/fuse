/*
  FUSE: Filesystem in Userspace
  Copyright (C) 2001-2007  Miklos Szeredi <miklos@szeredi.hu>

  This program can be distributed under the terms of the GNU LGPLv2.
  See the file COPYING.LIB
*/

#include "fuse_lowlevel.h"
#include <stdio.h>
#include <string.h>
#include <signal.h>
#if (__FreeBSD__ >= 10)
#include "fuse_darwin_private.h"
#endif /* __FreeBSD__ >= 10 */

static struct fuse_session *fuse_instance;

static void exit_handler(int sig)
{
	(void) sig;
#if (__FreeBSD__ >= 10)
	fuse_exit_handler_internal_np();
#else
	if (fuse_instance)
		fuse_session_exit(fuse_instance);
#endif
}

static int set_one_signal_handler(int sig, void (*handler)(int))
{
	struct sigaction sa;
	struct sigaction old_sa;

	memset(&sa, 0, sizeof(struct sigaction));
	sa.sa_handler = handler;
	sigemptyset(&(sa.sa_mask));
	sa.sa_flags = 0;

	if (sigaction(sig, NULL, &old_sa) == -1) {
		perror("fuse: cannot get old signal handler");
		return -1;
	}

	if (old_sa.sa_handler == SIG_DFL &&
	    sigaction(sig, &sa, NULL) == -1) {
		perror("fuse: cannot set signal handler");
		return -1;
	}
	return 0;
}

int fuse_set_signal_handlers(struct fuse_session *se)
{
	if (set_one_signal_handler(SIGHUP, exit_handler) == -1 ||
	    set_one_signal_handler(SIGINT, exit_handler) == -1 ||
	    set_one_signal_handler(SIGTERM, exit_handler) == -1 ||
	    set_one_signal_handler(SIGPIPE, SIG_IGN) == -1)
		return -1;

	fuse_instance = se;
	return 0;
}

void fuse_remove_signal_handlers(struct fuse_session *se)
{
#if (__FreeBSD__ >= 10)
	if (fuse_remove_signal_handlers_internal_np() != 0) {
		return;
	}
#else
	if (fuse_instance != se)
		fprintf(stderr,
			"fuse: fuse_remove_signal_handlers: unknown session\n");
	else
		fuse_instance = NULL;
#endif /* __FreeBSD__ >= 10 */
	set_one_signal_handler(SIGHUP, SIG_DFL);
	set_one_signal_handler(SIGINT, SIG_DFL);
	set_one_signal_handler(SIGTERM, SIG_DFL);
	set_one_signal_handler(SIGPIPE, SIG_DFL);
}

