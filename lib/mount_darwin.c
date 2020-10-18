/*
 * Copyright (c) 2006-2008 Amit Singh/Google Inc.
 * Copyright (c) 2011-2020 Benjamin Fleischer
 *
 * Derived from mount_bsd.c from the FUSE distribution.
 *
 *  FUSE: Filesystem in Userspace
 *  Copyright (C) 2005-2006 Csaba Henk <csaba.henk@creo.hu>
 *
 *  This program can be distributed under the terms of the GNU LGPLv2.
 *  See the file COPYING.LIB.
 */

#include "fuse_i.h"
#include "fuse_opt.h"
#include "fuse_darwin_private.h"

#include <errno.h>
#include <fcntl.h>
#include <libproc.h>
#include <paths.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/param.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/sysctl.h>
#include <sys/types.h>
#include <sys/un.h>
#include <sys/utsname.h>
#include <sys/wait.h>
#include <unistd.h>

#include <DiskArbitration/DiskArbitration.h>

static int quiet_mode = 0;

enum {
	KEY_ALLOW_ROOT,
	KEY_AUTO_CACHE,
	KEY_DIO,
	KEY_HELP,
	KEY_IGNORED,
	KEY_KERN,
	KEY_QUIET,
	KEY_RO,
	KEY_VERSION,
};

struct mount_opts {
	int allow_other;
	int allow_root;
	int ishelp;
	char *kernel_opts;
	char *modules;
	char *volicon;
};

static const struct fuse_opt fuse_mount_opts[] = {
	{ "allow_other", offsetof(struct mount_opts, allow_other), 1 },
	{ "allow_root", offsetof(struct mount_opts, allow_root), 1 },
	{ "modules=%s", offsetof(struct mount_opts, modules), 0 },
	FUSE_OPT_KEY("allow_root",	      KEY_ALLOW_ROOT),
	FUSE_OPT_KEY("auto_cache",	      KEY_AUTO_CACHE),
	FUSE_OPT_KEY("-r",		      KEY_RO),
	FUSE_OPT_KEY("-h",		      KEY_HELP),
	FUSE_OPT_KEY("--help",		      KEY_HELP),
	FUSE_OPT_KEY("-V",		      KEY_VERSION),
	FUSE_OPT_KEY("--version",	      KEY_VERSION),
	/* standard FreeBSD mount options */
	FUSE_OPT_KEY("dev",		      KEY_KERN),
	FUSE_OPT_KEY("async",		      KEY_KERN),
	FUSE_OPT_KEY("atime",		      KEY_KERN),
	FUSE_OPT_KEY("dev",		      KEY_KERN),
	FUSE_OPT_KEY("exec",		      KEY_KERN),
	FUSE_OPT_KEY("suid",		      KEY_KERN),
	FUSE_OPT_KEY("symfollow",	      KEY_KERN),
	FUSE_OPT_KEY("rdonly",		      KEY_KERN),
	FUSE_OPT_KEY("sync",		      KEY_KERN),
	FUSE_OPT_KEY("union",		      KEY_KERN),
	FUSE_OPT_KEY("userquota",	      KEY_KERN),
	FUSE_OPT_KEY("groupquota",	      KEY_KERN),
	FUSE_OPT_KEY("clusterr",	      KEY_KERN),
	FUSE_OPT_KEY("clusterw",	      KEY_KERN),
	FUSE_OPT_KEY("suiddir",		      KEY_KERN),
	FUSE_OPT_KEY("snapshot",	      KEY_KERN),
	FUSE_OPT_KEY("multilabel",	      KEY_KERN),
	FUSE_OPT_KEY("acls",		      KEY_KERN),
	FUSE_OPT_KEY("force",		      KEY_KERN),
	FUSE_OPT_KEY("update",		      KEY_KERN),
	FUSE_OPT_KEY("ro",		      KEY_KERN),
	FUSE_OPT_KEY("rw",		      KEY_KERN),
	FUSE_OPT_KEY("auto",		      KEY_KERN),
	/* options supported under both Linux and FBSD */
	FUSE_OPT_KEY("allow_other",	      KEY_KERN),
	FUSE_OPT_KEY("default_permissions",   KEY_KERN),
	/* FBSD FUSE specific mount options */
	FUSE_OPT_KEY("private",		      KEY_KERN),
	FUSE_OPT_KEY("neglect_shares",	      KEY_KERN),
	FUSE_OPT_KEY("push_symlinks_in",      KEY_KERN),
	/* stock FBSD mountopt parsing routine lets anything be negated... */
	FUSE_OPT_KEY("nodev",		      KEY_KERN),
	FUSE_OPT_KEY("noasync",		      KEY_KERN),
	FUSE_OPT_KEY("noatime",		      KEY_KERN),
	FUSE_OPT_KEY("nodev",		      KEY_KERN),
	FUSE_OPT_KEY("noexec",		      KEY_KERN),
	FUSE_OPT_KEY("nosuid",		      KEY_KERN),
	FUSE_OPT_KEY("nosymfollow",	      KEY_KERN),
	FUSE_OPT_KEY("nordonly",	      KEY_KERN),
	FUSE_OPT_KEY("nosync",		      KEY_KERN),
	FUSE_OPT_KEY("nounion",		      KEY_KERN),
	FUSE_OPT_KEY("nouserquota",	      KEY_KERN),
	FUSE_OPT_KEY("nogroupquota",	      KEY_KERN),
	FUSE_OPT_KEY("noclusterr",	      KEY_KERN),
	FUSE_OPT_KEY("noclusterw",	      KEY_KERN),
	FUSE_OPT_KEY("nosuiddir",	      KEY_KERN),
	FUSE_OPT_KEY("nosnapshot",	      KEY_KERN),
	FUSE_OPT_KEY("nomultilabel",	      KEY_KERN),
	FUSE_OPT_KEY("noacls",		      KEY_KERN),
	FUSE_OPT_KEY("noforce",		      KEY_KERN),
	FUSE_OPT_KEY("noupdate",	      KEY_KERN),
	FUSE_OPT_KEY("noro",		      KEY_KERN),
	FUSE_OPT_KEY("norw",		      KEY_KERN),
	FUSE_OPT_KEY("noauto",		      KEY_KERN),
	FUSE_OPT_KEY("noallow_other",	      KEY_KERN),
	FUSE_OPT_KEY("nodefault_permissions", KEY_KERN),
	FUSE_OPT_KEY("noprivate",	      KEY_KERN),
	FUSE_OPT_KEY("noneglect_shares",      KEY_KERN),
	FUSE_OPT_KEY("nopush_symlinks_in",    KEY_KERN),
	/* macOS options */
	FUSE_OPT_KEY("allow_recursion",	      KEY_KERN),
	FUSE_OPT_KEY("allow_root",	      KEY_KERN), /* need to pass this on */
	FUSE_OPT_KEY("auto_xattr",	      KEY_KERN),
	FUSE_OPT_KEY("automounted",	      KEY_IGNORED),
	FUSE_OPT_KEY("blocksize=",	      KEY_KERN),
	FUSE_OPT_KEY("daemon_timeout=",	      KEY_KERN),
	FUSE_OPT_KEY("default_permissions",   KEY_KERN),
	FUSE_OPT_KEY("defer_permissions",     KEY_KERN),
	FUSE_OPT_KEY("direct_io",	      KEY_DIO),
	FUSE_OPT_KEY("excl_create",	      KEY_KERN),
	FUSE_OPT_KEY("extended_security",     KEY_KERN),
	FUSE_OPT_KEY("fsid=",		      KEY_KERN),
	FUSE_OPT_KEY("fsname=",		      KEY_KERN),
	FUSE_OPT_KEY("fssubtype=",	      KEY_KERN),
	FUSE_OPT_KEY("fstypename=",	      KEY_KERN),
	FUSE_OPT_KEY("init_timeout=",	      KEY_KERN),
	FUSE_OPT_KEY("iosize=",		      KEY_KERN),
	FUSE_OPT_KEY("jail_symlinks",	      KEY_KERN),
	FUSE_OPT_KEY("kill_on_unmount",	      KEY_KERN),
	FUSE_OPT_KEY("local",		      KEY_KERN),
	FUSE_OPT_KEY("native_xattr",	      KEY_KERN),
	FUSE_OPT_KEY("negative_vncache",      KEY_KERN),
	FUSE_OPT_KEY("noalerts",	      KEY_KERN),
	FUSE_OPT_KEY("noappledouble",	      KEY_KERN),
	FUSE_OPT_KEY("noapplexattr",	      KEY_KERN),
	FUSE_OPT_KEY("noattrcache",	      KEY_KERN),
	FUSE_OPT_KEY("noautonotify",	      KEY_KERN),
	FUSE_OPT_KEY("nobrowse",	      KEY_KERN),
	FUSE_OPT_KEY("nolocalcaches",	      KEY_KERN),
	FUSE_OPT_KEY("noping_diskarb",	      KEY_IGNORED),
	FUSE_OPT_KEY("noreadahead",	      KEY_KERN),
	FUSE_OPT_KEY("nosynconclose",	      KEY_KERN),
	FUSE_OPT_KEY("nosyncwrites",	      KEY_KERN),
	FUSE_OPT_KEY("noubc",		      KEY_KERN),
	FUSE_OPT_KEY("novncache",	      KEY_KERN),
	FUSE_OPT_KEY("ping_diskarb",	      KEY_IGNORED),
	FUSE_OPT_KEY("quiet",		      KEY_QUIET),
	FUSE_OPT_KEY("slow_statfs",	      KEY_KERN),
	FUSE_OPT_KEY("sparse",		      KEY_KERN),
	FUSE_OPT_KEY("subtype=",	      KEY_IGNORED),
	{ "volicon=%s", offsetof(struct mount_opts, volicon), 0 },
	FUSE_OPT_KEY("volname=",	      KEY_KERN),
	FUSE_OPT_END
};

static void
mount_run(const char *mount_args)
{
	int err;

	char *mount_prog_path;
	char *mount_cmd;

	mount_prog_path = fuse_resource_path(OSXFUSE_MOUNT_PROG);
	if (!mount_prog_path) {
		fprintf(stderr, "fuse: mount program missing\n");
		goto out;
	}
	err = asprintf(&mount_cmd, "%s %s", mount_prog_path, mount_args);
	free(mount_prog_path);
	if (err == -1) {
		goto out;
	}

	system(mount_cmd);

out:
	free(mount_cmd);
}

static void
mount_help(void)
{
	mount_run("--help");
	fputc('\n', stderr);
}

static void
mount_version(void)
{
	mount_run("--version");
}

static int
fuse_mount_opt_proc(void *data, const char *arg, int key,
		    struct fuse_args *outargs)
{
	struct mount_opts *mo = data;

	switch (key) {

		case KEY_AUTO_CACHE:
			if (fuse_opt_add_opt(&mo->kernel_opts, "auto_cache") == -1 ||
			    fuse_opt_add_arg(outargs, "-oauto_cache") == -1)
				return -1;
			return 0;

		case KEY_ALLOW_ROOT:
			if (fuse_opt_add_opt(&mo->kernel_opts, "allow_other") == -1 ||
			    fuse_opt_add_arg(outargs, "-oallow_root") == -1)
				return -1;
			return 0;

		case KEY_RO:
			arg = "ro";
			/* fall through */

		case KEY_KERN:
			return fuse_opt_add_opt(&mo->kernel_opts, arg);

		case KEY_DIO:
			if (fuse_opt_add_opt(&mo->kernel_opts, "direct_io") == -1 ||
			    (fuse_opt_add_arg(outargs, "-odirect_io") == -1))
				return -1;
			return 0;

		case KEY_IGNORED:
			return 0;

		case KEY_QUIET:
			quiet_mode = 1;
			return 0;

		case KEY_HELP:
			mount_help();
			mo->ishelp = 1;
			break;

		case KEY_VERSION:
			mount_version();
			mo->ishelp = 1;
			break;
	}
	return 1;
}

void
fuse_kern_unmount(DADiskRef disk, int fd)
{
	struct stat sbuf;
	char dev[128];
	char *ep, *rp = NULL, *umount_cmd;

	if (!disk) {
		/*
		 * Filesystem has already been unmounted, all we need to do is
		 * make sure fd is closed.
		 */
		if (fd != -1)
			close(fd);
		return;
	}

	if (fstat(fd, &sbuf) == -1) {
		return;
	}

	devname_r(sbuf.st_rdev, S_IFCHR, dev, 128);

	if (strncmp(dev, OSXFUSE_DEVICE_BASENAME,
		    sizeof(OSXFUSE_DEVICE_BASENAME) - 1)) {
		return;
	}

	strtol(dev + sizeof(OSXFUSE_DEVICE_BASENAME) - 1, &ep, 10);
	if (*ep != '\0') {
		return;
	}

	DADiskUnmount(disk, kDADiskUnmountOptionDefault, NULL, NULL);
}

void
fuse_unmount_compat22(const char *mountpoint)
{
	(void)unmount(mountpoint, 0);
}

/* return value:
 * >= 0	 => fd
 * -1	 => error
 */
static int receive_fd(int sock_fd)
{
	struct msghdr msg;
	struct iovec iov;
	char buf[1];
	size_t rv;
	char ccmsg[CMSG_SPACE(sizeof(int))];
	struct cmsghdr *cmsg;
	int fd;

	iov.iov_base = buf;
	iov.iov_len = 1;

	memset(&msg, 0, sizeof(msg));
	msg.msg_name = 0;
	msg.msg_namelen = 0;
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	msg.msg_control = ccmsg;
	msg.msg_controllen = sizeof(ccmsg);

	while (((rv = recvmsg(sock_fd, &msg, 0)) == -1) && errno == EINTR);
	if (rv == -1) {
		perror("recvmsg");
		return -1;
	}
	if (!rv) {
		/* EOF */
		return -1;
	}

	cmsg = CMSG_FIRSTHDR(&msg);
	if (cmsg->cmsg_type != SCM_RIGHTS) {
		fprintf(stderr, "got control message of unknown type %d\n",
			cmsg->cmsg_type);
		return -1;
	}

	memcpy(&fd, CMSG_DATA(cmsg), sizeof(fd));
	return fd;
}

struct fuse_mount_core_wait_arg {
	int fd;
	void (*callback)(void *context, int res);
	void *context;
};

static void *
fuse_mount_core_wait(void *arg)
{
	int fd;
	void (*callback)(void *context, int res);
	void *context;

	int32_t status = -1;
	ssize_t rv = 0;

	{
		struct fuse_mount_core_wait_arg *a =
			(struct fuse_mount_core_wait_arg *)arg;
		fd = a->fd;
		callback = a->callback;
		context = a->context;
	}

	if (!callback) {
		goto out;
	}

	while (((rv = recv(fd, &status, sizeof(status), 0)) == -1) &&
	       errno == EINTR);
	if (rv == -1) {
		perror("receive mount status");
		goto out;
	}
	if (!rv) {
		/* EOF */
		goto out;
	}

	callback(context, status);

out:
	free(arg);
	return NULL;
}

static int
fuse_mount_core(const char *mountpoint, const char *opts,
		void (*callback)(void *, int), void *context)
{
	int fd;
	int result;
	char *dev;
	char *mount_prog_path;
	int fds[2];
	pid_t pid;
	int status;

	if (!mountpoint) {
		fprintf(stderr, "missing or invalid mount point\n");
		return -1;
	}

	signal(SIGCHLD, SIG_DFL); /* So that we can wait4() below. */

	if (getenv("FUSE_NO_MOUNT") || ! mountpoint) {
		goto out;
	}

	mount_prog_path = fuse_resource_path(OSXFUSE_MOUNT_PROG);
	if (!mount_prog_path) {
		fprintf(stderr, "fuse: mount program missing\n");
		return -1;
	}

	result = socketpair(AF_UNIX, SOCK_STREAM, 0, fds);
	if (result == -1) {
		fprintf(stderr, "fuse: socketpair() failed");
		return -1;
	}

	pid = fork();

	if (pid == -1) {
		perror("fuse: fork failed");
		close(fds[0]);
		close(fds[1]);
		return -1;
	}

	if (pid == 0) {
		pid_t cpid = fork();

		if (cpid == -1) {
			perror("fuse: fork failed");
			close(fds[0]);
			close(fds[1]);
			_exit(1);
		}

		if (cpid == 0) {
			char daemon_path[PROC_PIDPATHINFO_MAXSIZE];
			char commfd[10];

			const char *argv[32];
			int a = 0;

			close(fds[1]);
			fcntl(fds[0], F_SETFD, 0);

			if (proc_pidpath(getpid(), daemon_path, PROC_PIDPATHINFO_MAXSIZE)) {
				setenv("_FUSE_DAEMON_PATH", daemon_path, 1);
			}

			snprintf(commfd, sizeof(commfd), "%i", fds[0]);
			setenv("_FUSE_COMMFD", commfd, 1);
			setenv("_FUSE_COMMVERS", "2", 1);

			argv[a++] = mount_prog_path;
			if (opts) {
				argv[a++] = "-o";
				argv[a++] = opts;
			}
			if (quiet_mode) {
				argv[a++] = "-q";
			}
			argv[a++] = mountpoint;
			argv[a++] = NULL;

			execv(mount_prog_path, (char **)argv);
			perror("fuse: failed to exec mount program");
			_exit(1);
		}

		_exit(0);
	}

	free(mount_prog_path);

	close(fds[0]);
	fd = receive_fd(fds[1]);

	if (callback) {
		struct fuse_mount_core_wait_arg *arg =
			calloc(1, sizeof(struct fuse_mount_core_wait_arg));
		arg->fd = fds[1];
		arg->callback = callback;
		arg->context = context;

		pthread_t mount_wait_thread;
		int res = pthread_create(&mount_wait_thread, NULL,
					 &fuse_mount_core_wait, (void *)arg);
		if (res) {
			perror("fuse: failed to wait for mount status");
			goto mount_err_out;
		}
	}

	if (waitpid(pid, &status, 0) == -1 || WEXITSTATUS(status) != 0) {
		perror("fuse: failed to mount file system");
		goto mount_err_out;
	}

	goto out;

mount_err_out:
	close(fd);
	fd = -1;

out:
	return fd;
}

int
fuse_kern_mount(const char *mountpoint, struct fuse_args *args,
		void (*callback)(void *, int), void *context)
{
	struct mount_opts mo;
	int res = -1;

	memset(&mo, 0, sizeof(mo));

	/* to notify mount_macfuse it's called from lib */
	setenv("_FUSE_CALL_BY_LIB", "1", 1);

	if (args &&
		fuse_opt_parse(args, &mo, fuse_mount_opts, fuse_mount_opt_proc) == -1) {
		return -1;
	}

	if (mo.allow_other && mo.allow_root) {
		fprintf(stderr,
			"fuse: allow_other and allow_root are mutually exclusive\n");
		goto out;
	}

	if (mo.ishelp) {
		res = 0;
		goto out;
	}

	if (mo.volicon) {
		size_t modules_len;
		char *modules;
		char *modules_ptr;

		char iconpath_arg[MAXPATHLEN + 12];

		if (mo.modules) {
			modules_len = strlen(mo.modules);
		} else {
			modules_len = 0;
		}

		modules = (char *)malloc(modules_len + sizeof(":volicon"));
		if (!modules) {
			fprintf(stderr, "fuse: failed to allocate modules string\n");
			goto out;
		}

		/* build new modules string */
		modules_ptr = modules;
		if (modules_len) {
			modules_ptr = stpcpy(modules_ptr, mo.modules);
			*modules_ptr = ':';
			modules_ptr++;
		}
		modules_ptr = stpcpy(modules_ptr, "volicon");
		*modules_ptr = '\0';

		/* replace old modules string */
		if (mo.modules) {
			free(mo.modules);
		}
		mo.modules = modules;

		/* add iconpath argument */
		if (snprintf(iconpath_arg, sizeof(iconpath_arg),
			     "-oiconpath=%s", mo.volicon) <= 0) {
			fprintf(stderr, "fuse: failed to create iconpath argument\n");
			goto out;
		}
		if (fuse_opt_add_arg(args, iconpath_arg) == -1) {
			fprintf(stderr, "fuse: failed to add iconpath argument\n");
			goto out;
		}
	}

	if (mo.modules) {
		int err;

		size_t modules_arg_len = sizeof("-omodules=") + strlen(mo.modules);
		char *modules_arg = (char *)malloc(modules_arg_len);

		/* add modules argument */
		err = snprintf(modules_arg, modules_arg_len, "-omodules=%s",
			       mo.modules);
		if (err <= 0) {
			fprintf(stderr, "fuse: failed to create modules argument\n");
			free(modules_arg);
			goto out;
		}
		err = fuse_opt_add_arg(args, modules_arg);
		free(modules_arg);
		if (err == -1) {
			fprintf(stderr, "fuse: failed to add modules argument\n");
			goto out;
		}
	}

	res = fuse_mount_core(mountpoint, mo.kernel_opts, callback, context);

out:
	free(mo.kernel_opts);
	if (mo.modules) {
		free(mo.modules);
	}
	if (mo.volicon) {
		free(mo.volicon);
	}

	return res;
}
