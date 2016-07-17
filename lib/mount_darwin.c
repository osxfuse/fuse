/*
 * Copyright (c) 2006-2008 Amit Singh/Google Inc.
 * Copyright (c) 2011-2016 Benjamin Fleischer
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

#include <AssertMacros.h>
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

#include <CoreFoundation/CoreFoundation.h>

#ifdef MACFUSE_MODE
#define OSXFUSE_MACFUSE_MODE_ENV "OSXFUSE_MACFUSE_MODE"
#endif

static int quiet_mode = 0;

long
fuse_os_version_major_np(void)
{
	int ret = 0;
	long major = 0;
	char *c = NULL;
	struct utsname u;
	size_t oldlen;

	oldlen = sizeof(u.release);

	ret = sysctlbyname("kern.osrelease", u.release, &oldlen, NULL, 0);
	if (ret != 0) {
		return -1;
	}

	c = strchr(u.release, '.');
	if (c == NULL) {
		return -1;
	}

	*c = '\0';

	errno = 0;
	major = strtol(u.release, NULL, 10);
	if ((errno == EINVAL) || (errno == ERANGE)) {
		return -1;
	}

	return major;
}

#if MAC_OS_X_VERSION_MIN_REQUIRED < 1070

int
fuse_running_under_rosetta(void)
{
	int result = 0;
	int is_native = 1;
	size_t sz = sizeof(result);

	int ret = sysctlbyname("sysctl.proc_native", &result, &sz, NULL, (size_t)0);
	if ((ret == 0) && !result) {
		is_native = 0;
	}

	return !is_native;
}

#endif /* MAC_OS_X_VERSION_MIN_REQUIRED < 1070 */

static int
loadkmod(void)
{
	int result = -1;
	int pid, terminated_pid;
	union wait status;
	long major;
	char *load_prog_path;

	major = fuse_os_version_major_np();

	if (major < OSXFUSE_MIN_DARWIN_VERSION) {
		/* This is not a supported version of macOS */
		return EINVAL;
	}

	load_prog_path = fuse_resource_path(OSXFUSE_LOAD_PROG);
	if (!load_prog_path) {
		fprintf(stderr, "fuse: load program missing\n");
		goto Return;
	}

#ifdef MACFUSE_MODE
	if (osxfuse_is_macfuse_mode_enabled()) {
		setenv(OSXFUSE_MACFUSE_MODE_ENV, "1", 1);
	}
#endif

	pid = fork();

	if (pid == 0) {
		result = execl(load_prog_path, load_prog_path, NULL);

		/* exec failed */
		check_noerr_string(result, strerror(errno));
		_exit(1);
	}

	free(load_prog_path);

	require_action(pid != -1, Return, result = errno);

	while ((terminated_pid = wait4(pid, (int *)&status, 0, NULL)) < 0) {
		/* retry if EINTR, else break out with error */
		if (errno != EINTR) {
			break;
		}
	}

	if ((terminated_pid == pid) && (WIFEXITED(status))) {
		result = WEXITSTATUS(status);
	} else {
		result = -1;
	}

Return:
	check_noerr_string(result, strerror(errno));

	return result;
}

/* osxfuse notifications */

enum osxfuse_notification {
	NOTIFICATION_OS_IS_TOO_NEW,
	NOTIFICATION_OS_IS_TOO_OLD,
	NOTIFICATION_RUNTIME_VERSION_MISMATCH,
	NOTIFICATION_VERSION_MISMATCH
};

typedef enum osxfuse_notification osxfuse_notification_t;

const char * const osxfuse_notification_names[] = {
	"kOSXFUSEOSIsTooNew",		  // NOTIFICATION_OS_IS_TOO_NEW
	"kOSXFUSEOSIsTooOld",		  // NOTIFICATION_OS_IS_TOO_OLD
	"kOSXFUSERuntimeVersionMismatch", // NOTIFICATION_RUNTIME_VERSION_MISMATCH
	"kOSXFUSEVersionMismatch"	  // NOTIFICATION_VERSION_MISMATCH
};

const char * const osxfuse_notification_object = OSXFUSE_IDENTIFIER;

#ifdef MACFUSE_MODE
#define MACFUSE_NOTIFICATION_PREFIX "com.google.filesystems.libfuse"
#define MACFUSE_NOTIFICATION_OBJECT \
		MACFUSE_NOTIFICATION_PREFIX ".unotifications"

const char * const macfuse_notification_names[] = {
	MACFUSE_NOTIFICATION_PREFIX ".osistoonew",	       // NOTIFICATION_OS_IS_TOO_NEW
	MACFUSE_NOTIFICATION_PREFIX ".osistooold",	       // NOTIFICATION_OS_IS_TOO_OLD
	MACFUSE_NOTIFICATION_PREFIX ".runtimeversionmismatch", // NOTIFICATION_RUNTIME_VERSION_MISMATCH
	MACFUSE_NOTIFICATION_PREFIX ".versionmismatch"	       // NOTIFICATION_VERSION_MISMATCH
};

const char * const macfuse_notification_object = MACFUSE_NOTIFICATION_OBJECT;
#endif /* MACFUSE_MODE */

static void
post_notification(const osxfuse_notification_t  notification,
		  const char		       *dict[][2],
		  const int		        dict_count)
{
	CFNotificationCenterRef notification_center =
			CFNotificationCenterGetDistributedCenter();

	CFStringRef	       name	 = NULL;
	CFStringRef	       object	 = NULL;
	CFMutableDictionaryRef user_info = NULL;

#ifdef MACFUSE_MODE
	if (osxfuse_is_macfuse_mode_enabled()) {
		name   = CFStringCreateWithCString(kCFAllocatorDefault,
						   macfuse_notification_names[notification],
						   kCFStringEncodingUTF8);
		object = CFStringCreateWithCString(kCFAllocatorDefault,
						   macfuse_notification_object,
						   kCFStringEncodingUTF8);
	} else {
#endif
		name   = CFStringCreateWithCString(kCFAllocatorDefault,
						   osxfuse_notification_names[notification],
						   kCFStringEncodingUTF8);
		object = CFStringCreateWithCString(kCFAllocatorDefault,
						   osxfuse_notification_object,
						   kCFStringEncodingUTF8);
#ifdef MACFUSE_MODE
	}
#endif

	if (!name || !object) goto out;
	if (dict_count == 0)  goto post;

	user_info = CFDictionaryCreateMutable(kCFAllocatorDefault, dict_count,
						  &kCFCopyStringDictionaryKeyCallBacks,
						  &kCFTypeDictionaryValueCallBacks);

	CFStringRef key;
	CFStringRef value;
	int	    i;
	for (i = 0; i < dict_count; i++) {
		key   = CFStringCreateWithCString(kCFAllocatorDefault, dict[i][0],
						  kCFStringEncodingUTF8);
		value = CFStringCreateWithCString(kCFAllocatorDefault, dict[i][1],
						  kCFStringEncodingUTF8);

		if (!key || !value) {
			if (key)   CFRelease(key);
			if (value) CFRelease(value);
			goto out;
		}

		CFDictionarySetValue(user_info, key, value);
		CFRelease(key); key = NULL;
		CFRelease(value); value = NULL;
	}

post:
	CFNotificationCenterPostNotification(notification_center, name, object,
					     user_info, false);

out:
	if (name)      CFRelease(name);
	if (object)    CFRelease(object);
	if (user_info) CFRelease(user_info);
}

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

static void
mount_hash_purge_helper(char *key, void *data)
{
	free(key);
	free(data);
}

void
fuse_kern_unmount(const char *mountpoint, int fd)
{
	int ret;
	struct stat sbuf;
	char dev[128];
	char resolved_path[PATH_MAX];
	char *ep, *rp = NULL, *umount_cmd;

	unsigned int hs_complete = 0;

	pthread_mutex_lock(&mount_lock);
	if ((mount_count > 0) && mountpoint) {
		struct mount_info* mi =
		hash_search(mount_hash, (char *)mountpoint, NULL, NULL);
		if (mi) {
			hash_destroy(mount_hash, (char *)mountpoint,
				     mount_hash_purge_helper);
			--mount_count;
		}
	}
	pthread_mutex_unlock(&mount_lock);

	ret = ioctl(fd, FUSEDEVIOCGETHANDSHAKECOMPLETE, &hs_complete);
	if (ret || !hs_complete) {
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

	rp = realpath(mountpoint, resolved_path);
	if (rp) {
		ret = unmount(resolved_path, 0);
	}
	close(fd);

	return;
}

void
fuse_unmount_compat22(const char *mountpoint)
{
	char resolved_path[PATH_MAX];
	char *rp = realpath(mountpoint, resolved_path);
	if (rp) {
		(void)unmount(resolved_path, 0);
	}

	return;
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

static int
fuse_mount_core(const char *mountpoint, const char *opts)
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

#if MAC_OS_X_VERSION_MIN_REQUIRED < 1070
	if (fuse_running_under_rosetta()) {
		fprintf(stderr, "%s does not work under Rosetta\n",
			OSXFUSE_DISPLAY_NAME);
		return -1;
	}
#endif

	signal(SIGCHLD, SIG_DFL); /* So that we can wait4() below. */

	result = loadkmod();
#if !M_OSXFUSE_ENABLE_KEXT_VERSION_CHECK
	if (result == EBUSY) {
		result = 0;
	}
#endif
	if (result) {
		CFOptionFlags responseFlags;
		if (result == EINVAL) {
			if (!quiet_mode) {
				CFUserNotificationDisplayNotice(
					(CFTimeInterval)0,
					kCFUserNotificationCautionAlertLevel,
					(CFURLRef)0,
					(CFURLRef)0,
					(CFURLRef)0,
					CFSTR("Operating System Too Old"),
					CFSTR("The installed " OSXFUSE_DISPLAY_NAME " version is too new for the operating system. Please downgrade your " OSXFUSE_DISPLAY_NAME " installation to one that is compatible with the currently running operating system."),
					CFSTR("OK"));
			}
			post_notification(NOTIFICATION_OS_IS_TOO_OLD, NULL, 0);
		} else if (result == EBUSY) {
			if (!quiet_mode) {
				CFUserNotificationDisplayNotice(
					(CFTimeInterval)0,
					kCFUserNotificationCautionAlertLevel,
					(CFURLRef)0,
					(CFURLRef)0,
					(CFURLRef)0,
					CFSTR(OSXFUSE_DISPLAY_NAME " Version Mismatch"),
					CFSTR(OSXFUSE_DISPLAY_NAME " has been updated but an incompatible or old version of the " OSXFUSE_DISPLAY_NAME " kernel extension is already loaded. It failed to unload, possibly because a " OSXFUSE_DISPLAY_NAME " volume is currently mounted.\n\nPlease eject all " OSXFUSE_DISPLAY_NAME " volumes and try again, or simply restart the system for changes to take effect."),
					CFSTR("OK"));
			}
			post_notification(NOTIFICATION_VERSION_MISMATCH,
					  NULL, 0);
		}
		fprintf(stderr, "the " OSXFUSE_DISPLAY_NAME " file system is not available (%d)\n",
			result);
		return -1;
	} else {

		/* Module loaded, but now need to check for user<->kernel match. */

		char   version[MAXHOSTNAMELEN + 1] = { 0 };
		size_t version_len = MAXHOSTNAMELEN;
		size_t version_len_desired = 0;

		result = sysctlbyname(OSXFUSE_SYSCTL_VERSION_NUMBER, version,
				      &version_len, NULL, (size_t)0);
		if (result == 0) {
			/* sysctlbyname() includes the trailing '\0' in version_len */
			version_len_desired = strlen(OSXFUSE_VERSION) + 1;

			if ((version_len != version_len_desired) ||
			    strncmp(OSXFUSE_VERSION, version, version_len)) {
				result = -1;
			}
		}
	}

	if (result) {
		if (!quiet_mode) {
			CFUserNotificationDisplayNotice(
				(CFTimeInterval)0,
				kCFUserNotificationCautionAlertLevel,
				(CFURLRef)0,
				(CFURLRef)0,
				(CFURLRef)0,
				CFSTR(OSXFUSE_DISPLAY_NAME " Runtime Version Mismatch"),
				CFSTR("The " OSXFUSE_DISPLAY_NAME " library version this program is using is incompatible with the loaded " OSXFUSE_DISPLAY_NAME " kernel extension."),
				CFSTR("OK"));
		}
		post_notification(NOTIFICATION_RUNTIME_VERSION_MISMATCH,
				  NULL, 0);
		fprintf(stderr,
			"this " OSXFUSE_DISPLAY_NAME " library version is incompatible with "
			"the " OSXFUSE_DISPLAY_NAME " kernel extension\n");
		return -1;
	}

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
		char daemon_path[PROC_PIDPATHINFO_MAXSIZE];
		char commfd[10];

		const char *argv[32];
		int a = 0;

		close(fds[1]);
		fcntl(fds[0], F_SETFD, 0);

		if (proc_pidpath(getpid(), daemon_path, PROC_PIDPATHINFO_MAXSIZE)) {
			setenv("MOUNT_OSXFUSE_DAEMON_PATH", daemon_path, 1);
		}

		snprintf(commfd, sizeof(commfd), "%i", fds[0]);
		setenv("_FUSE_COMMFD", commfd, 1);

		argv[a++] = mount_prog_path;
		if (opts) {
			argv[a++] = "-o";
			argv[a++] = opts;
		}
		argv[a++] = mountpoint;
		argv[a++] = NULL;

		execv(mount_prog_path, (char **)argv);
		perror("fuse: failed to exec mount program");
		_exit(1);
	}

        free(mount_prog_path);

        close(fds[0]);
        fd = receive_fd(fds[1]);

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
fuse_kern_mount(const char *mountpoint, struct fuse_args *args)
{
	struct mount_opts mo;
	int res = -1;

	memset(&mo, 0, sizeof(mo));

	/* to notify mount_osxfuse it's called from lib */
	setenv("MOUNT_OSXFUSE_CALL_BY_LIB", "1", 1);

#ifdef MACFUSE_MODE
	if (osxfuse_is_macfuse_mode_enabled()) {
		setenv(OSXFUSE_MACFUSE_MODE_ENV, "1", 1);
	}
#endif

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

	pthread_mutex_lock(&mount_lock);
	if (hash_search(mount_hash, (char *)mountpoint, NULL, NULL) != NULL) {
		fprintf(stderr, "fuse: attempt to remount on active mount point: %s",
			mountpoint);
		goto out_unlock;
	}
	if (did_daemonize && mount_count > 0) {
		fprintf(stderr, "fuse: attempt to multi-mount after daemonized: %s",
			mountpoint);
		goto out_unlock;
	}
	struct mount_info *mi = calloc(1, sizeof(struct mount_info));
	if (!mi) {
		goto out_unlock;
	}

	res = fuse_mount_core(mountpoint, mo.kernel_opts);
	if (res < 0) {
		free(mi);
	} else {
		mi->fd = res;
		hash_search(mount_hash, (char *)mountpoint, mi, NULL);
		++mount_count;
	}

out_unlock:
	pthread_mutex_unlock(&mount_lock);

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
