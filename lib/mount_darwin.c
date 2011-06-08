/*
 * Amit Singh <singh@>
 * 
 * Derived from mount_bsd.c from the fuse distribution.
 * 
 *  FUSE: Filesystem in Userspace
 *  Copyright (C) 2005-2006 Csaba Henk <csaba.henk@creo.hu>
 *
 *  This program can be distributed under the terms of the GNU LGPLv2.
 *  See the file COPYING.LIB.
*/

#undef _POSIX_C_SOURCE
#include <sys/types.h>
#include <CoreFoundation/CoreFoundation.h>

#include "fuse_i.h"
#include "fuse_opt.h"

#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/sysctl.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stddef.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <paths.h>

#include <libproc.h>
#include <sys/utsname.h>

#include <sys/param.h>
#include <sys/mount.h>
#include <AssertMacros.h>

#include "fuse_darwin_private.h"

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

static int
loadkmod(void)
{
    int result = -1;
    int pid, terminated_pid;
    union wait status;
    long major;

    major = fuse_os_version_major_np();

    if (major < 9) { /* not Mac OS X 10.5+ */
        return EINVAL;
    }

    pid = fork();

    if (pid == 0) {
        result = execl(MACFUSE_LOAD_PROG, MACFUSE_LOAD_PROG, NULL);
        
        /* exec failed */
        goto Return;
    }

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

static int
post_notification(char   *name,
                  char   *udata_keys[],
                  char   *udata_values[],
                  CFIndex nf_num)
{
    CFIndex i;
    CFStringRef nf_name   = NULL;
    CFStringRef nf_object = NULL;
    CFMutableDictionaryRef nf_udata  = NULL;

    CFNotificationCenterRef distributedCenter;
    CFStringEncoding encoding = kCFStringEncodingUTF8;

    distributedCenter = CFNotificationCenterGetDistributedCenter();

    if (!distributedCenter) {
        return -1;
    }

    nf_name = CFStringCreateWithCString(kCFAllocatorDefault, name, encoding);
      
    nf_object = CFStringCreateWithCString(kCFAllocatorDefault,
                                          LIBFUSE_UNOTIFICATIONS_OBJECT,
                                          encoding);
 
    nf_udata = CFDictionaryCreateMutable(kCFAllocatorDefault,
                                         nf_num,
                                         &kCFCopyStringDictionaryKeyCallBacks,
                                         &kCFTypeDictionaryValueCallBacks);

    if (!nf_name || !nf_object || !nf_udata) {
        goto out;
    }

    for (i = 0; i < nf_num; i++) {
        CFStringRef a_key = CFStringCreateWithCString(kCFAllocatorDefault,
                                                      udata_keys[i],
                                                      kCFStringEncodingUTF8);
        CFStringRef a_value = CFStringCreateWithCString(kCFAllocatorDefault,
                                                        udata_values[i],
                                                        kCFStringEncodingUTF8);
        CFDictionarySetValue(nf_udata, a_key, a_value);
        CFRelease(a_key);
        CFRelease(a_value);
    }

    CFNotificationCenterPostNotification(distributedCenter,
                                         nf_name, nf_object, nf_udata, false);

out:
    if (nf_name) {
        CFRelease(nf_name);
    }

    if (nf_object) {
        CFRelease(nf_object);
    }

    if (nf_udata) {
        CFRelease(nf_udata);
    }

    return 0;
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
    KEY_VOLICON,
};

struct mount_opts {
    int allow_other;
    int allow_root;
    int ishelp;
    char *kernel_opts;
};

static const struct fuse_opt fuse_mount_opts[] = {
    { "allow_other", offsetof(struct mount_opts, allow_other), 1 },
    { "allow_root", offsetof(struct mount_opts, allow_root), 1 },
    FUSE_OPT_KEY("allow_root",          KEY_ALLOW_ROOT),
    FUSE_OPT_KEY("auto_cache",          KEY_AUTO_CACHE),
    FUSE_OPT_KEY("-r",                  KEY_RO),
    FUSE_OPT_KEY("-h",                  KEY_HELP),
    FUSE_OPT_KEY("--help",              KEY_HELP),
    FUSE_OPT_KEY("-V",                  KEY_VERSION),
    FUSE_OPT_KEY("--version",           KEY_VERSION),
    /* standard FreeBSD mount options */
    FUSE_OPT_KEY("dev",                 KEY_KERN),
    FUSE_OPT_KEY("async",               KEY_KERN),
    FUSE_OPT_KEY("atime",               KEY_KERN),
    FUSE_OPT_KEY("dev",                 KEY_KERN),
    FUSE_OPT_KEY("exec",                KEY_KERN),
    FUSE_OPT_KEY("suid",                KEY_KERN),
    FUSE_OPT_KEY("symfollow",           KEY_KERN),
    FUSE_OPT_KEY("rdonly",              KEY_KERN),
    FUSE_OPT_KEY("sync",                KEY_KERN),
    FUSE_OPT_KEY("union",               KEY_KERN),
    FUSE_OPT_KEY("userquota",           KEY_KERN),
    FUSE_OPT_KEY("groupquota",          KEY_KERN),
    FUSE_OPT_KEY("clusterr",            KEY_KERN),
    FUSE_OPT_KEY("clusterw",            KEY_KERN),
    FUSE_OPT_KEY("suiddir",             KEY_KERN),
    FUSE_OPT_KEY("snapshot",            KEY_KERN),
    FUSE_OPT_KEY("multilabel",          KEY_KERN),
    FUSE_OPT_KEY("acls",                KEY_KERN),
    FUSE_OPT_KEY("force",               KEY_KERN),
    FUSE_OPT_KEY("update",              KEY_KERN),
    FUSE_OPT_KEY("ro",                  KEY_KERN),
    FUSE_OPT_KEY("rw",                  KEY_KERN),
    FUSE_OPT_KEY("auto",                KEY_KERN),
    /* options supported under both Linux and FBSD */
    FUSE_OPT_KEY("allow_other",         KEY_KERN),
    FUSE_OPT_KEY("default_permissions", KEY_KERN),
    /* FBSD FUSE specific mount options */
    FUSE_OPT_KEY("private",             KEY_KERN),
    FUSE_OPT_KEY("neglect_shares",      KEY_KERN),
    FUSE_OPT_KEY("push_symlinks_in",    KEY_KERN),
    /* stock FBSD mountopt parsing routine lets anything be negated... */
    FUSE_OPT_KEY("nodev",               KEY_KERN),
    FUSE_OPT_KEY("noasync",             KEY_KERN),
    FUSE_OPT_KEY("noatime",             KEY_KERN),
    FUSE_OPT_KEY("nodev",               KEY_KERN),
    FUSE_OPT_KEY("noexec",              KEY_KERN),
    FUSE_OPT_KEY("nosuid",              KEY_KERN),
    FUSE_OPT_KEY("nosymfollow",         KEY_KERN),
    FUSE_OPT_KEY("nordonly",            KEY_KERN),
    FUSE_OPT_KEY("nosync",              KEY_KERN),
    FUSE_OPT_KEY("nounion",             KEY_KERN),
    FUSE_OPT_KEY("nouserquota",         KEY_KERN),
    FUSE_OPT_KEY("nogroupquota",        KEY_KERN),
    FUSE_OPT_KEY("noclusterr",          KEY_KERN),
    FUSE_OPT_KEY("noclusterw",          KEY_KERN),
    FUSE_OPT_KEY("nosuiddir",           KEY_KERN),
    FUSE_OPT_KEY("nosnapshot",          KEY_KERN),
    FUSE_OPT_KEY("nomultilabel",        KEY_KERN),
    FUSE_OPT_KEY("noacls",              KEY_KERN),
    FUSE_OPT_KEY("noforce",             KEY_KERN),
    FUSE_OPT_KEY("noupdate",            KEY_KERN),
    FUSE_OPT_KEY("noro",                KEY_KERN),
    FUSE_OPT_KEY("norw",                KEY_KERN),
    FUSE_OPT_KEY("noauto",              KEY_KERN),
    FUSE_OPT_KEY("noallow_other",       KEY_KERN),
    FUSE_OPT_KEY("nodefault_permissions", KEY_KERN),
    FUSE_OPT_KEY("noprivate",           KEY_KERN),
    FUSE_OPT_KEY("noneglect_shares",    KEY_KERN),
    FUSE_OPT_KEY("nopush_symlinks_in",  KEY_KERN),
    /* Mac OS X options */
    FUSE_OPT_KEY("allow_recursion",     KEY_KERN),
    FUSE_OPT_KEY("allow_root",          KEY_KERN), /* need to pass this on */
    FUSE_OPT_KEY("auto_xattr",          KEY_KERN),
    FUSE_OPT_KEY("automounted",         KEY_IGNORED),
    FUSE_OPT_KEY("blocksize=",          KEY_KERN),
    FUSE_OPT_KEY("daemon_timeout=",     KEY_KERN),
    FUSE_OPT_KEY("default_permissions", KEY_KERN),
    FUSE_OPT_KEY("defer_permissions",   KEY_KERN),
    FUSE_OPT_KEY("direct_io",           KEY_DIO),
    FUSE_OPT_KEY("extended_security",   KEY_KERN),
    FUSE_OPT_KEY("fsid=",               KEY_KERN),
    FUSE_OPT_KEY("fsname=",             KEY_KERN),
    FUSE_OPT_KEY("fssubtype=",          KEY_KERN),
    FUSE_OPT_KEY("fstypename=",         KEY_KERN),
    FUSE_OPT_KEY("init_timeout=",       KEY_KERN),
    FUSE_OPT_KEY("iosize=",             KEY_KERN),
    FUSE_OPT_KEY("jail_symlinks",       KEY_KERN),
    FUSE_OPT_KEY("kill_on_unmount",     KEY_KERN),
    FUSE_OPT_KEY("local",               KEY_KERN),
    FUSE_OPT_KEY("native_xattr",        KEY_KERN),
    FUSE_OPT_KEY("negative_vncache",    KEY_KERN),
    FUSE_OPT_KEY("noalerts",            KEY_KERN),
    FUSE_OPT_KEY("noappledouble",       KEY_KERN),
    FUSE_OPT_KEY("noapplexattr",        KEY_KERN),
    FUSE_OPT_KEY("noattrcache",         KEY_KERN),
    FUSE_OPT_KEY("nobrowse",            KEY_KERN),
    FUSE_OPT_KEY("nolocalcaches",       KEY_KERN),
    FUSE_OPT_KEY("noping_diskarb",      KEY_IGNORED),
    FUSE_OPT_KEY("noreadahead",         KEY_KERN),
    FUSE_OPT_KEY("nosynconclose",       KEY_KERN),
    FUSE_OPT_KEY("nosyncwrites",        KEY_KERN),
    FUSE_OPT_KEY("noubc",               KEY_KERN),
    FUSE_OPT_KEY("novncache",           KEY_KERN),
    FUSE_OPT_KEY("ping_diskarb",        KEY_IGNORED),
    FUSE_OPT_KEY("quiet",               KEY_QUIET),
    FUSE_OPT_KEY("slow_statfs",         KEY_KERN),
    FUSE_OPT_KEY("sparse",              KEY_KERN),
    FUSE_OPT_KEY("subtype=",            KEY_IGNORED),
    FUSE_OPT_KEY("volicon=",            KEY_VOLICON),
    FUSE_OPT_KEY("volname=",            KEY_KERN),
    FUSE_OPT_END
};

static void
mount_help(void)
{
    system(MACFUSE_MOUNT_PROG " --help");
    fputc('\n', stderr);
}

static void
mount_version(void)
{
    system(MACFUSE_MOUNT_PROG " --version");
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

    case KEY_VOLICON:
    {
        char volicon_arg[MAXPATHLEN + 32];
        char *volicon_path = strchr(arg, '=');
        if (!volicon_path) {
            return -1;
        }
        if (snprintf(volicon_arg, sizeof(volicon_arg), 
                     "-omodules=volicon,iconpath%s", volicon_path) <= 0) {
            return -1;
        }
        if (fuse_opt_add_arg(outargs, volicon_arg) == -1) {
            return -1;
        }

        return 0;
    }

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

    if (strncmp(dev, MACFUSE_DEVICE_BASENAME,
                sizeof(MACFUSE_DEVICE_BASENAME) - 1)) {
        return;
    }

    strtol(dev + 4, &ep, 10);
    if (*ep != '\0') {
        return;
    }

    rp = realpath(mountpoint, resolved_path);
    if (rp) {
        ret = unmount(resolved_path, 0);
    }

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

static int
fuse_mount_core(const char *mountpoint, const char *opts)
{
    int fd, pid;
    int result;
    char *fdnam, *dev;
    const char *mountprog = MACFUSE_MOUNT_PROG;

    if (!mountpoint) {
        fprintf(stderr, "missing or invalid mount point\n");
        return -1;
    }

    if (fuse_running_under_rosetta()) {
        fprintf(stderr, "MacFUSE does not work under Rosetta\n");
        return -1;
    }

    signal(SIGCHLD, SIG_DFL); /* So that we can wait4() below. */

    result = loadkmod();
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
                    CFSTR("The installed MacFUSE version is too new for the operating system. Please downgrade your MacFUSE installation to one that is compatible with the currently running operating system."),
                    CFSTR("OK")
                );
            }
            post_notification(
                LIBFUSE_UNOTIFICATIONS_NOTIFY_OSISTOOOLD, NULL, NULL, 0);
        } else if (result == EBUSY) {
            if (!quiet_mode) {
                CFUserNotificationDisplayNotice(
                    (CFTimeInterval)0,
                    kCFUserNotificationCautionAlertLevel,
                    (CFURLRef)0,
                    (CFURLRef)0,
                    (CFURLRef)0,
                    CFSTR("MacFUSE Version Mismatch"),
                    CFSTR("MacFUSE has been updated but an incompatible or old version of the MacFUSE kernel extension is already loaded. It failed to unload, possibly because a MacFUSE volume is currently mounted.\n\nPlease eject all MacFUSE volumes and try again, or simply restart the system for changes to take effect."),
                    CFSTR("OK")
                );
            }
            post_notification(LIBFUSE_UNOTIFICATIONS_NOTIFY_VERSIONMISMATCH,
                              NULL, NULL, 0);
        }
        fprintf(stderr, "the MacFUSE file system is not available (%d)\n",
                result);
        return -1;
    } else {

        /* Module loaded, but now need to check for user<->kernel match. */

        char   version[MAXHOSTNAMELEN + 1] = { 0 };
        size_t version_len = MAXHOSTNAMELEN;
        size_t version_len_desired = 0;

        result = sysctlbyname(SYSCTL_MACFUSE_VERSION_NUMBER, version,
                              &version_len, NULL, (size_t)0);
        if (result == 0) {
            /* sysctlbyname() includes the trailing '\0' in version_len */
            version_len_desired = strlen(MACFUSE_VERSION) + 1;

            if ((version_len != version_len_desired) ||
                strncmp(MACFUSE_VERSION, version, version_len)) {
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
                CFSTR("MacFUSE Runtime Version Mismatch"),
                CFSTR("The MacFUSE library version this program is using is incompatible with the loaded MacFUSE kernel extension."),
                CFSTR("OK")
            );
        }
        post_notification(LIBFUSE_UNOTIFICATIONS_NOTIFY_RUNTIMEVERSIONMISMATCH,
                          NULL, NULL, 0);
        fprintf(stderr,
                "this MacFUSE library version is incompatible with "
                "the MacFUSE kernel extension\n");
        return -1;
    }

    fdnam = getenv("FUSE_DEV_FD");

    if (fdnam) {

        char *ep;

        fd = strtol(fdnam, &ep, 10);

        if (*ep != '\0') {
            fprintf(stderr, "invalid value given in FUSE_DEV_FD\n");
            return -1;
        }

        if (fd < 0)
            return -1;

        goto mount;
    }

    dev = getenv("FUSE_DEV_NAME");

    if (dev) {
        if ((fd = open(dev, O_RDWR)) < 0) {
            perror("MacFUSE: failed to open device");
            return -1;
        }
    } else {
        int r, devidx = -1;
        char devpath[MAXPATHLEN];

        for (r = 0; r < MACFUSE_NDEVICES; r++) {
            snprintf(devpath, MAXPATHLEN - 1,
                     _PATH_DEV MACFUSE_DEVICE_BASENAME "%d", r);
            fd = open(devpath, O_RDWR);
            if (fd >= 0) {
                dev = devpath;
                devidx = r;
                break;
            }
        }
        if (devidx == -1) {
            perror("MacFUSE: failed to open device");
            return -1;
        }
    }

mount:
    if (getenv("FUSE_NO_MOUNT") || ! mountpoint)
        goto out;

    signal(SIGCHLD, SIG_IGN);

    pid = fork();

    if (pid == -1) {
        perror("MacFUSE: fork() failed");
        close(fd);
        return -1;
    }

    if (pid == 0) {

        pid = fork();
        if (pid == -1) {
            perror("MacFUSE: fork() failed");
            close(fd);
            exit(1);
        }

        if (pid == 0) {
            const char *argv[32];
            int a = 0;

            if (! fdnam)
                asprintf(&fdnam, "%d", fd);

            argv[a++] = mountprog;
            if (opts) {
                argv[a++] = "-o";
                argv[a++] = opts;
            }
            argv[a++] = fdnam;
            argv[a++] = mountpoint;
            argv[a++] = NULL;

            {
                char title[MAXPATHLEN + 1] = { 0 };
                u_int32_t len = MAXPATHLEN;
                int ret = proc_pidpath(getpid(), title, len);
                if (ret) {
                    setenv("MOUNT_FUSEFS_DAEMON_PATH", title, 1);
                }
            }
            execvp(mountprog, (char **) argv);
            perror("MacFUSE: failed to exec mount program");
            exit(1);
        }

        _exit(0);
    }

out:
    return fd;
}

int
fuse_kern_mount(const char *mountpoint, struct fuse_args *args)
{
    struct mount_opts mo;
    int res = -1;

    memset(&mo, 0, sizeof(mo));

    /* mount_fusefs should not try to spawn the daemon */
    setenv("MOUNT_FUSEFS_SAFE", "1", 1);

    /* to notify mount_fusefs it's called from lib */
    setenv("MOUNT_FUSEFS_CALL_BY_LIB", "1", 1);

    if (args &&
        fuse_opt_parse(args, &mo, fuse_mount_opts, fuse_mount_opt_proc) == -1) {
        return -1;
    }

    if (mo.allow_other && mo.allow_root) {
        fprintf(stderr,
                "MacFUSE: allow_other and allow_root are mutually exclusive\n");
        goto out;
    }

    if (mo.ishelp) {
        res = 0;
        goto out; 
    }

    pthread_mutex_lock(&mount_lock);
    if (hash_search(mount_hash, (char *)mountpoint, NULL, NULL) != NULL) {
        fprintf(stderr, "MacFUSE: attempt to remount on active mount point: %s",
                mountpoint);
        goto out_unlock;
    }
    if (did_daemonize && mount_count > 0) {
        fprintf(stderr, "MacFUSE: attempt to multi-mount after daemonized: %s",
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

    return res;
}
