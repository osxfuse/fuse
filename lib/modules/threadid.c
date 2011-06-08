/*
 * Per-thread override identity support for MacFUSE.
 *
 * Amit Singh <singh@>
 *
 *  This program can be distributed under the terms of the GNU LGPL.
 *  See the file COPYING.LIB for details.
 */

#define FUSE_USE_VERSION 26

#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/kauth.h>
#include <unistd.h>
#include <fuse.h>

extern int pthread_setugid_np(uid_t, gid_t);

#define THREADID_PRE()                                      \
                                                            \
    struct fuse_context *context = fuse_get_context();      \
                                                            \
    uid_t calleruid  = context->uid;                        \
    gid_t callergid  = context->gid;                        \
    uid_t issuser    = !geteuid();                          \
    int   needsettid = (issuser && calleruid);              \
                                                            \
    if (needsettid) {                                       \
        pthread_setugid_np(calleruid, callergid);           \
    }

#define THREADID_POST()                                     \
    if (needsettid) {                                       \
        pthread_setugid_np(KAUTH_UID_NONE, KAUTH_GID_NONE); \
    }

struct threadid {
    struct fuse_fs *next;
};

static struct threadid *
threadid_get(void)
{
    return fuse_get_context()->private_data;
}

/*
 * FUSE API Operations
 * Listed in the same order as in struct fuse_operations in <fuse.h>
 */

static int
threadid_getattr(const char *path, struct stat *buf)
{
    THREADID_PRE()
    int res = fuse_fs_getattr(threadid_get()->next, path, buf);
    THREADID_POST()

    return res;
}

static int
threadid_readlink(const char *path, char *buf, size_t size)
{
    THREADID_PRE()
    int res = fuse_fs_readlink(threadid_get()->next, path, buf, size);
    THREADID_POST()

    return res;
}

static int
threadid_mknod(const char *path, mode_t mode, dev_t rdev)
{
    THREADID_PRE()
    int res = fuse_fs_mknod(threadid_get()->next, path, mode, rdev);
    THREADID_POST()

    return res;
}

static int
threadid_mkdir(const char *path, mode_t mode)
{
    THREADID_PRE()
    int res = fuse_fs_mkdir(threadid_get()->next, path, mode);
    THREADID_POST()

    return res;
}

static int
threadid_unlink(const char *path)
{
    THREADID_PRE()
    int res = fuse_fs_unlink(threadid_get()->next, path);
    THREADID_POST()

    return res;
}

static int
threadid_rmdir(const char *path)
{
    THREADID_PRE()
    int res = fuse_fs_rmdir(threadid_get()->next, path);
    THREADID_POST()

    return res;
}

static int
threadid_symlink(const char *from, const char *path)
{
    THREADID_PRE()
    int res = fuse_fs_symlink(threadid_get()->next, from, path);
    THREADID_POST()

    return res;
}

static int threadid_setvolname(const char *volname)
{
    THREADID_PRE()
    int res = fuse_fs_setvolname(threadid_get()->next, volname);
    THREADID_POST()

    return res;
}

static int threadid_exchange(const char *path1, const char *path2,
                             unsigned long options)
{
    THREADID_PRE()
    int res = fuse_fs_exchange(threadid_get()->next, path1, path2, options);
    THREADID_POST()

    return res;
}

static int threadid_rename(const char *from, const char *to)
{
    THREADID_PRE()
    int res = fuse_fs_rename(threadid_get()->next, from, to);
    THREADID_POST()

    return res;
}

static int
threadid_link(const char *from, const char *to)
{
    THREADID_PRE()
    int res = fuse_fs_link(threadid_get()->next, from, to);
    THREADID_POST()

    return res;
}

static int
threadid_setattr_x(const char *path, struct setattr_x *attr)
{
    THREADID_PRE()
    int res = fuse_fs_setattr_x(threadid_get()->next, path, attr);
    THREADID_POST()

    return res;
}

static int
threadid_fsetattr_x(const char *path, struct setattr_x *attr,
		    struct fuse_file_info *fi)
{
    THREADID_PRE()
    int res = fuse_fs_fsetattr_x(threadid_get()->next, path, attr, fi);
    THREADID_POST()

    return res;
}

static int
threadid_chflags(const char *path, uint32_t flags)
{
    THREADID_PRE()
    int res = fuse_fs_chflags(threadid_get()->next, path, flags);
    THREADID_POST()

    return res;
}

static int
threadid_getxtimes(const char *path, struct timespec *bkuptime,
                   struct timespec *crtime)
{
    THREADID_PRE()
    int res = fuse_fs_getxtimes(threadid_get()->next, path, bkuptime, crtime);
    THREADID_POST()

    return res;
}

static int
threadid_setbkuptime(const char *path, const struct timespec *bkuptime)
{
    THREADID_PRE()
    int res = fuse_fs_setbkuptime(threadid_get()->next, path, bkuptime);
    THREADID_POST()

    return res;
}

static int
threadid_setchgtime(const char *path, const struct timespec *chgtime)
{
    THREADID_PRE()
    int res = fuse_fs_setchgtime(threadid_get()->next, path, chgtime);
    THREADID_POST()

    return res;
}

static int
threadid_setcrtime(const char *path, const struct timespec *crtime)
{
    THREADID_PRE()
    int res = fuse_fs_setcrtime(threadid_get()->next, path, crtime);
    THREADID_POST()

    return res;
}

static int
threadid_chmod(const char *path, mode_t mode)
{
    THREADID_PRE()
    int res = fuse_fs_chmod(threadid_get()->next, path, mode);
    THREADID_POST()

    return res;
}

static int
threadid_chown(const char *path, uid_t uid, gid_t gid)
{
    THREADID_PRE()
    int res = fuse_fs_chown(threadid_get()->next, path, uid, gid);
    THREADID_POST()

    return res;
}

static int
threadid_truncate(const char *path, off_t size)
{
    THREADID_PRE()
    int res = fuse_fs_truncate(threadid_get()->next, path, size);
    THREADID_POST()

    return res;
}

static int
threadid_open(const char *path, struct fuse_file_info *fi)
{
    THREADID_PRE()
    int res = fuse_fs_open(threadid_get()->next, path, fi);
    THREADID_POST()

    return res;
}

static int
threadid_read(const char *path, char *buf, size_t size, off_t off,
             struct fuse_file_info *fi)
{
    THREADID_PRE()
    int res = fuse_fs_read(threadid_get()->next, path, buf, size, off, fi);
    THREADID_POST()

    return res;
}

static int
threadid_write(const char *path, const char *buf, size_t size, off_t off,
              struct fuse_file_info *fi)
{
    THREADID_PRE()
    int res = fuse_fs_write(threadid_get()->next, path, buf, size, off, fi);
    THREADID_POST()

    return res;
}

static int
threadid_statfs(const char *path, struct statvfs *stbuf)
{
    THREADID_PRE()
    int res = fuse_fs_statfs(threadid_get()->next, path, stbuf);
    THREADID_POST()

    return res;
}

static int
threadid_flush(const char *path, struct fuse_file_info *fi)
{
    THREADID_PRE()
    int res = fuse_fs_flush(threadid_get()->next, path, fi);
    THREADID_POST()

    return res;
}

static int
threadid_release(const char *path, struct fuse_file_info *fi)
{
    THREADID_PRE()
    int res = fuse_fs_release(threadid_get()->next, path, fi);
    THREADID_POST()

    return res;
}

static int
threadid_fsync(const char *path, int isdatasync,
                        struct fuse_file_info *fi)
{
    THREADID_PRE()
    int res = fuse_fs_fsync(threadid_get()->next, path, isdatasync, fi);
    THREADID_POST()

    return res;
}

static int
threadid_setxattr(const char *path, const char *name, const char *value,
                 size_t size, int flags, uint32_t position)
{
    THREADID_PRE()
    int res = fuse_fs_setxattr(threadid_get()->next, path, name, value, size,
                               flags, position);
    THREADID_POST()

    return res;
}

static int
threadid_getxattr(const char *path, const char *name, char *value, size_t size,
                  uint32_t position)
{
    THREADID_PRE()
    int res = fuse_fs_getxattr(threadid_get()->next, path, name, value, size,
                               position);
    THREADID_POST()

    return res;
}

static int
threadid_listxattr(const char *path, char *list, size_t size)
{
    THREADID_PRE()
    int res = fuse_fs_listxattr(threadid_get()->next, path, list, size);
    THREADID_POST()

    return res;
}

static int
threadid_removexattr(const char *path, const char *name)
{
    THREADID_PRE()
    int res = fuse_fs_removexattr(threadid_get()->next, path, name);
    THREADID_POST()

    return res;
}

static int
threadid_opendir(const char *path, struct fuse_file_info *fi)
{
    THREADID_PRE()
    int res = fuse_fs_opendir(threadid_get()->next, path, fi);
    THREADID_POST()

    return res;
}

static int
threadid_readdir(const char *path, void *buf, fuse_fill_dir_t filler,
                off_t offset, struct fuse_file_info *fi)
{
    THREADID_PRE()
    int res = fuse_fs_readdir(threadid_get()->next, path, buf, filler,
                              offset, fi);
    THREADID_POST()

    return res;
}

static int
threadid_releasedir(const char *path, struct fuse_file_info *fi)
{
    THREADID_PRE()
    int res = fuse_fs_releasedir(threadid_get()->next, path, fi);
    THREADID_POST()

    return res;
}

static int
threadid_fsyncdir(const char *path, int isdatasync, struct fuse_file_info *fi)
{
    THREADID_PRE()
    int res = fuse_fs_fsyncdir(threadid_get()->next, path, isdatasync, fi);
    THREADID_POST()

    return res;
}

static void *
threadid_init(struct fuse_conn_info *conn)
{
    struct threadid *d = threadid_get();

    fuse_fs_init(d->next, conn);

    return d;
}

static void
threadid_destroy(void *data)
{
    struct threadid *d = data;

    fuse_fs_destroy(d->next);

    free(d);

    return;
}

static int
threadid_access(const char *path, int mask)
{
    THREADID_PRE()
    int res = fuse_fs_access(threadid_get()->next, path, mask);
    THREADID_POST()

    return res;
}

static int
threadid_create(const char *path, mode_t mode, struct fuse_file_info *fi)
{
    THREADID_PRE()
    int res = fuse_fs_create(threadid_get()->next, path, mode, fi);
    THREADID_POST()

    return res;
}

static int
threadid_ftruncate(const char *path, off_t size, struct fuse_file_info *fi)
{
    THREADID_PRE()
    int res = fuse_fs_ftruncate(threadid_get()->next, path, size, fi);
    THREADID_POST()

    return res;
}

static int
threadid_fgetattr(const char *path, struct stat *buf, struct fuse_file_info *fi)
{
    THREADID_PRE()
    int res = fuse_fs_fgetattr(threadid_get()->next, path, buf, fi);
    THREADID_POST()

    return res;
}

static int
threadid_lock(const char *path, struct fuse_file_info *fi, int cmd,
             struct flock *lock)
{
    THREADID_PRE()
    int res = fuse_fs_lock(threadid_get()->next, path, fi, cmd, lock);
    THREADID_POST()

    return res;
}

static int
threadid_utimens(const char *path, const struct timespec ts[2])
{
    THREADID_PRE()
    int res = fuse_fs_utimens(threadid_get()->next, path, ts);
    THREADID_POST()

    return res;
}

static int
threadid_bmap(const char *path, size_t blocksize, uint64_t *idx)
{
    THREADID_PRE()
    int res = fuse_fs_bmap(threadid_get()->next, path, blocksize, idx);
    THREADID_POST()

    return res;
}

/*
 * Listed in the same order as in struct fuse_operations in <fuse.h>
 */
static struct fuse_operations threadid_oper = {
    .getattr     = threadid_getattr,
    .readlink    = threadid_readlink,
    .mknod       = threadid_mknod,
    .mkdir       = threadid_mkdir,
    .unlink      = threadid_unlink,
    .rmdir       = threadid_rmdir,
    .symlink     = threadid_symlink,
    .rename      = threadid_rename,
    .link        = threadid_link,
    .chmod       = threadid_chmod,
    .chown       = threadid_chown,
    .truncate    = threadid_truncate,
    .open        = threadid_open,
    .read        = threadid_read,
    .write       = threadid_write,
    .statfs      = threadid_statfs,
    .flush       = threadid_flush,
    .release     = threadid_release,
    .fsync       = threadid_fsync,
    .setxattr    = threadid_setxattr,
    .getxattr    = threadid_getxattr,
    .listxattr   = threadid_listxattr,
    .removexattr = threadid_removexattr,
    .opendir     = threadid_opendir,
    .readdir     = threadid_readdir,
    .releasedir  = threadid_releasedir,
    .fsyncdir    = threadid_fsyncdir,
    .init        = threadid_init,
    .destroy     = threadid_destroy,
    .access      = threadid_access,
    .create      = threadid_create,
    .ftruncate   = threadid_ftruncate,
    .fgetattr    = threadid_fgetattr,
    .lock        = threadid_lock,
    .utimens     = threadid_utimens,
    .bmap        = threadid_bmap,
    .setvolname  = threadid_setvolname,
    .exchange    = threadid_exchange,
    .getxtimes   = threadid_getxtimes,
    .setbkuptime = threadid_setbkuptime,
    .setchgtime  = threadid_setchgtime,
    .setcrtime   = threadid_setcrtime,
    .chflags     = threadid_chflags,
    .setattr_x   = threadid_setattr_x,
    .fsetattr_x  = threadid_fsetattr_x,
};

static struct fuse_opt threadid_opts[] = {
    FUSE_OPT_KEY("-h", 0),
    FUSE_OPT_KEY("--help", 0),
    FUSE_OPT_END
};

static void
threadid_help(void)
{
}

static int
threadid_opt_proc(void *data, const char *arg, int key,
                  struct fuse_args *outargs)
{                
    (void)data;
    (void)arg;
    (void)outargs;

    if (!key) {
        threadid_help();
        return -1;
    }

    return 1;
}

static struct fuse_fs *
threadid_new(struct fuse_args *args, struct fuse_fs *next[])
{
    int ret;
    struct fuse_fs *fs;
    struct threadid *d;

    d = calloc(1, sizeof(*d));
    if (d == NULL) {
        fprintf(stderr, "threadid: memory allocation failed\n");
        return NULL;
    }

    if (fuse_opt_parse(args, d, threadid_opts, threadid_opt_proc) == -1) {
        goto out_free;
    }

    if (!next[0] || next[1]) {
        fprintf(stderr, "threadid: exactly one next filesystem required\n");
        goto out_free;
    }

    d->next = next[0];

    fs = fuse_fs_new(&threadid_oper, sizeof(threadid_oper), d);
    if (!fs) {
        goto out_free;
    }

    return fs;

 out_free:

    free(d);

    return NULL;
}

FUSE_REGISTER_MODULE(threadid, threadid_new);
