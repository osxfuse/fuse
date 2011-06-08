/*
 *  Custom volume icon support for MacFUSE.
 *
 *  - xattr'ification and overhaul by Amit Singh <singh@>
 *  - Made into a libfuse stack module by Andrew de los Reyes <adlr@google>
 *  - Original "volicon" code by Amit Singh <singh@>
 *
 *  This program can be distributed under the terms of the GNU LGPL.
 *  See the file COPYING.LIB for details.
 */

#define FUSE_USE_VERSION 26

#undef _POSIX_C_SOURCE
#include <sys/types.h>
#define _POSIX_C_SOURCE 200112L
#include <sys/attr.h>
#include <sys/xattr.h>
#include <sys/vnode.h>
#include <fuse.h>
#include <libgen.h>
#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <arpa/inet.h>

#define VOLICON_ROOT_MAGIC_PATH    "/"
#define VOLICON_ICON_MAGIC_PATH    "/.VolumeIcon.icns"
#define VOLICON_ICON_MAXSIZE       (1024 * 1024)

struct FndrGenericInfo {
    u_int32_t   ignored0;
    u_int32_t   ignored1;
    u_int16_t   flags;
    struct {
        int16_t ignored2;
        int16_t ignored3;
    } fdLocation;
    int16_t     ignored4;
} __attribute__((aligned(2), packed));
typedef struct FndrGenericInfo FndrGenericInfo;

#define kHasCustomIcon 0x0400

static const char finder_info[32] = {
    0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
    0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
    0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
    0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
};
#define XATTR_FINDERINFO_SIZE 32

#define ERROR_IF_MAGIC_FILE(path, e)     \
    if (volicon_is_a_magic_file(path)) { \
        return -e;                       \
    }

struct volicon {
    char *volicon;
    char *volicon_data;
    off_t volicon_size;
    uid_t volicon_uid;

    struct fuse_fs *next;
};

static struct volicon *
volicon_get(void)
{
    return fuse_get_context()->private_data;
}

static __inline__ int
volicon_is_icon_magic_file(const char *path)
{
    return (!strcmp(path, VOLICON_ICON_MAGIC_PATH));
}

static __inline__ int
volicon_is_a_magic_file(const char *path)
{
    return (volicon_is_icon_magic_file(path));
}

/*
 * FUSE API Operations
 * Listed in the same order as in struct fuse_operations in <fuse.h>
 */

static int
volicon_getattr(const char *path, struct stat *buf)
{
    int res = 0;

    if (volicon_is_icon_magic_file(path)) {

        memset((void *)buf, 0, sizeof(struct stat));

        buf->st_mode  = S_IFREG | 0444;
        buf->st_nlink = 1;
        buf->st_uid   = volicon_get()->volicon_uid;
        buf->st_gid = 0;
        buf->st_size  = volicon_get()->volicon_size;
        buf->st_atime = buf->st_ctime = buf->st_mtime = time(NULL);

    } else {
        res = fuse_fs_getattr(volicon_get()->next, path, buf);
    }

    return res;
}

static int
volicon_readlink(const char *path, char *buf, size_t size)
{
    ERROR_IF_MAGIC_FILE(path, EINVAL);

    return fuse_fs_readlink(volicon_get()->next, path, buf, size);
}

static int
volicon_mknod(const char *path, mode_t mode, dev_t rdev)
{
    ERROR_IF_MAGIC_FILE(path, EEXIST);

    return fuse_fs_mknod(volicon_get()->next, path, mode, rdev);
}

static int
volicon_mkdir(const char *path, mode_t mode)
{
    ERROR_IF_MAGIC_FILE(path, EEXIST);

    return fuse_fs_mkdir(volicon_get()->next, path, mode);
}

static int
volicon_unlink(const char *path)
{
    ERROR_IF_MAGIC_FILE(path, EACCES);

    return fuse_fs_unlink(volicon_get()->next, path);
}

static int
volicon_rmdir(const char *path)
{
    ERROR_IF_MAGIC_FILE(path, ENOTDIR);

    return fuse_fs_rmdir(volicon_get()->next, path);
}

static int
volicon_symlink(const char *from, const char *path)
{
    ERROR_IF_MAGIC_FILE(path, EEXIST);

    return fuse_fs_symlink(volicon_get()->next, from, path);
}

static int volicon_setvolname(const char *volname)
{
    return fuse_fs_setvolname(volicon_get()->next, volname);
}

static int volicon_exchange(const char *path1, const char *path2,
                            unsigned long options)
{
    ERROR_IF_MAGIC_FILE(path1, EACCES);
    ERROR_IF_MAGIC_FILE(path2, EACCES);

    return fuse_fs_exchange(volicon_get()->next, path1, path2, options);
}

static int volicon_rename(const char *from, const char *to)
{
    ERROR_IF_MAGIC_FILE(from, EACCES);
    ERROR_IF_MAGIC_FILE(to, EACCES);

    return fuse_fs_rename(volicon_get()->next, from, to);
}

static int
volicon_link(const char *from, const char *to)
{
    ERROR_IF_MAGIC_FILE(from, EACCES);
    ERROR_IF_MAGIC_FILE(to, EACCES);

    return fuse_fs_link(volicon_get()->next, from, to);
}

static int
volicon_setattr_x(const char *path, struct setattr_x *attr)
{
    ERROR_IF_MAGIC_FILE(path, EACCES);

    return fuse_fs_setattr_x(volicon_get()->next, path, attr);
}

static int
volicon_fsetattr_x(const char *path, struct setattr_x *attr,
		   struct fuse_file_info *fi)
{
    ERROR_IF_MAGIC_FILE(path, EACCES);

    return fuse_fs_fsetattr_x(volicon_get()->next, path, attr, fi);
}

static int
volicon_chflags(const char *path, uint32_t flags)
{
    ERROR_IF_MAGIC_FILE(path, EACCES);

    return fuse_fs_chflags(volicon_get()->next, path, flags);
}

static int
volicon_getxtimes(const char *path, struct timespec *bkuptime,
                  struct timespec *crtime)
{
    if (volicon_is_a_magic_file(path)) {
        bkuptime->tv_sec = 0;
        bkuptime->tv_nsec = 0;
        crtime->tv_sec = 0;
        crtime->tv_nsec = 0;
        return 0;
    }

    return fuse_fs_getxtimes(volicon_get()->next, path, bkuptime, crtime);
}

static int
volicon_setbkuptime(const char *path, const struct timespec *bkuptime)
{
    ERROR_IF_MAGIC_FILE(path, EPERM);

    return fuse_fs_setbkuptime(volicon_get()->next, path, bkuptime);
}

static int
volicon_setchgtime(const char *path, const struct timespec *chgtime)
{
    ERROR_IF_MAGIC_FILE(path, EPERM);

    return fuse_fs_setchgtime(volicon_get()->next, path, chgtime);
}

static int
volicon_setcrtime(const char *path, const struct timespec *crtime)
{
    ERROR_IF_MAGIC_FILE(path, EPERM);

    return fuse_fs_setcrtime(volicon_get()->next, path, crtime);
}

static int
volicon_chmod(const char *path, mode_t mode)
{
    ERROR_IF_MAGIC_FILE(path, EACCES);

    return fuse_fs_chmod(volicon_get()->next, path, mode);
}

static int
volicon_chown(const char *path, uid_t uid, gid_t gid)
{
    ERROR_IF_MAGIC_FILE(path, EACCES);

    return fuse_fs_chown(volicon_get()->next, path, uid, gid);
}

static int
volicon_truncate(const char *path, off_t size)
{
    ERROR_IF_MAGIC_FILE(path, EACCES);

    return fuse_fs_truncate(volicon_get()->next, path, size);
}

static int
volicon_open(const char *path, struct fuse_file_info *fi)
{
    if (volicon_is_a_magic_file(path)) {
        if (fi && ((fi->flags & O_ACCMODE) != O_RDONLY)) {
            return -EACCES;
        }

        return 0;
    }

    return fuse_fs_open(volicon_get()->next, path, fi);
}

static int
volicon_read(const char *path, char *buf, size_t size, off_t off,
             struct fuse_file_info *fi)
{
    int res = 0;

    if (volicon_is_icon_magic_file(path)) {
        size_t a_size = size;
        if (off < volicon_get()->volicon_size) {
            if ((off + size) > volicon_get()->volicon_size) {
                a_size = volicon_get()->volicon_size - off;
            }
            memcpy(buf, (char *)(volicon_get()->volicon_data) + off, a_size);
            res = a_size;
        }
    } else {
        res = fuse_fs_read(volicon_get()->next, path, buf, size, off, fi);
    }

    return res;
}

static int
volicon_write(const char *path, const char *buf, size_t size, off_t off,
              struct fuse_file_info *fi)
{
    ERROR_IF_MAGIC_FILE(path, EACCES);

    return fuse_fs_write(volicon_get()->next, path, buf, size, off, fi);
}

static int
volicon_statfs(const char *path, struct statvfs *stbuf)
{
    if (volicon_is_a_magic_file(path)) {
        return fuse_fs_statfs(volicon_get()->next, "/", stbuf);
    }

    return fuse_fs_statfs(volicon_get()->next, path, stbuf);
}

static int
volicon_flush(const char *path, struct fuse_file_info *fi)
{
    ERROR_IF_MAGIC_FILE(path, 0);

    return fuse_fs_flush(volicon_get()->next, path, fi);
}

static int
volicon_release(const char *path, struct fuse_file_info *fi)
{
    ERROR_IF_MAGIC_FILE(path, 0);

    return fuse_fs_release(volicon_get()->next, path, fi);
}

static int
volicon_fsync(const char *path, int isdatasync,
                        struct fuse_file_info *fi)
{
    ERROR_IF_MAGIC_FILE(path, 0);

    return fuse_fs_fsync(volicon_get()->next, path, isdatasync, fi);
}

static int
volicon_setxattr(const char *path, const char *name, const char *value,
                 size_t size, int flags, uint32_t position)
{
    ERROR_IF_MAGIC_FILE(path, EPERM);

    if ((strcmp(path, VOLICON_ROOT_MAGIC_PATH) == 0) &&
        (strcmp(name, XATTR_FINDERINFO_NAME) == 0)) {
        if ((size >= 8) && (size <= XATTR_FINDERINFO_SIZE)) {
            char finder_info[XATTR_FINDERINFO_SIZE];
            memcpy(finder_info, value, size);
            ((struct FndrGenericInfo *)&finder_info)->flags |= ntohs(0x0400);
            //finder_info[8] |= 0x100;
            return fuse_fs_setxattr(volicon_get()->next, path, name,
                                    finder_info, size, flags, position);
        }
    }

    return fuse_fs_setxattr(volicon_get()->next, path, name, value, size,
                            flags, position);
}

static int
volicon_getxattr(const char *path, const char *name, char *value, size_t size,
                 uint32_t position)
{
    ERROR_IF_MAGIC_FILE(path, EPERM);

    ssize_t res = 0;

    if ((strcmp(path, VOLICON_ROOT_MAGIC_PATH) == 0) &&
        (strcmp(name, XATTR_FINDERINFO_NAME) == 0)) {

        if (!size || !value) {
            return XATTR_FINDERINFO_SIZE;
        }

        if (size < XATTR_FINDERINFO_SIZE) {
            return -ERANGE;
        }

        res = fuse_fs_getxattr(volicon_get()->next, path, name, value, size,
                               position);

        if (res != XATTR_FINDERINFO_SIZE) {
            memcpy(value, finder_info, XATTR_FINDERINFO_SIZE);
        }

        ((struct FndrGenericInfo *)value)->flags |= ntohs(0x0400);

        return XATTR_FINDERINFO_SIZE;
    }

    res = fuse_fs_getxattr(volicon_get()->next, path, name, value, size,
                           position);

    if (res == -ENOSYS) {
        res = -ENOTSUP;
    }

    return res;
}

static int
volicon_listxattr(const char *path, char *list, size_t size)
{
    ERROR_IF_MAGIC_FILE(path, EPERM);

    ssize_t res = fuse_fs_listxattr(volicon_get()->next, path, list, size);

    if ((strcmp(path, VOLICON_ROOT_MAGIC_PATH) == 0)) {
        int done = 0;
        ssize_t sz = sizeof(XATTR_FINDERINFO_NAME);

        if (res == -ENOSYS) {
            res = 0;
        }

        if (!list) { /* size being queried */
            if (res > 0) {
                sz += res;
            }
            return sz;
        }

        /* list is good */

        if (res == -ERANGE) {
            return -ERANGE;
        }

        if (res > 0) {
            size_t len = 0;
            char *curr = list;
            do {
                size_t thislen = strlen(curr) + 1;
                if (strcmp(curr, XATTR_FINDERINFO_NAME) == 0) {
                    done = 1;
                    break;
                }
                curr += thislen;
                len += thislen;
            } while (len < res);
        }

        if (done) {
            return res;
        }

        if (size < (res + sizeof(XATTR_FINDERINFO_NAME))) {
            return -ERANGE;
        }

        memcpy((char *)list + res, XATTR_FINDERINFO_NAME,
               sizeof(XATTR_FINDERINFO_NAME));

        return (res + sizeof(XATTR_FINDERINFO_NAME));
    }

    if (res == -ENOSYS) {
        res = -ENOTSUP;
    }

    return res;
}

static int
volicon_removexattr(const char *path, const char *name)
{
    ERROR_IF_MAGIC_FILE(path, EPERM);

    if ((strcmp(path, VOLICON_ROOT_MAGIC_PATH) == 0) &&
        (strcmp(name, XATTR_FINDERINFO_NAME) == 0)) {
        return -EACCES;
    }

    return fuse_fs_removexattr(volicon_get()->next, path, name);
}

static int
volicon_opendir(const char *path, struct fuse_file_info *fi)
{
    ERROR_IF_MAGIC_FILE(path, ENOTDIR);

    return fuse_fs_opendir(volicon_get()->next, path, fi);
}

static int
volicon_readdir(const char *path, void *buf, fuse_fill_dir_t filler,
                off_t offset, struct fuse_file_info *fi)
{
    ERROR_IF_MAGIC_FILE(path, ENOTDIR);

    return fuse_fs_readdir(volicon_get()->next, path, buf, filler, offset, fi);
}

static int
volicon_releasedir(const char *path, struct fuse_file_info *fi)
{
    ERROR_IF_MAGIC_FILE(path, ENOTDIR);

    return fuse_fs_releasedir(volicon_get()->next, path, fi);
}

static int
volicon_fsyncdir(const char *path, int isdatasync, struct fuse_file_info *fi)
{
    ERROR_IF_MAGIC_FILE(path, ENOTDIR);

    return fuse_fs_fsyncdir(volicon_get()->next, path, isdatasync, fi);
}

static void *
volicon_init(struct fuse_conn_info *conn)
{
    struct volicon *d = volicon_get();

    fuse_fs_init(d->next, conn);

    return d;
}

static void
volicon_destroy(void *data)
{
    struct volicon *d = data;

    fuse_fs_destroy(d->next);

    free(d->volicon);
    free(d->volicon_data);
    free(d);

    return;
}

static int
volicon_access(const char *path, int mask)
{
    if (volicon_is_a_magic_file(path)) {
        if ((mask & W_OK) || (mask & X_OK)) {
            return -EACCES;
        }

        return 0;
    }

    return fuse_fs_access(volicon_get()->next, path, mask);
}

static int
volicon_create(const char *path, mode_t mode, struct fuse_file_info *fi)
{
    ERROR_IF_MAGIC_FILE(path, EEXIST);

    return fuse_fs_create(volicon_get()->next, path, mode, fi);
}

static int
volicon_ftruncate(const char *path, off_t size, struct fuse_file_info *fi)
{
    ERROR_IF_MAGIC_FILE(path, EACCES);

    return fuse_fs_ftruncate(volicon_get()->next, path, size, fi);
}

static int
volicon_fgetattr(const char *path, struct stat *buf, struct fuse_file_info *fi)
{
    int res = 0;

    if (volicon_is_icon_magic_file(path)) {

        memset((void *)buf, 0, sizeof(struct stat));

        buf->st_mode  = S_IFREG | 0444;
        buf->st_nlink = 1;
        buf->st_uid   = volicon_get()->volicon_uid;
        buf->st_gid = 0;
        buf->st_size  = volicon_get()->volicon_size;
        buf->st_atime = buf->st_ctime = buf->st_mtime = time(NULL);

    } else {
        res = fuse_fs_fgetattr(volicon_get()->next, path, buf, fi);
    }

    return res;
}

static int
volicon_lock(const char *path, struct fuse_file_info *fi, int cmd,
             struct flock *lock)
{
    ERROR_IF_MAGIC_FILE(path, ENOTSUP);

    return fuse_fs_lock(volicon_get()->next, path, fi, cmd, lock);
}

static int
volicon_utimens(const char *path, const struct timespec ts[2])
{
    ERROR_IF_MAGIC_FILE(path, EACCES);

    return fuse_fs_utimens(volicon_get()->next, path, ts);
}

static int
volicon_bmap(const char *path, size_t blocksize, uint64_t *idx)
{
    ERROR_IF_MAGIC_FILE(path, ENOTSUP);

    return fuse_fs_bmap(volicon_get()->next, path, blocksize, idx);
}

/*
 * Listed in the same order as in struct fuse_operations in <fuse.h>
 */
static struct fuse_operations volicon_oper = {
    .getattr     = volicon_getattr,
    .readlink    = volicon_readlink,
    .mknod       = volicon_mknod,
    .mkdir       = volicon_mkdir,
    .unlink      = volicon_unlink,
    .rmdir       = volicon_rmdir,
    .symlink     = volicon_symlink,
    .rename      = volicon_rename,
    .link        = volicon_link,
    .chmod       = volicon_chmod,
    .chown       = volicon_chown,
    .truncate    = volicon_truncate,
    .open        = volicon_open,
    .read        = volicon_read,
    .write       = volicon_write,
    .statfs      = volicon_statfs,
    .flush       = volicon_flush,
    .release     = volicon_release,
    .fsync       = volicon_fsync,
    .setxattr    = volicon_setxattr,
    .getxattr    = volicon_getxattr,
    .listxattr   = volicon_listxattr,
    .removexattr = volicon_removexattr,
    .opendir     = volicon_opendir,
    .readdir     = volicon_readdir,
    .releasedir  = volicon_releasedir,
    .fsyncdir    = volicon_fsyncdir,
    .init        = volicon_init,
    .destroy     = volicon_destroy,
    .access      = volicon_access,
    .create      = volicon_create,
    .ftruncate   = volicon_ftruncate,
    .fgetattr    = volicon_fgetattr,
    .lock        = volicon_lock,
    .utimens     = volicon_utimens,
    .bmap        = volicon_bmap,
    .setvolname  = volicon_setvolname,
    .exchange    = volicon_exchange,
    .getxtimes   = volicon_getxtimes,
    .setbkuptime = volicon_setbkuptime,
    .setchgtime  = volicon_setchgtime,
    .setcrtime   = volicon_setcrtime,
    .chflags     = volicon_chflags,
    .setattr_x   = volicon_setattr_x,
    .fsetattr_x  = volicon_fsetattr_x,
};

static struct fuse_opt volicon_opts[] = {
    FUSE_OPT_KEY("-h", 0),
    FUSE_OPT_KEY("--help", 0),
    { "iconpath=%s", offsetof(struct volicon, volicon), 0 },
    FUSE_OPT_END
};

static void
volicon_help(void)
{
    fprintf(stderr,
            "    -o iconpath=<icon path> display volume with custom icon\n");
}

static int
volicon_opt_proc(void *data, const char *arg, int key,
                 struct fuse_args *outargs)
{
    (void)data;
    (void)arg;
    (void)outargs;

    if (!key) {
        volicon_help();
        return -1;
    }

    return 1;
}

static struct fuse_fs *
volicon_new(struct fuse_args *args, struct fuse_fs *next[])
{
    int ret;
    int voliconfd = -1;
    struct stat sb;
    struct fuse_fs *fs;
    struct volicon *d;

    d = calloc(1, sizeof(*d));
    if (d == NULL) {
        fprintf(stderr, "volicon: memory allocation failed\n");
        return NULL;
    }

    if (fuse_opt_parse(args, d, volicon_opts, volicon_opt_proc) == -1) {
        goto out_free;
    }

    if (!next[0] || next[1]) {
        fprintf(stderr, "volicon: exactly one next filesystem required\n");
        goto out_free;
    }

    if (!d->volicon) {
        fprintf(stderr, "volicon: missing 'iconpath' option\n");
        goto out_free;
    }

    voliconfd = open(d->volicon, O_RDONLY);
    if (voliconfd < 0) {
        fprintf(stderr, "volicon: failed to access volume icon file (%d)\n",
                errno);
        goto out_free;
    }

    ret = fstat(voliconfd, &sb);
    if (ret) {
        fprintf(stderr, "volicon: failed to stat volume icon file (%d)\n",
                errno);
        goto out_free;
    }

    if (sb.st_size > (VOLICON_ICON_MAXSIZE)) {
        fprintf(stderr, "volicon: size limit exceeded for volume icon file\n");
        goto out_free;
    }

    d->volicon_data = malloc(sb.st_size);
    if (!d->volicon_data) {
        fprintf(stderr,
                "volicon: failed to allocate memory for volume icon data\n");
        goto out_free;
    }

    ret = read(voliconfd, d->volicon_data, sb.st_size);
    if (ret != sb.st_size) {
        fprintf(stderr, "volicon: failed to read data from volume icon file\n");
        goto out_free;
    }

    close(voliconfd);
    voliconfd = -1;

    d->volicon_size = sb.st_size;
    d->volicon_uid = getuid();

    d->next = next[0];

    fs = fuse_fs_new(&volicon_oper, sizeof(volicon_oper), d);
    if (!fs) {
        goto out_free;
    }

    return fs;

 out_free:

    if (d->volicon_data) {
        free(d->volicon_data);
    }
 
    if (voliconfd >= 0) {
        close(voliconfd);
    }

    if (d->volicon) {
        free(d->volicon);
    }

    free(d);

    return NULL;
}

FUSE_REGISTER_MODULE(volicon, volicon_new);
