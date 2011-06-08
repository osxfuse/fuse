/*
  FUSE: Filesystem in Userspace
  Copyright (C) 2001-2007  Miklos Szeredi <miklos@szeredi.hu>

  This program can be distributed under the terms of the GNU GPL.
  See the file COPYING.

  gcc -Wall `pkg-config fuse --cflags --libs` -lulockmgr fusexmp_fh.c -o fusexmp_fh
*/

#define FUSE_USE_VERSION 26

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#define _GNU_SOURCE

#include <fuse.h>
#if !(__FreeBSD__ >= 10)
#include <ulockmgr.h>
#endif /* __FreeBSD__ >= 10 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <dirent.h>
#include <errno.h>
#include <sys/time.h>
#ifdef HAVE_SETXATTR
#include <sys/xattr.h>
#endif

#include <sys/param.h>

#if (__FreeBSD__ >= 10)

#if defined(_POSIX_C_SOURCE)
typedef unsigned char  u_char;
typedef unsigned short u_short;
typedef unsigned int   u_int;
typedef unsigned long  u_long;
#endif

#include <sys/attr.h>

#define G_PREFIX			"org"
#define G_KAUTH_FILESEC_XATTR G_PREFIX 	".apple.system.Security"
#define A_PREFIX			"com"
#define A_KAUTH_FILESEC_XATTR A_PREFIX 	".apple.system.Security"
#define XATTR_APPLE_PREFIX		"com.apple."
#endif

static int xmp_getattr(const char *path, struct stat *stbuf)
{
	int res;

	res = lstat(path, stbuf);
	if (res == -1)
		return -errno;

	return 0;
}

static int xmp_fgetattr(const char *path, struct stat *stbuf,
			struct fuse_file_info *fi)
{
	int res;

	(void) path;

	res = fstat(fi->fh, stbuf);
	if (res == -1)
		return -errno;

	return 0;
}

static int xmp_access(const char *path, int mask)
{
	int res;

	res = access(path, mask);
	if (res == -1)
		return -errno;

	return 0;
}

static int xmp_readlink(const char *path, char *buf, size_t size)
{
	int res;

	res = readlink(path, buf, size - 1);
	if (res == -1)
		return -errno;

	buf[res] = '\0';
	return 0;
}

struct xmp_dirp {
	DIR *dp;
	struct dirent *entry;
	off_t offset;
};

static int xmp_opendir(const char *path, struct fuse_file_info *fi)
{
	int res;
	struct xmp_dirp *d = malloc(sizeof(struct xmp_dirp));
	if (d == NULL)
		return -ENOMEM;

	d->dp = opendir(path);
	if (d->dp == NULL) {
		res = -errno;
		free(d);
		return res;
	}
	d->offset = 0;
	d->entry = NULL;

	fi->fh = (unsigned long) d;
	return 0;
}

static inline struct xmp_dirp *get_dirp(struct fuse_file_info *fi)
{
	return (struct xmp_dirp *) (uintptr_t) fi->fh;
}

static int xmp_readdir(const char *path, void *buf, fuse_fill_dir_t filler,
		       off_t offset, struct fuse_file_info *fi)
{
	struct xmp_dirp *d = get_dirp(fi);

	(void) path;
	if (offset != d->offset) {
		seekdir(d->dp, offset);
		d->entry = NULL;
		d->offset = offset;
	}
	while (1) {
		struct stat st;
		off_t nextoff;

		if (!d->entry) {
			d->entry = readdir(d->dp);
			if (!d->entry)
				break;
		}

		memset(&st, 0, sizeof(st));
		st.st_ino = d->entry->d_ino;
		st.st_mode = d->entry->d_type << 12;
		nextoff = telldir(d->dp);
		if (filler(buf, d->entry->d_name, &st, nextoff))
			break;

		d->entry = NULL;
		d->offset = nextoff;
	}

	return 0;
}

static int xmp_releasedir(const char *path, struct fuse_file_info *fi)
{
	struct xmp_dirp *d = get_dirp(fi);
	(void) path;
	closedir(d->dp);
	free(d);
	return 0;
}

static int xmp_mknod(const char *path, mode_t mode, dev_t rdev)
{
	int res;

	if (S_ISFIFO(mode))
		res = mkfifo(path, mode);
	else
		res = mknod(path, mode, rdev);
	if (res == -1)
		return -errno;

	return 0;
}

static int xmp_mkdir(const char *path, mode_t mode)
{
	int res;

	res = mkdir(path, mode);
	if (res == -1)
		return -errno;

	return 0;
}

static int xmp_unlink(const char *path)
{
	int res;

	res = unlink(path);
	if (res == -1)
		return -errno;

	return 0;
}

static int xmp_rmdir(const char *path)
{
	int res;

	res = rmdir(path);
	if (res == -1)
		return -errno;

	return 0;
}

static int xmp_symlink(const char *from, const char *to)
{
	int res;

	res = symlink(from, to);
	if (res == -1)
		return -errno;

	return 0;
}

static int xmp_rename(const char *from, const char *to)
{
	int res;

	res = rename(from, to);
	if (res == -1)
		return -errno;

	return 0;
}

#if (__FreeBSD__ >= 10)

static int xmp_setvolname(const char *volname)
{
    (void)volname;
    return 0;
}

static int xmp_exchange(const char *path1, const char *path2,
			unsigned long options)
{
	int res;

	res = exchangedata(path1, path2, options);
	if (res == -1)
		return -errno;

	return 0;
}

#endif /* __FreeBSD__ >= 10 */

static int xmp_link(const char *from, const char *to)
{
	int res;

	res = link(from, to);
	if (res == -1)
		return -errno;

	return 0;
}

#if (__FreeBSD__ >= 10)

static int xmp_fsetattr_x(const char *path, struct setattr_x *attr,
			  struct fuse_file_info *fi)
{
	int res;
	uid_t uid = -1;
	gid_t gid = -1;

	if (SETATTR_WANTS_MODE(attr)) {
		res = lchmod(path, attr->mode);
		if (res == -1)
			return -errno;
	}

	if (SETATTR_WANTS_UID(attr))
		uid = attr->uid;

	if (SETATTR_WANTS_GID(attr))
		gid = attr->gid;

	if ((uid != -1) || (gid != -1)) {
		res = lchown(path, uid, gid);
		if (res == -1)
			return -errno;
	}

	if (SETATTR_WANTS_SIZE(attr)) {
		if (fi)
			res = ftruncate(fi->fh, attr->size);
		else
			res = truncate(path, attr->size);
		if (res == -1)
			return -errno;
	}

	if (SETATTR_WANTS_MODTIME(attr)) {
		struct timeval tv[2];
		if (!SETATTR_WANTS_ACCTIME(attr))
			gettimeofday(&tv[0], NULL);
		else {
			tv[0].tv_sec = attr->acctime.tv_sec;
			tv[0].tv_usec = attr->acctime.tv_nsec / 1000;
		}
		tv[1].tv_sec = attr->modtime.tv_sec;
		tv[1].tv_usec = attr->modtime.tv_nsec / 1000;
		res = utimes(path, tv);
		if (res == -1)
			return -errno;
	}

	if (SETATTR_WANTS_CRTIME(attr)) {
		struct attrlist attributes;

		attributes.bitmapcount = ATTR_BIT_MAP_COUNT;
		attributes.reserved = 0;
		attributes.commonattr = ATTR_CMN_CRTIME;
		attributes.dirattr = 0;
		attributes.fileattr = 0;
		attributes.forkattr = 0;
		attributes.volattr = 0;

		res = setattrlist(path, &attributes, &attr->crtime,
				  sizeof(struct timespec), FSOPT_NOFOLLOW);

		if (res == -1)
			return -errno;
	}

	if (SETATTR_WANTS_CHGTIME(attr)) {
		struct attrlist attributes;

		attributes.bitmapcount = ATTR_BIT_MAP_COUNT;
		attributes.reserved = 0;
		attributes.commonattr = ATTR_CMN_CHGTIME;
		attributes.dirattr = 0;
		attributes.fileattr = 0;
		attributes.forkattr = 0;
		attributes.volattr = 0;

		res = setattrlist(path, &attributes, &attr->chgtime,
				  sizeof(struct timespec), FSOPT_NOFOLLOW);

		if (res == -1)
			return -errno;
	}

	if (SETATTR_WANTS_BKUPTIME(attr)) {
		struct attrlist attributes;

		attributes.bitmapcount = ATTR_BIT_MAP_COUNT;
		attributes.reserved = 0;
		attributes.commonattr = ATTR_CMN_BKUPTIME;
		attributes.dirattr = 0;
		attributes.fileattr = 0;
		attributes.forkattr = 0;
		attributes.volattr = 0;

		res = setattrlist(path, &attributes, &attr->bkuptime,
				  sizeof(struct timespec), FSOPT_NOFOLLOW);

		if (res == -1)
			return -errno;
	}

	if (SETATTR_WANTS_FLAGS(attr)) {
		res = chflags(path, attr->flags);
		if (res == -1)
			return -errno;
	}

	return 0;
}

static int xmp_setattr_x(const char *path, struct setattr_x *attr)
{
	return xmp_fsetattr_x(path, attr, (struct fuse_file_info *)0);
}

static int xmp_chflags(const char *path, uint32_t flags)
{
	int res;

	res = chflags(path, flags);

	if (res == -1)
		return -errno;

	return 0;
}

static int xmp_getxtimes(const char *path, struct timespec *bkuptime,
			 struct timespec *crtime)
{
	int res = 0;
	struct attrlist attributes;

	attributes.bitmapcount = ATTR_BIT_MAP_COUNT;
	attributes.reserved    = 0;
	attributes.commonattr  = 0;
	attributes.dirattr     = 0;
	attributes.fileattr    = 0;
	attributes.forkattr    = 0;
	attributes.volattr     = 0;



	struct xtimeattrbuf {
		uint32_t size;
		struct timespec xtime;
	} __attribute__ ((packed));


	struct xtimeattrbuf buf;

	attributes.commonattr = ATTR_CMN_BKUPTIME;
	res = getattrlist(path, &attributes, &buf, sizeof(buf), FSOPT_NOFOLLOW);
	if (res == 0)
		(void)memcpy(bkuptime, &(buf.xtime), sizeof(struct timespec));
	else
		(void)memset(bkuptime, 0, sizeof(struct timespec));

	attributes.commonattr = ATTR_CMN_CRTIME;
	res = getattrlist(path, &attributes, &buf, sizeof(buf), FSOPT_NOFOLLOW);
	if (res == 0)
		(void)memcpy(crtime, &(buf.xtime), sizeof(struct timespec));
	else
		(void)memset(crtime, 0, sizeof(struct timespec));

	return 0;
}

static int xmp_setbkuptime(const char *path, const struct timespec *bkuptime)
{
	int res;

	struct attrlist attributes;

	attributes.bitmapcount = ATTR_BIT_MAP_COUNT;
	attributes.reserved = 0;
	attributes.commonattr = ATTR_CMN_BKUPTIME;
	attributes.dirattr = 0;
	attributes.fileattr = 0;
	attributes.forkattr = 0;
	attributes.volattr = 0;

	res = setattrlist(path, &attributes, bkuptime,
			  sizeof(struct timespec), FSOPT_NOFOLLOW);

	if (res == -1)
		return -errno;

	return 0;
}

static int xmp_setchgtime(const char *path, const struct timespec *chgtime)
{
	int res;

	struct attrlist attributes;

	attributes.bitmapcount = ATTR_BIT_MAP_COUNT;
	attributes.reserved = 0;
	attributes.commonattr = ATTR_CMN_CHGTIME;
	attributes.dirattr = 0;
	attributes.fileattr = 0;
	attributes.forkattr = 0;
	attributes.volattr = 0;

	res = setattrlist(path, &attributes, chgtime,
			  sizeof(struct timespec), FSOPT_NOFOLLOW);

	if (res == -1)
		return -errno;

	return 0;
}

static int xmp_setcrtime(const char *path, const struct timespec *crtime)
{
	int res;

	struct attrlist attributes;

	attributes.bitmapcount = ATTR_BIT_MAP_COUNT;
	attributes.reserved = 0;
	attributes.commonattr = ATTR_CMN_CRTIME;
	attributes.dirattr = 0;
	attributes.fileattr = 0;
	attributes.forkattr = 0;
	attributes.volattr = 0;

	res = setattrlist(path, &attributes, crtime,
			  sizeof(struct timespec), FSOPT_NOFOLLOW);

	if (res == -1)
		return -errno;

	return 0;
}

#endif /* __FreeBSD__ >= 10 */

static int xmp_chmod(const char *path, mode_t mode)
{
	int res;

#if (__FreeBSD__ >= 10)
	res = lchmod(path, mode);
#else
	res = chmod(path, mode);
#endif
	if (res == -1)
		return -errno;

	return 0;
}

static int xmp_chown(const char *path, uid_t uid, gid_t gid)
{
	int res;

	res = lchown(path, uid, gid);
	if (res == -1)
		return -errno;

	return 0;
}

static int xmp_truncate(const char *path, off_t size)
{
	int res;

	res = truncate(path, size);
	if (res == -1)
		return -errno;

	return 0;
}

static int xmp_ftruncate(const char *path, off_t size,
			 struct fuse_file_info *fi)
{
	int res;

	(void) path;

	res = ftruncate(fi->fh, size);
	if (res == -1)
		return -errno;

	return 0;
}

static int xmp_utimens(const char *path, const struct timespec ts[2])
{
	int res;
	struct timeval tv[2];

	tv[0].tv_sec = ts[0].tv_sec;
	tv[0].tv_usec = ts[0].tv_nsec / 1000;
	tv[1].tv_sec = ts[1].tv_sec;
	tv[1].tv_usec = ts[1].tv_nsec / 1000;

	res = utimes(path, tv);
	if (res == -1)
		return -errno;

	return 0;
}

static int xmp_create(const char *path, mode_t mode, struct fuse_file_info *fi)
{
	int fd;

	fd = open(path, fi->flags, mode);
	if (fd == -1)
		return -errno;

	fi->fh = fd;
	return 0;
}

static int xmp_open(const char *path, struct fuse_file_info *fi)
{
	int fd;

	fd = open(path, fi->flags);
	if (fd == -1)
		return -errno;

	fi->fh = fd;
	return 0;
}

static int xmp_read(const char *path, char *buf, size_t size, off_t offset,
		    struct fuse_file_info *fi)
{
	int res;

	(void) path;
	res = pread(fi->fh, buf, size, offset);
	if (res == -1)
		res = -errno;

	return res;
}

static int xmp_write(const char *path, const char *buf, size_t size,
		     off_t offset, struct fuse_file_info *fi)
{
	int res;

	(void) path;
	res = pwrite(fi->fh, buf, size, offset);
	if (res == -1)
		res = -errno;

	return res;
}

static int xmp_statfs(const char *path, struct statvfs *stbuf)
{
	int res;

	res = statvfs(path, stbuf);
	if (res == -1)
		return -errno;

	return 0;
}

static int xmp_flush(const char *path, struct fuse_file_info *fi)
{
	int res;

	(void) path;
	/* This is called from every close on an open file, so call the
	   close on the underlying filesystem.	But since flush may be
	   called multiple times for an open file, this must not really
	   close the file.  This is important if used on a network
	   filesystem like NFS which flush the data/metadata on close() */
	res = close(dup(fi->fh));
	if (res == -1)
		return -errno;

	return 0;
}

static int xmp_release(const char *path, struct fuse_file_info *fi)
{
	(void) path;
	close(fi->fh);

	return 0;
}

static int xmp_fsync(const char *path, int isdatasync,
		     struct fuse_file_info *fi)
{
	int res;
	(void) path;

#ifndef HAVE_FDATASYNC
	(void) isdatasync;
#else
	if (isdatasync)
		res = fdatasync(fi->fh);
	else
#endif
		res = fsync(fi->fh);
	if (res == -1)
		return -errno;

	return 0;
}

#ifdef HAVE_SETXATTR
/* xattr operations are optional and can safely be left unimplemented */
static int xmp_setxattr(const char *path, const char *name, const char *value,
#if (__FreeBSD__ >= 10)
			size_t size, int flags, uint32_t position)
#else
			size_t size, int flags)
#endif
{
#if (__FreeBSD__ >= 10)
	int res;
	if (!strncmp(name, XATTR_APPLE_PREFIX, sizeof(XATTR_APPLE_PREFIX) - 1)) {
		flags &= ~(XATTR_NOSECURITY);
	}
	if (!strcmp(name, A_KAUTH_FILESEC_XATTR)) {
		char new_name[MAXPATHLEN];
		memcpy(new_name, A_KAUTH_FILESEC_XATTR, sizeof(A_KAUTH_FILESEC_XATTR));
		memcpy(new_name, G_PREFIX, sizeof(G_PREFIX) - 1);
		res = setxattr(path, new_name, value, size, position, flags);
	} else {
		res = setxattr(path, name, value, size, position, flags);
	}
#else
	int res = lsetxattr(path, name, value, size, flags);
#endif
	if (res == -1)
		return -errno;
	return 0;
}

static int xmp_getxattr(const char *path, const char *name, char *value,
#if (__FreeBSD__ >= 10)
			size_t size, uint32_t position)
#else
			size_t size)
#endif
{
#if (__FreeBSD__ >= 10)
	int res;
	if (strcmp(name, A_KAUTH_FILESEC_XATTR) == 0) {
		char new_name[MAXPATHLEN];
		memcpy(new_name, A_KAUTH_FILESEC_XATTR, sizeof(A_KAUTH_FILESEC_XATTR));
		memcpy(new_name, G_PREFIX, sizeof(G_PREFIX) - 1);
		res = getxattr(path, new_name, value, size, position, XATTR_NOFOLLOW);
	} else {
		res = getxattr(path, name, value, size, position, XATTR_NOFOLLOW);
	}
#else
	int res = lgetxattr(path, name, value, size);
#endif
	if (res == -1)
		return -errno;
	return res;
}

static int xmp_listxattr(const char *path, char *list, size_t size)
{
#if (__FreeBSD__ >= 10)
	ssize_t res = listxattr(path, list, size, XATTR_NOFOLLOW);
	if (res > 0) {
		if (list) {
			size_t len = 0;
			char *curr = list;
			do { 
				size_t thislen = strlen(curr) + 1;
				if (strcmp(curr, G_KAUTH_FILESEC_XATTR) == 0) {
					memmove(curr, curr + thislen, res - len - thislen);
					res -= thislen;
					break;
				}
				curr += thislen;
				len += thislen;
			} while (len < res);
		} else {
			/*
			ssize_t res2 = getxattr(path, G_KAUTH_FILESEC_XATTR, NULL, 0, 0,
									XATTR_NOFOLLOW);
			if (res2 >= 0) {
				res -= sizeof(G_KAUTH_FILESEC_XATTR);
			}
			*/
		}
	}
#else
	int res = llistxattr(path, list, size);
#endif
	if (res == -1)
		return -errno;
	return res;
}

static int xmp_removexattr(const char *path, const char *name)
{
#if (__FreeBSD__ >= 10)
	int res;
	if (strcmp(name, A_KAUTH_FILESEC_XATTR) == 0) {
		char new_name[MAXPATHLEN];
		memcpy(new_name, A_KAUTH_FILESEC_XATTR, sizeof(A_KAUTH_FILESEC_XATTR));
		memcpy(new_name, G_PREFIX, sizeof(G_PREFIX) - 1);
		res = removexattr(path, new_name, XATTR_NOFOLLOW);
	} else {
		res = removexattr(path, name, XATTR_NOFOLLOW);
	}
#else
	int res = lremovexattr(path, name);
#endif
	if (res == -1)
		return -errno;
	return 0;
}
#endif /* HAVE_SETXATTR */

#if !(__FreeBSD__ >= 10)
static int xmp_lock(const char *path, struct fuse_file_info *fi, int cmd,
		    struct flock *lock)
{
	(void) path;

	return ulockmgr_op(fi->fh, cmd, lock, &fi->lock_owner,
			   sizeof(fi->lock_owner));
}
#endif /* __FreeBSD__ >= 10 */

void *
xmp_init(struct fuse_conn_info *conn)
{
#if (__FreeBSD__ >= 10)
	FUSE_ENABLE_SETVOLNAME(conn);
	FUSE_ENABLE_XTIMES(conn);
#endif /* __FreeBSD__ >= 10 */
	return NULL;
}

void
xmp_destroy(void *userdata)
{
}

static struct fuse_operations xmp_oper = {
	.init	   	= xmp_init,
	.destroy	= xmp_destroy,
	.getattr	= xmp_getattr,
	.fgetattr	= xmp_fgetattr,
#if !(__FreeBSD__ >= 10)
	.access		= xmp_access,
#endif /* !__FreeBSD__ >= 10 */
	.readlink	= xmp_readlink,
	.opendir	= xmp_opendir,
	.readdir	= xmp_readdir,
	.releasedir	= xmp_releasedir,
	.mknod		= xmp_mknod,
	.mkdir		= xmp_mkdir,
	.symlink	= xmp_symlink,
	.unlink		= xmp_unlink,
	.rmdir		= xmp_rmdir,
	.rename		= xmp_rename,
	.link		= xmp_link,
	.chmod		= xmp_chmod,
	.chown		= xmp_chown,
	.truncate	= xmp_truncate,
	.ftruncate	= xmp_ftruncate,
	.utimens	= xmp_utimens,
	.create		= xmp_create,
	.open		= xmp_open,
	.read		= xmp_read,
	.write		= xmp_write,
	.statfs		= xmp_statfs,
	.flush		= xmp_flush,
	.release	= xmp_release,
	.fsync		= xmp_fsync,
#ifdef HAVE_SETXATTR
	.setxattr	= xmp_setxattr,
	.getxattr	= xmp_getxattr,
	.listxattr	= xmp_listxattr,
	.removexattr	= xmp_removexattr,
#endif
#if !(__FreeBSD__ >= 10)
	.lock		= xmp_lock,
#endif /* __FreeBSD__ >= 10 */
#if (__FreeBSD__ >= 10)
	.setvolname	= xmp_setvolname,
	.exchange	= xmp_exchange,
	.getxtimes	= xmp_getxtimes,
	.setbkuptime	= xmp_setbkuptime,
	.setchgtime	= xmp_setchgtime,
	.setcrtime	= xmp_setcrtime,
	.chflags	= xmp_chflags,
	.setattr_x	= xmp_setattr_x,
	.fsetattr_x	= xmp_fsetattr_x,
#endif /* __FreeBSD__ >= 10 */
};

int main(int argc, char *argv[])
{
	umask(0);
	return fuse_main(argc, argv, &xmp_oper, NULL);
}
