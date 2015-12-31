## Process this file with automake to produce Makefile.in

AM_CPPFLAGS = -I$(top_srcdir)/include -DFUSERMOUNT_DIR=\"$(bindir)\" \
 -D_FILE_OFFSET_BITS=64 -D_REENTRANT -DFUSE_USE_VERSION=26

if DARWIN
AM_CPPFLAGS += -O -gdwarf-2
endif

if DARWIN
lib_LTLIBRARIES = libfuse.la libfuse_ino64.la
else
lib_LTLIBRARIES = libfuse.la libulockmgr.la
endif

if BSD
mount_source = mount_bsd.c
endif

if DARWIN
mount_source =			\
	mount_darwin.c		\
	fuse_darwin.c		\
	modules/threadid.c	\
	modules/volicon.c
endif

if LINUX
mount_source = mount.c mount_util.c mount_util.h
endif

if ICONV
iconv_source = modules/iconv.c
else
iconv_source =
endif

libfuse_la_SOURCES = 		\
	fuse.c			\
	fuse_i.h		\
	fuse_kern_chan.c	\
	fuse_loop.c		\
	fuse_loop_mt.c		\
	fuse_lowlevel.c		\
	fuse_misc.h		\
	fuse_mt.c		\
	fuse_opt.c		\
	fuse_session.c		\
	fuse_signals.c		\
	helper.c		\
	modules/subdir.c	\
	$(iconv_source)		\
	$(mount_source)

fuse_version_number=2:7:3

if DARWIN
libfuse_la_CPPFLAGS = $(AM_CPPFLAGS) -D_DARWIN_NO_64_BIT_INODE
libfuse_la_LDFLAGS = -pthread @libfuse_libs@ -version-number $(fuse_version_number)
libfuse_ino64_la_SOURCES = $(libfuse_la_SOURCES)
libfuse_ino64_la_CPPFLAGS = $(AM_CPPFLAGS) -D_DARWIN_USE_64_BIT_INODE
libfuse_ino64_la_LDFLAGS = -pthread @libfuse_libs@ -version-number $(fuse_version_number)
else
libfuse_la_LDFLAGS = -pthread @libfuse_libs@ -version-number $(fuse_version_number) \
	-Wl,--version-script,$(srcdir)/fuse_versionscript

libulockmgr_la_SOURCES = ulockmgr.c
libulockmgr_la_LDFLAGS = -version-number 1:0:1

EXTRA_DIST = fuse_versionscript
endif
