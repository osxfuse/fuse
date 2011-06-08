## Process this file with automake to produce Makefile.in

if DARWIN
AM_CPPFLAGS_DARWIN = -D__FreeBSD__=10
else
AM_CPPFLAGS_DARWIN =
endif

AM_CPPFLAGS = -I$(top_srcdir)/include -DFUSERMOUNT_DIR=\"$(bindir)\" \
 -D_FILE_OFFSET_BITS=64 -D_REENTRANT -DFUSE_USE_VERSION=26 $(AM_CPPFLAGS_DARWIN)

lib_LTLIBRARIES = libfuse.la libulockmgr.la

if BSD
mount_source = mount_bsd.c
extra_source =
endif

if DARWIN
mount_source = mount_darwin.c
extra_source = fuse_darwin.c modules/threadid.c modules/volicon.c
endif

if LINUX
mount_source = mount.c mount_util.c mount_util.h
extra_source =
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
	$(extra_source)		\
	$(iconv_source)		\
	$(mount_source)

if !DARWIN
libfuse_la_LDFLAGS = @libfuse_libs@ -version-number 2:7:3 \
	-Wl,--version-script,$(srcdir)/fuse_versionscript
else
libfuse_la_LDFLAGS = -version-number 2:7:3
endif

libulockmgr_la_SOURCES = ulockmgr.c
libulockmgr_la_LDFLAGS = -version-number 1:0:1

EXTRA_DIST = fuse_versionscript
