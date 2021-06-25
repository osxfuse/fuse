## Process this file with automake to produce Makefile.in

AUTOMAKE_OPTIONS = subdir-objects
AM_CPPFLAGS = -I$(top_srcdir)/include -DFUSERMOUNT_DIR=\"$(bindir)\" \
 -D_FILE_OFFSET_BITS=64 -D_REENTRANT -DFUSE_USE_VERSION=26

lib_LTLIBRARIES = libfuse.la

if DARWIN
AM_CPPFLAGS += -O -gdwarf-2
target_source =            \
    fuse_darwin.c        \
    modules/threadid.c    \
    modules/volicon.c    \
    mount_darwin.c
else
lib_LTLIBRARIES += libulockmgr.la
if BSD
target_source = mount_bsd.c
else
target_source = mount.c mount_util.c mount_util.h
endif
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
	fuse_loop_dispatch.c	\
	fuse_loop_mt.c		\
	fuse_lowlevel.c		\
	fuse_misc.h		\
	fuse_mt.c		\
	fuse_opt.c		\
	fuse_session.c		\
	fuse_signals.c		\
	buffer.c		\
	cuse_lowlevel.c		\
	helper.c		\
	modules/subdir.c	\
	$(iconv_source)		\
	$(target_source)

libfuse_la_LDFLAGS = -pthread @libfuse_libs@ -version-number 2:9:9

if !DARWIN
libfuse_la_LDFLAGS += -Wl,--version-script,$(srcdir)/fuse_versionscript

if NETBSD
libfuse_la_LIBADD = -lperfuse -lpuffs
endif

libulockmgr_la_SOURCES = ulockmgr.c
libulockmgr_la_LDFLAGS = -pthread -version-number 1:0:1

EXTRA_DIST = fuse_versionscript
endif
