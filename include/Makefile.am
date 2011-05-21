## Process this file with automake to produce Makefile.in

if DARWIN
osxfuseincludedir=$(includedir)/osxfuse
fuseincludedir=$(osxfuseincludedir)/fuse
else
fuseincludedir=$(includedir)/fuse
endif

fuseinclude_HEADERS = \
	fuse.h			\
	fuse_compat.h		\
	fuse_common.h		\
	fuse_common_compat.h    \
	fuse_lowlevel.h		\
	fuse_lowlevel_compat.h	\
	fuse_opt.h		\
	cuse_lowlevel.h

if DARWIN
fuseinclude_HEADERS += fuse_darwin.h
osxfuseinclude_HEADERS = old/fuse.h
else
include_HEADERS = old/fuse.h ulockmgr.h
endif

noinst_HEADERS = fuse_kernel.h
