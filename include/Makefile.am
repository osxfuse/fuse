## Process this file with automake to produce Makefile.in

fuseincludedir=$(includedir)/fuse

fuseinclude_HEADERS = \
	fuse.h			\
	fuse_compat.h		\
	fuse_common.h		\
	fuse_common_compat.h    \
	fuse_lowlevel.h		\
	fuse_lowlevel_compat.h	\
	fuse_opt.h

include_HEADERS = old/fuse.h

if !DARWIN
fuseinclude_HEADERS += cuse_lowlevel.h
include_HEADERS += ulockmgr.h
endif

noinst_HEADERS = fuse_kernel.h
