## Process this file with automake to produce Makefile.in

fuseincludedir=$(includedir)/fuse

if DARWIN
darwin_headers = fuse_darwin.h
darwin_headers_private = fuse_darwin_private.h
else
darwin_headers =
darwin_headers_private =
endif

fuseinclude_HEADERS = \
	$(darwin_headers)	\
	fuse.h			\
	fuse_compat.h		\
	fuse_common.h		\
	fuse_common_compat.h    \
	fuse_lowlevel.h		\
	fuse_lowlevel_compat.h	\
	fuse_opt.h

include_HEADERS = old/fuse.h ulockmgr.h

noinst_HEADERS = fuse_kernel.h $(darwin_headers_private)
