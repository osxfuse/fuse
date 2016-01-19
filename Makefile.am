## Process this file with automake to produce Makefile.in

ACLOCAL_AMFLAGS = -I m4

if DARWIN
SUBDIRS = @subdirs2@
else
SUBDIRS = @subdirs2@ doc
endif
AUTOMAKE_OPTIONS = subdir-objects

EXTRA_DIST =			\
	fuse.pc.in		\
	osxfuse.pc.in		\
	README*

pkgconfigdir = @pkgconfigdir@
if DARWIN
pkgconfig_DATA = osxfuse.pc
else
pkgconfig_DATA = fuse.pc
endif

$(pkgconfig_DATA): config.status