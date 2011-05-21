## Process this file with automake to produce Makefile.in

ACLOCAL_AMFLAGS = -I m4

SUBDIRS = @subdirs2@

EXTRA_DIST =			\
	fuse.pc.in		\
	osxfuse.pc.in		\
	README*			\
	Filesystems		\
	FAQ			\
	doc/how-fuse-works	\
	doc/kernel.txt		\
	doc/Doxyfile

pkgconfigdir = @pkgconfigdir@
if DARWIN
pkgconfig_DATA = osxfuse.pc
else
pkgconfig_DATA = fuse.pc
endif

$(pkgconfig_DATA): config.status
