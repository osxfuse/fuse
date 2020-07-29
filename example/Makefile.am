## Process this file with automake to produce Makefile.in

AM_CPPFLAGS = -I$(top_srcdir)/include -D_FILE_OFFSET_BITS=64 -D_REENTRANT
noinst_HEADERS = fioc.h
noinst_PROGRAMS = fusexmp fusexmp_fh null hello hello_ll fioc fioclient \
		  fsel fselclient cusexmp

LDADD = ../lib/libfuse.la

if DARWIN
fusexmp_fh_LDADD = ../lib/libfuse.la
else
fusexmp_fh_LDADD = ../lib/libfuse.la ../lib/libulockmgr.la
endif

fioclient_CPPFLAGS =
fioclient_LDFLAGS =
fioclient_LDADD =
fselclient_CPPFLAGS =
fselclient_LDFLAGS =
fselclient_LDADD =

