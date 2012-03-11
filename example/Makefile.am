## Process this file with automake to produce Makefile.in

AM_CPPFLAGS = -I$(top_srcdir)/include -D_FILE_OFFSET_BITS=64 -D_REENTRANT
noinst_PROGRAMS = fusexmp fusexmp_fh null hello hello_ll

if DARWIN
AM_CPPFLAGS += -D_DARWIN_USE_64_BIT_INODE
LDADD = ../lib/libfuse_ino64.la @libfuse_libs@
fusexmp_fh_LDADD = ../lib/libfuse_ino64.la @libfuse_libs@
else
LDADD = ../lib/libfuse.la @libfuse_libs@
fusexmp_fh_LDADD = ../lib/libfuse.la ../lib/libulockmgr.la @libfuse_libs@
endif
