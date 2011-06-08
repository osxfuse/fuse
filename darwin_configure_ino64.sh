#! /bin/sh

MACFUSE_SRCROOT=${MACFUSE_SRCROOT:-$1}
MACFUSE_SRCROOT=${MACFUSE_SRCROOT:?}

CFLAGS="-D__DARWIN_64_BIT_INO_T=1 -D__FreeBSD__=10 -D_POSIX_C_SOURCE=200112L -I$MACFUSE_SRCROOT/common -O -gdwarf-2 -arch i386 -arch ppc -arch x86_64 -isysroot /Developer/SDKs/MacOSX10.5.sdk -mmacosx-version-min=10.5" LDFLAGS="-arch i386 -arch ppc -arch x86_64 -framework CoreFoundation" ./configure --prefix=/usr/local --disable-dependency-tracking --disable-static
