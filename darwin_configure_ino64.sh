#! /bin/sh

OSXFUSE_SRCROOT=${OSXFUSE_SRCROOT:-$1}
OSXFUSE_SRCROOT=${OSXFUSE_SRCROOT:?}

./makeconf.sh && \
CFLAGS="-D__DARWIN_64_BIT_INO_T=1 -D__FreeBSD__=10 -DMACFUSE_MODE -D_POSIX_C_SOURCE=200112L -I$OSXFUSE_SRCROOT/common -O -gdwarf-2 -arch i386 -arch x86_64 -isysroot /Developer/SDKs/MacOSX10.6.sdk -mmacosx-version-min=10.6" LDFLAGS="-arch i386 -arch x86_64 -framework CoreFoundation" ./configure --prefix=/usr/local --disable-dependency-tracking --disable-static
