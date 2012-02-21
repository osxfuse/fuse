#!/bin/sh
# Copyrigth 2011, OSXFUSE Project
# All rights reserved.

OSXFUSE_SRCROOT=${OSXFUSE_SRCROOT:-$1}
OSXFUSE_SRCROOT=${OSXFUSE_SRCROOT:?}

OTHER_CFLAGS="-D__DARWIN_64_BIT_INO_T=0 -D__FreeBSD__=10 -D_POSIX_C_SOURCE=200112L -I$OSXFUSE_SRCROOT/common"
FRAMEWORKS="CoreFoundation"

CFLAGS="$OTHER_CFLAGS"
LDFLAGS=""

case "$COMPILER" in
    4.0|4.2)                       CC="gcc-$COMPILER";;
    com.apple.compilers.llvmgcc42) CC="llvm-gcc-4.2";;
    *)
        echo "`basename $0`: unsupported compiler '$COMPILER'" >&2
        exit 1
        ;;
esac
for arch in $ARCHS
do
    CFLAGS="$CFLAGS -arch $arch"
    LDFLAGS="$LDFLAGS -arch $arch"
done
if [ -n "$SDKROOT" ]
then
    CFLAGS="$CFLAGS -isysroot $SDKROOT"
fi
if [ -n "$MACOSX_DEPLOYMENT_TARGET" ]
then
    CFLAGS="$CFLAGS -mmacosx-version-min=$MACOSX_DEPLOYMENT_TARGET"
fi
if [ -n "$OSXFUSE_MACFUSE_MODE" ]
then
    CFLAGS="$CFLAGS -DMACFUSE_MODE=$OSXFUSE_MACFUSE_MODE"
fi
for framework in $FRAMEWORKS
do
    LDFLAGS="$LDFLAGS -framework $framework"
done

export CC="`xcrun -find "${CC}"`"
export CFLAGS
export LDFLAGS

./makeconf.sh && \
./configure --prefix=/usr/local --disable-dependency-tracking --disable-static
