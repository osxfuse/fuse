#! /bin/sh

test "`uname -s`" != "Darwin"
DARWIN=$?

if test $DARWIN -eq 1; then
    LIBTOOLIZE=glibtoolize
else
    LIBTOOLIZE=libtoolize
fi

echo Running libtoolize...
$LIBTOOLIZE --automake -c -f

if test $DARWIN -eq 1; then
    touch config.rpath
else
    CONFIG_RPATH=/usr/share/gettext/config.rpath
    if ! [ -f $CONFIG_RPATH ]; then
        CONFIG_RPATH=/usr/local/share/gettext/config.rpath
    fi
    if ! [ -f $CONFIG_RPATH ]; then
        if  [ -f config.rpath ]; then
            CONFIG_RPATH=
        else
            echo "config.rpath not found!" >&2
            exit 1
        fi
    fi
    if ! [ -z "$CONFIG_RPATH" ]; then
        cp "$CONFIG_RPATH" .
    fi
fi

if test ! -z "`which autoreconf`"; then
    echo Running autoreconf...
    autoreconf -i -f
else
    echo Running aclocal...
    aclocal
    echo Running autoheader...
    autoheader
    echo Running autoconf...
    autoconf
    echo Running automake...
    automake -a -c
    (
	echo Entering directory: kernel
	cd kernel
	echo Running autoheader...
	autoheader
	echo Running autoconf...
	autoconf
    )
fi

rm -f config.cache config.status
echo "To compile run './configure', and then 'make'."
