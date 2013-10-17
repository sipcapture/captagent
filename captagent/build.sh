#!/bin/sh

echo "You need to have m4, automake, autoconf, libtool...";
#aclocal
autoreconf --force --install
automake --add-missing
autoconf

#FreeBSD has libexpat in /usr/local/lib (ports installation)
./configure CFLAGS="-I /usr/local/include" LDFLAGS="-L /usr/local/lib"