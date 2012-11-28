#!/bin/sh

echo "You need to have m4, automake, autoconf, libtool...";
#aclocal
autoreconf --force --install
automake --add-missing
autoconf
