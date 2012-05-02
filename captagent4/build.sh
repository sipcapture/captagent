#!/bin/sh

echo "You need to have m4, automake, autoconf...";
aclocal
automake --add-missing
autoconf
