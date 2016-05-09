#!/bin/sh

echo "You need to have m4, automake, autoconf, libtool...";
#aclocal

list_of_config_files="./src/modules";
#
list_of_config_files_pro="./src/modules_pro";

#echo adding modules
#for file in $list_of_config_files; do
#     echo "AC_CONFIG_FILES([${list_of_config_files}/${file}])"
#done  > modules_makefiles.m4


autoreconf --force --install
automake --add-missing
autoconf

#FreeBSD has libexpat in /usr/local/lib (ports installation)
#./configure CFLAGS="-I/usr/local/include" LDFLAGS="-L/usr/local/lib"

