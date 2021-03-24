#!/bin/sh

echo "BUILD..."
./build.sh
echo
echo "CONFIGURE..."
./configure #--enable-tls --enable-ssl
echo
echo "MAKE and INSTALL..."
make && sudo make install
echo "Captagent built and installed succesfully!"
