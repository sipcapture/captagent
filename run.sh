#!/bin/sh

echo "BUILD..."
./build.sh
echo
echo "CONFIGURE..."
./configure
echo
echo "MAKE and INSTALL..."
make && sudo make install
echo "Captagent build succesfully!"
