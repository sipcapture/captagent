#!/bin/bash

mkdir -p work
cd work
rm -rf captagent
cp ../src/captagent.zip .
unzip -P 'XXX' captagent.zip
cd captagent
./build.sh
./configure --enable-ssl --enable-tls
make

export DESTDIR="`pwd`/debug-build"
make install
