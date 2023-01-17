#!/bin/bash

mkdir -p work
cd work
rm -rf captagent
cp ../src/captagent.zip .
unzip -P 'XXX' captagent.zip
rm captagent.zip
cd captagent
./build.sh

export CFLAGS="-g -O0 -fprofile-instr-generate -fcoverage-mapping"
export CC="clang"
CC=clang CFLAGS="-g -O0 -fprofile-instr-generate -fcoverage-mapping" ./configure \
     		--enable-tls --enable-ssl

find . -type f -print0 | xargs -0 sed -i 's/static volatile/static volatile/g'

make CFLAGS="-g -O0 -fprofile-instr-generate -fcoverage-mapping"

export DESTDIR="`pwd`/debug-build"
make install
