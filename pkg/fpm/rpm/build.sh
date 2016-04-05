#!/bin/bash
# CaptAgent 6 - CentOS Builder
export VERSION=$(date +%Y%m%d%H%M)
export TMP_DIR=/tmp/build
yum -y install json-c-devel expat-devel libpcap-devel flex-devel automake libtool bison

git clone https://github.com/sipcapture/captagent captagent
cd captagent/
./build.sh
./configure
make
mkdir -p /tmp/captagent
make DESTDIR=/tmp/captagent install

fpm -s dir -t rpm -C /tmp/captagent --name captagent --version 6.0.0 --iteration 1 --depends json-c,expat,libpcap --description "captagent" .

ls -alF *.rpm
cp -v *.rpm ${TMP_DIR}

echo "done!"
