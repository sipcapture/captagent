#!/bin/bash
# CaptAgent 6 - CentOS Builder
export VERSION=$(date +%Y%m%d%H%M)
export TMP_DIR=/tmp/build
apt-get -y update  && apt-get -y install git libexpat-dev libpcap-dev libjson0-dev libtool automake flex bison
git clone https://github.com/sipcapture/captagent captagent
cd captagent/
./build.sh
./configure
make
mkdir -p /tmp/captagent
make DESTDIR=/tmp/captagent install
fpm -s dir -t deb -C /tmp/captagent --name captagent --version 6.0.0 --iteration 1 --deb-no-default-config-files --depends libpcap,json-c,expat --description "captagent" .
ls -alF *.deb
cp -v *.deb ${TMP_DIR}

echo "done!"
