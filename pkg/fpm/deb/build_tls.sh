#!/bin/bash
# CaptAgent 6 TLS/SSL - Debian Builder
export VERSION=$(date +%Y%m%d%H%M)
export TMP_DIR=/tmp
export EXEC_DIR=$(pwd)

cd $TMP_DIR
apt-get -y update  && apt-get -y install git libexpat-dev libpcap-dev libjson0-dev libuv0.10-dev libtool automake flex bison libgcrypt20 libgcrypt20-dev libssl-dev
git clone https://github.com/sipcapture/captagent captagent
cd captagent/
./build.sh
./configure --enable-tls --enable-ssl
make
mkdir -p $TMP_DIR/captagent
make DESTDIR=$TMP_DIR/captagent_install install
export CODEVERSION=$(./src/captagent -v | cut -c10-)

fpm -s dir -t deb -C $TMP_DIR/captagent_install --name captagent --version $CODEVERSION --iteration 1 --deb-no-default-config-files --depends libpcap,json-c,expat,libssl --description "captagent-tls" .
ls -alF *.deb
cp *.deb /scripts/

# Clean up temp files
cd $TMP_DIR; rm -rf ./captagent ./captagent_install
cd $EXEC_DIR 

echo "done!"
