#!/bin/bash
# CaptAgent 6 - Debian Builder
export VERSION=$(date +%Y%m%d%H%M)
export TMP_DIR=/tmp

cd $TMP_DIR
apt-get -y update  && apt-get -y install git libexpat-dev libpcap-dev libjson0-dev libtool automake flex bison
git clone https://github.com/sipcapture/captagent captagent
cd captagent/
git checkout 6.1
./build.sh
./configure
make
mkdir -p $TMP_DIR/captagent
make DESTDIR=$TMP_DIR/captagent_install install
export CODEVERSION=$(./src/captagent -v | cut -c10-)

fpm -s dir -t deb -C $TMP_DIR/captagent_install --name captagent --version $CODEVERSION --iteration 1 --deb-no-default-config-files --depends libpcap,json-c,expat --description "captagent" .
ls -alF *.deb
cp -v *.deb ${TMP_DIR}/

# Clean up temp files
cd $TMP_DIR; rm -rf ./captagent ./captagent_install

echo "done!"
