#!/bin/bash
# CaptAgent 6 - CentOS Builder
export VERSION=$(date +%Y%m%d%H%M)
export TMP_DIR=/tmp

cd $TMP_DIR
yum -y install json-c-devel expat-devel libpcap-devel flex-devel automake libtool bison
git clone https://github.com/sipcapture/captagent captagent
cd captagent/
git checkout 6.1
./build.sh
./configure
make
mkdir -p $TMP_DIR/captagent
make DESTDIR=$TMP_DIR/captagent_install install
export CODEVERSION=$(./src/captagent -v | cut -c10-)

fpm -s dir -t rpm -C $TMP_DIR/captagent_install --name captagent --version $CODEVERSION --iteration 1 --depends json-c,expat,libpcap --description "captagent" .

ls -alF *.rpm
cp -v *.rpm ${TMP_DIR}

cd $TMP_DIR; rm -rf ./captagent ./captagent-installer

echo "done!"
