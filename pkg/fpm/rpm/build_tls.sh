#!/bin/bash
# CaptAgent 6 - CentOS Builder for Docker
export VERSION=$(date +%Y%m%d%H%M)
export TMP_DIR=/tmp
export EXEC_DIR=$(pwd)

cd $TMP_DIR
yum -y install epel-release
yum -y install json-c-devel expat-devel libpcap-devel flex-devel automake libtool bison libuv-devel openssl-devel libgcrypt-devel libgcrypt
git clone https://github.com/sipcapture/captagent captagent
cd captagent/
./build.sh
./configure --enable-ssl --enable-tls
make
mkdir -p $TMP_DIR/captagent
make DESTDIR=$TMP_DIR/captagent_install install
export CODEVERSION=$(./src/captagent -v | cut -c10-)

fpm -s dir -t rpm -C $TMP_DIR/captagent_install --name captagent --version $CODEVERSION --iteration 1 --depends json-c,expat,libpcap,libuv,openssl,libgcrypt --description "captagent" .

ls -alF *.rpm
cp -v *.rpm /scripts/

cd $TMP_DIR; rm -rf ./captagent ./captagent-installer

echo "done!"
