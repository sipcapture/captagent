#!/bin/bash
# CaptAgent 6 - CentOS Builder for Docker

VERSION_MAJOR="6.4"
VERSION_MINOR="0"
OS="centos"
VERSION_OS="el7"

# install libs
cd /tmp
cp -Rp /tmp/libuv-* .
rpm -i libuv-1.8.0-1.el7.centos.x86_64.rpm
rpm -i libuv-devel-1.8.0-1.el7.centos.x86_64.rpm
cp -Rp /tmp/epel-release-latest-7.noarch.rpm .
rpm -Uvh epel-release-latest-7.noarch.rpm
yum update
yum -y install epel-release
yum -y install json-c-devel expat-devel libpcap-devel flex-devel automake libtool bison libuv-devel openssl-devel libgcrypt-devel

# clone captagent and build it
git clone https://github.com/sipcapture/captagent captagent
cd captagent/
./build.sh
./configure --enable-tls --enable-ssl
make

# version
mkdir -p /tmp/captagent
make DESTDIR=$TMP_DIR/captagent_install install
export CODEVERSION=$(./src/captagent -v | cut -c10-)

DEPENDENCY="expat,json-c,libpcap,libuv";
echo $DEPENDENCY;

# create deb pkg with fpm
fpm -s dir -t rpm -C /tmp/captagent_install	--name captagent --version $CODEVERSION \
    -p "captagent-${VERSION_MAJOR}.${VERSION_MINOR}-${INV}.${VERSION_OS}.${OS}.x86_64.rpm" \
	--iteration 1 --depends ${DEPENDENCY} --description "captagent" .
ls -alF *.rpm
cp -v *.rpm /scripts/

# clean up temp files
cd /tmp; rm -rf ./captagent ./captagent-installer

echo "done!"
