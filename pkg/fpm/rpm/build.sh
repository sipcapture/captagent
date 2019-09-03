#!/bin/bash
# CaptAgent 6 - CentOS Builder for Docker

VERSION_MAJOR="6.3"
VERSION_MINOR="1"
OS="centos"
VERSION_OS="el7"

export TMP_DIR=/tmp
export EXEC_DIR=$(pwd)

# install libs
cd $TMP_DIR

yum update
yum -y install epel-release
yum -y install gcc make git json-c-devel expat-devel libpcap-devel flex-devel automake libtool bison libuv-devel openssl-devel

yum -y install ruby-devel rpm-build rubygems
gem install --no-ri --no-rdoc fpm

# clone captagent and build it
git clone https://github.com/sipcapture/captagent captagent
cd captagent/
./build.sh
./configure
make

# version
mkdir -p $TMP_DIR/captagent
make DESTDIR=$TMP_DIR/captagent_install install
export CODEVERSION="${VERSION_MAJOR}.${VERSION_MINOR}"

DEPENDENCY="expat,json-c,libpcap,libuv";
echo $DEPENDENCY;

# create deb pkg with fpm
fpm -s dir -t rpm -C $TMP_DIR/captagent_install --name captagent --version $CODEVERSION \
    -p "captagent-${VERSION_MAJOR}.${VERSION_MINOR}.${VERSION_OS}.${OS}.x86_64.rpm" \
	--iteration 1 --depends ${DEPENDENCY} --description "captagent" .

ls -alF *.rpm
cp -v *.rpm ${EXEC_DIR}

cd $TMP_DIR; rm -rf ./captagent ./captagent-installer


echo "done!"
