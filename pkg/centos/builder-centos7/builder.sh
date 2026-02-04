#!/bin/bash
#
# Captagent - Centos 7 Builder
#

VERSION_MAJOR="6.4"
VERSION_MINOR="2"
PROJECT_NAME="captagent"
OS="centos"
VERSION_OS="el7"

export CODE_VERSION="${VERSION_MAJOR}.${VERSION_MINOR}"
export TMP_DIR=/tmp/build

cp -Rp ${TMP_DIR}/libuv-* .

rpm -i libuv-1.8.0-1.el7.centos.x86_64.rpm
rpm -i libuv-devel-1.8.0-1.el7.centos.x86_64.rpm

cp -Rp ${TMP_DIR}/epel-release-latest-7.noarch.rpm .

rpm -Uvh epel-release-latest-7.noarch.rpm

yum update
# epel
yum -y install epel-release
# gcc make automake libtool
yum -y install gcc make automake libtool
# various
yum -y install json-c-devel expat-devel libpcap-devel flex flex-devel bison libmcrypt-devel openssl-devel

DEPENDENCY="libmcrypt,expat,json-c,libpcap,libuv";

cp -Rp ${TMP_DIR}/captagent_build .
cd captagent_build

# BUILD
./build.sh

# CONFIGURE
./configure

# Create dir for Captagent
TMP_CAPT=/tmp/captagent
mkdir -p ${TMP_CAPT}

# MAKE and MAKE INSTALL
make
make DESTDIR=${TMP_CAPT} install

# clean set
rm -rf  ${TMP_CAPT}/usr/local/captagent/etc/captagent/*
# copy configs
cp -Rp ${TMP_DIR}/captagent_build/conf/* ${TMP_CAPT}/usr/local/captagent/etc/captagent/

# Configs
mkdir -p ${TMP_CAPT}/etc/systemd/system/
mkdir -p ${TMP_CAPT}/etc/init.d/
mkdir -p ${TMP_CAPT}/etc/sysconfig/

# Service
cp init/el/captagent.service ${TMP_CAPT}/etc/systemd/system/
cp init/el/captagent.sysconfig ${TMP_CAPT}/etc/sysconfig/captagent
cp init/el/captagent.init ${TMP_CAPT}/etc/init.d/captagent
chmod +x ${TMP_CAPT}/etc/init.d/captagent

# FPM CAPTAGENT
fpm -s dir -t rpm -C ${TMP_CAPT} \
	--name ${PROJECT_NAME} --version ${CODE_VERSION} \
  	-p "captagent-${VERSION_MAJOR}.${VERSION_MINOR}.${VERSION_OS}.${OS}.x86_64.rpm" \
	--config-files /usr/local/${PROJECT_NAME}/etc/${PROJECT_NAME} --config-files /etc/sysconfig/${PROJECT_NAME} \
	--iteration 8 --depends ${DEPENDENCY} --description "${PROJECT_NAME} ${CODE_VERSION}" .


ls -alF *.rpm
cp -v *.rpm ${TMP_DIR}
rm -rf captagent_build
echo "done!"
