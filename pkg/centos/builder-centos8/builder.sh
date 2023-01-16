#!/bin/bash
#
# Captgent - CentOS 8 Builder
#

VERSION_MAJOR="6.4"
VERSION_MINOR="1"
PROJECT_NAME="captagent"
OS="centos"
VERSION_OS="el8"

export CODE_VERSION="${VERSION_MAJOR}.${VERSION_MINOR}"
export TMP_DIR=/tmp/build

# libuv
cp -Rp ${TMP_DIR}/libuv-* .
yum -y install libuv-1.34.2-1.module_el8+8340+1d027fbb.x86_64.rpm
yum -y install libuv-devel-1.34.2-1.module_el8+8340+1d027fbb.x86_64.rpm

# pkgconfig
yum -y install pkgconfig

yum -y install dnf-plugins-core
yum -y install 'dnf-command(config-manager)'
yum -y config-manager --set-enabled powertools

echo "ENABLE EPEL"
yum -y install https://dl.fedoraproject.org/pub/epel/epel-release-latest-8.noarch.rpm

yum -y update

# gcc - make
yum -y install gcc make automake libtool

# flex
yum -y install flex
yum -y --enablerepo=powertools install flex-devel

# mcrypt
yum --enablerepo=epel -y install libmcrypt-devel

# git
yum -y install git

# ruby - fpm
yum -y install @ruby:3.0 ruby-devel rpm-build rubygems
gem install --no-document fpm

# openssl
yum -y install openssl-devel

# various
yum -y install json-c-devel expat-devel libpcap-devel bison pcre-devel

DEPENDENCY="libmcrypt,expat,json-c,libpcap,pcre,libuv";

cp -Rp ${TMP_DIR}/captagent_build .
cd captagent_build

# BUILD
./build.sh

LDFLAGS = -L/usr/local/ssl/lib

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
