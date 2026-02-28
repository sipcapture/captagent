#!/bin/bash
set -euo pipefail
#
# Captagent - Rocky Linux 9 Builder
#

VERSION_MAJOR="6.4"
VERSION_MINOR="2"
PROJECT_NAME="captagent"
OS="rocky"
VERSION_OS="el9"

export CODE_VERSION="${VERSION_MAJOR}.${VERSION_MINOR}"
export TMP_DIR=/tmp/build

# pkgconfig
dnf -y install pkgconfig

dnf -y install dnf-plugins-core
# In Rocky Linux 9, powertools is called crb (CodeReady Builder)
dnf -y config-manager --enable crb

echo "ENABLE EPEL"
dnf -y install https://dl.fedoraproject.org/pub/epel/epel-release-latest-9.noarch.rpm

dnf -y update

# gcc - make
dnf -y install gcc make automake libtool

# flex
dnf -y install flex flex-devel

# mcrypt
dnf --enablerepo=epel -y install libmcrypt-devel

# libuv
dnf -y install libuv libuv-devel

# git
dnf -y install git

# ruby - fpm
dnf -y install ruby ruby-devel rpm-build rubygems
gem install --no-document fpm -v 1.17.0

# openssl
dnf -y install openssl-devel

# various
dnf -y install json-c-devel expat-devel libpcap-devel bison pcre-devel

DEPENDENCY="libmcrypt,expat,json-c,libpcap,pcre,libuv";

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
        --iteration 9 --depends ${DEPENDENCY} --description "${PROJECT_NAME} ${CODE_VERSION}" .


ls -alF *.rpm
cp -v *.rpm ${TMP_DIR}
rm -rf captagent_build
echo "done!"
