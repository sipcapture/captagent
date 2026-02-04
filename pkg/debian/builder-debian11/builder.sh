#!/bin/bash
#
# Captgent - Debian 11 Builder
#

VERSION_MAJOR="6.4"
VERSION_MINOR="1"
PROJECT_NAME="captagent"
OS="bullseye"
ARCH=$(dpkg --print-architecture)

export CODE_VERSION="${VERSION_MAJOR}.${VERSION_MINOR}"
export TMP_DIR=/tmp/build

apt-get -y update

# gcc - make
apt-get -y install make gcc-9 libtool automake autoconf build-essential

# flex
apt-get -y install flex libfl-dev

# libssl - libmcrypt
apt-get -y install libssl-dev libmcrypt-dev libgcrypt20-dev

# various
apt-get -y install curl libexpat-dev libpcap-dev libjson-c-dev bison libpcre3-dev libuv1-dev libgpg-error-dev

# ruby - fpm
apt-get -y install ruby-dev rubygems
#gem install rake
gem install public_suffix -v 4.0.7
gem install fpm

DEPENDENCY=$(dpkg -l | grep -E "libmcrypt|libfl|libexpat|libpcap|libjson-c|libpcre3|libuv" | grep -v "dev" | grep -v "pcre32" | awk '{print $2}' | sed -e "s/:${ARCH}//g" | tr '\n' ',')
# Remove last characters
DEPENDENCY=${DEPENDENCY%?};

cp -Rp ${TMP_DIR}/captagent_build .
cd captagent_build

# BUILD
./build.sh

# CONFIGURE
./configure ${STRING_PARAM}

# Create dir for Captagent
TMP_CAPT=/tmp/captagent
mkdir -p ${TMP_CAPT}

# MAKE and INSTALL
make
make DESTDIR=${TMP_CAPT} install

# clean set
rm -rf  ${TMP_CAPT}/usr/local/captagent/etc/captagent/*
# copy configs
cp -Rp ${TMP_DIR}/captagent_build/conf/* ${TMP_CAPT}/usr/local/captagent/etc/captagent/

# Configs
mkdir -p ${TMP_CAPT}/etc/systemd/system/
mkdir -p ${TMP_CAPT}/etc/init.d/
mkdir -p ${TMP_CAPT}/etc/default/

# Service
cp init/deb/debian/captagent.service ${TMP_CAPT}/etc/systemd/system/
cp init/deb/debian/captagent.default ${TMP_CAPT}/etc/default/captagent
cp init/deb/debian/captagent.init ${TMP_CAPT}/etc/init.d/captagent
chmod +x ${TMP_CAPT}/etc/init.d/captagent

# FPM CAPTAGENT
fpm -s dir -t deb -C ${TMP_CAPT} \
        --name ${PROJECT_NAME} --version ${CODE_VERSION} \
        -p "captagent_${VERSION_MAJOR}.${VERSION_MINOR}.${OS}.${ARCH}.deb" \
        --config-files /usr/local/${PROJECT_NAME}/etc/${PROJECT_NAME} --config-files /etc/default/${PROJECT_NAME} \
        --iteration 1 --deb-no-default-config-files --depends ${DEPENDENCY} --description "${PROJECT_NAME} ${CODE_VERSION}" .

ls -alF *.deb
cp -v *.deb ${TMP_DIR}
rm -rf captagent_pro
echo "done!"
