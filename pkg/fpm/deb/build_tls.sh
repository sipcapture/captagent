#!/bin/bash
# CaptAgent 6 (TLS version) - Debian 9 Builder

INV=1
OS="stretch"
VERSION_MAJOR="6.4"
VERSION_MINOR="0"

# install libs
cd /tmp
apt-get -y update  && apt-get -y install git make gcc libexpat-dev libpcap-dev libjson-c-dev libuv1-dev libtool automake autoconf flex bison

# clone captagent and build it
git clone https://github.com/sipcapture/captagent captagent
cd captagent/
./build.sh
./configure --enable-tls --enable-ssl
make

# version
mkdir -p /tmp/captagent
make DESTDIR=/tmp/captagent_install install
export CODEVERSION=$(./src/captagent -v | cut -c10-)

# install ruby and fpm
apt-get -y install ruby-dev rubygems build-essential
gem install rake
gem install --no-ri --no-rdoc fpm

#DEPENDECY
DEPENDENCY=`dpkg -l | grep -E "libexpat|libpcap|libjson-c|libuv" | grep -v "dev" | awk '{print $2}' | sed -e 's/:amd64//g' | tr '\n' ','`
DEPENDENCY=${DEPENDENCY%?}; #Remove last characters
echo $DEPENDENCY;

# create deb pkg with fpm
fpm -s dir -t deb -C /tmp/captagent_install --name captagent --version $CODEVERSION --iteration 1 \
    -p "captagent_${VERSION_MAJOR}.${VERSION_MINOR}-${INV}.${OS}.amd64.deb" \
    --deb-no-default-config-files --depends ${DEPENDENCY} --description "captagent" .
ls -alF *.deb
cp -v *.deb /scripts/

# clean up temp files
cd /tmp; rm -rf ./captagent ./captagent_install

echo "done!"
