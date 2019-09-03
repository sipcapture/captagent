#!/bin/bash
# CaptAgent 6 - Debian 9 Builder

OS="stretch"
VERSION_MAJOR="6.3"
VERSION_MINOR="1"
export TMP_DIR=/tmp
export EXEC_DIR=$(pwd)

# install libs
cd $TMP_DIR
apt-get -y update && apt-get -y install git make gcc libexpat-dev libpcap-dev libjson-c-dev libuv1-dev libtool automake autoconf flex bison

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

# install ruby and fpm
apt-get -y install ruby-dev rubygems build-essential
gem install rake
gem install --no-ri --no-rdoc fpm

#DEPENDECY
DEPENDENCY=`dpkg -l | grep -E "libexpat|libpcap|libjson-c|libuv" | grep -v "dev" | awk '{print $2}' | sed -e 's/:amd64//g' | tr '\n' ','`
DEPENDENCY=${DEPENDENCY%?}; #Remove last characters
echo $DEPENDENCY;

# create deb pkg with fpm
fpm -s dir -t deb -C $TMP_DIR/captagent_install --name captagent --version $CODEVERSION --iteration 1 \
    -p "captagent-${CODEVERSION}.${OS}.amd64.deb" \
    --deb-no-default-config-files --depends ${DEPENDENCY} --description "captagent" .
ls -alF *.deb
cp -v *.deb /scripts/

# clean up temp files
cd $TMP_DIR; rm -rf ./captagent ./captagent_install
cd $EXEC_DIR

echo "done!"
