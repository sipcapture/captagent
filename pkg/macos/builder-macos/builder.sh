#!/bin/bash
set -euo pipefail
#
# Captagent - macOS Builder
# Runs natively on the host (no Docker); designed for GitHub Actions macos-latest runners.
#

VERSION_MAJOR="6.4"
VERSION_MINOR="5"
PROJECT_NAME="captagent"
OS="macos"
ARCH=$(uname -m)   # arm64 or x86_64
ITERATION="1"

export CODE_VERSION="${VERSION_MAJOR}.${VERSION_MINOR}"
export TMP_DIR="${TMP_DIR:-/tmp/build}"

# Install build dependencies
brew update --quiet
brew install --quiet autoconf automake libtool pkg-config \
    flex bison libpcap libuv json-c expat pcre

# fpm (Ruby gem)
gem install --no-document fpm -v 1.17.0 2>/dev/null || true

DEPENDENCY="libpcap,libuv,json-c,expat,pcre"

# Homebrew on Apple Silicon installs to /opt/homebrew; Intel uses /usr/local.
BREW_PREFIX="$(brew --prefix)"
export PKG_CONFIG_PATH="${BREW_PREFIX}/lib/pkgconfig:${BREW_PREFIX}/opt/expat/lib/pkgconfig:${PKG_CONFIG_PATH:-}"
export LDFLAGS="-L${BREW_PREFIX}/lib"
export CPPFLAGS="-I${BREW_PREFIX}/include"

cd "${TMP_DIR}/captagent_build"

# BUILD
./build.sh

# CONFIGURE
./configure

# Stage install
TMP_CAPT=/tmp/captagent
mkdir -p "${TMP_CAPT}"

make
make DESTDIR="${TMP_CAPT}" install

# Remove placeholder configs; install actual configs
rm -rf "${TMP_CAPT}/usr/local/captagent/etc/captagent/"*
cp -Rp "${TMP_DIR}/captagent_build/conf/"* "${TMP_CAPT}/usr/local/captagent/etc/captagent/"

# launchd plist
LAUNCH_DAEMONS="${TMP_CAPT}/Library/LaunchDaemons"
mkdir -p "${LAUNCH_DAEMONS}"
cp init/macos/io.sipcapture.captagent.plist "${LAUNCH_DAEMONS}/"

# Package
fpm -s dir -t osxpkg -C "${TMP_CAPT}" \
    --name "${PROJECT_NAME}" --version "${CODE_VERSION}" \
    -p "captagent-${VERSION_MAJOR}.${VERSION_MINOR}-${ITERATION}.${OS}.${ARCH}.pkg" \
    --iteration "${ITERATION}" \
    --osxpkg-identifier-prefix io.sipcapture \
    --description "${PROJECT_NAME} ${CODE_VERSION}" .

ls -alF ./*.pkg
cp -v ./*.pkg "${TMP_DIR}/"
echo "done!"
