#!/bin/bash

set -e

export CFLAGS="-fsanitize=address -fno-omit-frame-pointer -g -O1"
export CXXFLAGS="-fsanitize=address -fno-omit-frame-pointer"
export LDFLAGS="-fsanitize=address"

homedir=$(pwd)

if [ ! -d nettle-3.4.1 ]; then
    rm -rf nettle-3.4.1.tar.gz
    wget https://ftp.gnu.org/gnu/nettle/nettle-3.4.1.tar.gz
    tar xf nettle-3.4.1.tar.gz
    cd nettle-3.4.1
    ./configure \
        --disable-openssl \
        --enable-shared
    make
    sudo make install
fi

cd "${homedir}"

if [ ! -d gnutls ]; then
    git clone https://gitlab.com/gnutls/gnutls.git
fi

cd gnutls
git pull origin master

prefix=${homedir}/gnutls-build
mkdir -p "${prefix}"

./bootstrap
git checkout --force
git apply ${homedir}/serv.c.patch
export LD_LIBRARY_PATH=${LD_LIBRARY_PATH}:/usr/local/lib
./configure \
    --prefix="${prefix}" \
    --with-included-libtasn1 \
    --with-guile-site-dir=no \
    --disable-guile
make
make install
