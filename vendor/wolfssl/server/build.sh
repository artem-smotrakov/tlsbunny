#!/bin/bash

if [ ! -d ws ]; then
    git clone git@github.com:wolfSSL/wolfssl.git ws
fi

prefix=$(pwd)/wolfssl-build
mkdir -p "${prefix}"

cd ws || exit
git pull origin master && echo repository updated ... || exit 1

export CFLAGS="-fsanitize=address -fno-omit-frame-pointer -fprofile-arcs -ftest-coverage"
export CXXFLAGS="-fsanitize=address -fno-omit-frame-pointer -fprofile-arcs -ftest-coverage"
export LDFLAGS="-fsanitize=address -fprofile-arcs -ftest-coverage"

if [ ! -f configure ]; then
    ./autogen.sh
fi

./configure \
    --prefix="${prefix}" \
    --enable-tls13 \
    --enable-webserver \
    --enable-debug \
    --enable-psk \
    --enable-poly1305 \
    --enable-chacha \
    --enable-session-ticket

make
make install
