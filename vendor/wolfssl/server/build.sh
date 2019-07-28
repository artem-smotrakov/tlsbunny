#!/bin/bash

if [ ! -d ws ]; then
    git clone git@github.com:wolfSSL/wolfssl.git ws
fi

prefix=$(pwd)/wolfssl-build
mkdir -p "${prefix}"

cd ws || exit
git pull

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
    --enable-debug

make
make install
