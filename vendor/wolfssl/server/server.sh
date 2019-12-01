#!/bin/bash

# looks like wolfssl server can exit if a wrong message was received
# so run it in a loop

set -x

rm -rf server.log
cd ws || exit
touch stop.file
echo "note: remove $(pwd)/stop.file to stop the server loop"
while [ -f stop.file ];
do
     ./examples/server/.libs/server \
        -p 40101 \
        -v 4 \
        -l TLS13-AES128-GCM-SHA256 \
        -d -i -g -b -x \
        -c ../../../../certs/server_cert.pem \
        -k ../../../../certs/server_key.pem 2>&1 \
            | tee -a ../server.log

    if grep AddressSanitizer ../server.log > /dev/null 2>&1 ; then
        echo "Achtung! AddressSanitizer found something!"
        exit 1
    fi
done
