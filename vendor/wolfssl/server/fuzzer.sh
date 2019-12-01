#!/bin/bash

rm -rf fuzzer.log

java -cp ../../../target/tlsbunny-1.0-SNAPSHOT-all.jar \
    com.gypsyengineer.tlsbunny.tls13.client.fuzzer.DeepHandshakeFuzzyClient resumption 2>&1 \
        | tee fuzzer.log

if grep AddressSanitizer server.log ; then
    echo "Achtung! AddressSanitizer found something!"
fi
