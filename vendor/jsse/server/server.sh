#!/bin/bash

rm -rf fuzzer.log

${JAVA_HOME}/bin/java -cp ../../../target/tlsbunny-1.0-SNAPSHOT-all.jar \
    -Djavax.net.ssl.keyStore=../../../certs/keystore \
    -Djavax.net.ssl.keyStorePassword=passphrase \
        com.gypsyengineer.tlsbunny.poc.jsse.JavaTls13Server 2>&1 \
            | tee server.log
