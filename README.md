[![Build Status](https://travis-ci.org/artem-smotrakov/tlsbunny.svg?branch=master)](https://travis-ci.org/artem-smotrakov/tlsbunny)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)

[![Coverage](https://sonarcloud.io/api/project_badges/measure?metric=coverage&project=tlsbunny)](https://sonarcloud.io/component_measures?id=tlsbunny&metric=coverage&view=list)
[![Lines of code](https://sonarcloud.io/api/project_badges/measure?metric=ncloc&project=tlsbunny)](https://sonarcloud.io/component_measures?id=tlsbunny&metric=ncloc&view=list)
[![Maintainability](https://sonarcloud.io/api/project_badges/measure?metric=sqale_rating&project=tlsbunny)](https://sonarcloud.io/component_measures?id=tlsbunny&metric=Maintainability&view=list)
[![Reliability](https://sonarcloud.io/api/project_badges/measure?metric=sqale_rating&project=tlsbunny)](https://sonarcloud.io/component_measures?id=tlsbunny&metric=Reliability&view=list)
[![Security](https://sonarcloud.io/api/project_badges/measure?metric=security_rating&project=tlsbunny)](https://sonarcloud.io/component_measures?id=tlsbunny&metric=Security&view=list)


# tlsbunny

This is a framework for building negative tests and fuzzers for TLS 1.3 implementations.
The idea is to split the handshake process and data exchange to simple steps which are easy to configure and re-use.
The framework provides a set of basic steps which can be used in TLS 1.3 communication, for example:

- generating a ClientHello message
- wrapping a handshake message into a Handshake structure
- wrapping a handshake message into a TLSPlaintext structure
- key exchange and generating symmetric keys
- receiving incoming data
- parsing a TLSCiphertext message
- decrypting a TLSCiphertext message and so on

These basic blocks allow to control and test each step in TLS 1.3 connection.

The framework also provides an engine which runs specified actions. The engine supports adding checks and analyzers which run after a connection finishes.

Here is an example on HTTPS connection using TLS 1.3:

```java
        Engine.init()
                .target(config.host())
                .target(config.port())
                .send(new OutgoingClientHello())
                .send(new OutgoingChangeCipherSpec())
                .receive(new IncomingServerHello())
                .receive(new IncomingChangeCipherSpec())
                .receive(new IncomingEncryptedExtensions())
                .receive(new IncomingCertificate())
                .receive(new IncomingCertificateVerify())
                .receive(new IncomingFinished())
                .send(new OutgoingFinished())
                .send(new OutgoingHttpGetRequest())
                .receive(new IncomingApplicationData());

                .connect()
                .run(new NoAlertCheck());
```

## Supported features

- [TLS 1.3 protocol defined in RFC 8446](https://tools.ietf.org/html/rfc8446) 
- Client and server sides
- Client and server authentication
- Key exchange with ECDHE using secp256r1 curve
- ecdsa_secp256r1_sha256 signatures
- AES-GCM cipher with 128-bit key

## Fuzzing

tlsbunny provides several fuzzers for TLS 1.3 sturctures such as TLSPlaintext, Handshake, ClientHello and Finished.
Fuzzers based on the framework can generate fuzzed messages and feed a target application via stdin, files or network sockets.

On the one hand, such a fuzzer is not going to be as fast as LibFuzzer. On the other hand, the fuzzer can be easily re-used with multiple TLS implementations written in different languages (not only C/C++). 

Traditionally, fuzzing is used for testing applications written in C/C++ to uncover memory corruption issues which most likely may have security implications. But fuzzing techniques can also be used for testing applications written in other languages even if those languages prevent using memory directly like Java. See for example [AFL-based Java fuzzers and the Java Security Manager](https://www.modzero.ch/modlog/archives/2018/09/20/java_bugs_with_and_without_fuzzing/index.html).

No matter which language is used, a good TLS implementation should properly handle incorrect data and react with an expected action, for example, by thowing a documented exception. An unexpected behavior in processing incorrect data may still have security implications.

## Similar projects

- [tlsfuzzer](https://github.com/tomato42/tlsfuzzer): SSL and TLS protocol test suite and fuzzer (python)
- [TLS-Attacker](https://github.com/RUB-NDS/TLS-Attacker): TLS-Attacker is a Java-based framework for analyzing TLS libraries. It is developed by the Ruhr University Bochum and the Hackmanit GmbH.
