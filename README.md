[![Build Status](https://travis-ci.org/artem-smotrakov/tlsbunny.svg?branch=master)](https://travis-ci.org/artem-smotrakov/tlsbunny)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Coverage](https://sonarcloud.io/api/project_badges/measure?metric=coverage&project=tlsbunny)](https://sonarcloud.io/component_measures?id=tlsbunny&metric=coverage&view=list)
[![Lines of code](https://sonarcloud.io/api/project_badges/measure?metric=ncloc&project=tlsbunny)](https://sonarcloud.io/component_measures?id=tlsbunny&metric=ncloc&view=list)
[![Maintainability](https://sonarcloud.io/api/project_badges/measure?metric=sqale_rating&project=tlsbunny)](https://sonarcloud.io/component_measures?id=tlsbunny&metric=Maintainability&view=list)

# tlsbunny

This is a framework for building negative tests and fuzzers for TLS 1.3 implementations.
The idea is to split the TLS handshake and application data exchange to simple steps 
which can be easily configured and re-used in various TLS clients and servers.

The framework provides a set of basic steps which can be used in a TLS connection, 
for example:

- Generating a `ClientHello` message
- Wrapping a handshake message into a `Handshake` structure
- Wrapping a handshake message into a `TLSPlaintext` structure
- Key exchange and deriving symmetric keys
- Receiving incoming encrypted data
- Parsing a `TLSCiphertext` message
- Decrypting a `TLSCiphertext` message
- and so on

These basic blocks allow to control and test each step in a TLS 1.3 connection.

The framework also provides an engine which runs specified actions.
The engine allows adding checks which can be run after a connection finishes.
The checks can examine the established connection, and detect potential issues.

## Supported features

- [TLS 1.3 protocol defined in RFC 8446](https://tools.ietf.org/html/rfc8446) 
- Client and server modes
- Key exchange with `ECDHE` mechanism and `secp256r1` curve
- Signatures with `ecdsa_secp256r1_sha256`
- Both client and server authentication
- AES-GCM cipher with 128-bit key

## Example

Here is what a simple HTTPS client looks like:

```java
Engine.init()
    .set("localhost", 433)
    .set(StructFactory.getDefault())
    .set(Negotiator.create(secp256r1))

    .run(generatingClientHello()
            .supportedVersions(TLSv13)
            .groups(secp256r1)
            .signatureSchemes(ecdsa_secp256r1_sha256)
            .keyShareEntries(Negotiator::createKeyShareEntry))
    .run(wrappingIntoHandshake()
            .type(client_hello)
            .update(Context.Element.first_client_hello))
    .run(wrappingIntoTLSPlaintexts()
            .type(handshake)
            .version(TLSv12))
    .send(OutgoingData::new)

    .send(OutgoingChangeCipherSpec::new)

    .until(Condition::serverDone)
    .receive(IncomingMessages::fromServer)

    .run(GeneratingFinished::new)
    .run(wrappingIntoHandshake()
            .type(finished)
            .update(Context.Element.client_finished))
    .run(WrappingHandshakeDataIntoTLSCiphertext::new)
    .send(OutgoingData::new)

    .run(PreparingHttpGetRequest::new)
    .run(WrappingApplicationDataIntoTLSCiphertext::new)
    .send(OutgoingData::new)

    .until(Condition::applicationDataReceived)
    .receive(IncomingMessages::fromServer)

    .run()
    .require(noFatalAlert());
```

## Fuzzing

tlsbunny provides several fuzzers for TLS 1.3 structures 
such as `TLSPlaintext`, `Handshake`, `ClientHello`, `Finished` and so on.

On the one hand, such a fuzzer is not going to be as fast as, for example, LibFuzzer.
On the other hand, the fuzzer can be easily re-used with multiple TLS implementations 
written in any language (not only C/C++). 

Traditionally, fuzzing is used for testing applications written in C/C++ 
to uncover memory corruption issues which most likely may have security implications. 
However, fuzzing can also be also used for testing applications written in other languages 
even if those languages, like Java, prevent using memory directly. 
See for example [AFL-based Java fuzzers and the Java Security Manager](https://www.modzero.ch/modlog/archives/2018/09/20/java_bugs_with_and_without_fuzzing/index.html).

No matter which programming language is used, 
a good TLS implementation should properly handle incorrect data 
and react in an expected way, for example, by throwing a documented exception. 
An unexpected behavior while processing incorrect data may still have security implications.
even it the TLS implementation is written in a memory-safe programming language.

## Example: Fuzzing TLSv1.3 server

Let's run `DeepHandshakeFuzzyClient` that fuzzes a TLSv1.3 server.

First, make sure that you use Java 11+. Then, build tlsbunny:

```bash
mvn clean install -DskipTests
```

Next, start a target TLSv1.3 server that you'd like to fuzz. Let's assume that it runs on port `50101`.
It is better to run the server with AddressSanitizer and other sanitizers. They'll report memory corruptions
that didn't result to a crash.

Then, prepare a config for tlsbunny:

```
client.certificate.path=certs/client_cert.pem
client.key.path=certs/client_key.pkcs8
target.host=localhost
target.port=50101
total=10000
```

The [certs](https://github.com/artem-smotrakov/tlsbunny/tree/master/certs) directory contains certiticates and keys for testing.

`total` is a number of iterations for the fuzzer.

Finally, run the fuzzer:

```bash
java -cp target/tlsbunny-1.0-SNAPSHOT-all.jar \
    com.gypsyengineer.tlsbunny.tls13.client.fuzzer.DeepHandshakeFuzzyClient
```

Watch how the server handles fuzzed TLS messages.

## Similar projects

- [tlsfuzzer](https://github.com/tomato42/tlsfuzzer): 
  SSL and TLS protocol test suite and fuzzer (python)
- [TLS-Attacker](https://github.com/RUB-NDS/TLS-Attacker): 
  TLS-Attacker is a Java-based framework for analyzing TLS libraries. 
  It is developed by the Ruhr University Bochum and the Hackmanit GmbH.

## Discovered bugs

- [Java: TLS 1.3 server fails if ClientHello doesn't have pre_shared_key and psk_key_exchange_modes](https://bugs.openjdk.java.net/browse/JDK-8210334), [patch](http://hg.openjdk.java.net/jdk/jdk/rev/b6ccd982e33d)
- [wolfSSL: Buffer overread while parsing key_share extension in TLS 1.3](https://wolfssl.zendesk.com/hc/en-us/requests/4798), [test](src/main/java/com/gypsyengineer/tlsbunny/poc/wolfssl/HeapOverReadInKeyShareEntry.java), [patch](https://github.com/wolfSSL/wolfssl/pull/2082)
- [wolfSSL: Buffer over-read in DoTls13SupportedVersions()](https://wolfssl.zendesk.com/hc/en-us/requests/5487), [test](src/main/java/com/gypsyengineer/tlsbunny/poc/wolfssl/SupportedVersionsHeapOverRead.java), [patch](https://github.com/wolfSSL/wolfssl/pull/2381)
