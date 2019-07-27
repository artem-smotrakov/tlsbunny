package com.gypsyengineer.tlsbunny.tls13.fuzzer;

import com.gypsyengineer.tlsbunny.fuzzer.FuzzedVector;
import com.gypsyengineer.tlsbunny.tls.Random;
import com.gypsyengineer.tlsbunny.tls.Vector;
import com.gypsyengineer.tlsbunny.tls13.struct.CipherSuite;
import com.gypsyengineer.tlsbunny.tls13.struct.ClientHello;
import com.gypsyengineer.tlsbunny.tls13.struct.CompressionMethod;
import com.gypsyengineer.tlsbunny.tls13.struct.ProtocolVersion;
import org.junit.Test;

import java.util.List;

import static com.gypsyengineer.tlsbunny.tls13.fuzzer.SimpleVectorFuzzer.simpleVectorFuzzer;
import static com.gypsyengineer.tlsbunny.tls13.fuzzer.Target.*;
import static org.junit.Assert.*;

public class CipherSuitesFuzzerTest {

    @Test
    public void iterate() {
        CipherSuitesFuzzer fuzzer = CipherSuitesFuzzer.cipherSuitesFuzzer();
        fuzzer.fuzzer(simpleVectorFuzzer());

        fuzzer.targets(client_hello);
        assertArrayEquals(new Target[]{client_hello}, fuzzer.targets());

        assertTrue(fuzzer.canFuzz());

        int expectedState = 0;

        Vector<CipherSuite> cipherSuites = Vector.wrap(2, List.of(
                CipherSuite.TLS_AES_128_GCM_SHA256,
                CipherSuite.TLS_AES_128_CCM_8_SHA256,
                CipherSuite.TLS_CHACHA20_POLY1305_SHA256));

        int m = 10;
        for (int i = 0; i < m; i++) {
            assertTrue(fuzzer.canFuzz());
            assertEquals("client_hello:" + expectedState, fuzzer.state());

            Vector<CipherSuite> fuzzed = fuzzer.fuzz(cipherSuites);
            assertNotEquals(fuzzed, cipherSuites);
            assertEquals(fuzzed, fuzzer.fuzz(cipherSuites));

            fuzzer.moveOn();
            expectedState++;
        }
    }

    @Test
    public void consistency() {
        CipherSuitesFuzzer one = CipherSuitesFuzzer.cipherSuitesFuzzer();
        one.fuzzer(simpleVectorFuzzer());
        one.targets(client_hello);
        assertTrue(one.canFuzz());


        CipherSuitesFuzzer two = CipherSuitesFuzzer.cipherSuitesFuzzer();
        two.fuzzer(simpleVectorFuzzer());
        two.targets(client_hello);
        assertTrue(two.canFuzz());

        Vector<CipherSuite> cipherSuites = Vector.wrap(2, List.of(
                CipherSuite.TLS_AES_128_GCM_SHA256,
                CipherSuite.TLS_AES_128_CCM_8_SHA256,
                CipherSuite.TLS_CHACHA20_POLY1305_SHA256));

        while (one.canFuzz()) {
            Vector fuzzedOne = one.fuzz(cipherSuites);
            Vector fuzzedTwo = two.fuzz(cipherSuites);
            assertEquals(fuzzedOne, fuzzedTwo);
            assertNotEquals(fuzzedOne, cipherSuites);
            assertNotEquals(fuzzedTwo, cipherSuites);

            one.moveOn();
            two.moveOn();
        }

        assertFalse(one.canFuzz());
        assertFalse(two.canFuzz());
    }

    @Test
    public void clientHello() {
        CipherSuitesFuzzer fuzzer = CipherSuitesFuzzer.cipherSuitesFuzzer();
        fuzzer.fuzzer(simpleVectorFuzzer());

        assertArrayEquals(new Target[]{client_hello, server_hello}, fuzzer.targets());

        fuzzer.moveOn();
        ClientHello clientHelloOne = fuzzer.createClientHello(
                ProtocolVersion.TLSv13,
                Random.create(),
                new byte[8],
                List.of(CipherSuite.TLS_AES_128_GCM_SHA256),
                List.of(CompressionMethod.None),
                List.of());
        assertTrue(clientHelloOne.cipherSuites() instanceof FuzzedVector);

        fuzzer.moveOn();
        ClientHello clientHelloTwo = fuzzer.createClientHello(
                ProtocolVersion.TLSv13,
                Random.create(),
                new byte[8],
                List.of(CipherSuite.TLS_AES_128_GCM_SHA256),
                List.of(CompressionMethod.None),
                List.of());
        assertTrue(clientHelloTwo.cipherSuites() instanceof FuzzedVector);

        assertNotEquals(clientHelloOne, clientHelloTwo);

        fuzzer.targets(tls_plaintext);
        assertArrayEquals(new Target[]{tls_plaintext}, fuzzer.targets());

        fuzzer.moveOn();
        clientHelloOne = fuzzer.createClientHello(
                ProtocolVersion.TLSv13,
                Random.create(),
                new byte[8],
                List.of(CipherSuite.TLS_AES_128_GCM_SHA256),
                List.of(CompressionMethod.None),
                List.of());
        assertFalse(clientHelloOne.cipherSuites() instanceof FuzzedVector);

        fuzzer.moveOn();
        clientHelloTwo = fuzzer.createClientHello(
                ProtocolVersion.TLSv13,
                Random.create(),
                new byte[8],
                List.of(CipherSuite.TLS_AES_128_GCM_SHA256),
                List.of(CompressionMethod.None),
                List.of());
        assertFalse(clientHelloTwo.cipherSuites() instanceof FuzzedVector);

        assertEquals(clientHelloOne, clientHelloTwo);

        fuzzer.targets(client_hello);
        assertArrayEquals(new Target[]{client_hello}, fuzzer.targets());

        fuzzer.moveOn();
        clientHelloOne = fuzzer.createClientHello(
                ProtocolVersion.TLSv13,
                Random.create(),
                new byte[8],
                List.of(CipherSuite.TLS_AES_128_GCM_SHA256),
                List.of(CompressionMethod.None),
                List.of());
        assertTrue(clientHelloOne.cipherSuites() instanceof FuzzedVector);

        fuzzer.moveOn();
        clientHelloTwo = fuzzer.createClientHello(
                ProtocolVersion.TLSv13,
                Random.create(),
                new byte[8],
                List.of(CipherSuite.TLS_AES_128_GCM_SHA256),
                List.of(CompressionMethod.None),
                List.of());
        assertTrue(clientHelloTwo.cipherSuites() instanceof FuzzedVector);

        assertNotEquals(clientHelloOne, clientHelloTwo);
    }
}
