package com.gypsyengineer.tlsbunny.tls13.fuzzer;

import com.gypsyengineer.tlsbunny.TestUtils.*;
import com.gypsyengineer.tlsbunny.fuzzer.Fuzzer;
import com.gypsyengineer.tlsbunny.tls13.client.Client;
import com.gypsyengineer.tlsbunny.tls13.client.HttpsClient;
import com.gypsyengineer.tlsbunny.tls13.connection.Engine;
import com.gypsyengineer.tlsbunny.tls13.struct.StructFactory;
import com.gypsyengineer.tlsbunny.tls13.utils.FuzzerConfig;
import com.gypsyengineer.tlsbunny.utils.Config;
import com.gypsyengineer.tlsbunny.output.Output;
import com.gypsyengineer.tlsbunny.utils.SystemPropertiesConfig;
import org.junit.Test;

import static com.gypsyengineer.tlsbunny.tls13.fuzzer.MutatedConfigs.*;
import static com.gypsyengineer.tlsbunny.tls13.fuzzer.MutatedConfigs.legacyCompressionMethodsConfigs;
import static com.gypsyengineer.tlsbunny.tls13.fuzzer.MutatedConfigs.legacySessionIdConfigs;
import static com.gypsyengineer.tlsbunny.tls13.fuzzer.MutatedServer.mutatedServer;
import static com.gypsyengineer.tlsbunny.tls13.server.HttpsServer.httpsServer;
import static org.junit.Assert.*;

public class MutatedServerTest {

    private static final int total = 3;
    private static final int parts = 1;

    private static final int no_message_fuzzed = 0;
    private static final int expected_fuzzed_tls_plaintexts = 7;
    private static final int expected_fuzzed_handshake = 5;
    private static final int expected_fuzzed_ccs = 1;
    private static final int expected_fuzzed_finished = 1;
    private static final int expected_fuzzed_extension_vector = 1;
    private static final int expected_fuzzed_legacy_session_id = 1;
    private static final int expected_fuzzed_server_hello = 1;
    private static final int expected_fuzzed_encrypted_extensions = 1;

    // number of connections during fuzzing
    private static final int n = total;

    private Config serverConfig = SystemPropertiesConfig.load();

    @Test
    public void tlsPlaintext() throws Exception {
        test(minimized(tlsPlaintextConfigs(serverConfig)), expected_fuzzed_tls_plaintexts);
    }

    @Test
    public void handshake() throws Exception {
        test(minimized(handshakeConfigs(serverConfig)), expected_fuzzed_handshake);
    }

    @Test
    public void clientHello() throws Exception {
        test(minimized(clientHelloConfigs(serverConfig)), no_message_fuzzed);
    }

    @Test
    public void serverHello() throws Exception {
        test(minimized(serverHelloConfigs(serverConfig)), expected_fuzzed_server_hello);
    }

    @Test
    public void encryptedExtensions() throws Exception {
        test(minimized(encryptedExtensionsConfigs(serverConfig)), expected_fuzzed_encrypted_extensions);
    }

    @Test
    public void ccs() throws Exception {
        test(minimized(ccsConfigs(serverConfig)), expected_fuzzed_ccs);
    }

    @Test
    public void finished() throws Exception {
        test(minimized(finishedConfigs(serverConfig)), expected_fuzzed_finished);
    }

    @Test
    public void cipherSuites() throws Exception {
        test(minimized(cipherSuitesConfigs(serverConfig)), no_message_fuzzed);
    }

    @Test
    public void extensionVector() throws Exception {
        test(minimized(extensionVectorConfigs(serverConfig)), expected_fuzzed_extension_vector);
    }

    @Test
    public void legacySessionId() throws Exception {
        test(minimized(legacySessionIdConfigs(serverConfig)), expected_fuzzed_legacy_session_id);
    }

    @Test
    public void legacyCompressionMethods() throws Exception {
        test(minimized(legacyCompressionMethodsConfigs(serverConfig)), no_message_fuzzed);
    }

    public void test(FuzzerConfig[] configs, int expectedFuzzedMessages)
            throws Exception {

        for (FuzzerConfig config : configs) {
            test(config, expectedFuzzedMessages);
        }
    }

    public void test(FuzzerConfig fuzzerConfig, int expectedFuzzedMessages)
            throws Exception {

        Output serverOutput = Output.standard("server");
        Output clientOutput = Output.standardClient();

        Config clientConfig = SystemPropertiesConfig.load();

        MutatedServer server = mutatedServer(httpsServer(), fuzzerConfig).set(serverOutput);

        Client client = new HttpsClient()
                .set(clientConfig)
                .set(clientOutput);

        try (client; server; clientOutput; serverOutput) {
            server.start();

            clientConfig.port(server.port());

            for (int i = 0; i < n; i++) {
                client.connect();
                assertEquals(1, client.engines().length);
                for (Engine engine : client.engines()) {
                    assertFalse(engine.context().hasAlert());
                }
            }
        }

        assertEquals(n, server.engines().length);
        for (Engine engine : server.engines()) {
            assertFalse(engine.context().hasAlert());
        }

        StructFactory structFactory = fuzzerConfig.factory();
        assertTrue(structFactory instanceof FuzzyStructFactory);
        FuzzyStructFactory fuzzyStructFactory = (FuzzyStructFactory) structFactory;
        Fuzzer fuzzer = fuzzyStructFactory.fuzzer();
        assertTrue(fuzzer instanceof FakeFuzzer);
        FakeFuzzer fakeFuzzer = (FakeFuzzer) fuzzer;
        assertEquals(n * expectedFuzzedMessages, fakeFuzzer.count());
    }

    private static FuzzerConfig[] minimized(FuzzerConfig[] configs) {
        FuzzerConfig config = configs[0];
        config.total(total);
        config.parts(parts);

        if (config.factory() instanceof MutatedStructFactory) {
            MutatedStructFactory factory = (MutatedStructFactory) config.factory();
            factory.fuzzer(new FakeFlipFuzzer());
        }

        if (config.factory() instanceof LegacySessionIdFuzzer) {
            LegacySessionIdFuzzer factory = (LegacySessionIdFuzzer) config.factory();
            factory.fuzzer(new FakeVectorFuzzer());
        }

        if (config.factory() instanceof LegacyCompressionMethodsFuzzer) {
            LegacyCompressionMethodsFuzzer factory = (LegacyCompressionMethodsFuzzer) config.factory();
            factory.fuzzer(new FakeCompressionMethodFuzzer());
        }

        if (config.factory() instanceof CipherSuitesFuzzer) {
            CipherSuitesFuzzer factory = (CipherSuitesFuzzer) config.factory();
            factory.fuzzer(new FakeCipherSuitesFuzzer());
        }

        if (config.factory() instanceof ExtensionVectorFuzzer) {
            ExtensionVectorFuzzer factory = (ExtensionVectorFuzzer) config.factory();
            factory.fuzzer(new FakeExtensionVectorFuzzer());
        }

        return new FuzzerConfig[] { config };
    }
}
