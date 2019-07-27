package com.gypsyengineer.tlsbunny.tls13.fuzzer;

import com.gypsyengineer.tlsbunny.TestUtils;
import com.gypsyengineer.tlsbunny.TestUtils.FakeTestAnalyzer;
import com.gypsyengineer.tlsbunny.tls13.client.HttpsClient;
import com.gypsyengineer.tlsbunny.tls13.connection.*;
import com.gypsyengineer.tlsbunny.tls13.server.HttpsServer;
import com.gypsyengineer.tlsbunny.tls13.utils.FuzzerConfig;
import com.gypsyengineer.tlsbunny.utils.Config;
import com.gypsyengineer.tlsbunny.output.Output;
import com.gypsyengineer.tlsbunny.utils.SystemPropertiesConfig;
import org.junit.Test;

import static com.gypsyengineer.tlsbunny.tls13.fuzzer.MutatedConfigs.*;
import static com.gypsyengineer.tlsbunny.tls13.server.HttpsServer.httpsServer;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;

public class MutatedClientTest {

    private static final int total = 3;
    private static final int parts = 1;

    // number of connections during fuzzing (we don't forget a smoke test)
    private static final int n = total + 1;

    private Config clientConfig = SystemPropertiesConfig.load();

    @Test
    public void tlsPlaintext() throws Exception {
        test(minimized(tlsPlaintextConfigs(clientConfig)));
    }

    @Test
    public void handshake() throws Exception {
        test(minimized(handshakeConfigs(clientConfig)));
    }

    @Test
    public void clientHello() throws Exception {
        test(minimized(clientHelloConfigs(clientConfig)));
    }

    @Test
    public void ccs() throws Exception {
        test(minimized(ccsConfigs(clientConfig)));
    }

    @Test
    public void finished() throws Exception {
        test(minimized(finishedConfigs(clientConfig)));
    }

    @Test
    public void cipherSuites() throws Exception {
        test(minimized(cipherSuitesConfigs(clientConfig)));
    }

    @Test
    public void extensionVector() throws Exception {
        test(minimized(extensionVectorConfigs(clientConfig)));
    }

    @Test
    public void legacySessionId() throws Exception {
        test(minimized(legacySessionIdConfigs(clientConfig)));
    }

    @Test
    public void legacyCompressionMethods() throws Exception {
        test(minimized(legacyCompressionMethodsConfigs(clientConfig)));
    }

    public void test(FuzzerConfig[] configs) throws Exception {
        for (FuzzerConfig config : configs) {
            test(config);
        }
    }

    public void test(FuzzerConfig fuzzerConfig) throws Exception {
        Output serverOutput = Output.standard("server");
        Output clientOutput = Output.standardClient();

        Config serverConfig = SystemPropertiesConfig.load();

        HttpsServer server = httpsServer()
                .set(serverConfig)
                .set(serverOutput)
                .maxConnections(n);

        MutatedClient fuzzyClient = new MutatedClient(
                new HttpsClient(), clientOutput, fuzzerConfig);

        FakeTestAnalyzer analyzer = new FakeTestAnalyzer();
        analyzer.set(clientOutput);

        try (fuzzyClient; server; clientOutput; serverOutput) {
            server.start();

            fuzzerConfig.port(server.port());

            fuzzyClient
                    .set(fuzzerConfig)
                    .set(clientOutput)
                    .set(analyzer)
                    .connect();
        }

        analyzer.run();
        assertEquals(n, analyzer.engines().length);
        for (Engine engine : analyzer.engines()) {
            assertFalse(engine.context().hasAlert());
        }
    }

    private static FuzzerConfig[] minimized(FuzzerConfig[] configs) {
        FuzzerConfig config = configs[0];
        config.total(total);
        config.parts(parts);

        if (config.factory() instanceof MutatedStructFactory) {
            MutatedStructFactory factory = (MutatedStructFactory) config.factory();
            factory.fuzzer(new TestUtils.FakeFlipFuzzer());
        }

        if (config.factory() instanceof LegacySessionIdFuzzer) {
            LegacySessionIdFuzzer factory = (LegacySessionIdFuzzer) config.factory();
            factory.fuzzer(new TestUtils.FakeVectorFuzzer());
        }

        if (config.factory() instanceof LegacyCompressionMethodsFuzzer) {
            LegacyCompressionMethodsFuzzer factory = (LegacyCompressionMethodsFuzzer) config.factory();
            factory.fuzzer(new TestUtils.FakeCompressionMethodFuzzer());
        }

        if (config.factory() instanceof CipherSuitesFuzzer) {
            CipherSuitesFuzzer factory = (CipherSuitesFuzzer) config.factory();
            factory.fuzzer(new TestUtils.FakeCipherSuitesFuzzer());
        }

        if (config.factory() instanceof ExtensionVectorFuzzer) {
            ExtensionVectorFuzzer factory = (ExtensionVectorFuzzer) config.factory();
            factory.fuzzer(new TestUtils.FakeExtensionVectorFuzzer());
        }

        return new FuzzerConfig[] { config };
    }
}
