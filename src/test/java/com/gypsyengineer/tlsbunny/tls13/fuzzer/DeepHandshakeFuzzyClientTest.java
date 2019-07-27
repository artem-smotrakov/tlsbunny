package com.gypsyengineer.tlsbunny.tls13.fuzzer;

import com.gypsyengineer.tlsbunny.TestUtils;
import com.gypsyengineer.tlsbunny.TestUtils.FakeTestAnalyzer;
import com.gypsyengineer.tlsbunny.tls13.client.HttpsClient;
import com.gypsyengineer.tlsbunny.tls13.connection.check.NoAlertCheck;
import com.gypsyengineer.tlsbunny.tls13.connection.Engine;
import com.gypsyengineer.tlsbunny.tls13.server.HttpsServer;
import com.gypsyengineer.tlsbunny.tls13.struct.HandshakeType;
import com.gypsyengineer.tlsbunny.tls13.utils.FuzzerConfig;
import com.gypsyengineer.tlsbunny.utils.Config;
import com.gypsyengineer.tlsbunny.output.Output;
import com.gypsyengineer.tlsbunny.utils.SystemPropertiesConfig;
import org.junit.Test;

import static com.gypsyengineer.tlsbunny.tls13.server.HttpsServer.httpsServer;
import static com.gypsyengineer.tlsbunny.tls13.struct.HandshakeType.*;
import static org.junit.Assert.*;

public class DeepHandshakeFuzzyClientTest {

    private static final int total = 1;
    private static final int parts = 1;

    // number of connections during fuzzing (we don't forget a smoke test)
    private static final int n = total + 1;

    private Config clientConfig = SystemPropertiesConfig.load();

    @Test
    public void noClientAuth() throws Exception {
        test(minimized(DeepHandshakeFuzzerConfigs.noClientAuth(clientConfig)));
    }

    public void test(FuzzerConfig[] configs) throws Exception {
        for (FuzzerConfig config : configs) {
            test(config);
        }
    }

    public void test(FuzzerConfig fuzzerConfig) throws Exception {
        Output serverOutput = Output.standard("server");
        Output clientOutput = Output.standardClient();

        fuzzerConfig.total(total);

        assertTrue(fuzzerConfig.factory() instanceof DeepHandshakeFuzzer);
        DeepHandshakeFuzzer deepHandshakeFuzzer = (DeepHandshakeFuzzer) fuzzerConfig.factory();

        Config serverConfig = SystemPropertiesConfig.load();

        HttpsServer server = httpsServer()
                .set(serverConfig)
                .set(serverOutput)
                .set(new NoAlertCheck())
                .maxConnections(n);

        DeepHandshakeFuzzyClient deepHandshakeFuzzyClient =
                new DeepHandshakeFuzzyClient(new HttpsClient(), fuzzerConfig, clientOutput);

        FakeTestAnalyzer analyzer = new FakeTestAnalyzer();
        analyzer.set(clientOutput);

        try (deepHandshakeFuzzyClient; server; clientOutput; serverOutput) {
            server.start();

            fuzzerConfig.port(server.port());

            deepHandshakeFuzzyClient
                    .set(fuzzerConfig)
                    .set(clientOutput)
                    .set(analyzer)
                    .connect();
        }

        assertEquals("0:0:10:1:0:-1:0.01:0.05:8", deepHandshakeFuzzer.state());

        assertArrayEquals(
                deepHandshakeFuzzer.targeted(),
                new HandshakeType[] { client_hello, finished });

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
        config.state("0:0:10:0:0:-1:0.01:0.05:7");

        DeepHandshakeFuzzer factory = (DeepHandshakeFuzzer) config.factory();
        factory.fuzzer(new TestUtils.FakeFlipFuzzer());

        return new FuzzerConfig[] { config };
    }
}
