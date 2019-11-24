package com.gypsyengineer.tlsbunny.tls13.client;

import com.gypsyengineer.tlsbunny.SimpleJSSEHttpsServer;
import com.gypsyengineer.tlsbunny.tls13.connection.Engine;
import com.gypsyengineer.tlsbunny.tls13.struct.CipherSuite;
import org.junit.Test;

import static com.gypsyengineer.tlsbunny.JSSEUtils.setKeyStores;
import static com.gypsyengineer.tlsbunny.JSSEUtils.supportsTls13;
import static com.gypsyengineer.tlsbunny.tls13.client.HttpsClient.httpsClient;
import static org.junit.Assert.assertEquals;
import static org.junit.Assume.assumeTrue;

public class HttpClientWithJSSEServerTest {

    @Test
    public void standardHandshake() throws Exception {
        assumeTrue(supportsTls13());
        setKeyStores();
        try (SimpleJSSEHttpsServer server = SimpleJSSEHttpsServer.start();
             HttpsClient client = httpsClient()) {

            client.to("localhost").to(server.port()).connect();

            Engine[] engines = client.engines();
            assertEquals(1, engines.length);
            Engine engine = engines[0];
            assertEquals(CipherSuite.TLS_AES_128_GCM_SHA256, engine.context().suite());

            server.stop();
        }
    }
}
