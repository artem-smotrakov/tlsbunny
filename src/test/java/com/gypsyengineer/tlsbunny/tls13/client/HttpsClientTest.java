package com.gypsyengineer.tlsbunny.tls13.client;

import com.gypsyengineer.tlsbunny.tls13.server.HttpsServer;
import org.junit.Test;

public class HttpsClientTest {

    @Test
    public void main() throws Exception {
        try (HttpsServer server = HttpsServer.httpsServer()) {
            server.maxConnections(1).start();
            HttpsClient.httpsClient().to(server).connect();
        }
    }
}
