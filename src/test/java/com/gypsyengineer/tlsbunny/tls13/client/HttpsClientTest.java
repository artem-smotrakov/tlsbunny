package com.gypsyengineer.tlsbunny.tls13.client;

import com.gypsyengineer.tlsbunny.tls13.server.HttpsServer;
import org.junit.Test;

import static com.gypsyengineer.tlsbunny.tls13.client.HttpsClient.httpsClient;
import static org.junit.Assert.assertEquals;

public class HttpsClientTest {

    @Test
    public void main() throws Exception {
        try (HttpsServer server = HttpsServer.httpsServer();
             HttpsClient client = httpsClient()) {

            server.maxConnections(1).start();
            client.to(server).connect();

            assertEquals(1, client.engines().length);
        }
    }
}
