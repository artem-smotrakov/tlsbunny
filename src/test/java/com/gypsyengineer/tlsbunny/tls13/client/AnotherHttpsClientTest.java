package com.gypsyengineer.tlsbunny.tls13.client;

import com.gypsyengineer.tlsbunny.tls13.server.HttpsServer;
import com.gypsyengineer.tlsbunny.tls13.struct.StructFactory;
import org.junit.Test;

import static org.junit.Assert.assertEquals;

public class AnotherHttpsClientTest {

    @Test
    public void main() throws Exception {
        try (HttpsServer server = HttpsServer.httpsServer();
             AnotherHttpsClient client = new AnotherHttpsClient()) {

            server.maxConnections(1).start();
            client.to(server).set(StructFactory.getDefault()).connect();

            assertEquals(1, client.engines().length);
        }
    }
}
