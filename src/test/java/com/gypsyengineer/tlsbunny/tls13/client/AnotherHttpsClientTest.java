package com.gypsyengineer.tlsbunny.tls13.client;

import com.gypsyengineer.tlsbunny.tls13.server.HttpsServer;
import com.gypsyengineer.tlsbunny.tls13.struct.StructFactory;
import org.junit.Test;

public class AnotherHttpsClientTest {

    @Test
    public void main() throws Exception {
        try (HttpsServer server = HttpsServer.httpsServer()) {
            server.maxConnections(1).start();

            try (AnotherHttpsClient client = new AnotherHttpsClient()) {
                client.port(server.port())
                        .set(StructFactory.getDefault()).connect();
            }
        }
    }
}
