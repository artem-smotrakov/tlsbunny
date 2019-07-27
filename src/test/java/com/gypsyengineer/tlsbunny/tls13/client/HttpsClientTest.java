package com.gypsyengineer.tlsbunny.tls13.client;

import com.gypsyengineer.tlsbunny.tls13.server.HttpsServer;
import com.gypsyengineer.tlsbunny.utils.Config;
import com.gypsyengineer.tlsbunny.utils.SystemPropertiesConfig;
import org.junit.Test;

public class HttpsClientTest {

    @Test
    public void main() throws Exception {
        Config config = SystemPropertiesConfig.load();
        try (HttpsServer server = HttpsServer.httpsServer()) {
            server.set(config).maxConnections(1).start();
            HttpsClient.main();
        }
    }
}
