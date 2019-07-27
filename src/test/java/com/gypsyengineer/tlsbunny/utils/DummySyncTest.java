package com.gypsyengineer.tlsbunny.utils;

import org.junit.Test;

import static com.gypsyengineer.tlsbunny.tls13.client.HttpsClient.httpsClient;
import static com.gypsyengineer.tlsbunny.tls13.server.HttpsServer.httpsServer;

public class DummySyncTest {

    @Test
    public void nothingHappens() throws Exception {
        // just make sure that nothing happens

        new DummySync()
                .set(httpsClient())
                .set(httpsServer())
                .logPrefix("test")
                .init()
                .start()
                .end()
                .close();
    }
}
