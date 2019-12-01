package com.gypsyengineer.tlsbunny.tls13.client;

import com.gypsyengineer.tlsbunny.SimpleJSSEHttpsServer;
import com.gypsyengineer.tlsbunny.tls13.connection.Engine;
import com.gypsyengineer.tlsbunny.tls13.struct.CipherSuite;
import org.junit.Test;

import javax.net.ssl.SSLSession;
import java.io.IOException;

import static com.gypsyengineer.tlsbunny.JSSEUtils.*;
import static com.gypsyengineer.tlsbunny.tls13.client.HttpsClient.httpsClient;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

public class HttpsClientWithSessionResumptionWithJSSEServerTest {

    @Test
    public void jsseSessionResumption() throws IOException {
        setKeyStores();
        setTrustStores();
        enableSessionTicketExtension();
        try (SimpleJSSEHttpsServer server = SimpleJSSEHttpsServer.start()) {
            SSLSession session = connectTo(server.port());

            assertEquals("TLSv1.3", session.getProtocol());
            assertEquals("TLS_AES_128_GCM_SHA256", session.getCipherSuite());
            assertTrue(session.isValid());

            SSLSession theSameSession = connectTo(server.port());

            assertEquals(session.getCipherSuite(), theSameSession.getCipherSuite());
            assertEquals(session.getProtocol(), theSameSession.getProtocol());

            // check session resumption
            assertEquals(session.getCreationTime(), theSameSession.getCreationTime());
        }
    }

    @Test
    public void sessionResumption() throws Exception {
        setKeyStores();
        setTrustStores();
        enableSessionTicketExtension();
        try (SimpleJSSEHttpsServer server = SimpleJSSEHttpsServer.start()) {
            Client client = HttpsClientWithSessionResumption.from(httpsClient());

            client.to("localhost").to(server.port()).connect();

            Engine[] engines = client.engines();
            assertEquals(1, engines.length);
            Engine engine = engines[0];
            assertEquals(CipherSuite.TLS_AES_128_GCM_SHA256, engine.context().suite());
        }
    }
}