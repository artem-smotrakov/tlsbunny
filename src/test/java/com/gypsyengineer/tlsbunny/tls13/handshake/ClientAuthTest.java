package com.gypsyengineer.tlsbunny.tls13.handshake;

import com.gypsyengineer.tlsbunny.tls13.client.*;
import com.gypsyengineer.tlsbunny.tls13.connection.Engine;
import com.gypsyengineer.tlsbunny.tls13.connection.NoAlertAnalyzer;
import com.gypsyengineer.tlsbunny.tls13.server.HttpsServer;
import com.gypsyengineer.tlsbunny.tls13.server.OneConnectionReceived;
import com.gypsyengineer.tlsbunny.utils.Config;
import com.gypsyengineer.tlsbunny.output.Output;
import com.gypsyengineer.tlsbunny.utils.SystemPropertiesConfig;
import org.junit.Test;

import static com.gypsyengineer.tlsbunny.tls13.server.HttpsServer.httpsServer;
import static com.gypsyengineer.tlsbunny.tls13.struct.NamedGroup.secp256r1;
import static org.junit.Assert.*;

public class ClientAuthTest {

    @Test
    public void httpsClient() throws Exception {
        Output serverOutput = Output.standard("server");
        Output clientOutput = Output.standardClient();

        Config serverConfig = SystemPropertiesConfig.load();

        HttpsServer server = httpsServer()
                .set(secp256r1)
                .set(serverConfig)
                .set(serverOutput)
                .stopWhen(new OneConnectionReceived());

        HttpsClientAuth client = new HttpsClientAuth();

        try (server; clientOutput; serverOutput) {
            server.start();

            Config clientConfig = SystemPropertiesConfig.load()
                    .port(server.port());
            client.set(clientConfig).set(clientOutput);

            try (client) {
                client.connect().engines()[0].apply(new NoAlertAnalyzer());
            }
        }

        Engine[] clientEngines = client.engines();
        Engine[] serverEngines = server.engines();

        assertEquals(1, clientEngines.length);
        assertEquals(1, serverEngines.length);

        boolean success = checkContexts(
                clientEngines[0].context(),
                serverEngines[0].context(),
                clientOutput);

        assertTrue("something went wrong!", success);
    }

    private static boolean checkContexts(
            Context clientContext, Context serverContext, Output output) {

        output.info("check client and server contexts");
        assertNotNull("client context should not be null", clientContext);
        assertNotNull("server context should not be null", serverContext);

        assertArrayEquals("contexts: dh_shared_secret are not equal",
                clientContext.dh_shared_secret(),
                serverContext.dh_shared_secret());

        assertArrayEquals("contexts: early_secret are not equal",
                clientContext.early_secret(),
                serverContext.early_secret());

        assertArrayEquals("contexts: binder_key are not equal",
                clientContext.binder_key(),
                serverContext.binder_key());

        assertArrayEquals("contexts: client_early_traffic_secret are not equal",
                clientContext.client_early_traffic_secret(),
                serverContext.client_early_traffic_secret());

        assertArrayEquals("contexts: early_exporter_master_secret are not equal",
                clientContext.early_exporter_master_secret(),
                serverContext.early_exporter_master_secret());

        assertArrayEquals("contexts: handshake_secret_salt are not equal",
                clientContext.handshake_secret_salt(),
                serverContext.handshake_secret_salt());

        assertArrayEquals("contexts: handshake_secret are not equal",
                clientContext.handshake_secret(),
                serverContext.handshake_secret());

        assertArrayEquals("contexts: client_handshake_traffic_secret are not equal",
                clientContext.client_handshake_traffic_secret(),
                serverContext.client_handshake_traffic_secret());

        assertArrayEquals("contexts: server_handshake_traffic_secret are not equal",
                clientContext.server_handshake_traffic_secret(),
                serverContext.server_handshake_traffic_secret());

        assertArrayEquals("contexts: master_secret are not equal",
                clientContext.master_secret(),
                serverContext.master_secret());

        assertArrayEquals("contexts: client_application_traffic_secret_0 are not equal",
                clientContext.client_application_traffic_secret_0(),
                serverContext.client_application_traffic_secret_0());

        assertArrayEquals("contexts: server_application_traffic_secret_0 are not equal",
                clientContext.server_application_traffic_secret_0(),
                serverContext.server_application_traffic_secret_0());

        assertArrayEquals("contexts: exporter_master_secret are not equal",
                clientContext.exporter_master_secret(),
                serverContext.exporter_master_secret());

        assertArrayEquals("contexts: resumption_master_secret are not equal",
                clientContext.resumption_master_secret(),
                serverContext.resumption_master_secret());

        assertArrayEquals("contexts: client_handshake_write_key are not equal",
                clientContext.client_handshake_write_key(),
                serverContext.client_handshake_write_key());

        assertArrayEquals("contexts: client_handshake_write_iv are not equal",
                clientContext.client_handshake_write_iv(),
                serverContext.client_handshake_write_iv());

        assertArrayEquals("contexts: server_handshake_write_key are not equal",
                clientContext.server_handshake_write_key(),
                serverContext.server_handshake_write_key());

        assertArrayEquals("contexts: server_handshake_write_iv are not equal",
                clientContext.server_handshake_write_iv(),
                serverContext.server_handshake_write_iv());

        assertArrayEquals("contexts: client_application_write_key are not equal",
                clientContext.client_application_write_key(),
                serverContext.client_application_write_key());

        assertArrayEquals("contexts: client_application_write_iv are not equal",
                clientContext.client_application_write_iv(),
                serverContext.client_application_write_iv());

        assertArrayEquals("contexts: server_application_write_key are not equal",
                clientContext.server_application_write_key(),
                serverContext.server_application_write_key());

        assertArrayEquals("contexts: server_application_write_iv are not equal",
                clientContext.server_application_write_iv(),
                serverContext.server_application_write_iv());

        return true;
    }
}
