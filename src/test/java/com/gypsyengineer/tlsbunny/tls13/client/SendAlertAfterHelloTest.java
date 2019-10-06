package com.gypsyengineer.tlsbunny.tls13.client;

import com.gypsyengineer.tlsbunny.tls13.connection.BaseEngineFactory;
import com.gypsyengineer.tlsbunny.tls13.connection.Engine;
import com.gypsyengineer.tlsbunny.tls13.connection.action.Side;
import com.gypsyengineer.tlsbunny.tls13.connection.action.composite.IncomingMessages;
import com.gypsyengineer.tlsbunny.tls13.connection.action.composite.OutgoingMainServerFlight;
import com.gypsyengineer.tlsbunny.tls13.connection.action.simple.IncomingData;
import com.gypsyengineer.tlsbunny.tls13.connection.action.simple.OutgoingData;
import com.gypsyengineer.tlsbunny.tls13.connection.action.simple.PreparingHttpResponse;
import com.gypsyengineer.tlsbunny.tls13.connection.action.simple.WrappingApplicationDataIntoTLSCiphertext;
import com.gypsyengineer.tlsbunny.tls13.connection.check.AlertCheck;
import com.gypsyengineer.tlsbunny.tls13.handshake.ECDHENegotiator;
import com.gypsyengineer.tlsbunny.tls13.server.SingleThreadServer;
import com.gypsyengineer.tlsbunny.tls13.struct.NamedGroup;
import com.gypsyengineer.tlsbunny.tls13.struct.StructFactory;
import com.gypsyengineer.tlsbunny.utils.Config;
import com.gypsyengineer.tlsbunny.utils.Utils;
import org.junit.Test;

import static junit.framework.TestCase.assertEquals;
import static org.junit.Assert.assertNotNull;

public class SendAlertAfterHelloTest {

    @Test
    public void test() throws Exception {
        SingleThreadServer server = new SingleThreadServer()
                .set(new EngineFactoryImpl())
                .set(new AlertCheck())
                .maxConnections(1);

        try (server; SendAlertAfterHello client = new SendAlertAfterHello()) {
            server.start();
            client.to(server).connect();
        }

        Utils.waitStop(server);

        assertEquals(1, server.engines().length);
        assertNotNull(server.engines()[0].context().getAlert());
    }

    private static class EngineFactoryImpl extends BaseEngineFactory {

        private final String certificate = Config.instance.getString("server.certificate.path");
        private final String key = Config.instance.getString("server.key.path");

        @Override
        protected Engine createImpl() throws Exception {
            return Engine.init()
                    .set(structFactory)

                    .set(ECDHENegotiator.create(NamedGroup.secp256r1, StructFactory.getDefault()))

                    .receive(new IncomingData())

                    // process ClientHello
                    .until(context -> !context.hasFirstClientHello() && !context.hasAlert())
                    .receive(() -> new IncomingMessages(Side.server))

                    // send messages
                    .send(new OutgoingMainServerFlight(certificate, key))

                    // receive Finished and application data
                    .until(context -> !context.receivedApplicationData() && !context.hasAlert())
                    .receive(() -> new IncomingMessages(Side.server))

                    // send application data
                    .run(new PreparingHttpResponse())
                    .run(new WrappingApplicationDataIntoTLSCiphertext())
                    .send(new OutgoingData());
        }
    }
}
