package com.gypsyengineer.tlsbunny.tls13.client;

import com.gypsyengineer.tlsbunny.tls13.client.ccs.StartWithCCS;
import com.gypsyengineer.tlsbunny.tls13.connection.BaseEngineFactory;
import com.gypsyengineer.tlsbunny.tls13.connection.Engine;
import com.gypsyengineer.tlsbunny.tls13.connection.action.composite.IncomingChangeCipherSpec;
import com.gypsyengineer.tlsbunny.tls13.connection.action.simple.*;
import com.gypsyengineer.tlsbunny.tls13.handshake.Context;
import com.gypsyengineer.tlsbunny.tls13.server.SingleThreadServer;
import com.gypsyengineer.tlsbunny.tls13.struct.AlertDescription;
import com.gypsyengineer.tlsbunny.tls13.struct.AlertLevel;
import org.junit.Test;

import static com.gypsyengineer.tlsbunny.tls13.struct.ContentType.alert;
import static com.gypsyengineer.tlsbunny.tls13.struct.ContentType.handshake;
import static com.gypsyengineer.tlsbunny.tls13.struct.HandshakeType.client_hello;
import static com.gypsyengineer.tlsbunny.tls13.struct.ProtocolVersion.TLSv12;
import static org.junit.Assert.assertNotNull;

public class StartWithCCSTest {

    @Test
    public void test() throws Exception {
        SingleThreadServer server = new SingleThreadServer()
                .set(new EngineFactoryImpl())
                .maxConnections(1);

        StartWithCCS client = new StartWithCCS();
        try (server) {
            server.start();
            client.to(server).connect();
        }

        assertNotNull(client.engines()[0].context().getAlert());
    }

    private static class EngineFactoryImpl extends BaseEngineFactory {

        @Override
        protected Engine createImpl() throws Exception {
            return Engine.init()
                    .set(structFactory)

                    // receive an invalid CCS
                    .receive(new IncomingChangeCipherSpec())

                    // process ClientHello
                    .receive(new IncomingData())
                    .run(new ProcessingTLSPlaintext()
                            .expect(handshake))
                    .run(new ProcessingHandshake()
                            .expect(client_hello)
                            .updateContext(Context.Element.first_client_hello))
                    .run(new ProcessingClientHello())

                    // send an alert
                    .run(new GeneratingAlert()
                            .level(AlertLevel.fatal)
                            .description(AlertDescription.unexpected_message))
                    .run(new WrappingIntoTLSPlaintexts()
                            .version(TLSv12)
                            .type(alert))
                    .send(new OutgoingData());
        }
    }
}
