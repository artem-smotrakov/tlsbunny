package com.gypsyengineer.tlsbunny.tls13.client;

import com.gypsyengineer.tlsbunny.tls13.connection.BaseEngineFactory;
import com.gypsyengineer.tlsbunny.tls13.connection.Engine;
import com.gypsyengineer.tlsbunny.tls13.connection.action.simple.*;
import com.gypsyengineer.tlsbunny.tls13.handshake.Context;
import com.gypsyengineer.tlsbunny.tls13.server.SingleThreadServer;
import com.gypsyengineer.tlsbunny.tls13.struct.AlertDescription;
import com.gypsyengineer.tlsbunny.tls13.struct.AlertLevel;
import org.junit.Test;

import static com.gypsyengineer.tlsbunny.tls13.struct.ContentType.alert;
import static com.gypsyengineer.tlsbunny.tls13.struct.ContentType.handshake;
import static com.gypsyengineer.tlsbunny.tls13.struct.HandshakeType.finished;
import static com.gypsyengineer.tlsbunny.tls13.struct.ProtocolVersion.TLSv12;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

public class StartWithFinishedTest {

    @Test
    public void test() throws Exception {
        SingleThreadServer server = new SingleThreadServer()
                .set(new EngineFactoryImpl())
                .maxConnections(1);

        StartWithFinished client = new StartWithFinished();

        try (server) {
            server.start();
            client.to(server).connect();
        }

        Engine[] engines = client.engines();
        assertNotNull(engines);
        assertEquals(1, engines.length);
        assertNotNull(engines[0].context().getAlert());
    }

    private static class EngineFactoryImpl extends BaseEngineFactory {

        @Override
        protected Engine createImpl() throws Exception {
            return Engine.init()
                    .set(structFactory)

                    // receive ServerHello
                    .receive(new IncomingData())
                    .run(new ProcessingTLSPlaintext()
                            .expect(handshake))
                    .run(new ProcessingHandshake()
                            .expect(finished)
                            .updateContext(Context.Element.client_finished))
                    .run(new PrintingData())

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
