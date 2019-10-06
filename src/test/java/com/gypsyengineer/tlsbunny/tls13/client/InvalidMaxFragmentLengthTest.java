package com.gypsyengineer.tlsbunny.tls13.client;

import com.gypsyengineer.tlsbunny.tls13.connection.BaseEngineFactory;
import com.gypsyengineer.tlsbunny.tls13.connection.Engine;
import com.gypsyengineer.tlsbunny.tls13.connection.action.Side;
import com.gypsyengineer.tlsbunny.tls13.connection.action.composite.IncomingChangeCipherSpec;
import com.gypsyengineer.tlsbunny.tls13.connection.action.composite.IncomingMessages;
import com.gypsyengineer.tlsbunny.tls13.connection.action.composite.OutgoingMainServerFlight;
import com.gypsyengineer.tlsbunny.tls13.connection.action.simple.*;
import com.gypsyengineer.tlsbunny.tls13.handshake.Context;
import com.gypsyengineer.tlsbunny.tls13.server.NonStop;
import com.gypsyengineer.tlsbunny.tls13.server.SingleThreadServer;
import com.gypsyengineer.tlsbunny.tls13.struct.AlertDescription;
import com.gypsyengineer.tlsbunny.tls13.struct.AlertLevel;
import com.gypsyengineer.tlsbunny.utils.Config;
import org.junit.Test;

import static com.gypsyengineer.tlsbunny.tls13.struct.ContentType.alert;
import static com.gypsyengineer.tlsbunny.tls13.struct.ContentType.handshake;
import static com.gypsyengineer.tlsbunny.tls13.struct.HandshakeType.client_hello;
import static com.gypsyengineer.tlsbunny.tls13.struct.ProtocolVersion.TLSv12;
import static org.junit.Assert.assertEquals;

public class InvalidMaxFragmentLengthTest {

    @Test
    public void run() throws Exception {
        InvalidMaxFragmentLength client = new InvalidMaxFragmentLength();

        SingleThreadServer server = new SingleThreadServer()
                .set(new EngineFactoryImpl())
                .stopWhen(new NonStop());

        try (client; server) {
            server.start();
            client.to(server).connect();

            assertEquals(257, client.engines().length);
        }
    }

    private static class EngineFactoryImpl extends BaseEngineFactory {

        private final String certificate = Config.instance.getString("server.certificate.path");
        private final String key = Config.instance.getString("server.key.path");
        private int counter = 0;

        @Override
        protected Engine createImpl() throws Exception {
            counter++;
            if (counter <= 5) {
                return fullHandshake();
            } else {
                return sendAlert();
            }
        }

        private Engine sendAlert() throws Exception {
            return Engine.init()
                    .set(structFactory)
                    .receive(new IncomingData())

                    // receive an invalid ClientHello
                    .run(new ProcessingTLSPlaintext()
                            .expect(handshake))
                    .run(new ProcessingHandshake()
                            .expect(client_hello)
                            .updateContext(Context.Element.first_client_hello))
                    .run(new ProcessingClientHello())

                    // receive a CCS
                    .receive(new IncomingChangeCipherSpec())

                    // send an alert
                    .run(new GeneratingAlert()
                            .level(AlertLevel.fatal)
                            .description(AlertDescription.unexpected_message))
                    .run(new WrappingIntoTLSPlaintexts()
                            .version(TLSv12)
                            .type(alert))
                    .send(new OutgoingData());
        }

        Engine fullHandshake() throws Exception {
            return Engine.init()
                    .set(structFactory)
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
