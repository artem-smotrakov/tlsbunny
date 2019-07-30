package com.gypsyengineer.tlsbunny.tls13.client;

import com.gypsyengineer.tlsbunny.tls13.connection.BaseEngineFactory;
import com.gypsyengineer.tlsbunny.tls13.connection.Engine;
import com.gypsyengineer.tlsbunny.tls13.connection.action.composite.IncomingServerHello;
import com.gypsyengineer.tlsbunny.tls13.connection.action.simple.*;
import com.gypsyengineer.tlsbunny.tls13.handshake.Context;
import com.gypsyengineer.tlsbunny.tls13.server.SingleThreadServer;
import com.gypsyengineer.tlsbunny.tls13.struct.AlertDescription;
import com.gypsyengineer.tlsbunny.tls13.struct.AlertLevel;
import org.junit.Test;

import static com.gypsyengineer.tlsbunny.tls13.struct.ContentType.alert;
import static com.gypsyengineer.tlsbunny.tls13.struct.ContentType.handshake;
import static com.gypsyengineer.tlsbunny.tls13.struct.HandshakeType.client_hello;
import static com.gypsyengineer.tlsbunny.tls13.struct.NamedGroup.secp256r1;
import static com.gypsyengineer.tlsbunny.tls13.struct.ProtocolVersion.TLSv12;
import static com.gypsyengineer.tlsbunny.tls13.struct.ProtocolVersion.TLSv13;
import static com.gypsyengineer.tlsbunny.tls13.struct.SignatureScheme.ecdsa_secp256r1_sha256;
import static org.junit.Assert.assertNotNull;

public class StartWithServerHelloTest {

    @Test
    public void test() throws Exception {
        SingleThreadServer server = new SingleThreadServer()
                .set(new EngineFactoryImpl())
                .maxConnections(1);

        StartWithServerHello client = new StartWithServerHello();

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

                    // generate a ClientHello message to initialize the negotiator
                    .run(new GeneratingClientHello()
                            .supportedVersions(TLSv13)
                            .groups(secp256r1)
                            .signatureSchemes(ecdsa_secp256r1_sha256)
                            .keyShareEntries(context -> context.negotiator().createKeyShareEntry()))
                    .run(new WrappingIntoHandshake()
                            .type(client_hello)
                            .update(Context.Element.first_client_hello))
                    .run(new WrappingIntoTLSPlaintexts()
                            .type(handshake)
                            .version(TLSv12))
                    .run(new PrintingData())

                    // receive ServerHello
                    .receive(new IncomingServerHello())

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
