package com.gypsyengineer.tlsbunny.tls13.client;

import com.gypsyengineer.tlsbunny.tls13.connection.BaseEngineFactory;
import com.gypsyengineer.tlsbunny.tls13.connection.Engine;
import com.gypsyengineer.tlsbunny.tls13.connection.action.ActionFailed;
import com.gypsyengineer.tlsbunny.tls13.connection.action.Side;
import com.gypsyengineer.tlsbunny.tls13.connection.action.composite.OutgoingChangeCipherSpec;
import com.gypsyengineer.tlsbunny.tls13.connection.action.simple.*;
import com.gypsyengineer.tlsbunny.tls13.handshake.Context;
import com.gypsyengineer.tlsbunny.tls13.server.NConnectionsReceived;
import com.gypsyengineer.tlsbunny.tls13.server.OneConnectionReceived;
import com.gypsyengineer.tlsbunny.tls13.server.SingleThreadServer;
import com.gypsyengineer.tlsbunny.tls13.struct.Alert;
import com.gypsyengineer.tlsbunny.tls13.struct.AlertDescription;
import com.gypsyengineer.tlsbunny.tls13.struct.AlertLevel;
import com.gypsyengineer.tlsbunny.tls13.struct.ContentType;
import com.gypsyengineer.tlsbunny.utils.Config;
import org.junit.Test;

import static com.gypsyengineer.tlsbunny.tls13.struct.ContentType.*;
import static com.gypsyengineer.tlsbunny.tls13.struct.HandshakeType.*;
import static com.gypsyengineer.tlsbunny.tls13.struct.NamedGroup.secp256r1;
import static com.gypsyengineer.tlsbunny.tls13.struct.ProtocolVersion.TLSv12;
import static com.gypsyengineer.tlsbunny.tls13.struct.ProtocolVersion.TLSv13_draft_26;
import static com.gypsyengineer.tlsbunny.tls13.struct.SignatureScheme.ecdsa_secp256r1_sha256;
import static org.junit.Assert.*;

public class StartWithEmptyTLSPlaintextTest {

    @Test
    public void expectedAlertReceived() throws Exception {
        CorrectServerEngineFactoryImpl serverEngineFactory
                = new CorrectServerEngineFactoryImpl();

        SingleThreadServer server = new SingleThreadServer()
                .set(serverEngineFactory)
                .stopWhen(new NConnectionsReceived(4));

        try (server) {
            server.start();

            serverEngineFactory.set(handshake);
            test(handshake, server.port());

            serverEngineFactory.set(change_cipher_spec);
            test(change_cipher_spec, server.port());

            serverEngineFactory.set(application_data);
            test(application_data, server.port());

            serverEngineFactory.set(alert);
            test(alert, server.port());
        }
    }

    private static void test(ContentType type, int port) throws Exception {
        try (StartWithEmptyTLSPlaintext client = new StartWithEmptyTLSPlaintext()) {
            client.set(type).to(port).connect();

            Alert alert = client.engines()[0].context().getAlert();
            assertNotNull(alert);
            assertEquals(alert.getLevel(), AlertLevel.fatal);
            assertEquals(alert.getDescription(), AlertDescription.unexpected_message);
        }
    }

    @Test
    public void noExpectedAlertReceived() throws Exception {
        SingleThreadServer server = new SingleThreadServer()
                .set(new IncorrectServerEngineFactoryImpl())
                .stopWhen(new OneConnectionReceived());

        StartWithEmptyTLSPlaintext client = new StartWithEmptyTLSPlaintext();

        try (client; server) {
            server.start();
            client.to(server).connect();

            fail("expected ActionFailed");
        } catch (ActionFailed e) {
            assertEquals("check failed: alert received", e.getMessage());
        }

        Alert alert = client.engines()[0].context().getAlert();
        assertNull(alert);
    }

    // sends an alert after receiving an empty TLSPlaintext
    private static class CorrectServerEngineFactoryImpl extends BaseEngineFactory {

        private ContentType type;

        // TODO: add synchronization
        public CorrectServerEngineFactoryImpl set(ContentType type) {
            this.type = type;
            return this;
        }

        @Override
        protected Engine createImpl() throws Exception {
            return Engine.init()
                    .set(structFactory)


                    .receive(new IncomingData())

                    // process an empty TLSPlaintext
                    .run(new ProcessingTLSPlaintext()
                            .expect(type))

                    // send an alert
                    .run(new GeneratingAlert()
                            .level(AlertLevel.fatal)
                            .description(AlertDescription.unexpected_message))
                    .run(new WrappingIntoTLSPlaintexts()
                            .type(alert)
                            .version(TLSv12))
                    .send(new OutgoingData());
        }
    }

    // don't send an alert after receiving an empty TLSPlaintext
    private static class IncorrectServerEngineFactoryImpl extends BaseEngineFactory {

        private String serverCertificate = Config.instance.getString("server.certificate.path");
        private String serverKey = Config.instance.getString("server.key.path");

        @Override
        protected Engine createImpl() throws Exception {
            return Engine.init()
                    .set(structFactory)


                    // process an empty TLSPlaintext
                    .receive(new IncomingData())
                    .run(new ProcessingTLSPlaintext())

                    // process ClientHello
                    .receive(new IncomingData())
                    .run(new ProcessingTLSPlaintext()
                            .expect(handshake))
                    .run(new ProcessingHandshake()
                            .expect(client_hello)
                            .updateContext(Context.Element.first_client_hello))
                    .run(new ProcessingClientHello())

                    // send ServerHello
                    .run(new GeneratingServerHello()
                            .supportedVersion(TLSv13_draft_26)
                            .group(secp256r1)
                            .signatureScheme(ecdsa_secp256r1_sha256)
                            .keyShareEntry(context -> context.negotiator().createKeyShareEntry()))
                    .run(new WrappingIntoHandshake()
                            .type(server_hello)
                            .update(Context.Element.server_hello))
                    .run(new WrappingIntoTLSPlaintexts()
                            .type(handshake)
                            .version(TLSv12))
                    .store()

                    .run(new OutgoingChangeCipherSpec())
                    .store()

                    .run(new NegotiatingServerDHSecret())

                    .run(new ComputingHandshakeTrafficKeys()
                            .server())

                    // send EncryptedExtensions
                    .run(new GeneratingEncryptedExtensions())
                    .run(new WrappingIntoHandshake()
                            .type(encrypted_extensions)
                            .update(Context.Element.encrypted_extensions))
                    .run(new WrappingHandshakeDataIntoTLSCiphertext())
                    .store()

                    // send Certificate
                    .run(new GeneratingCertificate()
                            .certificate(serverCertificate))
                    .run(new WrappingIntoHandshake()
                            .type(certificate)
                            .update(Context.Element.server_certificate))
                    .run(new WrappingHandshakeDataIntoTLSCiphertext())
                    .store()

                    // send CertificateVerify
                    .run(new GeneratingCertificateVerify()
                            .server()
                            .key(serverKey))
                    .run(new WrappingIntoHandshake()
                            .type(certificate_verify)
                            .update(Context.Element.server_certificate_verify))
                    .run(new WrappingHandshakeDataIntoTLSCiphertext())
                    .store()

                    .run(new GeneratingFinished(Side.server))
                    .run(new WrappingIntoHandshake()
                            .type(finished)
                            .update(Context.Element.server_finished))
                    .run(new WrappingHandshakeDataIntoTLSCiphertext())
                    .store()

                    .restore()
                    .send(new OutgoingData())

                    .receive(new IncomingData())

                    .run(new ProcessingHandshakeTLSCiphertext()
                            .expect(handshake))
                    .run(new ProcessingHandshake()
                            .expect(finished))
                    .run(new ProcessingFinished(Side.server))

                    .run(new ComputingApplicationTrafficKeys()
                            .server())

                    // receive application data
                    .receive(new IncomingData())
                    .run(new ProcessingApplicationDataTLSCiphertext()
                            .expect(application_data))
                    .run(new PrintingData())

                    // send application data
                    .run(new PreparingHttpResponse())
                    .run(new WrappingApplicationDataIntoTLSCiphertext())
                    .send(new OutgoingData());
        }
    }
}
