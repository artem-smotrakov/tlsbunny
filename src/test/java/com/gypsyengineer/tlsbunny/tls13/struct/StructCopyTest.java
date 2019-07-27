package com.gypsyengineer.tlsbunny.tls13.struct;

import com.gypsyengineer.tlsbunny.tls.Struct;
import com.gypsyengineer.tlsbunny.tls13.client.HttpsClientAuth;
import com.gypsyengineer.tlsbunny.tls13.connection.Analyzer;
import com.gypsyengineer.tlsbunny.tls13.connection.BaseEngineFactory;
import com.gypsyengineer.tlsbunny.tls13.connection.Engine;
import com.gypsyengineer.tlsbunny.tls13.connection.NoAlertAnalyzer;
import com.gypsyengineer.tlsbunny.tls13.connection.action.Side;
import com.gypsyengineer.tlsbunny.tls13.connection.action.composite.IncomingChangeCipherSpec;
import com.gypsyengineer.tlsbunny.tls13.connection.action.composite.OutgoingChangeCipherSpec;
import com.gypsyengineer.tlsbunny.tls13.connection.action.simple.*;
import com.gypsyengineer.tlsbunny.tls13.handshake.Context;
import com.gypsyengineer.tlsbunny.tls13.server.OneConnectionReceived;
import com.gypsyengineer.tlsbunny.tls13.server.SingleThreadServer;
import com.gypsyengineer.tlsbunny.utils.Config;
import com.gypsyengineer.tlsbunny.output.Output;
import com.gypsyengineer.tlsbunny.utils.SystemPropertiesConfig;
import org.junit.Test;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import static com.gypsyengineer.tlsbunny.tls13.struct.ContentType.application_data;
import static com.gypsyengineer.tlsbunny.tls13.struct.ContentType.handshake;
import static com.gypsyengineer.tlsbunny.tls13.struct.HandshakeType.*;
import static com.gypsyengineer.tlsbunny.tls13.struct.NamedGroup.secp256r1;
import static com.gypsyengineer.tlsbunny.tls13.struct.ProtocolVersion.TLSv12;
import static com.gypsyengineer.tlsbunny.tls13.struct.ProtocolVersion.TLSv13_draft_26;
import static com.gypsyengineer.tlsbunny.tls13.struct.SignatureScheme.ecdsa_secp256r1_sha256;
import static com.gypsyengineer.tlsbunny.tls13.struct.SignatureScheme.rsa_pkcs1_sha256;
import static org.junit.Assert.*;

public class StructCopyTest {

    @Test
    public void copyTlsPlaintext() throws IOException {
        copyTest(StructFactory.getDefault().createTLSPlaintext(
                ContentType.application_data, ProtocolVersion.TLSv13, new byte[16]));
    }

    @Test
    public void copyTlsInnerPlaintext() throws IOException {
        copyTest(StructFactory.getDefault().createTLSInnerPlaintext(
                ContentType.application_data, new byte[16], new byte[8]));
    }

    @Test
    public void copyAlert() throws IOException {
        StructFactory factory = StructFactory.getDefault();
        copyTest(factory.createAlert(
                AlertLevel.fatal, AlertDescription.handshake_failure));
        copyTest(factory.createAlert(
                factory.createAlertLevel(200),
                factory.createAlertDescription(100)));
    }

    @Test
    public void copyCertificateStatusTypeImpl() throws IOException {
        copyTest(StructFactory.getDefault().createCertificateStatusType(42));
        copyTest(CertificateStatusType.ocsp);
    }

    @Test
    public void copyCookie() throws IOException {
        copyTest(StructFactory.getDefault().createCookie(new byte[32]));
    }

    @Test
    public void copyHkdfLabel() throws IOException {
        copyTest(StructFactory.getDefault().createHkdfLabel(10, new byte[15], new byte[32]));
    }

    @Test
    public void copyMaxFragmentLength() throws IOException {
        copyTest(StructFactory.getDefault().createMaxFragmentLength(42));
        copyTest(MaxFragmentLength.two_pos_twelve);
    }

    @Test
    public void handshakeAndCopy() throws Exception {
        // instead of creating Struct objects manually we start a handshake process
        // and collect handshake messages which were created during handshaking

        Output serverOutput = Output.standard("server");
        Output clientOutput = Output.standardClient();

        Config serverConfig = SystemPropertiesConfig.load();
        SingleThreadServer server = new SingleThreadServer()
                .set(new EngineFactoryImpl()
                        .set(serverConfig)
                        .set(serverOutput))
                .set(serverConfig)
                .set(serverOutput)
                .stopWhen(new OneConnectionReceived());

        HttpsClientAuth client = new HttpsClientAuth();

        Analyzer analyzer = new NoAlertAnalyzer().set(clientOutput);

        try (server; client; clientOutput; serverOutput) {
            server.start();

            Config clientConfig = SystemPropertiesConfig.load()
                    .port(server.port());
            client.set(clientConfig).set(clientOutput);

            client.connect();
        }

        Engine[] clientEngines = client.engines();
        Engine[] serverEngines = server.engines();

        assertEquals(1, clientEngines.length);
        assertEquals(1, serverEngines.length);

        client.apply(analyzer);
        server.apply(analyzer);
        analyzer.run();

        for (Engine engine : clientEngines) {
            copyTest(engine.context());
        }

        for (Engine engine : serverEngines) {
            copyTest(engine.context());
        }
    }

    private static void copyTest(Context context) throws IOException {
        assertNotNull(context);

        Struct[] messages = messagesIn(context);
        assertNotNull(messages);
        assertTrue(messages.length > 0);

        for (Struct object : messages) {
            copyTest(object);
        }
    }

    private static void copyTest(Struct object) throws IOException {
        assertNotNull(object);

        Struct clone = object.copy();
        assertNotNull(clone);
        assertFalse(clone == object);
        assertEquals(clone, object);
        assertEquals(clone.hashCode(), object.hashCode());
        assertNotNull(clone.toString());
        assertNotNull(object.toString());

        assertEquals(clone.encodingLength(), object.encodingLength());
        assertArrayEquals(clone.encoding(), object.encoding());
    }

    // TODO: support HelloRetryRequest and EndOfEarlyData
    private static Struct[] messagesIn(Context context) {
        List<Struct> list = new ArrayList<>();
        StructParser parser = StructFactory.getDefault().parser();
        for (Handshake handshake : context.allMessages()) {
            list.add(handshake);
            byte[] body = handshake.getBody();
            if (handshake.containsClientHello()) {
                list.add(parser.parseClientHello(body));
            } else if (handshake.containsServerHello()) {
                list.add(parser.parseServerHello(body));
            } else if (handshake.containsEncryptedExtensions()) {
                list.add(parser.parseEncryptedExtensions(body));
            } else if (handshake.containsCertificateRequest()) {
                list.add(parser.parseCertificateRequest(body));
            } else if (handshake.containsCertificate()) {
                list.add(parser.parseCertificate(
                        body,
                        buf -> parser.parseX509CertificateEntry(buf)));
            } else if (handshake.containsCertificateVerify()) {
                list.add(parser.parseCertificateVerify(body));
            } else if (handshake.containsFinished()) {
                list.add(parser.parseFinished(body, context.suite().hashLength()));
            } else if (handshake.containsNewSessionTicket()) {
                list.add(parser.parseNewSessionTicket(body));
            } else {
                fail("unexpected handshake message: " + handshake.getMessageType());
            }
        }
        return list.toArray(new Struct[list.size()]);
    }

    private static class EngineFactoryImpl extends BaseEngineFactory {

        private Config config;

        public EngineFactoryImpl set(Config config) {
            this.config = config;
            return this;
        }

        @Override
        protected Engine createImpl() throws Exception {
            return Engine.init()
                    .set(structFactory)
                    .set(output)

                    .receive(new IncomingData())

                    // process ClientHello
                    .run(new ProcessingTLSPlaintext()
                            .expect(handshake))
                    .run(new ProcessingHandshake()
                            .expect(client_hello)
                            .updateContext(Context.Element.first_client_hello))
                    .run(new ProcessingClientHello())

                    .receive(new IncomingChangeCipherSpec())

                    // send ServerHello
                    .run(new GeneratingServerHello()
                            .supportedVersion(TLSv13_draft_26)
                            .group(secp256r1)
                            .signatureScheme(ecdsa_secp256r1_sha256)
                            .keyShareEntry(context -> context.negotiator().createKeyShareEntry()))
                    .run(new WrappingIntoHandshake()
                            .type(server_hello)
                            .updateContext(Context.Element.server_hello))
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
                            .updateContext(Context.Element.encrypted_extensions))
                    .run(new WrappingHandshakeDataIntoTLSCiphertext())
                    .store()

                    // send CertificateRequest
                    .run(new GeneratingCertificateRequest()
                            .signatures(rsa_pkcs1_sha256))
                    .run(new WrappingIntoHandshake()
                            .type(certificate_request)
                            .updateContext(Context.Element.server_certificate_request))
                    .run(new WrappingHandshakeDataIntoTLSCiphertext())
                    .store()

                    // send Certificate
                    .run(new GeneratingCertificate()
                            .certificate(config.serverCertificate()))
                    .run(new WrappingIntoHandshake()
                            .type(certificate)
                            .updateContext(Context.Element.server_certificate))
                    .run(new WrappingHandshakeDataIntoTLSCiphertext())
                    .store()

                    // send CertificateVerify
                    .run(new GeneratingCertificateVerify()
                            .server()
                            .key(config.serverKey()))
                    .run(new WrappingIntoHandshake()
                            .type(certificate_verify)
                            .updateContext(Context.Element.server_certificate_verify))
                    .run(new WrappingHandshakeDataIntoTLSCiphertext())
                    .store()

                    .run(new GeneratingFinished(Side.server))
                    .run(new WrappingIntoHandshake()
                            .type(finished)
                            .updateContext(Context.Element.server_finished))
                    .run(new WrappingHandshakeDataIntoTLSCiphertext())
                    .store()

                    .restore()
                    .send(new OutgoingData())

                    .run(new ComputingApplicationTrafficKeys()
                            .server())

                    .receive(new IncomingData())
                    .run(new ProcessingHandshakeTLSCiphertext()
                            .expect(handshake))
                    .run(new ProcessingHandshake()
                            .expect(certificate)
                            .updateContext(Context.Element.client_certificate))
                    .run(new ProcessingCertificate())

                    .receive(new IncomingData())
                    .run(new ProcessingHandshakeTLSCiphertext()
                            .expect(handshake))
                    .run(new ProcessingHandshake()
                            .expect(certificate_verify)
                            .updateContext(Context.Element.client_certificate_verify))
                    .run(new ProcessingCertificateVerify())

                    .receive(new IncomingData())
                    .run(new ProcessingHandshakeTLSCiphertext()
                            .expect(handshake))
                    .run(new ProcessingHandshake()
                            .expect(finished))
                    .run(new ProcessingFinished(Side.server))

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
