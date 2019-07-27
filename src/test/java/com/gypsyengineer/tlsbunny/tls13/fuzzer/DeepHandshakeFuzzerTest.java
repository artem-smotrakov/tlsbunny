package com.gypsyengineer.tlsbunny.tls13.fuzzer;

import com.gypsyengineer.tlsbunny.TestUtils;
import com.gypsyengineer.tlsbunny.tls.Random;
import com.gypsyengineer.tlsbunny.tls.Struct;
import com.gypsyengineer.tlsbunny.tls13.client.HttpsClientAuth;
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
import com.gypsyengineer.tlsbunny.tls13.struct.*;
import com.gypsyengineer.tlsbunny.utils.Config;
import com.gypsyengineer.tlsbunny.output.Output;
import com.gypsyengineer.tlsbunny.utils.SystemPropertiesConfig;
import org.junit.Test;

import java.io.IOException;
import java.util.Arrays;
import java.util.List;

import static com.gypsyengineer.tlsbunny.TestUtils.expectWhatTheHell;
import static com.gypsyengineer.tlsbunny.fuzzer.ByteFlipFuzzer.newByteFlipFuzzer;
import static com.gypsyengineer.tlsbunny.tls13.fuzzer.DeepHandshakeFuzzer.*;
import static com.gypsyengineer.tlsbunny.tls13.struct.ContentType.application_data;
import static com.gypsyengineer.tlsbunny.tls13.struct.ContentType.handshake;
import static com.gypsyengineer.tlsbunny.tls13.struct.HandshakeType.*;
import static com.gypsyengineer.tlsbunny.tls13.struct.HandshakeType.certificate;
import static com.gypsyengineer.tlsbunny.tls13.struct.HandshakeType.certificate_verify;
import static com.gypsyengineer.tlsbunny.tls13.struct.NamedGroup.secp256r1;
import static com.gypsyengineer.tlsbunny.tls13.struct.ProtocolVersion.TLSv12;
import static com.gypsyengineer.tlsbunny.tls13.struct.ProtocolVersion.TLSv13;
import static com.gypsyengineer.tlsbunny.tls13.struct.SignatureScheme.ecdsa_secp256r1_sha256;
import static com.gypsyengineer.tlsbunny.tls13.struct.SignatureScheme.rsa_pkcs1_sha256;
import static com.gypsyengineer.tlsbunny.utils.Utils.cast;
import static org.junit.Assert.*;

public class DeepHandshakeFuzzerTest {

    @Test
    public void fuzzing() throws IOException {
        DeepHandshakeFuzzer fuzzer = deepHandshakeFuzzer().fuzzer(new TestUtils.ZeroFuzzer());
        fuzzer.recording();
        ClientHello hello = createClientHello(
                fuzzer,
                List.of(fuzzer.createExtension(
                        ExtensionType.supported_versions, new byte[32])));

        assertNotNull(hello);

        byte[] encoding = hello.encoding();
        assertFalse(Arrays.equals(encoding, new byte[encoding.length]));

        fuzzer.rounds(1);
        fuzzer.fuzzing();
        Struct fuzzed = fuzzer.fuzz(hello);
        assertNotEquals(hello, fuzzed);
        assertZeroEncoding(fuzzed);

        fuzzer.moveOn();
        assertZeroEncoding(cast(fuzzer.fuzz(hello), ClientHello.class).element(0));

        fuzzer.moveOn();
        assertZeroEncoding(cast(fuzzer.fuzz(hello), ClientHello.class).element(1));

        fuzzer.moveOn();
        assertZeroEncoding(cast(fuzzer.fuzz(hello), ClientHello.class).element(2));

        fuzzer.moveOn();
        assertZeroEncoding(cast(fuzzer.fuzz(hello), ClientHello.class).element(3));

        fuzzer.moveOn();
        assertZeroEncoding(cast(fuzzer.fuzz(hello), ClientHello.class).element(3).element(0));

        fuzzer.moveOn();
        assertZeroEncoding(cast(fuzzer.fuzz(hello), ClientHello.class).element(4));

        fuzzer.moveOn();
        assertZeroEncoding(cast(fuzzer.fuzz(hello), ClientHello.class).element(4).element(0));

        fuzzer.moveOn();
        assertZeroEncoding(cast(fuzzer.fuzz(hello), ClientHello.class).element(5));

        fuzzer.moveOn();
        assertZeroEncoding(cast(fuzzer.fuzz(hello), ClientHello.class).element(5).element(0));

        fuzzer.moveOn();
        assertZeroEncoding(cast(fuzzer.fuzz(hello), ClientHello.class).element(5).element(0).element(0));

        fuzzer.moveOn();
        assertZeroEncoding(cast(fuzzer.fuzz(hello), ClientHello.class).element(5).element(0).element(1));

        fuzzer.moveOn();
        fuzzed = fuzzer.fuzz(hello);
        assertNotEquals(hello, fuzzed);
        assertZeroEncoding(fuzzed);
    }

    private static void assertZeroEncoding(Struct struct) throws IOException {
        assertNotNull(struct);
        assertArrayEquals(zeroes(struct.encodingLength()), struct.encoding());
    }

    private static byte[] zeroes(int n) {
        return new byte[n];
    }

    @Test
    public void recording() {
        DeepHandshakeFuzzer fuzzer = deepHandshakeFuzzer().fuzzer(newByteFlipFuzzer());
        assertTrue(fuzzer.targeted().length == 0);

        // check that recording is not enabled by default
        assertNotNull(createClientHello(fuzzer));
        assertTrue(fuzzer.targeted().length == 0);

        // enable recording
        fuzzer.recording();
        assertTrue(fuzzer.targeted().length == 0);
        assertNotNull(createClientHello(fuzzer));
        assertTrue(fuzzer.targeted().length == 1);
        assertNotNull(createClientHello(fuzzer));
        assertTrue(fuzzer.targeted().length == 2);
        assertNotNull(createFinished(fuzzer));
        assertTrue(fuzzer.targeted().length == 3);
        assertArrayEquals(
                fuzzer.targeted(),
                new HandshakeType[] { client_hello, client_hello, finished });

        // disable recording
        fuzzer.fuzzing();
        assertTrue(fuzzer.targeted().length == 3);
        assertArrayEquals(
                fuzzer.targeted(),
                new HandshakeType[] { client_hello, client_hello, finished});
        assertNotNull(createClientHello(fuzzer));
        assertTrue(fuzzer.targeted().length == 3);
        assertArrayEquals(
                fuzzer.targeted(),
                new HandshakeType[] { client_hello, client_hello, finished });

        // enable recording again
        fuzzer.recording();
        assertTrue(fuzzer.targeted().length == 0);
        assertNotNull(createClientHello(fuzzer));
        assertTrue(fuzzer.targeted().length == 1);
        assertNotNull(createFinished(fuzzer));
        assertTrue(fuzzer.targeted().length == 2);
        assertNotNull(createFinished(fuzzer));
        assertTrue(fuzzer.targeted().length == 3);
        assertArrayEquals(
                fuzzer.targeted(),
                new HandshakeType[] { client_hello, finished, finished });
    }

    private static ClientHello createClientHello(StructFactory factory) {
        return createClientHello(factory, List.of());
    }

    private static ClientHello createClientHello(
            StructFactory factory, List<Extension> extensions) {

        return factory.createClientHello(
                TLSv13,
                Random.create(),
                new byte[32],
                List.of(CipherSuite.TLS_AES_128_GCM_SHA256),
                List.of(CompressionMethod.None),
                extensions);
    }

    private static Finished createFinished(StructFactory factory) {
        return factory.createFinished(new byte[32]);
    }

    @Test
    public void noFuzzing() throws Exception {
        DeepHandshakeFuzzer fuzzer = deepHandshakeFuzzer();

        // fuzzing mode is not enabled
        expectWhatTheHell(() -> fuzzer.fuzz(createFinished(StructFactory.getDefault())));
        fuzzer.recording();
        expectWhatTheHell(() -> fuzzer.fuzz(createFinished(StructFactory.getDefault())));

        // no message has been targeted
        fuzzer.fuzzing();
        expectWhatTheHell(() -> fuzzer.fuzz(createFinished(StructFactory.getDefault())));
    }

    @Test
    public void handshake() throws Exception {
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

        DeepHandshakeFuzzer fuzzer = deepHandshakeFuzzer();
        fuzzer.recording();

        try (server; clientOutput; serverOutput) {
            server.start();

            Config clientConfig = SystemPropertiesConfig.load()
                    .port(server.port());
            client.set(fuzzer).set(clientConfig).set(clientOutput);

            try (client) {
                client.connect().engines()[0].apply(new NoAlertAnalyzer());
            }
        }

        assertArrayEquals(
                fuzzer.targeted(),
                new HandshakeType[] { client_hello, certificate, certificate_verify, finished });

        List<DeepHandshakeFuzzer.Holder> holders = fuzzer.recorded();
        holders.get(0).message().type().equals(client_hello);
        holders.get(1).message().type().equals(certificate);
        holders.get(2).message().type().equals(certificate_verify);
        holders.get(3).message().type().equals(finished);

        assertEquals(
                holders.get(0).paths().length,
                1       // client_hello
                        + 6     // structs in client hello
                        + 1     // cipher_suite
                        + 1     // compression_method
                        + 4     // extensions
                        + 8     // content of extensions
        );

        assertArrayEquals(
                holders.get(0).paths()[0].indexes(),
                new Integer[] {});
        assertArrayEquals(
                holders.get(0).paths()[1].indexes(),
                new Integer[] { 0 });
        assertArrayEquals(
                holders.get(0).paths()[2].indexes(),
                new Integer[] { 1 });
        assertArrayEquals(
                holders.get(0).paths()[3].indexes(),
                new Integer[] { 2 });
        assertArrayEquals(
                holders.get(0).paths()[holders.get(0).paths().length - 1].indexes(),
                new Integer[] { 5, 3, 1 });
    }

    @Test
    public void browse() {
        StructFactory factory = StructFactory.getDefault();
        Holder holder = new Holder(createClientHello(
                factory, List.of(factory.createExtension(
                        ExtensionType.supported_versions, new byte[32]))));
        Path[] paths = holder.paths();

        assertEquals(paths.length, 12);
        assertArrayEquals(
                paths[0].indexes(),
                new Integer[] {});
        assertArrayEquals(
                paths[1].indexes(),
                new Integer[] { 0 });
        assertArrayEquals(
                paths[2].indexes(),
                new Integer[] { 1 });
        assertArrayEquals(
                paths[3].indexes(),
                new Integer[] { 2 });
        assertArrayEquals(
                paths[4].indexes(),
                new Integer[] { 3 });
        assertArrayEquals(
                paths[5].indexes(),
                new Integer[] { 3, 0 });
        assertArrayEquals(
                paths[6].indexes(),
                new Integer[] { 4 });
        assertArrayEquals(
                paths[7].indexes(),
                new Integer[] { 4, 0 });
        assertArrayEquals(
                paths[8].indexes(),
                new Integer[] { 5 });
        assertArrayEquals(
                paths[9].indexes(),
                new Integer[] { 5, 0 });
        assertArrayEquals(
                paths[10].indexes(),
                new Integer[] { 5, 0, 0 });
        assertArrayEquals(
                paths[11].indexes(),
                new Integer[] { 5, 0, 1 });
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
                            .supportedVersion(TLSv13)
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
