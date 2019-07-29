package com.gypsyengineer.tlsbunny.tls13.client;

import com.gypsyengineer.tlsbunny.tls13.connection.Engine;
import com.gypsyengineer.tlsbunny.tls13.connection.action.Side;
import com.gypsyengineer.tlsbunny.tls13.connection.action.composite.IncomingMessages;
import com.gypsyengineer.tlsbunny.tls13.connection.action.composite.OutgoingChangeCipherSpec;
import com.gypsyengineer.tlsbunny.tls13.connection.action.simple.*;
import com.gypsyengineer.tlsbunny.tls13.connection.check.NoFatalAlertCheck;
import com.gypsyengineer.tlsbunny.tls13.connection.check.NoExceptionCheck;
import com.gypsyengineer.tlsbunny.tls13.connection.check.SuccessCheck;
import com.gypsyengineer.tlsbunny.tls13.handshake.Context;
import com.gypsyengineer.tlsbunny.tls13.handshake.NegotiatorException;
import com.gypsyengineer.tlsbunny.tls13.struct.ProtocolVersion;

import java.security.NoSuchAlgorithmException;
import java.util.List;

import static com.gypsyengineer.tlsbunny.tls13.struct.ContentType.handshake;
import static com.gypsyengineer.tlsbunny.tls13.struct.HandshakeType.client_hello;
import static com.gypsyengineer.tlsbunny.tls13.struct.HandshakeType.finished;
import static com.gypsyengineer.tlsbunny.tls13.struct.NamedGroup.secp256r1;
import static com.gypsyengineer.tlsbunny.tls13.struct.ProtocolVersion.TLSv12;
import static com.gypsyengineer.tlsbunny.tls13.struct.ProtocolVersion.TLSv13;
import static com.gypsyengineer.tlsbunny.tls13.struct.SignatureScheme.ecdsa_secp256r1_sha256;

public class HttpsClient extends SingleConnectionClient {

    private ProtocolVersion protocolVersion = TLSv13;

    public static void main(String... args) throws Exception {
        try (HttpsClient client = new HttpsClient()) {
            client.connect();
        }
    }

    public static HttpsClient httpsClient() {
        return new HttpsClient();
    }

    public HttpsClient() {
        checks = List.of(
                new NoFatalAlertCheck(),
                new SuccessCheck(),
                new NoExceptionCheck());
    }

    public HttpsClient version(ProtocolVersion protocolVersion) {
        this.protocolVersion = protocolVersion;
        return this;
    }

    @Override
    protected Engine createEngine()
            throws NegotiatorException, NoSuchAlgorithmException {

        return Engine.init()
                .target(host)
                .target(port)
                .set(factory)
                .set(negotiator)

                // send ClientHello
                .run(new GeneratingClientHello()
                        .supportedVersions(protocolVersion)
                        .groups(secp256r1)
                        .signatureSchemes(ecdsa_secp256r1_sha256)
                        .keyShareEntries(context -> context.negotiator().createKeyShareEntry()))
                .run(new WrappingIntoHandshake()
                        .type(client_hello)
                        .updateContext(Context.Element.first_client_hello))
                .run(new WrappingIntoTLSPlaintexts()
                        .type(handshake)
                        .version(TLSv12))
                .send(new OutgoingData())

                .send(new OutgoingChangeCipherSpec())

                // receive a ServerHello, EncryptedExtensions, Certificate,
                // CertificateVerify and Finished messages
                // TODO: how can we make it more readable?
                .loop(context -> !context.receivedServerFinished() && !context.hasAlert())
                    .receive(() -> new IncomingMessages(Side.client))

                // send Finished
                .run(new GeneratingFinished())
                .run(new WrappingIntoHandshake()
                        .type(finished)
                        .updateContext(Context.Element.client_finished))
                .run(new WrappingHandshakeDataIntoTLSCiphertext())
                .send(new OutgoingData())

                // send application data
                .run(new PreparingHttpGetRequest())
                .run(new WrappingApplicationDataIntoTLSCiphertext())
                .send(new OutgoingData())

                // receive session tickets and application data
                .loop(context -> !context.receivedApplicationData() && !context.hasAlert())
                    .receive(() -> new IncomingMessages(Side.client));
    }

}
