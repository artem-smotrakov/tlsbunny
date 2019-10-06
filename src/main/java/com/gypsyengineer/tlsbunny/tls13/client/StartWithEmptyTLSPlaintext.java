package com.gypsyengineer.tlsbunny.tls13.client;

import com.gypsyengineer.tlsbunny.tls13.connection.Engine;
import com.gypsyengineer.tlsbunny.tls13.connection.action.Side;
import com.gypsyengineer.tlsbunny.tls13.connection.action.composite.IncomingMessages;
import com.gypsyengineer.tlsbunny.tls13.connection.action.simple.*;
import com.gypsyengineer.tlsbunny.tls13.connection.check.AlertCheck;
import com.gypsyengineer.tlsbunny.tls13.handshake.Context;
import com.gypsyengineer.tlsbunny.tls13.handshake.NegotiatorException;
import com.gypsyengineer.tlsbunny.tls13.struct.ContentType;
import com.gypsyengineer.tlsbunny.tls13.struct.StructFactory;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.security.NoSuchAlgorithmException;
import java.util.List;

import static com.gypsyengineer.tlsbunny.tls13.struct.ContentType.*;
import static com.gypsyengineer.tlsbunny.tls13.struct.HandshakeType.client_hello;
import static com.gypsyengineer.tlsbunny.tls13.struct.HandshakeType.finished;
import static com.gypsyengineer.tlsbunny.tls13.struct.NamedGroup.secp256r1;
import static com.gypsyengineer.tlsbunny.tls13.struct.ProtocolVersion.TLSv12;
import static com.gypsyengineer.tlsbunny.tls13.struct.ProtocolVersion.TLSv13;
import static com.gypsyengineer.tlsbunny.tls13.struct.SignatureScheme.ecdsa_secp256r1_sha256;

public class StartWithEmptyTLSPlaintext extends SingleConnectionClient {

    private static final Logger logger = LogManager.getLogger(StartWithEmptyTLSPlaintext.class);

    private ContentType type = handshake;

    public static void main(String[] args) throws Exception {
        StructFactory factory = StructFactory.getDefault();

        try (StartWithEmptyTLSPlaintext client = new StartWithEmptyTLSPlaintext()) {

            /**
             * The TLS 1.3 spec says the following:
             *
             *    A change_cipher_spec record received before the first ClientHello message
             *    or after the peer's Finished message MUST be treated as an unexpected record type
             *
             *  https://tools.ietf.org/html/draft-ietf-tls-tls13-28#section-5
             */
            client.set(change_cipher_spec)
                    .set(factory)
                    .connect();
        }

        try (StartWithEmptyTLSPlaintext client = new StartWithEmptyTLSPlaintext()) {

            /**
             * The TLS 1.3 spec says the following:
             *
             *      Implementations MUST NOT send None-length fragments of Handshake
             *      types, even if those fragments contain padding.
             *
             *  https://tools.ietf.org/html/draft-ietf-tls-tls13-28#section-5.1
             *
             *  Should it expect an alert them
             *  after sending an empty TLSPlaintext message of handshake type?
             */
            client.set(handshake)
                    .set(factory)
                    .connect();
        }

        try (StartWithEmptyTLSPlaintext client = new StartWithEmptyTLSPlaintext()) {

            client.set(application_data)
                    .set(factory)
                    .connect();
        }

        try (StartWithEmptyTLSPlaintext client = new StartWithEmptyTLSPlaintext()) {

            client.set(alert)
                    .set(factory)
                    .connect();
        }
    }

    public StartWithEmptyTLSPlaintext() {
        checks = List.of(new AlertCheck());
    }

    public StartWithEmptyTLSPlaintext set(ContentType type) {
        this.type = type;
        return this;
    }

    protected Engine createEngine()
            throws NegotiatorException, NoSuchAlgorithmException {

        logger.info("test: start handshake with an empty TLSPlaintext ({})", type);

        return Engine.init()
                .target(host)
                .target(port)
                .set(factory)

                .run(new GeneratingEmptyTLSPlaintext()
                        .type(type)
                        .version(TLSv12))
                .send(new OutgoingData())

                // send ClientHello
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
                .send(new OutgoingData())

                // receive a ServerHello, EncryptedExtensions, Certificate,
                // CertificateVerify and Finished messages
                // TODO: how can we make it more readable?
                .until(context -> !context.receivedServerFinished() && !context.hasAlert())
                    .receive(() -> new IncomingMessages(Side.client))

                // send Finished
                .run(new GeneratingFinished())
                .run(new WrappingIntoHandshake()
                        .type(finished)
                        .update(Context.Element.client_finished))
                .run(new WrappingHandshakeDataIntoTLSCiphertext())
                .send(new OutgoingData())

                // send application data
                .run(new PreparingHttpGetRequest())
                .run(new WrappingApplicationDataIntoTLSCiphertext())
                .send(new OutgoingData())

                // receive session tickets and application data
                .until(context -> !context.receivedApplicationData() && !context.hasAlert())
                    .receive(() -> new IncomingMessages(Side.client));
    }

}
