package com.gypsyengineer.tlsbunny.tls13.client;

import com.gypsyengineer.tlsbunny.tls13.connection.Condition;
import com.gypsyengineer.tlsbunny.tls13.connection.Engine;
import com.gypsyengineer.tlsbunny.tls13.connection.action.composite.IncomingMessages;
import com.gypsyengineer.tlsbunny.tls13.connection.action.composite.OutgoingChangeCipherSpec;
import com.gypsyengineer.tlsbunny.tls13.connection.action.simple.*;
import com.gypsyengineer.tlsbunny.tls13.connection.check.NoExceptionCheck;
import com.gypsyengineer.tlsbunny.tls13.connection.check.NoFatalAlertCheck;
import com.gypsyengineer.tlsbunny.tls13.connection.check.SuccessCheck;
import com.gypsyengineer.tlsbunny.tls13.handshake.Context;
import com.gypsyengineer.tlsbunny.tls13.handshake.Negotiator;
import com.gypsyengineer.tlsbunny.tls13.handshake.NegotiatorException;
import com.gypsyengineer.tlsbunny.utils.Config;

import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.util.List;

import static com.gypsyengineer.tlsbunny.tls13.connection.action.composite.OutgoingClientCertificate.outgoingClientCertificate;
import static com.gypsyengineer.tlsbunny.tls13.connection.action.composite.OutgoingClientCertificateVerify.outgoingClientCertificateVerify;
import static com.gypsyengineer.tlsbunny.tls13.connection.action.simple.GeneratingClientHello.generatingClientHello;
import static com.gypsyengineer.tlsbunny.tls13.connection.action.simple.WrappingIntoHandshake.wrappingIntoHandshake;
import static com.gypsyengineer.tlsbunny.tls13.connection.action.simple.WrappingIntoTLSPlaintexts.wrappingIntoTLSPlaintexts;
import static com.gypsyengineer.tlsbunny.tls13.struct.ContentType.handshake;
import static com.gypsyengineer.tlsbunny.tls13.struct.HandshakeType.client_hello;
import static com.gypsyengineer.tlsbunny.tls13.struct.HandshakeType.finished;
import static com.gypsyengineer.tlsbunny.tls13.struct.NamedGroup.secp256r1;
import static com.gypsyengineer.tlsbunny.tls13.struct.ProtocolVersion.TLSv12;
import static com.gypsyengineer.tlsbunny.tls13.struct.ProtocolVersion.TLSv13;
import static com.gypsyengineer.tlsbunny.tls13.struct.SignatureScheme.ecdsa_secp256r1_sha256;

public class HttpsClientAuth extends SingleConnectionClient {

    private String clientCertificate = Config.instance.getString("client.certificate.path");
    private String clientKey = Config.instance.getString("client.key.path");

    public static void main(String[] args) throws Exception {
        try (HttpsClientAuth client = new HttpsClientAuth()) {
            client.connect();
        }
    }

    public static HttpsClientAuth httpsClientAuth() {
        return new HttpsClientAuth();
    }

    public HttpsClientAuth() {
        checks = List.of(
                new NoFatalAlertCheck(),
                new SuccessCheck(),
                new NoExceptionCheck());
    }

    @Override
    protected Engine createEngine()
            throws NegotiatorException, NoSuchAlgorithmException, IOException {

        return Engine.init()
                .set(host, port)
                .set(factory)
                .set(negotiator)

                // send ClientHello
                .run(generatingClientHello()
                        .supportedVersions(TLSv13)
                        .groups(secp256r1)
                        .signatureSchemes(ecdsa_secp256r1_sha256)
                        .keyShareEntries(Negotiator::createKeyShareEntry))
                .run(wrappingIntoHandshake()
                        .type(client_hello)
                        .update(Context.Element.first_client_hello))
                .run(wrappingIntoTLSPlaintexts()
                        .type(handshake)
                        .version(TLSv12))
                .send(OutgoingData::new)

                .send(OutgoingChangeCipherSpec::new)

                /* receive ServerHello
                 *         EncryptedExtensions
                 *         Certificate,
                 *         CertificateVerify
                 *         Finished
                 * or an alert
                 */
                .until(Condition::serverDone)
                .receive(IncomingMessages::fromServer)

                .send(outgoingClientCertificate()
                        .with(clientCertificate))
                .send(outgoingClientCertificateVerify()
                        .with(clientKey))

                // send Finished
                .run(GeneratingFinished::new)
                .run(wrappingIntoHandshake()
                        .type(finished)
                        .update(Context.Element.client_finished))
                .run(WrappingHandshakeDataIntoTLSCiphertext::new)
                .send(OutgoingData::new)

                // send application data
                .run(PreparingHttpGetRequest::new)
                .run(WrappingApplicationDataIntoTLSCiphertext::new)
                .send(OutgoingData::new)

                // receive session tickets and application data
                .until(Condition::applicationDataReceived)
                .receive(IncomingMessages::fromServer);
    }

}
