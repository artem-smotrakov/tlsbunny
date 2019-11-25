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
import com.gypsyengineer.tlsbunny.tls13.struct.ProtocolVersion;

import java.security.NoSuchAlgorithmException;
import java.util.List;

import static com.gypsyengineer.tlsbunny.tls13.connection.action.simple.GeneratingClientHello.generatingClientHello;
import static com.gypsyengineer.tlsbunny.tls13.connection.action.simple.WrappingIntoHandshake.wrappingIntoHandshake;
import static com.gypsyengineer.tlsbunny.tls13.connection.action.simple.WrappingIntoTLSPlaintexts.wrappingIntoTLSPlaintexts;
import static com.gypsyengineer.tlsbunny.tls13.struct.ContentType.handshake;
import static com.gypsyengineer.tlsbunny.tls13.struct.HandshakeType.client_hello;
import static com.gypsyengineer.tlsbunny.tls13.struct.HandshakeType.finished;
import static com.gypsyengineer.tlsbunny.tls13.struct.NamedGroup.secp256r1;
import static com.gypsyengineer.tlsbunny.tls13.struct.ProtocolVersion.TLSv12;
import static com.gypsyengineer.tlsbunny.tls13.struct.ProtocolVersion.TLSv13;
import static com.gypsyengineer.tlsbunny.tls13.struct.PskKeyExchangeMode.psk_dhe_ke;
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
                .set(host, port)
                .set(factory)
                .set(negotiator)

                .run(generatingClientHello()
                        .supportedVersions(protocolVersion)
                        .groups(secp256r1)
                        .signatureSchemes(ecdsa_secp256r1_sha256)
                        .keyShareEntries(Negotiator::createKeyShareEntry)
                        .pskKeyExchangeModes(psk_dhe_ke))
                .run(wrappingIntoHandshake()
                        .type(client_hello)
                        .update(Context.Element.first_client_hello))
                .run(wrappingIntoTLSPlaintexts()
                        .type(handshake)
                        .version(TLSv12))
                .send(OutgoingData::new)

                .send(OutgoingChangeCipherSpec::new)

                .until(Condition::serverDone)
                .receive(IncomingMessages::fromServer)

                .run(GeneratingFinished::new)
                .run(wrappingIntoHandshake()
                        .type(finished)
                        .update(Context.Element.client_finished))
                .run(WrappingHandshakeDataIntoTLSCiphertext::new)
                .send(OutgoingData::new)

                .run(PreparingHttpGetRequest::new)
                .run(WrappingApplicationDataIntoTLSCiphertext::new)
                .send(OutgoingData::new)

                .until(Condition::applicationDataReceived)
                .receive(IncomingMessages::fromServer);
    }

}
