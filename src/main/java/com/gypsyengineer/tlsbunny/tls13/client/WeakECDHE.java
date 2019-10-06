package com.gypsyengineer.tlsbunny.tls13.client;

import com.gypsyengineer.tlsbunny.tls13.connection.Engine;
import com.gypsyengineer.tlsbunny.tls13.connection.action.composite.OutgoingChangeCipherSpec;
import com.gypsyengineer.tlsbunny.tls13.connection.action.simple.*;
import com.gypsyengineer.tlsbunny.tls13.connection.check.NoExceptionCheck;
import com.gypsyengineer.tlsbunny.tls13.connection.check.NoFatalAlertCheck;
import com.gypsyengineer.tlsbunny.tls13.connection.check.SuccessCheck;
import com.gypsyengineer.tlsbunny.tls13.handshake.Context;
import com.gypsyengineer.tlsbunny.tls13.handshake.NegotiatorException;
import com.gypsyengineer.tlsbunny.tls13.handshake.WeakECDHENegotiator;
import com.gypsyengineer.tlsbunny.tls13.struct.NamedGroup;
import com.gypsyengineer.tlsbunny.tls13.struct.StructFactory;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.security.NoSuchAlgorithmException;
import java.util.List;

import static com.gypsyengineer.tlsbunny.tls13.struct.AlertDescription.close_notify;
import static com.gypsyengineer.tlsbunny.tls13.struct.AlertLevel.warning;
import static com.gypsyengineer.tlsbunny.tls13.struct.ContentType.alert;
import static com.gypsyengineer.tlsbunny.tls13.struct.ContentType.handshake;
import static com.gypsyengineer.tlsbunny.tls13.struct.HandshakeType.client_hello;
import static com.gypsyengineer.tlsbunny.tls13.struct.NamedGroup.secp256r1;
import static com.gypsyengineer.tlsbunny.tls13.struct.ProtocolVersion.TLSv12;
import static com.gypsyengineer.tlsbunny.tls13.struct.ProtocolVersion.TLSv13;
import static com.gypsyengineer.tlsbunny.tls13.struct.SignatureScheme.ecdsa_secp256r1_sha256;

public class WeakECDHE extends AbstractClient {

    private static final Logger logger = LogManager.getLogger(WeakECDHE.class);

    // TODO: should it be more?
    private int n = 1;

    public WeakECDHE() {
        checks = List.of(
                new NoFatalAlertCheck(), new SuccessCheck(), new NoExceptionCheck());
    }

    public WeakECDHE connections(int n) {
        this.n = n;
        return this;
    }

    @Override
    public WeakECDHE connectImpl() throws Exception {
        for (int i = 0; i < n; i++) {
            logger.info("test #{}", i);
            engines.add(createEngine().run().require(checks));
        }

        return this;
    }

    private Engine createEngine() throws NegotiatorException, NoSuchAlgorithmException {
        WeakECDHENegotiator negotiator = WeakECDHENegotiator.create(
                NamedGroup.Secp.secp256r1, StructFactory.getDefault());

        return Engine.init()
                .target(host)
                .target(port)

                .set(negotiator)

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

                .send(new OutgoingChangeCipherSpec())

                // receive incoming data and check if it's an alert
                .receive(new IncomingData())
                .run(new CheckingForAlert())

                .run(new GeneratingAlert().level(warning).description(close_notify))
                .run(new WrappingIntoTLSPlaintexts()
                        .type(alert)
                        .version(TLSv12))
                .send(new OutgoingData());
    }

}
