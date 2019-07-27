package com.gypsyengineer.tlsbunny.tls13.client.ccs;

import com.gypsyengineer.tlsbunny.tls13.client.AbstractClient;
import com.gypsyengineer.tlsbunny.tls13.client.Client;
import com.gypsyengineer.tlsbunny.tls13.connection.*;
import com.gypsyengineer.tlsbunny.tls13.connection.action.ActionFailed;
import com.gypsyengineer.tlsbunny.tls13.connection.action.Side;
import com.gypsyengineer.tlsbunny.tls13.connection.action.composite.*;
import com.gypsyengineer.tlsbunny.tls13.connection.action.simple.*;
import com.gypsyengineer.tlsbunny.tls13.connection.check.AlertCheck;
import com.gypsyengineer.tlsbunny.tls13.handshake.Context;
import com.gypsyengineer.tlsbunny.tls13.handshake.NegotiatorException;
import com.gypsyengineer.tlsbunny.output.Output;

import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.util.List;

import static com.gypsyengineer.tlsbunny.tls13.struct.ChangeCipherSpec.max;
import static com.gypsyengineer.tlsbunny.tls13.struct.ChangeCipherSpec.min;
import static com.gypsyengineer.tlsbunny.tls13.struct.ChangeCipherSpec.valid_value;
import static com.gypsyengineer.tlsbunny.tls13.struct.ContentType.handshake;
import static com.gypsyengineer.tlsbunny.tls13.struct.HandshakeType.client_hello;
import static com.gypsyengineer.tlsbunny.tls13.struct.HandshakeType.finished;
import static com.gypsyengineer.tlsbunny.tls13.struct.NamedGroup.secp256r1;
import static com.gypsyengineer.tlsbunny.tls13.struct.ProtocolVersion.TLSv12;
import static com.gypsyengineer.tlsbunny.tls13.struct.ProtocolVersion.TLSv13;
import static com.gypsyengineer.tlsbunny.tls13.struct.SignatureScheme.ecdsa_secp256r1_sha256;
import static com.gypsyengineer.tlsbunny.utils.WhatTheHell.whatTheHell;

public class InvalidCCS extends AbstractClient {

    private int start = min;
    private int end = max;

    public static void main(String[] args) throws Exception {
        try (Output output = Output.standardClient();
             InvalidCCS client = new InvalidCCS()) {

            client.set(output).connect();
        }
    }

    public InvalidCCS() {
        checks = List.of(new AlertCheck());
    }

    public InvalidCCS startWith(int ccsValue) {
        start = check(ccsValue);
        return this;
    }

    public InvalidCCS endWith(int ccsValue) {
        end = check(ccsValue);
        return this;
    }

    @Override
    public Client connectImpl() throws NoSuchAlgorithmException, NegotiatorException,
            EngineException, ActionFailed {

        if (start > end) {
            throw whatTheHell("starting ccs value (%d) is greater " +
                    "than end ccs value (%d)", start, end);
        }

        Analyzer analyzer = new NoAlertAnalyzer().set(output);
        for (int ccsValue = start; ccsValue <= end; ccsValue++) {
            if (ccsValue == valid_value) {
                continue;
            }

            sync().start();
            try {
                output.info("try CCS with %d", ccsValue);
                Engine engine = createEngine(ccsValue)
                        .connect()
                        .run(checks)
                        .apply(analyzer);
                engines.add(engine);
            } catch (EngineException e) {
                Throwable cause = e.getCause();
                if (cause instanceof IOException) {
                    // we expect that the server might have closed the connection
                    // after receiving an invalid CCS message
                    output.info("exception: %s", e.getMessage());
                } else {
                    throw e;
                }
            } finally {
                sync().end();
            }
        }
        analyzer.run();

        return this;
    }

    private Engine createEngine(int ccsValue)
            throws NegotiatorException, NoSuchAlgorithmException {

        return Engine.init()
                .target(config.host())
                .target(config.port())
                .set(factory)
                .set(output)
                .label(String.format("invalid_ccs:%d", ccsValue))

                // send ClientHello
                .run(new GeneratingClientHello()
                        .supportedVersions(TLSv13)
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

                .send(new OutgoingChangeCipherSpec()
                        .set(ccsValue))

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

    private static int check(int ccsValue) {
        if (ccsValue < 0 || ccsValue > 255) {
            throw whatTheHell("incorrect ccs value (%d)", ccsValue);
        }

        return ccsValue;
    }

}
