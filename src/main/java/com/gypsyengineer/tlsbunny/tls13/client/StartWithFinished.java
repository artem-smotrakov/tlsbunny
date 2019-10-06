package com.gypsyengineer.tlsbunny.tls13.client;

import com.gypsyengineer.tlsbunny.tls13.connection.Engine;
import com.gypsyengineer.tlsbunny.tls13.connection.action.Side;
import com.gypsyengineer.tlsbunny.tls13.connection.action.composite.IncomingMessages;
import com.gypsyengineer.tlsbunny.tls13.connection.action.composite.OutgoingChangeCipherSpec;
import com.gypsyengineer.tlsbunny.tls13.connection.action.simple.*;
import com.gypsyengineer.tlsbunny.tls13.connection.check.AlertCheck;
import com.gypsyengineer.tlsbunny.tls13.handshake.Context;
import com.gypsyengineer.tlsbunny.tls13.handshake.NegotiatorException;

import java.security.NoSuchAlgorithmException;
import java.util.List;

import static com.gypsyengineer.tlsbunny.tls13.struct.ContentType.handshake;
import static com.gypsyengineer.tlsbunny.tls13.struct.HandshakeType.finished;
import static com.gypsyengineer.tlsbunny.tls13.struct.ProtocolVersion.TLSv12;

public class StartWithFinished extends SingleConnectionClient {

    public static void main(String[] args) throws Exception {
        try (StartWithFinished client = new StartWithFinished()) {
            client.connect();
        }
    }

    public StartWithFinished() {
        checks = List.of(new AlertCheck());
    }

    @Override
    protected Engine createEngine()
            throws NegotiatorException, NoSuchAlgorithmException {

        return Engine.init()
                .target(host)
                .target(port)
                .set(factory)


                // send Finished
                .run(new GeneratingRandomFinishedKey())
                .run(new GeneratingFinished())
                .run(new WrappingIntoHandshake()
                        .type(finished)
                        .run((context, message) -> context.setClientFinished(message)))
                .run(new WrappingIntoTLSPlaintexts()
                        .type(handshake)
                        .version(TLSv12))
                .send(new OutgoingData())

                .send(new OutgoingChangeCipherSpec())

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
