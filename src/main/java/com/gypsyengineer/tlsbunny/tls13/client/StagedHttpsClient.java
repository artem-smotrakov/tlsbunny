package com.gypsyengineer.tlsbunny.tls13.client;

import com.gypsyengineer.tlsbunny.output.Output;
import com.gypsyengineer.tlsbunny.tls13.connection.Engine;
import com.gypsyengineer.tlsbunny.tls13.connection.action.Side;
import com.gypsyengineer.tlsbunny.tls13.connection.action.composite.IncomingMessages;
import com.gypsyengineer.tlsbunny.tls13.connection.action.simple.*;
import com.gypsyengineer.tlsbunny.tls13.connection.check.NoAlertCheck;
import com.gypsyengineer.tlsbunny.tls13.connection.check.NoExceptionCheck;
import com.gypsyengineer.tlsbunny.tls13.connection.check.SuccessCheck;
import com.gypsyengineer.tlsbunny.tls13.handshake.Context;
import com.gypsyengineer.tlsbunny.tls13.handshake.NegotiatorException;

import java.security.NoSuchAlgorithmException;
import java.util.List;

import static com.gypsyengineer.tlsbunny.tls13.struct.ContentType.change_cipher_spec;
import static com.gypsyengineer.tlsbunny.tls13.struct.ContentType.handshake;
import static com.gypsyengineer.tlsbunny.tls13.struct.HandshakeType.client_hello;
import static com.gypsyengineer.tlsbunny.tls13.struct.HandshakeType.finished;
import static com.gypsyengineer.tlsbunny.tls13.struct.NamedGroup.secp256r1;
import static com.gypsyengineer.tlsbunny.tls13.struct.ProtocolVersion.TLSv12;
import static com.gypsyengineer.tlsbunny.tls13.struct.ProtocolVersion.TLSv13;
import static com.gypsyengineer.tlsbunny.tls13.struct.SignatureScheme.ecdsa_secp256r1_sha256;

public class StagedHttpsClient extends AbstractClient {

    public interface Stage {
        void run(Engine engine) throws NegotiatorException, NoSuchAlgorithmException;
    }

    public static StagedHttpsClient stagedHttpsClient() {
        return new StagedHttpsClient();
    }

    private Stage configuringGeneratingClientHello = engine ->
            engine.run(new GeneratingClientHello()
                        .supportedVersions(TLSv13)
                        .groups(secp256r1)
                        .signatureSchemes(ecdsa_secp256r1_sha256)
                        .keyShareEntries(context -> context.negotiator().createKeyShareEntry()))
                .run(new WrappingIntoHandshake()
                        .type(client_hello)
                        .updateContext(Context.Element.first_client_hello))
                .run(new WrappingIntoTLSPlaintexts()
                        .type(handshake)
                        .version(TLSv12));

    private Stage configuringGeneratingCCS = engine ->
            engine.run(new GeneratingChangeCipherSpec())
                    .run(new WrappingIntoTLSPlaintexts()
                            .type(change_cipher_spec)
                            .version(TLSv12));

    private Stage configuringReceivingSecondFlight = engine ->
            engine.loop(context -> !context.receivedServerFinished() && !context.hasAlert())
                    .receive(() -> new IncomingMessages(Side.client));

    private Stage configuringGeneratingFinished = engine ->
            engine.run(new GeneratingFinished())
                    .run(new WrappingIntoHandshake()
                            .type(finished)
                            .updateContext(Context.Element.client_finished))
                    .run(new WrappingHandshakeDataIntoTLSCiphertext());

    private Stage configuringSendingApplicationData = engine ->
            engine.run(new PreparingHttpGetRequest())
                    .run(new WrappingApplicationDataIntoTLSCiphertext());

    private Stage configureReceivingApplicationData = engine ->
            engine.loop(context -> !context.receivedApplicationData() && !context.hasAlert())
                    .receive(() -> new IncomingMessages(Side.client));

    public StagedHttpsClient() {
        checks = List.of(
                new NoAlertCheck(),
                new SuccessCheck(),
                new NoExceptionCheck());
    }


    @Override
    public StagedHttpsClient connectImpl() throws Exception {
        sync().start();
        try {
            output.info("connect to %s:%d", config.host(), config.port());
            Engine engine = createEngine();
            engines.add(engine);
            engine.connect();
            engine.run(checks);
            return this;
        } finally {
            sync().end();
        }
    }

    protected final Engine createEngine()
            throws NegotiatorException, NoSuchAlgorithmException {

        Engine engine = Engine.init()
                .target(config.host())
                .target(config.port())
                .set(factory)
                .set(negotiator)
                .set(output);

        // send ClientHello
        configuringGeneratingClientHello.run(engine);
        engine.send(new OutgoingData());

        // send CCS
        configuringGeneratingCCS.run(engine);
        engine.send(new OutgoingData());

        // receive a ServerHello, EncryptedExtensions, Certificate,
        // CertificateVerify and Finished messages
        configuringReceivingSecondFlight.run(engine);

        // send Finished
        configuringGeneratingFinished.run(engine);
        engine.send(new OutgoingData());

        // send application data
        configuringSendingApplicationData.run(engine);
        engine.send(new OutgoingData());

        // receive application data
        configureReceivingApplicationData.run(engine);

        return engine;
    }

    public StagedHttpsClient configuringGeneratingClientHello(Stage stage) {
        configuringGeneratingClientHello = stage;
        return this;
    }

    public StagedHttpsClient configuringGeneratingCCS(Stage stage) {
        configuringGeneratingCCS = stage;
        return this;
    }

    public StagedHttpsClient configuringReceivingSecondFlight(Stage stage) {
        configuringReceivingSecondFlight = stage;
        return this;
    }

    public StagedHttpsClient configuringGeneratingFinished(Stage stage) {
        configuringGeneratingFinished = stage;
        return this;
    }

    public StagedHttpsClient configuringSendingApplicationData(Stage stage) {
        configuringSendingApplicationData = stage;
        return this;
    }

    public StagedHttpsClient configureReceivingApplicationData(Stage stage) {
        configureReceivingApplicationData = stage;
        return this;
    }

}
