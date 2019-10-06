package com.gypsyengineer.tlsbunny.tls13.client;

import com.gypsyengineer.tlsbunny.tls13.connection.Engine;
import com.gypsyengineer.tlsbunny.tls13.connection.action.Side;
import com.gypsyengineer.tlsbunny.tls13.connection.action.composite.IncomingMessages;
import com.gypsyengineer.tlsbunny.tls13.connection.action.simple.*;
import com.gypsyengineer.tlsbunny.tls13.connection.check.NoExceptionCheck;
import com.gypsyengineer.tlsbunny.tls13.connection.check.NoFatalAlertCheck;
import com.gypsyengineer.tlsbunny.tls13.connection.check.SuccessCheck;
import com.gypsyengineer.tlsbunny.tls13.handshake.Context;
import com.gypsyengineer.tlsbunny.tls13.handshake.NegotiatorException;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

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

    private static final Logger logger = LogManager.getLogger(StagedHttpsClient.class);

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
                        .update(Context.Element.first_client_hello))
                .run(new WrappingIntoTLSPlaintexts()
                        .type(handshake)
                        .version(TLSv12));

    private Stage configuringGeneratingCCS = engine ->
            engine.run(new GeneratingChangeCipherSpec())
                    .run(new WrappingIntoTLSPlaintexts()
                            .type(change_cipher_spec)
                            .version(TLSv12));

    private Stage configuringReceivingSecondFlight = engine ->
            engine.until(context -> !context.receivedServerFinished() && !context.hasAlert())
                    .receive(() -> new IncomingMessages(Side.client));

    private Stage configuringGeneratingFinished = engine ->
            engine.run(new GeneratingFinished())
                    .run(new WrappingIntoHandshake()
                            .type(finished)
                            .update(Context.Element.client_finished))
                    .run(new WrappingHandshakeDataIntoTLSCiphertext());

    private Stage configuringSendingApplicationData = engine ->
            engine.run(new PreparingHttpGetRequest())
                    .run(new WrappingApplicationDataIntoTLSCiphertext());

    private Stage configureReceivingApplicationData = engine ->
            engine.until(context -> !context.receivedApplicationData() && !context.hasAlert())
                    .receive(() -> new IncomingMessages(Side.client));

    public StagedHttpsClient() {
        checks = List.of(
                new NoFatalAlertCheck(),
                new SuccessCheck(),
                new NoExceptionCheck());
    }


    @Override
    public StagedHttpsClient connectImpl() throws Exception {
            logger.info("connect to {}:{}", host, port);
            Engine engine = createEngine();
            engines.add(engine);
            engine.run();
            engine.require(checks);
            return this;
    }

    protected final Engine createEngine()
            throws NegotiatorException, NoSuchAlgorithmException {

        Engine engine = Engine.init()
                .target(host)
                .target(port)
                .set(factory)
                .set(negotiator)
                ;

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
