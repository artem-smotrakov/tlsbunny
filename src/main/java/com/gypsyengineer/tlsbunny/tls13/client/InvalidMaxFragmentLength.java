package com.gypsyengineer.tlsbunny.tls13.client;

import com.gypsyengineer.tlsbunny.tls13.connection.Engine;
import com.gypsyengineer.tlsbunny.tls13.connection.EngineException;
import com.gypsyengineer.tlsbunny.tls13.connection.action.ActionFailed;
import com.gypsyengineer.tlsbunny.tls13.connection.action.simple.GeneratingClientHello;
import com.gypsyengineer.tlsbunny.tls13.connection.action.simple.WrappingIntoHandshake;
import com.gypsyengineer.tlsbunny.tls13.connection.action.simple.WrappingIntoTLSPlaintexts;
import com.gypsyengineer.tlsbunny.tls13.connection.check.AlertCheck;
import com.gypsyengineer.tlsbunny.tls13.connection.check.FailureCheck;
import com.gypsyengineer.tlsbunny.tls13.connection.check.SuccessCheck;
import com.gypsyengineer.tlsbunny.tls13.handshake.Context;
import com.gypsyengineer.tlsbunny.tls13.handshake.NegotiatorException;
import com.gypsyengineer.tlsbunny.tls13.struct.MaxFragmentLength;
import com.gypsyengineer.tlsbunny.utils.Utils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.security.NoSuchAlgorithmException;

import static com.gypsyengineer.tlsbunny.tls13.connection.action.simple.GeneratingClientHello.no_max_fragment_length;
import static com.gypsyengineer.tlsbunny.tls13.struct.ContentType.handshake;
import static com.gypsyengineer.tlsbunny.tls13.struct.HandshakeType.client_hello;
import static com.gypsyengineer.tlsbunny.tls13.struct.NamedGroup.secp256r1;
import static com.gypsyengineer.tlsbunny.tls13.struct.ProtocolVersion.TLSv12;
import static com.gypsyengineer.tlsbunny.tls13.struct.ProtocolVersion.TLSv13;
import static com.gypsyengineer.tlsbunny.tls13.struct.SignatureScheme.ecdsa_secp256r1_sha256;

public class InvalidMaxFragmentLength extends StagedHttpsClient {

    private static final Logger logger = LogManager.getLogger(InvalidMaxFragmentLength.class);

    private final static int WITHOUT_MAX_FRAGMENT_LENGTH = -1;

    @Override
    public InvalidMaxFragmentLength connectImpl()
            throws NoSuchAlgorithmException, NegotiatorException,
            EngineException, ActionFailed {

        logger.info("connect to {}:{}", host, port);

        logger.info("send no max_fragment_length extension, " +
                "expect a successful connection");
        configuringGeneratingClientHello(clientHelloStage(WITHOUT_MAX_FRAGMENT_LENGTH));
        Engine engine = createEngine();
        engines.add(engine);
        engine.run();
        engine.require(new SuccessCheck());

        for (int code : MaxFragmentLength.codes()) {
            logger.info("send valid max_fragment_length extension ({}), " +
                    "expect successful connection", code);
            configuringGeneratingClientHello(clientHelloStage(code));
            engine = createEngine();
            engines.add(engine);
            engine.run();
            engine.require(new SuccessCheck());

        }

        for (int code = 0; code < 256; code++) {
            if (Utils.contains(code, MaxFragmentLength.codes())) {
                continue;
            }

            logger.info("send invalid max_fragment_length extension ({}), " +
                    "expect connection failure", code);
            configuringGeneratingClientHello(clientHelloStage(code));
            engine = createEngine();
            engines.add(engine);
            engine.run();
            engine.requireOne(new FailureCheck(), new AlertCheck());
        }

        return this;
    }

    private Stage clientHelloStage(int code) {
        return engine -> engine.run(new GeneratingClientHello()
                .supportedVersions(TLSv13)
                .groups(secp256r1)
                .signatureSchemes(ecdsa_secp256r1_sha256)
                .keyShareEntries(context -> context.negotiator().createKeyShareEntry())
                .set(maxFragmentLength(code)))
                .run(new WrappingIntoHandshake()
                        .type(client_hello)
                        .update(Context.Element.first_client_hello))
                .run(new WrappingIntoTLSPlaintexts()
                        .type(handshake)
                        .version(TLSv12));
    }

    private MaxFragmentLength maxFragmentLength(int code) {
        if (code > 0) {
            return factory.createMaxFragmentLength(code);
        }

        return no_max_fragment_length;
    }
}
