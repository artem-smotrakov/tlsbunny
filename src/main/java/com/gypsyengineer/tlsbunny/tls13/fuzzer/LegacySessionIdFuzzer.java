package com.gypsyengineer.tlsbunny.tls13.fuzzer;

import com.gypsyengineer.tlsbunny.tls.Random;
import com.gypsyengineer.tlsbunny.tls.Vector;
import com.gypsyengineer.tlsbunny.tls13.struct.*;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.io.IOException;
import java.util.List;

import static com.gypsyengineer.tlsbunny.tls13.fuzzer.Target.client_hello;
import static com.gypsyengineer.tlsbunny.tls13.fuzzer.Target.server_hello;
import static com.gypsyengineer.tlsbunny.utils.HexDump.printHexDiff;

public class LegacySessionIdFuzzer extends FuzzyStructFactory<Vector<Byte>> {

    private static final Logger logger = LogManager.getLogger(LegacySessionIdFuzzer.class);

    public static LegacySessionIdFuzzer legacySessionIdFuzzer() {
        return new LegacySessionIdFuzzer();
    }

    public LegacySessionIdFuzzer() {
        this(StructFactory.getDefault());
    }

    public LegacySessionIdFuzzer(StructFactory factory) {
        super(factory);
        targets(client_hello, server_hello);
    }

    @Override
    public synchronized ClientHello createClientHello(ProtocolVersion legacy_version,
                                                      Random random,
                                                      byte[] legacy_session_id,
                                                      List<CipherSuite> cipher_suites,
                                                      List<CompressionMethod> legacy_compression_methods,
                                                      List<Extension> extensions) {

        ClientHello hello = factory.createClientHello(
                legacy_version,
                random,
                legacy_session_id,
                cipher_suites,
                legacy_compression_methods,
                extensions);

        if (targeted(client_hello)) {
            logger.info("fuzz legacy session ID in ClientHello");
            Vector<Byte> fuzzed = fuzz(hello.legacySessionId());
            hello.legacySessionId(fuzzed);
        }

        return hello;
    }

    @Override
    public synchronized ServerHello createServerHello(ProtocolVersion version,
                                                      Random random,
                                                      byte[] legacy_session_id_echo,
                                                      CipherSuite cipher_suite,
                                                      CompressionMethod legacy_compression_method,
                                                      List<Extension> extensions) {

        ServerHello hello = factory.createServerHello(
                version,
                random,
                legacy_session_id_echo,
                cipher_suite,
                legacy_compression_method,
                extensions);

        if (targeted(server_hello)) {
            logger.info("fuzz legacy session ID echo in ServerHello");
            Vector<Byte> fuzzed = fuzz(hello.legacySessionIdEcho());
            hello.legacySessionIdEcho(fuzzed);
        }

        return hello;
    }

    @Override
    public synchronized Vector<Byte> fuzz(Vector<Byte> sessionId) {
        Vector<Byte> fuzzedSessionId = fuzzer.fuzz(sessionId);

        try {
            byte[] encoding = sessionId.encoding();
            byte[] fuzzed = fuzzedSessionId.encoding();
            logger.info("legacy session ID (original): %n");
            logger.info("{}%n", printHexDiff(encoding, fuzzed));
            logger.info("legacy session ID (fuzzed): %n");
            logger.info("{}%n", printHexDiff(fuzzed, encoding));

            if (Vector.equals(fuzzedSessionId, sessionId)) {
                logger.info("nothing actually fuzzed");
            }
        } catch (IOException e) {
            logger.warn("what the hell?", e);
        }

        return fuzzedSessionId;
    }

}
