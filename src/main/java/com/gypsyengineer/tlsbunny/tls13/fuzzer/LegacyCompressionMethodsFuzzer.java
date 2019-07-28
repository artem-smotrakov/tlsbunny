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

public class LegacyCompressionMethodsFuzzer
        extends FuzzyStructFactory<Vector<CompressionMethod>> {

    private static final Logger logger = LogManager.getLogger(LegacyCompressionMethodsFuzzer.class);

    public static LegacyCompressionMethodsFuzzer legacyCompressionMethodsFuzzer() {
        return new LegacyCompressionMethodsFuzzer();
    }

    public LegacyCompressionMethodsFuzzer() {
        this(StructFactory.getDefault());
    }

    public LegacyCompressionMethodsFuzzer(StructFactory factory) {
        super(factory);
        targets(client_hello, server_hello);
    }

    @Override
    public ClientHello createClientHello(ProtocolVersion legacy_version,
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
            logger.info("fuzz legacy compression methods in ClientHello");
            Vector<CompressionMethod> fuzzed = fuzz(hello.legacyCompressionMethods());
            hello.legacyCompressionMethods(fuzzed);
        }

        return hello;
    }

    @Override
    public synchronized Vector<CompressionMethod> fuzz(
            Vector<CompressionMethod> compressionMethods) {

        Vector<CompressionMethod> fuzzedCompressionMethods = fuzzer.fuzz(compressionMethods);

        try {
            byte[] encoding = compressionMethods.encoding();
            byte[] fuzzed = fuzzedCompressionMethods.encoding();
            logger.info("legacy compression methods (original): %n");
            logger.info("{}%n", printHexDiff(encoding, fuzzed));
            logger.info("legacy compression methods (fuzzed): %n");
            logger.info("{}%n", printHexDiff(fuzzed, encoding));

            if (Vector.equals(fuzzedCompressionMethods, compressionMethods)) {
                logger.info("nothing actually fuzzed");
            }
        } catch (IOException e) {
            logger.warn("what the hell?", e);
        }

        return fuzzedCompressionMethods;
    }

}
