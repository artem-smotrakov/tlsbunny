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

public class ExtensionVectorFuzzer extends FuzzyStructFactory<Vector<Extension>> {

    private static final Logger logger = LogManager.getLogger(ExtensionVectorFuzzer.class);

    public static ExtensionVectorFuzzer newExtensionVectorFuzzer() {
        return new ExtensionVectorFuzzer();
    }

    public ExtensionVectorFuzzer() {
        this(StructFactory.getDefault());
    }

    public ExtensionVectorFuzzer(StructFactory factory) {
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
            logger.info("fuzz extension vector in ClientHello");
            Vector<Extension> fuzzed = fuzz(hello.extensions());
            hello.extensions(fuzzed);
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
            logger.info("fuzz extensions in ServerHello");
            Vector<Extension> fuzzed = fuzz(hello.extensions());
            hello.extensions(fuzzed);
        }

        return hello;
    }

    @Override
    public synchronized Vector<Extension> fuzz(Vector<Extension> extensions) {
        Vector<Extension> fuzzedExtensions = fuzzer.fuzz(extensions);

        try {
            byte[] encoding = extensions.encoding();
            byte[] fuzzed = fuzzedExtensions.encoding();
            logger.info("extensions (original): %n");
            logger.info("{}%n", printHexDiff(encoding, fuzzed));
            logger.info("extensions (fuzzed): %n");
            logger.info("{}%n", printHexDiff(fuzzed, encoding));

            if (Vector.equals(fuzzedExtensions, extensions)) {
                logger.info("nothing actually fuzzed");
            }
        } catch (IOException e) {
            logger.warn("what the hell?", e);
        }

        return fuzzedExtensions;
    }

}
