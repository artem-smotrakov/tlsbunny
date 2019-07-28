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

public class CipherSuitesFuzzer extends FuzzyStructFactory<Vector<CipherSuite>> {

    private static final Logger logger = LogManager.getLogger(CipherSuitesFuzzer.class);

    public static CipherSuitesFuzzer cipherSuitesFuzzer() {
        return new CipherSuitesFuzzer();
    }

    public CipherSuitesFuzzer() {
        this(StructFactory.getDefault());
    }

    public CipherSuitesFuzzer(StructFactory factory) {
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

        ClientHello clientHello = factory.createClientHello(
                legacy_version,
                random,
                legacy_session_id,
                cipher_suites,
                legacy_compression_methods,
                extensions);

        if (targeted(client_hello)) {
            logger.info("fuzz cipher suites in ClientHello");
            Vector<CipherSuite> fuzzed = fuzz(clientHello.cipherSuites());
            clientHello.cipherSuites(fuzzed);
        }

        return clientHello;
    }

    @Override
    public synchronized Vector<CipherSuite> fuzz(Vector<CipherSuite> cipherSuites) {
        Vector<CipherSuite> fuzzedCipherSuites = fuzzer.fuzz(cipherSuites);

        try {
            byte[] encoding = cipherSuites.encoding();
            byte[] fuzzed = fuzzedCipherSuites.encoding();
            logger.info("cipher suites (original)");
            logger.info("{}", printHexDiff(encoding, fuzzed));
            logger.info("cipher suites (fuzzed):");
            logger.info("{}", printHexDiff(fuzzed, encoding));

            if (Vector.equals(fuzzedCipherSuites, cipherSuites)) {
                logger.info("nothing actually fuzzed");
            }
        } catch (IOException e) {
            logger.warn("what the hell?", e);
        }

        return fuzzedCipherSuites;
    }

}
