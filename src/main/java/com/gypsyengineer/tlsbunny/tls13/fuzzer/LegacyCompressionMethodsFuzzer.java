package com.gypsyengineer.tlsbunny.tls13.fuzzer;

import com.gypsyengineer.tlsbunny.tls.Random;
import com.gypsyengineer.tlsbunny.tls.Vector;
import com.gypsyengineer.tlsbunny.tls13.struct.*;
import com.gypsyengineer.tlsbunny.output.Output;

import java.io.IOException;
import java.util.List;

import static com.gypsyengineer.tlsbunny.tls13.fuzzer.Target.client_hello;
import static com.gypsyengineer.tlsbunny.tls13.fuzzer.Target.server_hello;
import static com.gypsyengineer.tlsbunny.utils.HexDump.printHexDiff;

public class LegacyCompressionMethodsFuzzer
        extends FuzzyStructFactory<Vector<CompressionMethod>> {

    public static LegacyCompressionMethodsFuzzer legacyCompressionMethodsFuzzer() {
        return new LegacyCompressionMethodsFuzzer();
    }

    public LegacyCompressionMethodsFuzzer() {
        this(StructFactory.getDefault(), Output.standard());
    }

    public LegacyCompressionMethodsFuzzer(StructFactory factory,
                                          Output output) {
        super(factory, output);
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
            output.info("fuzz legacy compression methods in ClientHello");
            Vector<CompressionMethod> fuzzed = fuzz(hello.legacyCompressionMethods());
            hello.legacyCompressionMethods(fuzzed);
        }

        return hello;
    }

    @Override
    synchronized public Vector<CompressionMethod> fuzz(
            Vector<CompressionMethod> compressionMethods) {

        Vector<CompressionMethod> fuzzedCompressionMethods = fuzzer.fuzz(compressionMethods);

        try {
            byte[] encoding = compressionMethods.encoding();
            byte[] fuzzed = fuzzedCompressionMethods.encoding();
            output.info("legacy compression methods (original): %n");
            output.increaseIndent();
            output.info("%s%n", printHexDiff(encoding, fuzzed));
            output.decreaseIndent();
            output.info("legacy compression methods (fuzzed): %n");
            output.increaseIndent();
            output.info("%s%n", printHexDiff(fuzzed, encoding));
            output.decreaseIndent();

            if (Vector.equals(fuzzedCompressionMethods, compressionMethods)) {
                output.important("nothing actually fuzzed");
            }
        } catch (IOException e) {
            output.achtung("what the hell?", e);
        }

        return fuzzedCompressionMethods;
    }

}
