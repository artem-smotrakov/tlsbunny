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

public class ExtensionVectorFuzzer extends FuzzyStructFactory<Vector<Extension>> {

    public static ExtensionVectorFuzzer newExtensionVectorFuzzer() {
        return new ExtensionVectorFuzzer();
    }

    public ExtensionVectorFuzzer() {
        this(StructFactory.getDefault(), Output.standard());
    }

    public ExtensionVectorFuzzer(StructFactory factory,
                                 Output output) {
        super(factory, output);
        targets(client_hello, server_hello);
    }

    @Override
    synchronized public ClientHello createClientHello(ProtocolVersion legacy_version,
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
            output.info("fuzz extension vector in ClientHello");
            Vector<Extension> fuzzed = fuzz(hello.extensions());
            hello.extensions(fuzzed);
        }

        return hello;
    }

    @Override
    synchronized public ServerHello createServerHello(ProtocolVersion version,
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
            output.info("fuzz extensions in ServerHello");
            Vector<Extension> fuzzed = fuzz(hello.extensions());
            hello.extensions(fuzzed);
        }

        return hello;
    }

    @Override
    synchronized public Vector<Extension> fuzz(Vector<Extension> extensions) {
        Vector<Extension> fuzzedExtensions = fuzzer.fuzz(extensions);

        try {
            byte[] encoding = extensions.encoding();
            byte[] fuzzed = fuzzedExtensions.encoding();
            output.info("extensions (original): %n");
            output.increaseIndent();
            output.info("%s%n", printHexDiff(encoding, fuzzed));
            output.decreaseIndent();
            output.info("extensions (fuzzed): %n");
            output.increaseIndent();
            output.info("%s%n", printHexDiff(fuzzed, encoding));
            output.decreaseIndent();

            if (Vector.equals(fuzzedExtensions, extensions)) {
                output.important("nothing actually fuzzed");
            }
        } catch (IOException e) {
            output.achtung("what the hell?", e);
        }

        return fuzzedExtensions;
    }

}
