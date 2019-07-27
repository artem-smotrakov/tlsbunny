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

public class LegacySessionIdFuzzer extends FuzzyStructFactory<Vector<Byte>> {

    public static LegacySessionIdFuzzer legacySessionIdFuzzer() {
        return new LegacySessionIdFuzzer();
    }

    public LegacySessionIdFuzzer() {
        this(StructFactory.getDefault(), Output.standard());
    }

    public LegacySessionIdFuzzer(StructFactory factory, Output output) {
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
            output.info("fuzz legacy session ID in ClientHello");
            Vector<Byte> fuzzed = fuzz(hello.legacySessionId());
            hello.legacySessionId(fuzzed);
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
            output.info("fuzz legacy session ID echo in ServerHello");
            Vector<Byte> fuzzed = fuzz(hello.legacySessionIdEcho());
            hello.legacySessionIdEcho(fuzzed);
        }

        return hello;
    }

    @Override
    synchronized public Vector<Byte> fuzz(Vector<Byte> sessionId) {
        Vector<Byte> fuzzedSessionId = fuzzer.fuzz(sessionId);

        try {
            byte[] encoding = sessionId.encoding();
            byte[] fuzzed = fuzzedSessionId.encoding();
            output.info("legacy session ID (original): %n");
            output.increaseIndent();
            output.info("%s%n", printHexDiff(encoding, fuzzed));
            output.decreaseIndent();
            output.info("legacy session ID (fuzzed): %n");
            output.increaseIndent();
            output.info("%s%n", printHexDiff(fuzzed, encoding));
            output.decreaseIndent();

            if (Vector.equals(fuzzedSessionId, sessionId)) {
                output.important("nothing actually fuzzed");
            }
        } catch (IOException e) {
            output.achtung("what the hell?", e);
        }

        return fuzzedSessionId;
    }

}
