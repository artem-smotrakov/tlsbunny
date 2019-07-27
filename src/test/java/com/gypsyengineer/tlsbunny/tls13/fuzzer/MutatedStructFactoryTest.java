package com.gypsyengineer.tlsbunny.tls13.fuzzer;

import com.gypsyengineer.tlsbunny.fuzzer.ByteFlipFuzzer;
import com.gypsyengineer.tlsbunny.tls.Struct;
import com.gypsyengineer.tlsbunny.tls13.struct.ContentType;
import com.gypsyengineer.tlsbunny.tls13.struct.ProtocolVersion;
import com.gypsyengineer.tlsbunny.tls13.struct.StructFactory;
import com.gypsyengineer.tlsbunny.tls13.struct.TLSPlaintext;
import com.gypsyengineer.tlsbunny.output.Output;
import org.junit.Test;

import java.io.IOException;
import java.util.Arrays;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertFalse;

public class MutatedStructFactoryTest {

    public static final double MIN_RATIO = 0.2;
    public static final double MAX_RATIO = 0.8;
    public static final byte[] CONTENT = new byte[] { 0, 1, 2, 3};

    @Test
    public void checkConsistency() throws IOException {
        try (Output output = Output.standard()) {
            output.info("check if %s is consistent",
                    MutatedStructFactory.class.getSimpleName());

            StructFactory factory = StructFactory.getDefault();

            FuzzyStructFactory fuzzer = new MutatedStructFactory(factory, output)
                    .fuzzer(new ByteFlipFuzzer()
                            .minRatio(MIN_RATIO)
                            .maxRatio(MAX_RATIO));

            output.info("test case #1");
            TLSPlaintext tlsPlaintext_1 = factory.createTLSPlaintext(
                    ContentType.application_data, ProtocolVersion.TLSv12, CONTENT);
            TLSPlaintext tlsPlaintext_2 = factory.createTLSPlaintext(
                    ContentType.application_data, ProtocolVersion.TLSv12, CONTENT);
            assertEqualEncodings(tlsPlaintext_1, tlsPlaintext_2);

            output.info("test case #2");
            fuzzer.targets(Target.tls_plaintext);
            TLSPlaintext fuzzed_tlsPlaintext_1 = fuzzer.createTLSPlaintext(
                    ContentType.application_data, ProtocolVersion.TLSv12, CONTENT);
            TLSPlaintext fuzzed_tlsPlaintext_2 = fuzzer.createTLSPlaintext(
                    ContentType.application_data, ProtocolVersion.TLSv12, CONTENT);
            assertEqualEncodings(fuzzed_tlsPlaintext_1, fuzzed_tlsPlaintext_2);

            output.info("test case #3");
            fuzzer.moveOn();
            TLSPlaintext fuzzed_tlsPlaintext_3 = fuzzer.createTLSPlaintext(
                    ContentType.application_data, ProtocolVersion.TLSv12, CONTENT);
            assertNotEqualEncodings(fuzzed_tlsPlaintext_2, fuzzed_tlsPlaintext_3);

            output.info("holy cow! test passed!");
        }
    }

    private static void assertEqualEncodings(Struct first, Struct second)
            throws IOException {

        assertArrayEquals(first.encoding(), second.encoding());
    }

    private static void assertNotEqualEncodings(Struct first, Struct second)
            throws IOException {

        assertFalse(Arrays.equals(first.encoding(), second.encoding()));
    }
}
