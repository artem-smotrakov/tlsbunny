package com.gypsyengineer.tlsbunny.tls13.fuzzer;

import com.gypsyengineer.tlsbunny.tls.Struct;
import com.gypsyengineer.tlsbunny.tls13.struct.ContentType;
import com.gypsyengineer.tlsbunny.tls13.struct.ProtocolVersion;
import com.gypsyengineer.tlsbunny.tls13.struct.StructFactory;
import com.gypsyengineer.tlsbunny.tls13.struct.TLSPlaintext;
import org.junit.Test;

import java.io.IOException;
import java.util.Arrays;

import static com.gypsyengineer.tlsbunny.fuzzer.ByteFlipFuzzer.byteFlipFuzzer;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertFalse;

public class MutatedStructFactoryTest {

    private static final double min_ratio = 0.2;
    private static final double max_ratio = 0.8;
    private static final byte[] content = { 0, 1, 2, 3 };

    @Test
    public void checkConsistency() throws IOException {
        StructFactory factory = StructFactory.getDefault();

        FuzzyStructFactory fuzzer = new MutatedStructFactory(factory)
                .fuzzer(byteFlipFuzzer(min_ratio, max_ratio));

        TLSPlaintext tlsPlaintext_1 = factory.createTLSPlaintext(
                ContentType.application_data, ProtocolVersion.TLSv12, content);
        TLSPlaintext tlsPlaintext_2 = factory.createTLSPlaintext(
                ContentType.application_data, ProtocolVersion.TLSv12, content);
        assertEqualEncodings(tlsPlaintext_1, tlsPlaintext_2);

        fuzzer.targets(Target.tls_plaintext);
        TLSPlaintext fuzzed_tlsPlaintext_1 = fuzzer.createTLSPlaintext(
                ContentType.application_data, ProtocolVersion.TLSv12, content);
        TLSPlaintext fuzzed_tlsPlaintext_2 = fuzzer.createTLSPlaintext(
                ContentType.application_data, ProtocolVersion.TLSv12, content);
        assertEqualEncodings(fuzzed_tlsPlaintext_1, fuzzed_tlsPlaintext_2);

        fuzzer.moveOn();
        TLSPlaintext fuzzed_tlsPlaintext_3 = fuzzer.createTLSPlaintext(
                ContentType.application_data, ProtocolVersion.TLSv12, content);
        assertNotEqualEncodings(fuzzed_tlsPlaintext_2, fuzzed_tlsPlaintext_3);
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
