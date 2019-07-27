package com.gypsyengineer.tlsbunny.tls13.fuzzer;

import com.gypsyengineer.tlsbunny.TestUtils;
import org.junit.Test;

import static org.junit.Assert.*;

public class MutatedStructTest {

    @Test
    public void basic() {
        MutatedStruct fuzzed = new MutatedStruct(new byte[32]);
        assertNotNull(fuzzed);
        assertEquals(fuzzed.encodingLength(), 32);
        assertArrayEquals(fuzzed.encoding(), new byte[32]);
    }

    @Test
    public void unsupported() throws Exception {
        TestUtils.expectUnsupportedMethods(
                new MutatedStruct(new byte[32]),
                "hashCode", "encodingLength", "encoding", "copy", "type");
    }
}
