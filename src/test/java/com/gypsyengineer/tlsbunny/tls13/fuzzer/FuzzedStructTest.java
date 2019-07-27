package com.gypsyengineer.tlsbunny.tls13.fuzzer;

import com.gypsyengineer.tlsbunny.TestUtils;
import org.junit.Test;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.util.List;

import static com.gypsyengineer.tlsbunny.tls13.fuzzer.FuzzedStruct.fuzzedHandshakeMessage;
import static org.junit.Assert.*;

public class FuzzedStructTest {

    @Test
    public void basic() {
        FuzzedStruct fuzzed = fuzzedHandshakeMessage(new byte[32]);
        assertNotNull(fuzzed);
        assertEquals(fuzzed.encodingLength(), 32);
        assertArrayEquals(fuzzed.encoding(), new byte[32]);
    }

    @Test
    public void unsupported() throws Exception {
        TestUtils.expectUnsupportedMethods(
                fuzzedHandshakeMessage(new byte[32]),
                "hashCode", "encodingLength", "encoding", "copy");
    }
}
