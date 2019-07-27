package com.gypsyengineer.tlsbunny.tls13.fuzzer;

import com.gypsyengineer.tlsbunny.fuzzer.FuzzedVector;
import com.gypsyengineer.tlsbunny.tls.Vector;
import com.gypsyengineer.tlsbunny.output.Output;
import com.gypsyengineer.tlsbunny.utils.WhatTheHell;
import org.junit.Test;

import java.util.HashSet;
import java.util.Set;

import static com.gypsyengineer.tlsbunny.tls13.fuzzer.SimpleVectorFuzzer.simpleVectorFuzzer;
import static org.junit.Assert.*;

public class SimpleVectorFuzzerTest {

    @Test
    public void iterate() {
        try (Output output = Output.standard()) {
            SimpleVectorFuzzer fuzzer = new SimpleVectorFuzzer();

            fuzzer.set(output);
            assertEquals(output, fuzzer.output());

            assertTrue(fuzzer.canFuzz());

            int expectedState = 0;
            Vector<Byte> vector = Vector.wrap(1, new byte[] { 0, 1, 2});
            Set<Vector> previous = new HashSet<>();
            while (fuzzer.canFuzz()) {
                assertEquals(String.valueOf(expectedState), fuzzer.state());

                Vector<Byte> fuzzed = fuzzer.fuzz(vector);
                assertNotEquals(vector, fuzzed);
                assertFalse(previous.contains(fuzzed));
                assertEquals(fuzzed, fuzzer.fuzz(vector));
                assertTrue(fuzzed instanceof FuzzedVector);

                fuzzer.moveOn();
                expectedState++;
            }

            assertFalse(fuzzer.canFuzz());

            try {
                fuzzer.fuzz(vector);
                fail("expected an exception");
            } catch (WhatTheHell e) {
                // good
            }
        }
    }

    @Test
    public void set() {
        try (Output output = Output.standard()) {
            SimpleVectorFuzzer fuzzer = simpleVectorFuzzer();
            fuzzer.set(output);

            try {
                fuzzer.state(String.valueOf(Integer.MAX_VALUE / 2));
                fail("expected an exception");
            } catch (WhatTheHell e) {
                // good
            }

            int expectedState = 10;

            fuzzer.state(String.valueOf(expectedState));
            assertEquals(String.valueOf(expectedState), fuzzer.state());

            Vector<Byte> vector = Vector.wrap(2, new byte[] {});
            Vector<Byte> previous = null;
            while (fuzzer.canFuzz()) {
                assertEquals(String.valueOf(expectedState), fuzzer.state());

                Vector<Byte> fuzzed = fuzzer.fuzz(vector);
                assertNotEquals(vector, fuzzed);
                assertNotEquals(previous, fuzzed);
                assertEquals(fuzzed, fuzzer.fuzz(vector));
                assertTrue(fuzzed instanceof FuzzedVector);

                fuzzer.moveOn();
                expectedState++;
            }
        }
    }
}
