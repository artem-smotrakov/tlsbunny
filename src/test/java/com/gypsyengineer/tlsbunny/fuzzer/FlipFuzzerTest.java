package com.gypsyengineer.tlsbunny.fuzzer;

import com.gypsyengineer.tlsbunny.output.Output;
import com.gypsyengineer.tlsbunny.utils.WhatTheHell;
import org.junit.Test;

import java.util.Arrays;

import static com.gypsyengineer.tlsbunny.fuzzer.BitFlipFuzzer.newBitFlipFuzzer;
import static com.gypsyengineer.tlsbunny.fuzzer.ByteFlipFuzzer.newByteFlipFuzzer;
import static org.junit.Assert.*;

public class FlipFuzzerTest {

    @Test
    public void byteFlipWrongParameters() {
        checkWhatTheHell(() -> newByteFlipFuzzer().minRatio(0));
        checkWhatTheHell(() -> newByteFlipFuzzer().minRatio(1.1));
        checkWhatTheHell(() -> newByteFlipFuzzer()
                .minRatio(0.5).maxRatio(0.3).fuzz(new byte[10]));
        checkWhatTheHell(() -> newByteFlipFuzzer().startIndex(-1));
        checkWhatTheHell(() -> newByteFlipFuzzer().endIndex(10).startIndex(15));
        checkWhatTheHell(() -> newByteFlipFuzzer().startIndex(15).endIndex(10));
        checkWhatTheHell(() -> new ByteFlipFuzzer(0.5, 0.4, 0, 10));
        checkWhatTheHell(() -> new ByteFlipFuzzer(0.4, 0.5, 10, 5));
        checkWhatTheHell(() -> new ByteFlipFuzzer(0.4, 0.5, 0, 0));
        checkWhatTheHell(() -> new ByteFlipFuzzer(0.4, 0.5, 5, 5));
    }

    @Test
    public void bitFlipWrongParameters() {
        checkWhatTheHell(() -> newBitFlipFuzzer().minRatio(0));
        checkWhatTheHell(() -> newBitFlipFuzzer().minRatio(1.1));
        checkWhatTheHell(() -> newBitFlipFuzzer()
                .minRatio(0.5).maxRatio(0.3).fuzz(new byte[10]));
        checkWhatTheHell(() -> newBitFlipFuzzer().startIndex(-1));
        checkWhatTheHell(() -> newBitFlipFuzzer().endIndex(10).startIndex(15));
        checkWhatTheHell(() -> newBitFlipFuzzer().startIndex(15).endIndex(10));
        checkWhatTheHell(() -> new BitFlipFuzzer(0.5, 0.4, 0, 10));
        checkWhatTheHell(() -> new BitFlipFuzzer(0.4, 0.5, 10, 5));
        checkWhatTheHell(() -> new BitFlipFuzzer(0.4, 0.5, 0, 0));
        checkWhatTheHell(() -> new BitFlipFuzzer(0.4, 0.5, 5, 5));
    }

    private void checkWhatTheHell(Runnable test) {
        try {
            test.run();
            fail("expected WhatTheHell");
        } catch (WhatTheHell e) {
            // good
        }
    }

    @Test
    public void byteFlitFuzzerRatio() {
        try (Output output = Output.standard()) {
            ByteFlipFuzzer fuzzer = newByteFlipFuzzer();
            fuzzer.set(output);

            testRatios(fuzzer, 100, 0.01, 0.02);
            testRatios(fuzzer, 100, 0.01, 0.05);
            testRatios(fuzzer, 100, 0.015, 0.3);
            testRatios(fuzzer, 100, 0.02, 0.025);
            testRatios(fuzzer, 100, 0.07, 0.7);
            testRatios(fuzzer, 100, 0.6, 0.9);
            testRatios(fuzzer, 100, 0.9, 1.0);
            testRatios(fuzzer, 100, 0.001, 0.1);
            testRatios(fuzzer, 10000, 0.01, 0.02);
            testRatios(fuzzer, 10000, 0.01, 0.05);
            testRatios(fuzzer, 10000, 0.015, 0.3);
            testRatios(fuzzer, 10000, 0.02, 0.025);
            testRatios(fuzzer, 10000, 0.07, 0.7);
            testRatios(fuzzer, 10000, 0.6, 0.9);
            testRatios(fuzzer, 10000, 0.9, 1.0);
            testRatios(fuzzer, 10000, 0.001, 0.1);
        }
    }

    private static void testRatios(ByteFlipFuzzer fuzzer, int n, double min, double max) {
        byte[] array = new byte[n];
        fuzzer.minRatio(min).maxRatio(max);
        byte[] fuzzed = fuzzer.fuzz(array);
        int m = numberOfDifferentBytes(array, fuzzed);

        int nMax = (int) (n * max);
        int nMin = (int) (n * min);
        assertTrue(m <= nMax);
        assertTrue(m >= nMin);
    }

    private static int numberOfDifferentBytes(byte[] first, byte[] second) {
        assertEquals(first.length, second.length);
        int counter = 0;
        for (int i = 0; i < first.length; i++) {
            if (first[i] != second[i]) {
                counter++;
            }
        }
        return counter;
    }

    @Test
    public void iterateBitFlipFuzzer() {
        iterate(newBitFlipFuzzer());
    }

    @Test
    public void consistencyOfBitFlipFuzzer() {
        consistencyOf(newBitFlipFuzzer(), newBitFlipFuzzer());
    }

    @Test
    public void setTestInBitFlipFuzzer() {
        setTestIn(newBitFlipFuzzer());
    }

    @Test
    public void iterateByteFlipFuzzer() {
        iterate(newByteFlipFuzzer());
    }

    @Test
    public void consistencyOfByteFlipFuzzer() {
        consistencyOf(newByteFlipFuzzer(), newByteFlipFuzzer());
    }

    @Test
    public void setTestInByteFlipFuzzer() {
        setTestIn(newByteFlipFuzzer());
    }

    @Test
    public void oneByteArrayWithBitFlipFuzzer() {
        oneByteArray(newBitFlipFuzzer());
    }

    @Test
    public void oneByteArrayWithByteFlipFuzzer() {
        oneByteArray(newByteFlipFuzzer());
    }

    private static void iterate(Fuzzer<byte[]> fuzzer) {
        try (Output output = Output.standard()) {
            fuzzer.set(output);
            assertEquals(output, fuzzer.output());

            assertTrue(fuzzer.canFuzz());

            int expectedState = 0;

            int n = 200;
            byte[] array = new byte[n];

            int m = 300;
            for (int i = 0; i < m; i++) {
                assertTrue(fuzzer.canFuzz());
                assertEquals("0:-1:0.01:0.05:" + expectedState, fuzzer.state());

                byte[] fuzzed = fuzzer.fuzz(array);
                assertFalse(Arrays.equals(array, fuzzed));
                assertArrayEquals(fuzzed, fuzzer.fuzz(array));

                fuzzer.moveOn();
                expectedState++;
            }
        }
    }

    private static void consistencyOf(Fuzzer<byte[]> fuzzerOne, Fuzzer<byte[]> fuzzerTwo) {
        try (Output output = Output.standard()) {
            fuzzerOne.set(output);
            fuzzerTwo.set(output);

            assertTrue(fuzzerOne.canFuzz());
            assertTrue(fuzzerTwo.canFuzz());

            int expectedState = 0;

            int n = 1000;
            byte[] array = new byte[n];

            int m = 300;
            for (int i = 0; i < m; i++) {
                assertTrue(fuzzerOne.canFuzz());
                assertTrue(fuzzerTwo.canFuzz());

                assertEquals("0:-1:0.01:0.05:" + expectedState, fuzzerOne.state());
                assertEquals("0:-1:0.01:0.05:" + expectedState, fuzzerTwo.state());

                byte[] fuzzedOne = fuzzerOne.fuzz(array);
                byte[] fuzzedTwo = fuzzerTwo.fuzz(array);
                assertArrayEquals(fuzzedOne, fuzzedTwo);

                fuzzerOne.moveOn();
                fuzzerTwo.moveOn();

                expectedState++;
            }
        }
    }


    private static void setTestIn(Fuzzer<byte[]> fuzzer) {
        try (Output output = Output.standard()) {
            output.info("setTest: fuzzer = %s", fuzzer.toString());

            fuzzer.set(output);
            assertEquals(output, fuzzer.output());

            assertTrue(fuzzer.canFuzz());

            int n = 100;
            byte[] array = new byte[n];
            String prefix = "0:-1:0.01:0.3:";

            long expectedState = Long.MAX_VALUE - 50;
            fuzzer.state(prefix + expectedState);
            while (expectedState < Long.MAX_VALUE) {
                assertTrue(fuzzer.canFuzz());
                assertEquals(prefix + expectedState, fuzzer.state());

                byte[] fuzzed = fuzzer.fuzz(array);
                assertFalse(Arrays.equals(array, fuzzed));
                assertArrayEquals(fuzzed, fuzzer.fuzz(array));

                fuzzer.moveOn();
                expectedState++;
            }

            assertEquals(prefix + Long.MAX_VALUE, fuzzer.state());
            assertFalse(fuzzer.canFuzz());
        }
    }

    private static void oneByteArray(Fuzzer<byte[]> fuzzer) {
        try (Output output = Output.standard()) {
            fuzzer.set(output);

            byte[] array = new byte[] { 1 };
            byte[] fuzzed = fuzzer.fuzz(array);
            assertFalse(Arrays.equals(array, fuzzed));
            assertArrayEquals(fuzzed, fuzzer.fuzz(array));
        }
    }

}
