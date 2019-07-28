package com.gypsyengineer.tlsbunny.fuzzer;

import com.gypsyengineer.tlsbunny.utils.WhatTheHell;
import org.junit.Test;

import java.util.Arrays;

import static com.gypsyengineer.tlsbunny.fuzzer.BitFlipFuzzer.bitFlipFuzzer;
import static com.gypsyengineer.tlsbunny.fuzzer.ByteFlipFuzzer.byteFlipFuzzer;
import static org.junit.Assert.*;

public class FlipFuzzerTest {

    @Test
    public void byteFlipWrongParameters() {
        checkWhatTheHell(() -> byteFlipFuzzer().minRatio(0));
        checkWhatTheHell(() -> byteFlipFuzzer().minRatio(1.1));
        checkWhatTheHell(() -> byteFlipFuzzer()
                .minRatio(0.5).maxRatio(0.3).fuzz(new byte[10]));
        checkWhatTheHell(() -> byteFlipFuzzer().startIndex(-1));
        checkWhatTheHell(() -> byteFlipFuzzer().endIndex(10).startIndex(15));
        checkWhatTheHell(() -> byteFlipFuzzer().startIndex(15).endIndex(10));
        checkWhatTheHell(() -> byteFlipFuzzer(0.5, 0.4, 0, 10));
        checkWhatTheHell(() -> byteFlipFuzzer(0.4, 0.5, 10, 5));
        checkWhatTheHell(() -> byteFlipFuzzer(0.4, 0.5, 0, 0));
        checkWhatTheHell(() -> byteFlipFuzzer(0.4, 0.5, 5, 5));
    }

    @Test
    public void bitFlipWrongParameters() {
        checkWhatTheHell(() -> bitFlipFuzzer().minRatio(0));
        checkWhatTheHell(() -> bitFlipFuzzer().minRatio(1.1));
        checkWhatTheHell(() -> bitFlipFuzzer()
                .minRatio(0.5).maxRatio(0.3).fuzz(new byte[10]));
        checkWhatTheHell(() -> bitFlipFuzzer().startIndex(-1));
        checkWhatTheHell(() -> bitFlipFuzzer().endIndex(10).startIndex(15));
        checkWhatTheHell(() -> bitFlipFuzzer().startIndex(15).endIndex(10));
        checkWhatTheHell(() -> byteFlipFuzzer(0.5, 0.4, 0, 10));
        checkWhatTheHell(() -> byteFlipFuzzer(0.4, 0.5, 10, 5));
        checkWhatTheHell(() -> byteFlipFuzzer(0.4, 0.5, 0, 0));
        checkWhatTheHell(() -> byteFlipFuzzer(0.4, 0.5, 5, 5));
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
        ByteFlipFuzzer fuzzer = byteFlipFuzzer();

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
        iterate(bitFlipFuzzer());
    }

    @Test
    public void consistencyOfBitFlipFuzzer() {
        consistencyOf(bitFlipFuzzer(), bitFlipFuzzer());
    }

    @Test
    public void setTestInBitFlipFuzzer() {
        setTestIn(bitFlipFuzzer());
    }

    @Test
    public void iterateByteFlipFuzzer() {
        iterate(byteFlipFuzzer());
    }

    @Test
    public void consistencyOfByteFlipFuzzer() {
        consistencyOf(byteFlipFuzzer(), byteFlipFuzzer());
    }

    @Test
    public void setTestInByteFlipFuzzer() {
        setTestIn(byteFlipFuzzer());
    }

    @Test
    public void oneByteArrayWithBitFlipFuzzer() {
        oneByteArray(bitFlipFuzzer());
    }

    @Test
    public void oneByteArrayWithByteFlipFuzzer() {
        oneByteArray(byteFlipFuzzer());
    }

    private static void iterate(Fuzzer<byte[]> fuzzer) {
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

    private static void consistencyOf(Fuzzer<byte[]> fuzzerOne, Fuzzer<byte[]> fuzzerTwo) {
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


    private static void setTestIn(Fuzzer<byte[]> fuzzer) {
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

    private static void oneByteArray(Fuzzer<byte[]> fuzzer) {
        byte[] array = new byte[]{1};
        byte[] fuzzed = fuzzer.fuzz(array);
        assertFalse(Arrays.equals(array, fuzzed));
        assertArrayEquals(fuzzed, fuzzer.fuzz(array));
    }

}
