package com.gypsyengineer.tlsbunny.utils;

import org.junit.Test;

import java.math.BigInteger;

import static org.junit.Assert.assertArrayEquals;

public class MathUtilsTest {

    @Test
    public void toBytes() {
        assertArrayEquals(
                MathUtils.toBytes(BigInteger.ONE, 1),
                new byte[] {1});
        assertArrayEquals(
                MathUtils.toBytes(BigInteger.ONE, 5),
                new byte[] {0, 0, 0, 0, 1});
    }
}
