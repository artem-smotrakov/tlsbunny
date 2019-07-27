package com.gypsyengineer.tlsbunny.utils;

import org.junit.Test;

import static com.gypsyengineer.tlsbunny.TestUtils.expectWhatTheHell;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

public class UtilsTest {

    @Test
    public void contains() {
        assertTrue(Utils.contains(1, 1, 2, 3));
        assertFalse(Utils.contains(4, 1, 2, 3));
        assertFalse(Utils.contains(4, new int[0]));
        assertFalse(Utils.contains(4, null));
    }

    @Test
    public void lastBytesEquals() {
        assertTrue(Utils.lastBytesEquals(new byte[] {1, 2, 3}, new byte[] {2, 3}));
        assertFalse(Utils.lastBytesEquals(new byte[] {1, 2, 3}, new byte[] {1, 3}));
    }

    @Test
    public void xor() throws Exception {
        assertArrayEquals(
                Utils.xor(new byte[] {-127, 0, -127}, new byte[] {0, -127, 0}),
                new byte[] {-127, -127, -127});
        expectWhatTheHell(() -> Utils.xor(new byte[2], new byte[3]));
    }
}
