package com.gypsyengineer.tlsbunny.tls13.crypto;

import org.junit.Test;

import java.util.Arrays;

import static junit.framework.TestCase.assertEquals;
import static org.junit.Assert.assertTrue;

public class RawKeyTest {

    @Test
    public void main() {
        RawKey key = new RawKey(new byte[] {1, 2, 3}, "AES");
        assertEquals("AES", key.getAlgorithm());
        assertEquals("RAW", key.getFormat());
        assertTrue(Arrays.equals(new byte[] {1, 2, 3}, key.getEncoded()));
    }
}
