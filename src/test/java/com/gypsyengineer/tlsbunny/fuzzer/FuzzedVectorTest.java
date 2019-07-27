package com.gypsyengineer.tlsbunny.fuzzer;

import org.junit.Test;

import static com.gypsyengineer.tlsbunny.TestUtils.expectWhatTheHell;
import static org.junit.Assert.*;

public class FuzzedVectorTest {

    @Test
    public void set() throws Exception {
        FuzzedVector<Byte> vector = new FuzzedVector<>(
                1, 3, new byte[] {0, 1, 2});
        vector.set(0, (byte) 42);
        assertArrayEquals(new byte[] {3, 42, 1, 2}, vector.encoding());

        expectWhatTheHell(() -> vector.set(10, (byte) 42));
    }

    @Test
    public void unsupported() {
        FuzzedVector<Byte> vector = new FuzzedVector<>(1, 3, new byte[] {0, 1, 2});
        unsupported(() -> vector.size());
        unsupported(() -> vector.isEmpty());
        unsupported(() -> vector.get(0));
        unsupported(() -> vector.first());
        unsupported(() -> vector.add((byte) 0));
        unsupported(() -> vector.clear());
        unsupported(() -> vector.toList());

    }

    @Test
    public void create() {
        FuzzedVector<Byte> vector = new FuzzedVector<>(1, 3, new byte[]{0, 1, 2});
        assertEquals(vector.lengthBytes(), 1);
        assertEquals(vector.encodingLength(), 4);
        assertArrayEquals(vector.encoding(), new byte[] {3, 0, 1, 2});

        vector = new FuzzedVector<>(2, 4, new byte[]{0, 1, 2, 3});
        assertEquals(vector.lengthBytes(), 2);
        assertEquals(vector.encodingLength(), 6);
        assertArrayEquals(vector.encoding(), new byte[] {0, 4, 0, 1, 2, 3});

        vector = new FuzzedVector<>(1, 16, new byte[]{0, 1, 2, 3});
        assertEquals(vector.lengthBytes(), 1);
        assertEquals(vector.encodingLength(), 5);
        assertArrayEquals(vector.encoding(), new byte[] {16, 0, 1, 2, 3});

        try {
            new FuzzedVector<>(1, 256, new byte[]{0, 1, 2, 3});
            fail("expected IllegalArgumentException");
        } catch (IllegalArgumentException e) {
            // good
        }
    }

    @Test
    public void equals() {
        FuzzedVector<Byte> one = new FuzzedVector<>(1, 3, new byte[]{0, 1, 2});
        FuzzedVector<Byte> two = new FuzzedVector<>(1, 3, new byte[]{0, 1, 2});
        assertEquals(one, two);
        assertEquals(one.hashCode(), two.hashCode());

        one = new FuzzedVector<>(1, 3, new byte[] {0, 1, 2});
        two = new FuzzedVector<>(2, 3, new byte[] {0, 1, 2});
        assertNotEquals(one, two);
        assertNotEquals(one.hashCode(), two.hashCode());

        one = new FuzzedVector<>(2, 3, new byte[] {0, 1, 2});
        two = new FuzzedVector<>(2, 3, new byte[] {0, 3, 2});
        assertNotEquals(one, two);
        assertNotEquals(one.hashCode(), two.hashCode());

        one = new FuzzedVector<>(1, 10, new byte[] {0, 1, 2});
        two = new FuzzedVector<>(1, 20, new byte[] {0, 1, 2});
        assertNotEquals(one, two);
        assertNotEquals(one.hashCode(), two.hashCode());
    }

    private static void unsupported(Runnable task) {
        try {
            task.run();
            fail("expected UnsupportedOperationException");
        } catch (UnsupportedOperationException e) {
            // good
        }
    }
}
