package com.gypsyengineer.tlsbunny.tls;

import com.gypsyengineer.tlsbunny.tls13.struct.ProtocolVersion;
import org.junit.Test;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.util.List;

import static com.gypsyengineer.tlsbunny.TestUtils.expectIllegalState;
import static com.gypsyengineer.tlsbunny.TestUtils.expectWhatTheHell;
import static org.junit.Assert.*;

public class VectorTest {

    @Test
    public void opaqueTest() throws IOException {
        opaqueTest(1, 0);
        opaqueTest(1, 1);
        opaqueTest(1, 7);
        opaqueTest(1, 16);
        opaqueTest(1, 42);
        opaqueTest(1, 64);
        opaqueTest(1, 100);
        opaqueTest(1, 128);
        opaqueTest(1, 200);
        opaqueTest(1, 255);
        opaqueTest(2, 0);
        opaqueTest(2, 1);
        opaqueTest(2, 7);
        opaqueTest(2, 16);
        opaqueTest(2, 42);
        opaqueTest(2, 64);
        opaqueTest(2, 100);
        opaqueTest(2, 128);
        opaqueTest(2, 200);
        opaqueTest(2, 255);
        opaqueTest(2, 256);
        opaqueTest(2, 1000);
        opaqueTest(2, 22345);
        opaqueTest(2, 65535);
        opaqueTest(3, 0);
        opaqueTest(3, 1);
        opaqueTest(3, 100000);
    }

    @Test
    public void overflow() throws Exception {
        expectIllegalState(() -> opaqueTest(1, 256));
        expectIllegalState(() -> opaqueTest(2, 65536));
    }

    private static void opaqueTest(int lengthBytes, int n) throws IOException {
        Vector one = Vector.wrap(lengthBytes, new byte[n]);
        Vector two = Vector.parseOpaqueVector(ByteBuffer.wrap(one.encoding()), lengthBytes);
        assertEquals(one, two);
        assertEquals(one.lengthBytes(), two.lengthBytes());
        assertArrayEquals(one.encoding(), two.encoding());
        assertArrayEquals(one.bytes(), two.bytes());
        assertEquals(one.toList(), two.toList());
        assertEquals(one.size(), two.size());
        assertEquals(one.isEmpty(), two.isEmpty());
        if (!one.isEmpty()) {
            assertEquals(one.first(), two.first());
        }
    }

    @Test
    public void composite() throws Exception {
        Vector<Struct> vector = Vector.wrap(2, List.of(
                ProtocolVersion.TLSv13, ProtocolVersion.TLSv12, ProtocolVersion.TLSv11));

        assertTrue(vector.composite());
        assertEquals(vector.total(), 3);
        assertEquals(vector.element(0), ProtocolVersion.TLSv13);
        assertEquals(vector.element(1), ProtocolVersion.TLSv12);
        assertEquals(vector.element(2), ProtocolVersion.TLSv11);

        assertEquals(vector.element(0), vector.get(0));
        assertEquals(vector.element(1), vector.get(1));
        assertEquals(vector.element(2), vector.get(2));

        expectWhatTheHell(() -> vector.element(-1));
        expectWhatTheHell(() -> vector.element(4));

        vector.element(0, ProtocolVersion.TLSv10);
        vector.element(1, ProtocolVersion.TLSv10);
        vector.element(2, ProtocolVersion.TLSv10);
        assertEquals(vector.element(0), ProtocolVersion.TLSv10);
        assertEquals(vector.element(1), ProtocolVersion.TLSv10);
        assertEquals(vector.element(2), ProtocolVersion.TLSv10);

        expectWhatTheHell(() -> vector.element(-1, ProtocolVersion.SSLv3));
        expectWhatTheHell(() -> vector.element(40, ProtocolVersion.SSLv3));
    }

    @Test
    public void notComposite() throws Exception {
        Vector<Byte> vector = Vector.wrap(1, new byte[16]);

        assertFalse(vector.composite());
        assertEquals(vector.total(), 0);

        expectWhatTheHell(() -> vector.element(0));
        expectWhatTheHell(() -> vector.element(0, ProtocolVersion.TLSv12));
    }

}
