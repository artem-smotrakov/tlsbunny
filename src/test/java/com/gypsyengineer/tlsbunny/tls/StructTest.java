package com.gypsyengineer.tlsbunny.tls;

import com.gypsyengineer.tlsbunny.tls13.struct.ContentType;
import com.gypsyengineer.tlsbunny.tls13.struct.ProtocolVersion;
import com.gypsyengineer.tlsbunny.tls13.struct.impl.ProtocolVersionImpl;
import com.gypsyengineer.tlsbunny.utils.Utils;
import com.gypsyengineer.tlsbunny.utils.WhatTheHell;
import org.junit.Test;

import static com.gypsyengineer.tlsbunny.TestUtils.expectUnsupported;
import static org.junit.Assert.*;

public class StructTest {

    @Test
    public void cast() {
        Object object = Utils.cast(ProtocolVersion.TLSv13, ProtocolVersionImpl.class);
        assertTrue(object instanceof ProtocolVersion);
        assertEquals(object, ProtocolVersion.TLSv13);

        object = Utils.cast(ProtocolVersion.TLSv13, ProtocolVersion.class);
        assertTrue(object instanceof ProtocolVersion);
        assertEquals(object, ProtocolVersion.TLSv13);

        object = Utils.cast(ProtocolVersion.TLSv13, Struct.class);
        assertTrue(object instanceof ProtocolVersion);
        assertEquals(object, ProtocolVersion.TLSv13);

        try {
            Utils.cast(ProtocolVersion.TLSv13, ContentType.class);
            fail("expected an exception");
        } catch (WhatTheHell e) {
            // good
        }
    }

    @Test
    public void defaultIterationMethods() throws Exception {
        Struct struct = new TestStruct();

        assertFalse(struct.composite());
        assertEquals(struct.total(), 0);

        expectUnsupported(() -> struct.element(0));
        expectUnsupported(() -> struct.element(0, ProtocolVersion.TLSv13));
    }

    private static class TestStruct implements Struct {

        private final byte[] bytes = new byte[16];

        @Override
        public int encodingLength() {
            return bytes.length;
        }

        @Override
        public byte[] encoding() {
            return bytes;
        }

        @Override
        public Struct copy() {
            return new TestStruct();
        }
    }
}
