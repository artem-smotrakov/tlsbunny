package com.gypsyengineer.tlsbunny.tls13.struct.impl;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.util.Objects;

import com.gypsyengineer.tlsbunny.tls13.struct.NamedGroup;

public class NamedGroupImpl implements NamedGroup {

    public final int code;

    NamedGroupImpl(int code) {
        this.code = code;
    }

    @Override
    public int encodingLength() {
        return encoding_length;
    }

    @Override
    public byte[] encoding() throws IOException {
        return ByteBuffer.allocate(encoding_length).putShort((short) code).array();
    }

    @Override
    public NamedGroupImpl copy() {
        return new NamedGroupImpl(code);
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) {
            return true;
        }
        if (o == null || o instanceof NamedGroupImpl == false) {
            return false;
        }
        NamedGroupImpl that = (NamedGroupImpl) o;
        return code == that.code;
    }

    @Override
    public int hashCode() {
        return Objects.hash(code);
    }

    @Override
    public String toString() {
        return String.format("named groups { code: %s }", code);
    }

    static class SecpImpl extends NamedGroupImpl implements Secp {

        private final String curve;
        
        SecpImpl(int code, String curve) {
            super(code);
            this.curve = curve;
        }

        @Override
        public String getCurve() {
            return curve;
        }

        @Override
        public String toString() {
            return String.format("named groups, ecdhe { code: %d, curve: %s }",
                    code, curve);
        }

    }

    static class XImpl extends NamedGroupImpl implements X {

        XImpl(int code) {
            super(code);
        }

        @Override
        public String toString() {
            return String.format("named groups, x { code: %s }", code);
        }

    }

    static class FFDHEImpl extends NamedGroupImpl implements FFDHE {

        FFDHEImpl(int code) {
            super(code);
        }

        @Override
        public String toString() {
            return String.format("named groups, ffdhe { code: %d }", code);
        }

    }

}
