package com.gypsyengineer.tlsbunny.tls13.struct.impl;

import com.gypsyengineer.tlsbunny.tls13.struct.SignatureScheme;
import java.io.IOException;
import java.nio.ByteBuffer;

public class SignatureSchemeImpl implements SignatureScheme {

    private final int code;

    SignatureSchemeImpl(int code) {
        check(code);
        this.code = code;
    }

    @Override
    public int getCode() {
        return code;
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
    public SignatureSchemeImpl copy() {
        return new SignatureSchemeImpl(code);
    }

    @Override
    public int hashCode() {
        int hash = 5;
        hash = 11 * hash + this.code;
        return hash;
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj == null) {
            return false;
        }
        if (getClass() != obj.getClass()) {
            return false;
        }
        final SignatureSchemeImpl other = (SignatureSchemeImpl) obj;
        return this.code == other.code;
    }

    @Override
    public String toString() {
        return String.format("signature scheme (%d)", code);
    }

    private static void check(int code) {
        if (code < 0 || code > 65535) {
            throw new IllegalArgumentException();
        }
    }
}
