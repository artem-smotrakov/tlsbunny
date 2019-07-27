package com.gypsyengineer.tlsbunny.tls13.struct.impl;

import java.io.IOException;

import com.gypsyengineer.tlsbunny.tls13.struct.ExtensionType;
import java.nio.ByteBuffer;

public class ExtensionTypeImpl implements ExtensionType {

    private final int code;

    ExtensionTypeImpl(int code) {
        check(code);
        this.code = code;
    }

    @Override
    public int code() {
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
    public ExtensionTypeImpl copy() {
        return new ExtensionTypeImpl(code);
    }

    @Override
    public int hashCode() {
        int hash = 3;
        hash = 29 * hash + this.code;
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
        final ExtensionTypeImpl other = (ExtensionTypeImpl) obj;
        return this.code == other.code;
    }

    private static void check(int code) {
        if (code < 0 || code > 65535) {
            throw new IllegalArgumentException();
        }
    }

}
