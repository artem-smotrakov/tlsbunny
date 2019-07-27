package com.gypsyengineer.tlsbunny.tls;

import java.nio.ByteBuffer;
import java.util.Arrays;

public class Bytes implements Struct {

    public static final Bytes EMPTY = new Bytes(new byte[0]);

    private final byte[] bytes;

    public Bytes(byte[] bytes) {
        this.bytes = bytes;
    }

    @Override
    public int encodingLength() {
        return bytes.length;
    }

    @Override
    public byte[] encoding() {
        return bytes;
    }

    @Override
    public Bytes copy() {
        return new Bytes(bytes.clone());
    }

    public static Bytes parse(ByteBuffer buffer, int length) {
        byte[] body = new byte[length];
        buffer.get(body);
        
        return new Bytes(body);
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) {
            return true;
        }

        if (o == null || getClass() != o.getClass()) {
            return false;
        }

        Bytes bytes1 = (Bytes) o;
        return Arrays.equals(bytes, bytes1.bytes);
    }

    @Override
    public int hashCode() {
        return Arrays.hashCode(bytes);
    }
}
