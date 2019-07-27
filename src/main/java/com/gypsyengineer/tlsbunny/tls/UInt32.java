package com.gypsyengineer.tlsbunny.tls;

import java.nio.ByteBuffer;
import java.util.Arrays;

public class UInt32 implements Struct {

    public static final int encoding_length = 4;

    public final byte[] value;

    private UInt32(byte[] value) {
        this.value = value;
    }

    @Override
    public int encodingLength() {
        return encoding_length;
    }
    
    @Override
    public byte[] encoding() {
        return ByteBuffer.allocate(encoding_length).put(value).array();
    }

    @Override
    public UInt32 copy() {
        return new UInt32(value);
    }

    public static UInt32 parse(ByteBuffer data) {
        byte[] value = new byte[encoding_length];
        data.get(value);
        return new UInt32(value);
    }

    public static UInt32 create(int n) {
        return new UInt32(ByteBuffer.allocate(encoding_length).putInt(n).array());
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) {
            return true;
        }
        if (o == null || getClass() != o.getClass()) {
            return false;
        }
        UInt32 uInt32 = (UInt32) o;
        return Arrays.equals(value, uInt32.value);
    }

    @Override
    public int hashCode() {
        return Arrays.hashCode(value);
    }
}
