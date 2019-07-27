package com.gypsyengineer.tlsbunny.tls;

import java.nio.ByteBuffer;
import java.util.Arrays;
import java.util.Objects;

public class UInt24 implements Struct {

    public static final int encoding_length = 3;
    public static final int BASE_POW_1 = 256;
    public static final int BASE_POW_2 = BASE_POW_1 * BASE_POW_1;
    public static final int MAX = 16777215;
    public static final int MIN = 0;
    public static final UInt24 ZERO = new UInt24(0);

    public final int value;

    public UInt24(int value) {
        if (value < MIN || value > MAX) {
            throw new IllegalArgumentException();
        }

        this.value = value;
    }

    public int getValue() {
        return value;
    }

    @Override
    public int encodingLength() {
        return encoding_length;
    }

    @Override
    public byte[] encoding() {
        byte[] array = ByteBuffer.allocate(4).putInt(value).array();
        return Arrays.copyOfRange(array, 1, array.length);
    }

    @Override
    public UInt24 copy() {
        return new UInt24(value);
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) {
            return true;
        }
        if (o == null || getClass() != o.getClass()) {
            return false;
        }
        UInt24 uInt24 = (UInt24) o;
        return value == uInt24.value;
    }

    @Override
    public int hashCode() {
        return Objects.hash(value);
    }

    public static UInt24 parse(byte[] data) {
        return parse(ByteBuffer.wrap(data));
    }

    public static UInt24 parse(ByteBuffer data) {
        int value = (data.get() & 0xFF) * BASE_POW_2
                + (data.get() & 0xFF) * BASE_POW_1
                + (data.get() & 0xFF);
        
        return new UInt24(value);
    }

    @Override
    public String toString() {
        return String.format("UInt24 (%d)", value);
    }
}
