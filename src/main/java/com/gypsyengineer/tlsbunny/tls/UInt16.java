package com.gypsyengineer.tlsbunny.tls;

import java.nio.ByteBuffer;
import java.util.Objects;

public class UInt16 implements Struct {

    public static final int encoding_length = 2;
    public static final int MAX = 65535;
    public static final int MIN = 0;
    public static final UInt16 ZERO = new UInt16(0);

    public final int value;

    public UInt16(int value) {
        if (value < MIN || value > MAX) {
            throw new IllegalArgumentException(
                    String.format("wrong value (%d)", value));
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
        return ByteBuffer.allocate(encoding_length).putShort((short) value).array();
    }

    @Override
    public UInt16 copy() {
        return new UInt16(value);
    }

    public static UInt16 parse(ByteBuffer data) {
        return new UInt16(data.getShort() & 0xFFFF);
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) {
            return true;
        }

        if (o == null || getClass() != o.getClass()) {
            return false;
        }

        UInt16 uInt16 = (UInt16) o;
        return value == uInt16.value;
    }

    @Override
    public int hashCode() {

        return Objects.hash(value);
    }
}
