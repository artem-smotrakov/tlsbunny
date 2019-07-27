package com.gypsyengineer.tlsbunny.tls13.struct.impl;

import com.gypsyengineer.tlsbunny.tls13.struct.ChangeCipherSpec;

public class ChangeCipherSpecImpl implements ChangeCipherSpec {

    private final int value;

    ChangeCipherSpecImpl(int value) {
        check(value);
        this.value = value;
    }

    @Override
    public int getValue() {
        return value;
    }

    @Override
    public boolean isValid() {
        return value == valid_value;
    }

    @Override
    public int encodingLength() {
        return encoding_length;
    }

    @Override
    public byte[] encoding() {
        return new byte[] { (byte) value };
    }

    @Override
    public ChangeCipherSpecImpl copy() {
        return new ChangeCipherSpecImpl(value);
    }

    @Override
    public int hashCode() {
        int hash = 7;
        hash = 59 * hash + this.value;
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
        final ChangeCipherSpecImpl other = (ChangeCipherSpecImpl) obj;
        return this.value == other.value;
    }

    private static void check(int value) {
        if (value < 0 || value > 255) {
            throw new IllegalArgumentException();
        }
    }

}
