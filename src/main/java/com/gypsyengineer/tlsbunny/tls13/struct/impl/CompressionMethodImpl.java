package com.gypsyengineer.tlsbunny.tls13.struct.impl;

import com.gypsyengineer.tlsbunny.tls13.struct.CompressionMethod;

import java.util.Objects;

public class CompressionMethodImpl implements CompressionMethod {

    private final int code;

    CompressionMethodImpl(int code) {
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
    public byte[] encoding() {
        return new byte[] { (byte) code };
    }

    @Override
    public CompressionMethodImpl copy() {
        return new CompressionMethodImpl(code);
    }

    private static void check(int code) {
        if (code < 0 || code > 255) {
            throw new IllegalArgumentException();
        }
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) {
            return true;
        }

        if (o == null || getClass() != o.getClass()) {
            return false;
        }

        CompressionMethodImpl that = (CompressionMethodImpl) o;
        return code == that.code;
    }

    @Override
    public int hashCode() {
        return Objects.hash(code);
    }
}
