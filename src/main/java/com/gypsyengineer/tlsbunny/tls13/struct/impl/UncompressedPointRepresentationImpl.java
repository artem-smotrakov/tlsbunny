package com.gypsyengineer.tlsbunny.tls13.struct.impl;

import java.nio.ByteBuffer;
import java.util.Arrays;
import java.util.Objects;

import com.gypsyengineer.tlsbunny.tls13.struct.UncompressedPointRepresentation;

public class UncompressedPointRepresentationImpl implements UncompressedPointRepresentation {

    private final byte legacy_form = 4;
    private final byte[] X;
    private final byte[] Y;

    UncompressedPointRepresentationImpl(byte[] X, byte[] Y) {
        this.X = X;
        this.Y = Y;
    }

    @Override
    public byte[] getX() {
        return X;
    }

    @Override
    public byte[] getY() {
        return Y;
    }

    @Override
    public int encodingLength() {
        return 1 + X.length + Y.length;
    }

    @Override
    public byte[] encoding() {
        return ByteBuffer.allocate(encodingLength())
            .put(legacy_form)
            .put(X)
            .put(Y)
            .array();
    }

    @Override
    public UncompressedPointRepresentationImpl copy() {
        return new UncompressedPointRepresentationImpl(X.clone(), Y.clone());
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) {
            return true;
        }
        if (o == null || getClass() != o.getClass()) {
            return false;
        }
        UncompressedPointRepresentationImpl that = (UncompressedPointRepresentationImpl) o;
        return legacy_form == that.legacy_form &&
                Arrays.equals(X, that.X) &&
                Arrays.equals(Y, that.Y);
    }

    @Override
    public int hashCode() {
        int result = Objects.hash(legacy_form);
        result = 31 * result + Arrays.hashCode(X);
        result = 31 * result + Arrays.hashCode(Y);
        return result;
    }
}
