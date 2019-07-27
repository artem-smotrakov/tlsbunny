package com.gypsyengineer.tlsbunny.tls;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.util.Arrays;

import static com.gypsyengineer.tlsbunny.utils.WhatTheHell.whatTheHell;

public class RandomImpl implements Random {

    private byte[] bytes;

    RandomImpl(byte[] bytes) {
        if (bytes.length != length) {
            throw new IllegalArgumentException();
        }
        
        this.bytes = bytes.clone();
    }

    RandomImpl() {
        this(new byte[length]);
    }

    @Override
    public byte[] getBytes() {
        return bytes.clone();
    }

    @Override
    public void setBytes(byte[] bytes) {
        if (bytes.length != length) {
            throw new IllegalArgumentException();
        }
        
        this.bytes = bytes.clone();
    }

    @Override
    public int encodingLength() {
        return length;
    }

    @Override
    public byte[] encoding() throws IOException {
        return ByteBuffer.allocate(length).put(bytes).array();
    }

    @Override
    public Random copy() {
        return new RandomImpl(bytes.clone());
    }

    @Override
    public void setLastBytes(byte[] lastBytes) {
        if (lastBytes == null) {
            throw whatTheHell("bytes is null!");
        }

        if (lastBytes.length > bytes.length) {
            throw whatTheHell("it's too long!");
        }

        int i = 0;
        int j = bytes.length - lastBytes.length;
        while (i < lastBytes.length) {
            bytes[j++] = lastBytes[i++];
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
        RandomImpl random = (RandomImpl) o;
        return Arrays.equals(bytes, random.bytes);
    }

    @Override
    public int hashCode() {
        return Arrays.hashCode(bytes);
    }
}
