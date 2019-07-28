package com.gypsyengineer.tlsbunny.tls13.fuzzer;

import com.gypsyengineer.tlsbunny.fuzzer.FuzzedVector;
import com.gypsyengineer.tlsbunny.fuzzer.Fuzzer;
import com.gypsyengineer.tlsbunny.tls.Vector;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.io.IOException;

import static com.gypsyengineer.tlsbunny.utils.WhatTheHell.whatTheHell;

public class SimpleVectorFuzzer<T> implements Fuzzer<Vector<T>> {

    private static final Logger logger = LogManager.getLogger(SimpleVectorFuzzer.class);

    static SimpleVectorFuzzer simpleVectorFuzzer() {
        return new SimpleVectorFuzzer();
    }

    private final Generator[] generators;
    private int state = 0;

    @Override
    public String toString() {
        return String.format("%s (generators = %d, state = %d)",
                getClass().getSimpleName(), generators.length, state);
    }

    public SimpleVectorFuzzer() {
        generators = new Generator[] {
                vector -> new FuzzedVector(
                        vector.lengthBytes(), 0, vector.bytes()),
                vector -> new FuzzedVector(
                        vector.lengthBytes(), 1, vector.bytes()),
                vector -> new FuzzedVector(vector.lengthBytes(),
                        255, vector.bytes()),

                vector -> new FuzzedVector(
                        vector.lengthBytes(), 0, generateArray(1, 0x00)),
                vector -> new FuzzedVector(
                        vector.lengthBytes(), 0, generateArray(100, 0x00)),
                vector -> new FuzzedVector(
                        vector.lengthBytes(), 0, generateArray(255, 0x00)),
                vector -> new FuzzedVector(
                        vector.lengthBytes(), 100, generateArray(1, 0x00)),
                vector -> new FuzzedVector(
                        vector.lengthBytes(), 100, generateArray(100, 0x00)),
                vector -> new FuzzedVector(
                        vector.lengthBytes(), 100, generateArray(255, 0x00)),
                vector -> new FuzzedVector(
                        vector.lengthBytes(), 255, generateArray(1, 0x00)),
                vector -> new FuzzedVector(
                        vector.lengthBytes(), 255, generateArray(100, 0x00)),
                vector -> new FuzzedVector(
                        vector.lengthBytes(), 255, generateArray(255, 0x00)),

                vector -> new FuzzedVector(
                        vector.lengthBytes(), 0, generateArray(1, 0x17)),
                vector -> new FuzzedVector(
                        vector.lengthBytes(), 0, generateArray(100, 0x17)),
                vector -> new FuzzedVector(
                        vector.lengthBytes(), 0, generateArray(255, 0x17)),
                vector -> new FuzzedVector(
                        vector.lengthBytes(), 100, generateArray(1, 0x17)),
                vector -> new FuzzedVector(
                        vector.lengthBytes(), 100, generateArray(100, 0x17)),
                vector -> new FuzzedVector(
                        vector.lengthBytes(), 100, generateArray(255, 0x17)),
                vector -> new FuzzedVector(
                        vector.lengthBytes(), 255, generateArray(1, 0x17)),
                vector -> new FuzzedVector(
                        vector.lengthBytes(), 255, generateArray(100, 0x17)),
                vector -> new FuzzedVector(
                        vector.lengthBytes(), 255, generateArray(255, 0x17)),

                vector -> new FuzzedVector(
                        vector.lengthBytes(), 0, generateArray(1, 0xFF)),
                vector -> new FuzzedVector(
                        vector.lengthBytes(), 0, generateArray(100, 0xFF)),
                vector -> new FuzzedVector(
                        vector.lengthBytes(), 0, generateArray(255, 0xFF)),
                vector -> new FuzzedVector(
                        vector.lengthBytes(), 100, generateArray(1, 0xFF)),
                vector -> new FuzzedVector(
                        vector.lengthBytes(), 100, generateArray(100, 0xFF)),
                vector -> new FuzzedVector(
                        vector.lengthBytes(), 100, generateArray(255, 0xFF)),
                vector -> new FuzzedVector(
                        vector.lengthBytes(), 255, generateArray(1, 0xFF)),
                vector -> new FuzzedVector(
                        vector.lengthBytes(), 255, generateArray(100, 0xFF)),
                vector -> new FuzzedVector(
                        vector.lengthBytes(), 255, generateArray(255, 0xFF)),

                vector -> new FuzzedVector(
                        vector.lengthBytes(), 0, generateArray(1)),
                vector -> new FuzzedVector(
                        vector.lengthBytes(), 0, generateArray(100)),
                vector -> new FuzzedVector(
                        vector.lengthBytes(), 0, generateArray(255)),
                vector -> new FuzzedVector(
                        vector.lengthBytes(), 100, generateArray(1)),
                vector -> new FuzzedVector(
                        vector.lengthBytes(), 100, generateArray(100)),
                vector -> new FuzzedVector(
                        vector.lengthBytes(), 100, generateArray(255)),
                vector -> new FuzzedVector(
                        vector.lengthBytes(), 255, generateArray(1)),
                vector -> new FuzzedVector(
                        vector.lengthBytes(), 255, generateArray(100)),
                vector -> new FuzzedVector(
                        vector.lengthBytes(), 255, generateArray(255)),
        };
    }

    @Override
    public synchronized String state() {
        return String.valueOf(state);
    }

    @Override
    public synchronized void state(String string) {
        state = check(Integer.parseInt(string));
    }

    @Override
    public synchronized boolean canFuzz() {
        return state <= generators.length - 1;
    }

    @Override
    public synchronized void moveOn() {
        if (state == Integer.MAX_VALUE) {
            throw new IllegalStateException("I can't fuzz any more!");
        }
        state++;
    }

    @Override
    public synchronized final Vector<T> fuzz(Vector<T> vector) {
        if (!canFuzz()) {
            throw whatTheHell("I can't fuzz anymore!");
        }

        try {
            return generators[state].run(vector);
        } catch (IOException e) {
            throw whatTheHell("unexpected exception", e);
        }
    }

    private int check(long state) {
        if (state < 0 || state > generators.length - 1) {
            throw whatTheHell(
                    "state should be in [0, %d], but %d received",
                    generators.length - 1, state);
        }

        return (int) state;
    }

    private static byte[] generateArray(int length) {
        byte[] array = new byte[length];
        for (int i = 0; i < length; i++) {
            array[i] = (byte) (0xFF & i);
        }
        return array;
    }

    private static byte[] generateArray(int length, int value) {
        byte[] array = new byte[length];
        for (int i = 0; i < length; i++) {
            array[i] = (byte) (0xFF & value);
        }
        return array;
    }

    private interface Generator<T> {
        Vector<Byte> run (Vector<T> vector) throws IOException;
    }
}
