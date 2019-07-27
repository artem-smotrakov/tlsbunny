package com.gypsyengineer.tlsbunny.fuzzer;

import com.gypsyengineer.tlsbunny.output.Output;

import java.util.Random;
import java.util.Scanner;

import static com.gypsyengineer.tlsbunny.utils.WhatTheHell.whatTheHell;

public abstract class AbstractFlipFuzzer implements Fuzzer<byte[]> {

    static final double default_min_ratio = 0.01;
    static final double default_max_ratio = 0.05;

    static final int from_the_beginning = 0;
    static final int not_specified = -1;

    protected int startIndex;
    protected int endIndex;
    protected double minRatio;
    protected double maxRatio;
    protected long state = 0;

    protected final Random random;
    protected Output output;

    public AbstractFlipFuzzer() {
        this(default_min_ratio, default_max_ratio, from_the_beginning, not_specified);
    }

    public AbstractFlipFuzzer(double minRatio, double maxRatio,
            int startIndex, int endIndex) {

        check(minRatio, maxRatio);
        this.minRatio = minRatio;
        this.maxRatio = maxRatio;

        if (endIndex == 0) {
            throw whatTheHell("end index is zero!");
        }

        if (startIndex == endIndex && startIndex > 0) {
            throw whatTheHell("end and start indexes are the same!");
        }

        if (endIndex >= 0 && startIndex > endIndex) {
            throw whatTheHell("start index is greater than end index!");
        }
        this.startIndex = startIndex;
        this.endIndex = endIndex;

        random = new Random(state);
        random.setSeed(state);
    }

    synchronized public AbstractFlipFuzzer minRatio(double ratio) {
        minRatio = check(ratio);
        return this;
    }

    synchronized public AbstractFlipFuzzer maxRatio(double ratio) {
        maxRatio = check(ratio);
        return this;
    }

    synchronized public AbstractFlipFuzzer startIndex(int index) {
        if (index < 0) {
            throw whatTheHell("start index is negative!");
        }

        if (endIndex >= 0 && index >= endIndex) {
            throw whatTheHell("start index should not be greater than end index!");
        }

        startIndex = index;
        return this;
    }

    synchronized public AbstractFlipFuzzer endIndex(int index) {
        if (index > 0 && index < startIndex) {
            throw whatTheHell("end index should not be less than start index!");
        }
        endIndex = index;
        return this;
    }

    @Override
    synchronized public String state() {
        return String.format("%d:%d:%s:%s:%d",
                startIndex, endIndex, minRatio, maxRatio, state);
    }

    @Override
    synchronized public void state(String string) {
        try (Scanner scanner = new Scanner(string)) {
            scanner.useDelimiter(":");
            startIndex = scanner.nextInt();
            endIndex = scanner.nextInt();
            minRatio = scanner.nextDouble();
            maxRatio = scanner.nextDouble();
            state = scanner.nextLong();

            if (scanner.hasNext()) {
                throw whatTheHell("state is too long!");
            }
        }
    }

    @Override
    synchronized public boolean canFuzz() {
        return state < Long.MAX_VALUE;
    }

    @Override
    synchronized public void moveOn() {
        if (state == Long.MAX_VALUE) {
            throw whatTheHell("I can't move on because max state is reached!");
        }
        state++;
        random.setSeed(state);
    }

    @Override
    synchronized public final byte[] fuzz(byte[] array) {
        random.setSeed(state);
        return fuzzImpl(array);
    }

    @Override
    synchronized public Fuzzer<byte[]> set(Output output) {
        this.output = output;
        return this;
    }

    @Override
    synchronized public Output output() {
        return output;
    }

    @Override
    public String toString() {
        return String.format(
                "%s (state = %d, min ratio = %.2f, max ratio = %.2f, " +
                        "start index = %d, end index = %d)",
                this.getClass().getSimpleName(), state, minRatio, maxRatio,
                startIndex, endIndex);
    }

    protected abstract byte[] fuzzImpl(byte[] array);

    protected int getStartIndex() {
        if (startIndex > 0) {
            return startIndex;
        }

        return 0;
    }

    protected int getEndIndex(byte[] array) {
        if (endIndex > 0 && endIndex < array.length) {
            return endIndex;
        }

        return array.length - 1;
    }

    protected double getRatio() {
        return minRatio + (maxRatio - minRatio) * random.nextDouble();
    }

    private static double check(double ratio) {
        if (ratio <= 0 || ratio > 1) {
            throw whatTheHell("wrong ratio: %.2f", ratio);
        }

        return ratio;
    }

    protected static void check(double minRatio, double maxRatio) {
        check(minRatio);
        check(maxRatio);
        if (minRatio > maxRatio) {
            throw whatTheHell("min ratio should not be greater than max ratio!");
        }
    }

}
