package com.gypsyengineer.tlsbunny.fuzzer;

public class Ratio {

    private final double min;
    private final double max;

    public Ratio(double min, double max) {
        this.min = min;
        this.max = max;
    }

    public double min() {
        return min;
    }

    public double max() {
        return max;
    }
}
