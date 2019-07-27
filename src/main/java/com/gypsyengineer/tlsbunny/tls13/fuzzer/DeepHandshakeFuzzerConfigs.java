package com.gypsyengineer.tlsbunny.tls13.fuzzer;

import com.gypsyengineer.tlsbunny.fuzzer.Ratio;
import com.gypsyengineer.tlsbunny.tls13.utils.FuzzerConfig;
import com.gypsyengineer.tlsbunny.utils.Config;

import java.util.ArrayList;
import java.util.List;

import static com.gypsyengineer.tlsbunny.fuzzer.BitFlipFuzzer.newBitFlipFuzzer;
import static com.gypsyengineer.tlsbunny.fuzzer.ByteFlipFuzzer.newByteFlipFuzzer;
import static com.gypsyengineer.tlsbunny.utils.WhatTheHell.whatTheHell;

public class DeepHandshakeFuzzerConfigs {

    // settings for minimized configs
    private static boolean fullConfigs = Boolean.valueOf(
            System.getProperty("tlsbunny.fuzzer.full.configs", "false"));
    private static final int total = 3;
    private static final int parts = 1;

    private static final long long_read_timeout = 5000;

    private static List<Ratio> generateRatios(double start, double end, double step) {
        if (start < 0) {
            throw whatTheHell("start is negative!");
        }

        if (end < 0) {
            throw whatTheHell("end is negative!");
        }

        if (start >= end) {
            throw whatTheHell("start is more than end!");
        }

        if (step <= 0 || step >= end - start) {
            throw whatTheHell("wrong step!");
        }

        List<Ratio> ratios = new ArrayList<>();
        double a = start;
        double b = a + step;
        while (b < end) {
            ratios.add(new Ratio(a, b));
            a = b;
            b = a + step;
        }

        return ratios;
    }

    private static final List<Ratio> byte_flip_ratios = new ArrayList<>();
    static {
        if (fullConfigs) {
            byte_flip_ratios.addAll(generateRatios(0.01, 0.5, 0.01));
            byte_flip_ratios.addAll(generateRatios(0.5, 1.0, 0.1));
        } else {
            byte_flip_ratios.add(new Ratio(0.01, 0.02));
        }
    }

    private static final List<Ratio> bit_flip_ratios = new ArrayList<>();
    static {
        if (fullConfigs) {
            bit_flip_ratios.addAll(generateRatios(0.005, 0.25, 0.005));
        } else {
            bit_flip_ratios.add(new Ratio(0.01, 0.02));
        }
    }

    public static FuzzerConfig[] noClientAuth(Config config) {
        return minimizeIfNecessary(
                concatenate(
                    enumerateByteFlipRatios(
                            DeepHandshakeFuzzer::deepHandshakeFuzzer,
                            new FuzzerConfig(config)
                                    .readTimeout(long_read_timeout)
                                    .total(2000)
                                    .parts(5)),
                    enumerateBitFlipRatios(
                            DeepHandshakeFuzzer::deepHandshakeFuzzer,
                            new FuzzerConfig(config)
                                    .readTimeout(long_read_timeout)
                                    .total(2000)
                                    .parts(5))
                )
        );
    }

    public static FuzzerConfig[] clientAuth(Config config) {
        return minimizeIfNecessary(
                concatenate(
                    enumerateByteFlipRatios(
                            DeepHandshakeFuzzer::deepHandshakeFuzzer,
                            new FuzzerConfig(config)
                                    .readTimeout(long_read_timeout)
                                    .total(2000)
                                    .parts(5)),
                    enumerateBitFlipRatios(
                            DeepHandshakeFuzzer::deepHandshakeFuzzer,
                            new FuzzerConfig(config)
                                    .readTimeout(long_read_timeout)
                                    .total(2000)
                                    .parts(5))
                )
        );
    }

    // helper methods

    public static FuzzerConfig[] minimizeIfNecessary(FuzzerConfig... configs) {
        if (fullConfigs) {
            return configs;
        }

        for (FuzzerConfig config : configs) {
            config.total(total);
            config.parts(parts);
        }

        return configs;
    }

    private static FuzzerConfig[] enumerateByteFlipRatios(
            FuzzyStructFactoryBuilder builder, FuzzerConfig config) {

        // don't enumerate if a state is set
        if (config.hasState()) {
            FuzzerConfig newConfig = config.copy();
            DeepHandshakeFuzzer deepHandshakeFuzzer = builder.build();
            deepHandshakeFuzzer.fuzzer(newByteFlipFuzzer());
            newConfig.factory(deepHandshakeFuzzer);
            return new FuzzerConfig[] { newConfig };
        }

        List<FuzzerConfig> generatedConfigs = new ArrayList<>();
        for (Ratio ratio : byte_flip_ratios) {
            FuzzerConfig newConfig = config.copy();
            DeepHandshakeFuzzer deepHandshakeFuzzer = builder.build();
            deepHandshakeFuzzer.fuzzer(newByteFlipFuzzer()
                    .minRatio(ratio.min())
                    .maxRatio(ratio.max()));
            newConfig.factory(deepHandshakeFuzzer);

            generatedConfigs.add(newConfig);
        }

        return generatedConfigs.toArray(new FuzzerConfig[0]);
    }

    private static FuzzerConfig[] enumerateBitFlipRatios(
            FuzzyStructFactoryBuilder builder, FuzzerConfig config) {

        // don't enumerate if a state is set
        if (config.hasState()) {
            FuzzerConfig newConfig = config.copy();
            DeepHandshakeFuzzer deepHandshakeFuzzer = builder.build();
            deepHandshakeFuzzer.fuzzer(newBitFlipFuzzer());
            newConfig.factory(deepHandshakeFuzzer);
            return new FuzzerConfig[] { newConfig };
        }

        List<FuzzerConfig> generatedConfigs = new ArrayList<>();
        for (Ratio ratio : bit_flip_ratios) {
            FuzzerConfig newConfig = config.copy();
            DeepHandshakeFuzzer deepHandshakeFuzzer = builder.build();
            deepHandshakeFuzzer.fuzzer(newBitFlipFuzzer()
                    .minRatio(ratio.min())
                    .maxRatio(ratio.max()));
            newConfig.factory(deepHandshakeFuzzer);

            generatedConfigs.add(newConfig);
        }

        return generatedConfigs.toArray(new FuzzerConfig[0]);
    }

    private static FuzzerConfig[] concatenate(FuzzerConfig[]... lists) {
        List<FuzzerConfig> result = new ArrayList<>();
        for (FuzzerConfig[] configs : lists) {
            result.addAll(List.of(configs));
        }
        return result.toArray(new FuzzerConfig[0]);
    }

    private interface FuzzyStructFactoryBuilder {
        DeepHandshakeFuzzer build();
    }
}
