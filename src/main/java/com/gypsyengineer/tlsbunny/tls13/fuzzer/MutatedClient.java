package com.gypsyengineer.tlsbunny.tls13.fuzzer;

import com.gypsyengineer.tlsbunny.tls13.client.Client;
import com.gypsyengineer.tlsbunny.tls13.connection.Analyzer;
import com.gypsyengineer.tlsbunny.tls13.connection.Engine;
import com.gypsyengineer.tlsbunny.tls13.connection.EngineException;
import com.gypsyengineer.tlsbunny.tls13.connection.check.Check;
import com.gypsyengineer.tlsbunny.tls13.connection.check.NoAlertCheck;
import com.gypsyengineer.tlsbunny.tls13.connection.check.SuccessCheck;
import com.gypsyengineer.tlsbunny.tls13.handshake.Negotiator;
import com.gypsyengineer.tlsbunny.tls13.struct.StructFactory;
import com.gypsyengineer.tlsbunny.utils.Config;
import com.gypsyengineer.tlsbunny.tls13.utils.FuzzerConfig;
import com.gypsyengineer.tlsbunny.output.Output;
import com.gypsyengineer.tlsbunny.utils.Sync;

import java.io.IOException;
import java.net.ConnectException;
import java.util.Arrays;
import java.util.stream.Collectors;

import static com.gypsyengineer.tlsbunny.utils.WhatTheHell.whatTheHell;

public class MutatedClient extends AbstractFuzzyClient {

    private static final int max_attempts = 3;
    private static final int delay = 3000; // in millis

    private Client client;
    private Output output;
    private Analyzer analyzer;
    private Check[] checks;
    private FuzzerConfig fuzzerConfig;
    private long test = 0;

    public static MutatedClient mutatedClient() {
        return new MutatedClient();
    }

    private MutatedClient() {}

    public MutatedClient(Client client, Output output, FuzzerConfig fuzzerConfig) {
        this.client = client;
        this.output = output;
        this.fuzzerConfig = fuzzerConfig;
    }

    public MutatedClient from(Client client) {
        this.client = client;
        return this;
    }

    @Override
    public Output output() {
        return output;
    }

    @Override
    public Config config() {
        return fuzzerConfig;
    }

    @Override
    public MutatedClient set(Config config) {
        if (config instanceof FuzzerConfig == false) {
            throw whatTheHell("expected FuzzerConfig!");
        }
        this.fuzzerConfig = (FuzzerConfig) config;
        return this;
    }

    @Override
    public MutatedClient set(StructFactory factory) {
        throw new UnsupportedOperationException("no factories for you!");
    }

    @Override
    public MutatedClient set(Negotiator negotiator) {
        throw new UnsupportedOperationException("no negotiators for you!");
    }

    @Override
    public MutatedClient set(Output output) {
        this.output = output;
        return this;
    }

    @Override
    public MutatedClient set(Check... checks) {
        this.checks = checks;
        return this;
    }

    @Override
    public MutatedClient set(Analyzer analyzer) {
        this.analyzer = analyzer;
        return this;
    }

    @Override
    public MutatedClient connect() {
        run();
        return this;
    }

    @Override
    public Engine[] engines() {
        throw new UnsupportedOperationException("no engines for you!");
    }

    @Override
    public void close() {
        if (output != null) {
            output.flush();
        }
    }

    @Override
    protected void runImpl() {
        if (fuzzerConfig.noFactory()) {
            throw whatTheHell("no fuzzy set specified!");
        }

        StructFactory factory = fuzzerConfig.factory();
        if (factory instanceof FuzzyStructFactory == false) {
            throw whatTheHell("expected FuzzyStructFactory!");
        }

        FuzzyStructFactory fuzzyStructFactory = (FuzzyStructFactory) factory;
        fuzzyStructFactory.set(output);

        sync().start();
        try {
            output.info("run a smoke test before fuzzing");
            client.set(StructFactory.getDefault())
                    .set(fuzzerConfig)
                    .set(output)
                    .set(analyzer)
                    .set(new SuccessCheck())
                    .set(new NoAlertCheck())
                    .connect();

            output.info("smoke test passed, start fuzzing");
        } catch (Exception e) {
            throw whatTheHell("smoke test failed", e);
        } finally {
            output.flush();
            sync().end();
        }

        if (fuzzerConfig.hasState()) {
            fuzzyStructFactory.state(fuzzerConfig.state());
        }

        output.important("run fuzzer config:");
        output.important("  targets     = %s",
                Arrays.stream(fuzzyStructFactory.targets())
                        .map(Object::toString)
                        .collect(Collectors.joining(", ")));
        output.important("  fuzzer      = %s",
                fuzzyStructFactory.fuzzer() != null
                        ? fuzzyStructFactory.fuzzer().toString()
                        : "null");
        output.important("  total tests = %d", fuzzerConfig.total());
        output.important("  state       = %s",
                fuzzerConfig.hasState() ? fuzzerConfig.state() : "not specified");

        client.set(fuzzyStructFactory)
                .set(fuzzerConfig)
                .set(output)
                .set(analyzer)
                .set(checks);

        try {
            test = 0;
            while (shouldRun(fuzzyStructFactory)) {
                sync().start();
                try {
                    run(fuzzyStructFactory);
                } finally {
                    output.flush();
                    sync().end();
                    fuzzyStructFactory.moveOn();
                    test++;
                }
            }
        } catch (Exception e) {
            output.achtung("what the hell? unexpected exception", e);
        } finally {
            output.flush();
        }
    }

    private void run(FuzzyStructFactory fuzzyStructFactory) throws Exception {
        String message = String.format("test #%d, %s/%s, targets: [%s]",
                test,
                getClass().getSimpleName(),
                fuzzyStructFactory.fuzzer().getClass().getSimpleName(),
                Arrays.stream(fuzzyStructFactory.targets)
                        .map(Enum::toString)
                        .collect(Collectors.joining(", ")));
        output.important(message);
        output.important("state: %s", fuzzyStructFactory.state());

        int attempt = 0;
        while (attempt <= max_attempts) {
            try {
                client.connect();
                break;
            } catch (EngineException e) {
                Throwable cause = e.getCause();
                if (cause instanceof ConnectException == false) {
                    // an EngineException may occur due to multiple reasons
                    // if the exception was not caused by ConnectException
                    // we tolerate EngineException here to let the fuzzer to continue
                    output.achtung("an exception occurred, but we continue fuzzing", e);
                    break;
                }

                // if the exception was caused by ConnectException
                // then we try again several times

                if (attempt == max_attempts) {
                    throw new IOException("looks like the server closed connection");
                }
                attempt++;

                output.important("connection failed: %s ", cause.getMessage());
                output.important("let's wait a bit and try again (attempt %d)", attempt);
                Thread.sleep(delay);
            } finally {
                output.flush();
            }
        }
    }

    private boolean shouldRun(FuzzyStructFactory fuzzyStructFactory) {
        return fuzzyStructFactory.canFuzz() && test < fuzzerConfig.total();
    }

}
