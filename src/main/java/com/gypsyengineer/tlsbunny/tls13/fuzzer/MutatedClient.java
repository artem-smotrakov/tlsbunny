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
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.io.IOException;
import java.net.ConnectException;
import java.util.Arrays;
import java.util.stream.Collectors;

import static com.gypsyengineer.tlsbunny.utils.WhatTheHell.whatTheHell;

public class MutatedClient extends AbstractFuzzyClient {

    private static final Logger logger = LogManager.getLogger(MutatedClient.class);

    private static final int max_attempts = 3;
    private static final int delay = 3000; // in millis

    private Client client;
    private Analyzer analyzer;
    private Check[] checks;
    private long test = 0;
    private FuzzyStructFactory fuzzer;
    private int total = 0;

    public static MutatedClient mutatedClient() {
        return new MutatedClient();
    }

    private MutatedClient() {}

    public MutatedClient(Client client) {
        this.client = client;
    }

    public MutatedClient from(Client client) {
        this.client = client;
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

    }

    @Override
    protected void runImpl() {
        if (fuzzer == null) {
            throw whatTheHell("no fuzzy set specified!");
        }

        if (total <= 0) {
            throw whatTheHell("no total!");
        }

        try {
            logger.info("run a smoke test before fuzzing");
            client.set(StructFactory.getDefault())
                    .set(analyzer)
                    .set(new SuccessCheck())
                    .set(new NoAlertCheck())
                    .connect();

            logger.info("smoke test passed, start fuzzing");
        } catch (Exception e) {
            throw whatTheHell("smoke test failed", e);
        }

        if (state != null && !state.isEmpty()) {
            fuzzer.state(state);
        }

        logger.info("run fuzzer config:");
        logger.info("  targets     = {}",
                Arrays.stream(fuzzer.targets())
                        .map(Object::toString)
                        .collect(Collectors.joining(", ")));
        logger.info("  fuzzer      = {}",
                fuzzer.fuzzer() != null
                        ? fuzzer.fuzzer().toString()
                        : "null");
        logger.info("  total tests = {}", total);
        logger.info("  state       = {}",
                state != null ? state : "not specified");

        client.set(fuzzer)
                .set(analyzer)
                .set(checks);

        try {
            test = 0;
            while (shouldRun(fuzzer)) {
                try {
                    run(fuzzer);
                } finally {
                    fuzzer.moveOn();
                    test++;
                }
            }
        } catch (Exception e) {
            logger.warn("what the hell? unexpected exception", e);
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
        logger.info(message);
        logger.info("state: {}", fuzzyStructFactory.state());

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
                    logger.warn("an exception occurred, but we continue fuzzing", e);
                    break;
                }

                // if the exception was caused by ConnectException
                // then we try again several times

                if (attempt == max_attempts) {
                    throw new IOException("looks like the server closed connection");
                }
                attempt++;

                logger.info("connection failed: {} ", cause.getMessage());
                logger.info("let's wait a bit and try again (attempt {})", attempt);
                Thread.sleep(delay);
            }
        }
    }

    private boolean shouldRun(FuzzyStructFactory fuzzyStructFactory) {
        return fuzzyStructFactory.canFuzz() && test < total;
    }

}
