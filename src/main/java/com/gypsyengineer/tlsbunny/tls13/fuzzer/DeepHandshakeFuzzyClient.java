package com.gypsyengineer.tlsbunny.tls13.fuzzer;

import com.gypsyengineer.tlsbunny.tls13.client.Client;
import com.gypsyengineer.tlsbunny.tls13.connection.Analyzer;
import com.gypsyengineer.tlsbunny.tls13.connection.Engine;
import com.gypsyengineer.tlsbunny.tls13.connection.EngineException;
import com.gypsyengineer.tlsbunny.tls13.connection.check.Check;
import com.gypsyengineer.tlsbunny.tls13.connection.check.SuccessCheck;
import com.gypsyengineer.tlsbunny.tls13.handshake.Negotiator;
import com.gypsyengineer.tlsbunny.tls13.struct.StructFactory;
import com.gypsyengineer.tlsbunny.utils.Utils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.io.IOException;
import java.net.ConnectException;
import java.util.Arrays;
import java.util.stream.Collectors;

import static com.gypsyengineer.tlsbunny.utils.Achtung.achtung;
import static com.gypsyengineer.tlsbunny.utils.WhatTheHell.whatTheHell;

public class DeepHandshakeFuzzyClient extends AbstractFuzzyClient {

    private static final Logger logger = LogManager.getLogger(DeepHandshakeFuzzyClient.class);

    private static final int max_attempts = 3;
    private static final int delay = 3000; // in millis

    private Client client;
    private Check[] checks;
    private Analyzer analyzer;
    private long test = 0;
    private DeepHandshakeFuzzer fuzzer;
    private int total = 0;

    public static DeepHandshakeFuzzyClient deepHandshakeFuzzyClient() {
        return new DeepHandshakeFuzzyClient();
    }

    public static DeepHandshakeFuzzyClient deepHandshakeFuzzyClient(Client client) {
        return new DeepHandshakeFuzzyClient(client);
    }

    private DeepHandshakeFuzzyClient() {}

    public DeepHandshakeFuzzyClient(Client client) {
        this.client = client;
    }

    public DeepHandshakeFuzzyClient from(Client client) {
        this.client = client;
        return this;
    }

    @Override
    public DeepHandshakeFuzzyClient set(StructFactory factory) {
        throw new UnsupportedOperationException("no factories for you!");
    }

    @Override
    public DeepHandshakeFuzzyClient set(Negotiator negotiator) {
        throw new UnsupportedOperationException("no negotiators for you!");
    }

    @Override
    public DeepHandshakeFuzzyClient set(Check... checks) {
        this.checks = checks;
        return this;
    }

    @Override
    public DeepHandshakeFuzzyClient set(Analyzer analyzer) {
        this.analyzer = analyzer;
        return this;
    }

    @Override
    public DeepHandshakeFuzzyClient connect() {
        run();
        return this;
    }

    @Override
    public Engine[] engines() {
        throw new UnsupportedOperationException("no engines for you!");
    }

    @Override
    public void close() {
        stop();
    }

    public DeepHandshakeFuzzyClient set(DeepHandshakeFuzzer fuzzer) {
        this.fuzzer = fuzzer;
        return this;
    }

    public DeepHandshakeFuzzyClient total(int n) {
        total = n;
        return this;
    }

    @Override
    protected void runImpl() {
        if (fuzzer == null) {
            throw whatTheHell("no factory provided!");
        }

        if (total == 0) {
            throw whatTheHell("total is zero!");
        }

        fuzzer.recording();
        try {
            logger.info("run a smoke test before fuzzing");
            Engine[] engines = client.set(StructFactory.getDefault())
                    .set(fuzzer)
                    .connect()
                    .engines();

            if (engines == null || engines.length == 0) {
                throw whatTheHell("no engines!");
            }

            if (analyzer != null) {
                analyzer.add(engines);
            }

            for (Engine engine : engines) {
                engine.run(new SuccessCheck());
            }

            logger.info("smoke test passed, start fuzzing");
        } catch (Exception e) {
            throw whatTheHell("smoke test failed", e);
        }

        if (state != null && !state.isEmpty()) {
            fuzzer.state(state);
        }

        if (fuzzer.targeted().length == 0) {
            throw achtung("no targets found!");
        }

        String targets = Arrays.stream(fuzzer.targeted())
                .map(Object::toString)
                .collect(Collectors.joining( ", " ));

        logger.info("run fuzzer config:");
        logger.info("targets     = {}", targets);
        logger.info("fuzzer      = {}",
                fuzzer.fuzzer() != null
                        ? fuzzer.fuzzer().toString()
                        : "null");
        logger.info("total tests = {}", total);
        logger.info("state       = {}", state != null ? state : "not specified");

        try {
            fuzzer.fuzzing();

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

    private void run(DeepHandshakeFuzzer deepHandshakeFuzzer) throws Exception {
        String message = String.format("test #%d, %s/%s, targeted: [%s]",
                test,
                deepHandshakeFuzzer.getClass().getSimpleName(),
                deepHandshakeFuzzer.fuzzer().getClass().getSimpleName(),
                Arrays.stream(deepHandshakeFuzzer.targeted())
                        .map(Object::toString)
                        .collect(Collectors.joining(", ")));
        logger.info(message);
        logger.info("state: {}", deepHandshakeFuzzer.state());

        int attempt = 0;
        while (true) {
            try {
                client.set(deepHandshakeFuzzer)
                        .set(checks)
                        .set(analyzer)
                        .connect();

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
                    throw new IOException("looks like the server is not responding");
                }
                attempt++;

                logger.info("connection failed: {} ", cause.getMessage());
                logger.info("let's wait a bit and try again (attempt %d)", attempt);
                Utils.sleep(delay);
            }
        }
    }

    private boolean shouldRun(DeepHandshakeFuzzer fuzzer) {
        synchronized (this) {
            return !stopped() && fuzzer.canFuzz() && test < total;
        }
    }

}
