package com.gypsyengineer.tlsbunny.tls13.client.fuzzer;

import com.gypsyengineer.tlsbunny.fuzzer.BitFlipFuzzer;
import com.gypsyengineer.tlsbunny.fuzzer.ByteFlipFuzzer;
import com.gypsyengineer.tlsbunny.fuzzer.Fuzzer;
import com.gypsyengineer.tlsbunny.tls13.client.Client;
import com.gypsyengineer.tlsbunny.tls13.client.HttpsClient;
import com.gypsyengineer.tlsbunny.tls13.client.HttpsClientAuth;
import com.gypsyengineer.tlsbunny.tls13.connection.Analyzer;
import com.gypsyengineer.tlsbunny.tls13.connection.Engine;
import com.gypsyengineer.tlsbunny.tls13.connection.EngineException;
import com.gypsyengineer.tlsbunny.tls13.connection.check.Check;
import com.gypsyengineer.tlsbunny.tls13.fuzzer.DeepHandshakeFuzzer;
import com.gypsyengineer.tlsbunny.tls13.handshake.Negotiator;
import com.gypsyengineer.tlsbunny.tls13.server.Server;
import com.gypsyengineer.tlsbunny.tls13.struct.StructFactory;
import com.gypsyengineer.tlsbunny.utils.Config;
import com.gypsyengineer.tlsbunny.utils.Utils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.io.IOException;
import java.net.ConnectException;
import java.util.Arrays;
import java.util.Objects;
import java.util.stream.Collectors;

import static com.gypsyengineer.tlsbunny.tls13.connection.check.SuccessCheck.successCheck;
import static com.gypsyengineer.tlsbunny.tls13.fuzzer.DeepHandshakeFuzzer.deepHandshakeFuzzer;
import static com.gypsyengineer.tlsbunny.utils.Achtung.achtung;
import static com.gypsyengineer.tlsbunny.utils.WhatTheHell.whatTheHell;

public class DeepHandshakeFuzzyClient extends AbstractFuzzyClient {

    private static final Logger logger = LogManager.getLogger(DeepHandshakeFuzzyClient.class);

    private static final int max_attempts = 3;
    private static final int delay = 3000; // in millis

    private final Client client;
    private Check[] checks;
    private Analyzer analyzer;
    private long test = 0;
    private DeepHandshakeFuzzer fuzzer = deepHandshakeFuzzer();
    private int total = Config.instance.getInt("total", 1000);

    public static DeepHandshakeFuzzyClient from(Client client) {
        return new DeepHandshakeFuzzyClient(client);
    }

    /**
     * Private constructor. Use factory methods to create an instance.
     */
    private DeepHandshakeFuzzyClient(Client client) {
        Objects.requireNonNull(client, "what the hell! client can't be null!");
        this.client = client;
    }

    public DeepHandshakeFuzzer fuzzer() {
        return fuzzer;
    }

    @Override
    public Client to(int port) {
        client.to(port);
        return this;
    }

    @Override
    public Client to(Server server) {
        client.to(server);
        return this;
    }

    @Override
    public DeepHandshakeFuzzyClient set(StructFactory factory) {
        if (factory instanceof DeepHandshakeFuzzer == false) {
            throw whatTheHell("Hey! Give me an instance of DeepHandshakeFuzzer");
        }
        set((DeepHandshakeFuzzer) factory);
        return this;
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
            throw whatTheHell("no fuzzer provided!");
        }

        if (total <= 0) {
            throw whatTheHell("total is not positive!");
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
                engine.run(successCheck());
            }

            logger.info("smoke test passed, start fuzzing");
        } catch (Exception e) {
            throw whatTheHell("smoke test failed", e);
        }

        if (state != null) {
            fuzzer.state(state);
        }

        if (fuzzer.targeted().length == 0) {
            throw achtung("no targets found!");
        }

        String targets = Arrays.stream(fuzzer.targeted())
                .map(Object::toString)
                .collect(Collectors.joining( ", " ));

        logger.info("fuzzer config:");
        logger.info("targets     = {}", targets);
        logger.info("fuzzer      = {}",
                () -> fuzzer.fuzzer() != null ? fuzzer.fuzzer() : "null");
        logger.info("total tests = {}", total);
        logger.info("state       = {}",
                () -> state != null ? state : "not specified");

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
                logger.info("let's wait a bit and try again (attempt {})", attempt);
                Utils.sleep(delay);
            }
        }
    }

    private boolean shouldRun(DeepHandshakeFuzzer fuzzer) {
        synchronized (this) {
            return !stopped() && fuzzer.canFuzz() && test < total;
        }
    }

    public static void main(String... args) {
        fuzz(ByteFlipFuzzer::new, HttpsClient::new);
        fuzz(BitFlipFuzzer::new, HttpsClient::new);
        fuzz(ByteFlipFuzzer::new, HttpsClientAuth::new);
        fuzz(BitFlipFuzzer::new, HttpsClientAuth::new);
    }

    private static void fuzz(FuzzerFactory fuzzerFactory, ClientFactory clientFactory) {
        for (double ratio = minRatio; ratio <= maxRatio; ratio += ratioStep) {
            try (DeepHandshakeFuzzyClient client = DeepHandshakeFuzzyClient.from(clientFactory.create())) {
                client.fuzzer().set(fuzzerFactory.create(ratio));
                client.connect();
            }
        }
    }

    private static final double minRatio = 0.05;
    private static final double maxRatio = 0.5;
    private static final double ratioStep = 0.05;

    private interface FuzzerFactory {
        Fuzzer<byte[]> create(double ratio);
    }

    private interface ClientFactory {
        Client create();
    }
}
