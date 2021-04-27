package com.gypsyengineer.tlsbunny.tls13.client.fuzzer;

import com.gypsyengineer.tlsbunny.fuzzer.BitFlipFuzzer;
import com.gypsyengineer.tlsbunny.fuzzer.ByteFlipFuzzer;
import com.gypsyengineer.tlsbunny.fuzzer.Fuzzer;
import com.gypsyengineer.tlsbunny.tls13.client.Client;
import com.gypsyengineer.tlsbunny.tls13.client.HttpsClient;
import com.gypsyengineer.tlsbunny.tls13.client.HttpsClientAuth;
import com.gypsyengineer.tlsbunny.tls13.client.HttpsClientWithSessionResumption;
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

import static com.gypsyengineer.tlsbunny.tls13.client.HttpsClient.httpsClient;
import static com.gypsyengineer.tlsbunny.tls13.connection.check.ApplicationDataCheck.applicationDataCheck;
import static com.gypsyengineer.tlsbunny.tls13.connection.check.SuccessCheck.successCheck;
import static com.gypsyengineer.tlsbunny.utils.Achtung.achtung;
import static com.gypsyengineer.tlsbunny.utils.WhatTheHell.whatTheHell;

public class DeepHandshakeFuzzyClient extends AbstractFuzzyClient {

    private static final Logger logger = LogManager.getLogger(DeepHandshakeFuzzyClient.class);

    private static final double minRatio = 0.05;
    private static final double maxRatio = 0.5;
    private static final double ratioStep = 0.05;

    private static final int max_attempts = 3;
    private static final int delay = 3000; // in millis

    private final Client client;
    private Analyzer analyzer;
    private long test = 0;
    private DeepHandshakeFuzzer deepHandshakeFuzzer = DeepHandshakeFuzzer.deepHandshakeFuzzer();
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

    public DeepHandshakeFuzzer deepHandshakeFuzzer() {
        return deepHandshakeFuzzer;
    }

    @Override
    public Client to(String host) {
        client.to(host);
        return this;
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
        if (factory instanceof DeepHandshakeFuzzer) {
            set((DeepHandshakeFuzzer) factory);
            return this;
        }
        throw whatTheHell("Hey! Give me an instance of DeepHandshakeFuzzer");
    }

    @Override
    public DeepHandshakeFuzzyClient set(Negotiator negotiator) {
        client.set(negotiator);
        return this;
    }

    @Override
    public DeepHandshakeFuzzyClient set(Check... checks) {
        client.set(checks);
        return this;
    }

    @Override
    public DeepHandshakeFuzzyClient set(Analyzer analyzer) {
        client.set(analyzer);
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
        return client.engines();
    }

    @Override
    public void close() throws Exception {
        client.close();
        stop();
    }

    public DeepHandshakeFuzzyClient set(DeepHandshakeFuzzer fuzzer) {
        this.deepHandshakeFuzzer = fuzzer;
        return this;
    }

    public DeepHandshakeFuzzyClient total(int n) {
        total = n;
        return this;
    }

    @Override
    protected void runImpl() {
        if (deepHandshakeFuzzer == null) {
            throw whatTheHell("no fuzzer provided!");
        }

        if (total <= 0) {
            throw whatTheHell("total is not positive!");
        }

        deepHandshakeFuzzer.recording();
        try {
            logger.info("run a smoke test before fuzzing, " +
                    "and record which messages are sent out");
            Engine[] engines = client
                    .set(deepHandshakeFuzzer)
                    .connect()
                    .engines();

            if (engines == null || engines.length == 0) {
                throw whatTheHell("no engines!");
            }

            if (analyzer != null) {
                analyzer.add(engines);
            }

            for (Engine engine : engines) {
                engine.require(successCheck());
                engine.require(applicationDataCheck());
            }

            logger.info("smoke test passed, start fuzzing");
        } catch (Exception e) {
            throw whatTheHell("smoke test failed", e);
        }

        if (state != null) {
            deepHandshakeFuzzer.state(state);
        }

        if (deepHandshakeFuzzer.targeted().length == 0) {
            throw achtung("no targets found!");
        }

        String targets = Arrays.stream(deepHandshakeFuzzer.targeted())
                .map(Object::toString)
                .collect(Collectors.joining( ", " ));

        logger.info("fuzzer config:");
        logger.info("targets     = {}", targets);
        logger.info("fuzzer      = {}",
                () -> deepHandshakeFuzzer.fuzzer() != null ? deepHandshakeFuzzer.fuzzer() : "null");
        logger.info("total tests = {}", total);
        logger.info("state       = {}",
                () -> state != null ? state : "not specified");

        try {
            deepHandshakeFuzzer.fuzzing();

            test = 0;
            while (shouldRun(deepHandshakeFuzzer)) {
                try {
                    run(deepHandshakeFuzzer);
                } finally {
                    deepHandshakeFuzzer.moveOn();
                    test++;
                }
            }
        } catch (Exception e) {
            logger.warn("what the hell? unexpected exception", e);
        }
    }

    private void run(DeepHandshakeFuzzer fuzzer) throws Exception {
        logger.info("test #{}, {}/{}, targeted: [{}]",
                test,
                fuzzer.getClass().getSimpleName(),
                fuzzer.fuzzer().getClass().getSimpleName(),
                Arrays.stream(fuzzer.targeted())
                        .map(Object::toString)
                        .collect(Collectors.joining(", ")));
        logger.info("state: {}", fuzzer.state());

        int attempt = 0;
        while (true) {
            try {
                client.set(fuzzer)
                        .set(analyzer)
                        .set(no_checks)
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

    public static void main(String... args) throws Exception {
        String mode = args.length > 0 ? args[0] : "all";

        if (selected(mode, "standard")) {
            fuzz(ByteFlipFuzzer::new, HttpsClient::new);
            fuzz(BitFlipFuzzer::new, HttpsClient::new);
        }

        if (selected(mode, "client_auth")) {
            fuzz(ByteFlipFuzzer::new, HttpsClientAuth::new);
            fuzz(BitFlipFuzzer::new, HttpsClientAuth::new);
        }

        if (selected(mode, "resumption")) {
            ClientFactory factory = () -> HttpsClientWithSessionResumption.from(
                    ProtectedClient.from(httpsClient()).withUnmodifiableStructFactory());
            fuzz(ByteFlipFuzzer::new, factory);
            fuzz(BitFlipFuzzer::new, factory);
        }
    }

    private static boolean selected(String actualMode, String expectedMode) {
        return "all".equals(actualMode) || actualMode.equals(expectedMode);
    }

    private static void fuzz(FuzzerFactory fuzzerFactory, ClientFactory clientFactory)
            throws Exception {

        for (double ratio = minRatio; ratio <= maxRatio; ratio += ratioStep) {
            try (Client client = clientFactory.create();
                 DeepHandshakeFuzzyClient fuzzyClient = DeepHandshakeFuzzyClient.from(client)) {

                Fuzzer<byte[]> underlyingFuzzer = fuzzerFactory.create(ratio);
                fuzzyClient.deepHandshakeFuzzer().set(underlyingFuzzer);
                fuzzyClient.connect();
            }
        }
    }

    private interface FuzzerFactory {
        Fuzzer<byte[]> create(double ratio);
    }

    private interface ClientFactory {
        Client create();
    }
}
