package com.gypsyengineer.tlsbunny.tls13.fuzzer;

import com.gypsyengineer.tlsbunny.tls13.client.Client;
import com.gypsyengineer.tlsbunny.tls13.connection.Analyzer;
import com.gypsyengineer.tlsbunny.tls13.connection.Engine;
import com.gypsyengineer.tlsbunny.tls13.connection.check.Check;
import com.gypsyengineer.tlsbunny.tls13.handshake.Negotiator;
import com.gypsyengineer.tlsbunny.tls13.struct.StructFactory;
import com.gypsyengineer.tlsbunny.tls13.utils.FuzzerConfig;
import com.gypsyengineer.tlsbunny.utils.Config;
import com.gypsyengineer.tlsbunny.output.Output;
import com.gypsyengineer.tlsbunny.utils.Sync;

import static com.gypsyengineer.tlsbunny.tls13.utils.FuzzerConfigUpdater.fuzzerConfigUpdater;
import static com.gypsyengineer.tlsbunny.utils.WhatTheHell.whatTheHell;

public class MultiConfigClient implements Client, AutoCloseable {

    private Client client;
    private FuzzerConfig[] configs = new FuzzerConfig[0];
    private Status status = Status.not_started;
    private boolean stopped = false;

    public static MultiConfigClient multiConfigClient() {
        return new MultiConfigClient();
    }

    private MultiConfigClient() {}

    public MultiConfigClient configs(FuzzerConfig... configs) {
        if (configs == null || configs.length == 0) {
            throw whatTheHell("no configs!");
        }

        this.configs = configs;

        return this;
    }

    public MultiConfigClient from(Client client) {
        this.client = client;
        return this;
    }

    @Override
    public Config config() {
        return fuzzerConfigUpdater(configs);
    }

    @Override
    public MultiConfigClient set(Config config) {
        throw new UnsupportedOperationException("no configs for you!");
    }

    @Override
    public MultiConfigClient set(StructFactory factory) {
        client.set(factory);
        return this;
    }

    @Override
    public MultiConfigClient set(Negotiator negotiator) {
        client.set(negotiator);
        return this;
    }

    @Override
    public MultiConfigClient set(Output output) {
        client.set(output);
        return this;
    }

    @Override
    public MultiConfigClient set(Check... checks) {
        client.set(checks);
        return this;
    }

    @Override
    public MultiConfigClient set(Analyzer analyzer) {
        client.set(analyzer);
        return this;
    }

    @Override
    public MultiConfigClient set(Sync sync) {
        client.set(sync);
        return this;
    }

    @Override
    public Output output() {
        return client.output();
    }

    @Override
    public MultiConfigClient connect() throws Exception {
        synchronized (this) {
            stopped = false;
            status = Status.running;
        }

        try {
            for (FuzzerConfig config : configs) {
                synchronized (this) {
                    if (stopped) {
                        break;
                    }
                }
                client.set(config).connect();
            }
        } finally {
            synchronized (this) {
                status = Status.done;
            }
        }

        return this;
    }

    @Override
    public Status status() {
        synchronized (this) {
            return status;
        }
    }

    @Override
    public Engine[] engines() {
        return client.engines();
    }

    @Override
    public MultiConfigClient apply(Analyzer analyzer) {
        client.apply(analyzer);
        return this;
    }

    @Override
    public MultiConfigClient stop() {
        synchronized (this) {
            stopped = true;
        }
        client.stop();
        return this;
    }

    @Override
    public void close() {
        stop();
    }

}
