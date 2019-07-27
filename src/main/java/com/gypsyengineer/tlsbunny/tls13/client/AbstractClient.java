package com.gypsyengineer.tlsbunny.tls13.client;

import com.gypsyengineer.tlsbunny.tls13.connection.Analyzer;
import com.gypsyengineer.tlsbunny.tls13.connection.check.Check;
import com.gypsyengineer.tlsbunny.tls13.connection.Engine;
import com.gypsyengineer.tlsbunny.tls13.handshake.Negotiator;
import com.gypsyengineer.tlsbunny.tls13.handshake.NegotiatorException;
import com.gypsyengineer.tlsbunny.tls13.struct.NamedGroup;
import com.gypsyengineer.tlsbunny.tls13.struct.StructFactory;
import com.gypsyengineer.tlsbunny.utils.*;
import com.gypsyengineer.tlsbunny.output.Output;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import static com.gypsyengineer.tlsbunny.utils.WhatTheHell.whatTheHell;

public abstract class AbstractClient implements Client, AutoCloseable {

    private static final Check[] no_checks = new Check[0];

    protected Config config = SystemPropertiesConfig.load();
    protected StructFactory factory = StructFactory.getDefault();
    protected Negotiator negotiator;
    protected Output output = Output.local();
    protected Analyzer analyzer;
    protected List<Engine> engines = new ArrayList<>();
    protected List<Check> checks = Collections.emptyList();
    protected Sync sync = Sync.dummy();

    protected Status status = Status.not_started;

    public AbstractClient() {
        try {
            negotiator = Negotiator.create(NamedGroup.secp256r1, StructFactory.getDefault());
        } catch (NegotiatorException e) {
            throw whatTheHell("could not create a negotiator!", e);
        }
    }

    @Override
    public synchronized Status status() {
        return status;
    }

    @Override
    // TODO should it run checks and analyzers? should they be private?
    //      if so, connectImpl should probably return engines
    public final Client connect() throws Exception {
        synchronized (this) {
            status = Status.running;
            engines = new ArrayList<>();
        }

        try {
            return connectImpl();
        } finally {
            synchronized (this) {
                status = Status.done;
                if (analyzer != null) {
                    analyzer.add(engines.toArray(new Engine[0]));
                }
            }
        }
    }

    protected abstract Client connectImpl() throws Exception;

    @Override
    public Output output() {
        return output;
    }

    @Override
    public Config config() {
        return config;
    }

    @Override
    public Client set(Config config) {
        this.config = config;
        return this;
    }

    @Override
    public Client set(StructFactory factory) {
        this.factory = factory;
        return this;
    }

    @Override
    public Client set(Negotiator negotiator) {
        this.negotiator = negotiator;
        return this;
    }

    @Override
    public Client set(Output output) {
        this.output = output;
        return this;
    }

    @Override
    public Client set(Check... checks) {
        this.checks = List.of(checks != null ? checks : no_checks);
        return this;
    }

    @Override
    public Client set(Analyzer analyzer) {
        this.analyzer = analyzer;
        return this;
    }

    @Override
    synchronized public Client set(Sync sync) {
        this.sync = sync;
        return this;
    }

    synchronized public Sync sync() {
        return sync;
    }

    @Override
    public void close() {
        stop();
        if (output != null) {
            output.flush();
        }
    }

    @Override
    public Client stop() {
        // do nothing
        return this;
    }

    @Override
    public Engine[] engines() {
        return engines.toArray(new Engine[0]);
    }

}
