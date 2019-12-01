package com.gypsyengineer.tlsbunny.tls13.client;

import com.gypsyengineer.tlsbunny.tls13.connection.Analyzer;
import com.gypsyengineer.tlsbunny.tls13.connection.Engine;
import com.gypsyengineer.tlsbunny.tls13.connection.check.Check;
import com.gypsyengineer.tlsbunny.tls13.handshake.Negotiator;
import com.gypsyengineer.tlsbunny.tls13.handshake.NegotiatorException;
import com.gypsyengineer.tlsbunny.tls13.server.Server;
import com.gypsyengineer.tlsbunny.tls13.struct.NamedGroup;
import com.gypsyengineer.tlsbunny.tls13.struct.StructFactory;
import com.gypsyengineer.tlsbunny.utils.Config;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import static com.gypsyengineer.tlsbunny.utils.WhatTheHell.whatTheHell;

public abstract class AbstractClient implements Client, AutoCloseable {

    private static final Check[] no_checks = new Check[0];

    protected StructFactory factory = StructFactory.getDefault();
    protected Negotiator negotiator;
    protected Analyzer analyzer;
    protected List<Engine> engines = new ArrayList<>();
    protected List<Check> checks = Collections.emptyList();
    protected Status status = Status.not_started;
    protected String host = Config.instance.getString("target.host", "localhost");
    protected int port = Config.instance.getInt("target.port", 433);

    protected AbstractClient() {
        try {
            negotiator = Negotiator.create(NamedGroup.secp256r1);
        } catch (NegotiatorException e) {
            throw whatTheHell("could not create a negotiator!", e);
        }
    }

    @Override
    public AbstractClient to(Server server) {
        this.port = server.port();
        return this;
    }

    @Override
    public AbstractClient to(int port) {
        this.port = port;
        return this;
    }

    @Override
    public AbstractClient to(String host) {
        this.host = host;
        return this;
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
    public void close() {
        stop();
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
