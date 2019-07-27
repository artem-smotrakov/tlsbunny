package com.gypsyengineer.tlsbunny.tls13.client;

import com.gypsyengineer.tlsbunny.tls13.connection.Analyzer;
import com.gypsyengineer.tlsbunny.tls13.connection.check.Check;
import com.gypsyengineer.tlsbunny.tls13.connection.Engine;
import com.gypsyengineer.tlsbunny.tls13.handshake.Negotiator;
import com.gypsyengineer.tlsbunny.tls13.struct.StructFactory;
import com.gypsyengineer.tlsbunny.utils.Config;
import com.gypsyengineer.tlsbunny.output.HasOutput;
import com.gypsyengineer.tlsbunny.output.Output;
import com.gypsyengineer.tlsbunny.utils.Sync;

import static com.gypsyengineer.tlsbunny.utils.WhatTheHell.whatTheHell;

public interface Client extends AutoCloseable, Runnable, HasOutput<Client> {

    enum Status {
        not_started, running, done
    }

    Config config();
    Client set(Config config);
    Client set(StructFactory factory);
    Client set(Negotiator negotiator);
    Client set(Output output);
    Client set(Check... checks);
    Client set(Analyzer analyzer);
    Client set(Sync sync);
    Client connect() throws Exception;

    Status status();
    Engine[] engines();

    default void run() {
        try {
            connect();
        } catch (Exception e) {
            throw whatTheHell("exception on client side", e);
        }
    }

    /**
     * Starts the client in a new thread.
     *
     * @return the thread where the client is running
     */
    default Thread start() {
        String name = String.format("%s-thread", getClass().getSimpleName());
        Thread thread = new Thread(this, name);
        thread.start();
        return thread;
    }

    /**
     * Applies an analyzer to all engines in the client.
     */
    // TODO: we also have set(Analyzer) - do we need it?
    default Client apply(Analyzer analyzer) {
        for (Engine engine : engines()) {
            engine.apply(analyzer);
        }

        return this;
    }

    /**
     * Stops the client.
     */
    Client stop();

    /**
     * @return true if the client is running, false otherwise
     */
    default boolean running() {
        return status() == Status.running;
    }

    /**
     * @return true if the client is done, false otherwise
     */
    default boolean done() {
        return status() == Status.done;
    }

}
