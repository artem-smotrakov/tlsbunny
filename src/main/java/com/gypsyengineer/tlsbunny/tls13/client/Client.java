package com.gypsyengineer.tlsbunny.tls13.client;

import com.gypsyengineer.tlsbunny.tls13.connection.Analyzer;
import com.gypsyengineer.tlsbunny.tls13.connection.Engine;
import com.gypsyengineer.tlsbunny.tls13.connection.check.Check;
import com.gypsyengineer.tlsbunny.tls13.handshake.Negotiator;
import com.gypsyengineer.tlsbunny.tls13.server.Server;
import com.gypsyengineer.tlsbunny.tls13.struct.StructFactory;

import static com.gypsyengineer.tlsbunny.utils.WhatTheHell.whatTheHell;

public interface Client extends AutoCloseable, Runnable {

    enum Status {
        not_started, running, done
    }

    Client to(String host);
    Client to(int port);
    Client to(Server server);
    Client set(StructFactory factory);
    Client set(Negotiator negotiator);
    Client set(Check... checks);
    Client set(Analyzer analyzer);
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
        Thread thread = new Thread(this, "server");
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
