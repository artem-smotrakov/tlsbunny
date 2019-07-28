package com.gypsyengineer.tlsbunny.tls13.server;

import com.gypsyengineer.tlsbunny.tls13.connection.Analyzer;
import com.gypsyengineer.tlsbunny.tls13.connection.Engine;
import com.gypsyengineer.tlsbunny.tls13.connection.EngineFactory;
import com.gypsyengineer.tlsbunny.tls13.connection.check.Check;

public interface Server extends Runnable, AutoCloseable {

    enum Status {
        not_started, ready, accepted, done
    }

    Server set(EngineFactory engineFactory);

    // TODO it should accept multiple checks
    Server set(Check check);

    Server stopWhen(StopCondition condition);

    EngineFactory engineFactory();
    Status status();

    /**
     * Stops the server.
     */
    Server stop();

    /**
     * @return true if the server is running, false otherwise
     */
    default boolean running() {
        Status status = status();
        return status == Server.Status.ready || status == Server.Status.accepted;
    }

    /**
     * @return true if the server is ready to accept a connection,
     *         false otherwise
     */
    default boolean ready() {
        return status() == Server.Status.ready;
    }

    default boolean done() {
        return status() == Server.Status.done;
    }

    /**
     * @return the port number on which the server is running
     */
    int port();

    /**
     * @return all Engine instances which were used to handle connections
     */
    Engine[] engines();

    /**
     * @return false if the check failed at least once, true otherwise
     */
    boolean failed();

    /**
     * Starts the server in a new thread.
     *
     * @return the thread where the server is running
     */
    Thread start();

    /**
     * Applies an analyzer to all engines in the server.
     */
    default Server apply(Analyzer analyzer) {
        for (Engine engine : engines()) {
            engine.apply(analyzer);
        }

        return this;
    }
}
