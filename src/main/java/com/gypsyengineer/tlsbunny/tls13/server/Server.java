package com.gypsyengineer.tlsbunny.tls13.server;

import com.gypsyengineer.tlsbunny.tls13.connection.Analyzer;
import com.gypsyengineer.tlsbunny.tls13.connection.check.Check;
import com.gypsyengineer.tlsbunny.tls13.connection.Engine;
import com.gypsyengineer.tlsbunny.tls13.connection.EngineFactory;
import com.gypsyengineer.tlsbunny.utils.Config;
import com.gypsyengineer.tlsbunny.output.HasOutput;
import com.gypsyengineer.tlsbunny.utils.Sync;

public interface Server extends Runnable, AutoCloseable, HasOutput<Server> {

    enum Status {
        not_started, ready, accepted, done
    }

    Server set(Config config);
    Server set(EngineFactory engineFactory);
    Server set(Sync sync);

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
    default Thread start() {
        String name = String.format("%s-thread", getClass().getSimpleName());
        Thread thread = new Thread(this, name);
        thread.start();

        try {
            Thread.sleep(1000); // one second
        } catch (InterruptedException e) {
            output().achtung("exception: ", e);
        }

        return thread;
    }

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
