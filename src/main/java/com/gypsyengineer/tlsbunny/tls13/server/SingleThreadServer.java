package com.gypsyengineer.tlsbunny.tls13.server;

import com.gypsyengineer.tlsbunny.tls13.connection.Engine;
import com.gypsyengineer.tlsbunny.tls13.connection.EngineException;
import com.gypsyengineer.tlsbunny.tls13.connection.EngineFactory;
import com.gypsyengineer.tlsbunny.tls13.connection.action.ActionFailed;
import com.gypsyengineer.tlsbunny.tls13.connection.action.simple.GeneratingAlert;
import com.gypsyengineer.tlsbunny.tls13.connection.action.simple.WrappingIntoTLSPlaintexts;
import com.gypsyengineer.tlsbunny.tls13.connection.check.Check;
import com.gypsyengineer.tlsbunny.tls13.crypto.AEADException;
import com.gypsyengineer.tlsbunny.tls13.handshake.NegotiatorException;
import com.gypsyengineer.tlsbunny.utils.Connection;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.io.IOException;
import java.net.ServerSocket;
import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import static com.gypsyengineer.tlsbunny.tls13.struct.AlertDescription.handshake_failure;
import static com.gypsyengineer.tlsbunny.tls13.struct.AlertLevel.fatal;
import static com.gypsyengineer.tlsbunny.tls13.struct.ContentType.alert;
import static com.gypsyengineer.tlsbunny.utils.WhatTheHell.whatTheHell;

public class SingleThreadServer extends AbstractServer {

    private static final Logger logger = LogManager.getLogger(SingleThreadServer.class);

    static final int free_port = 0;

    private ServerSocket serverSocket;

    // TODO: add synchronization
    private EngineFactory factory;
    private StopCondition stopCondition = new NonStop();
    private Check check;
    private boolean failed = false;
    private Status status = Status.not_started;
    private int port = 0;

    private final List<Engine> engines = Collections.synchronizedList(new ArrayList<>());

    public SingleThreadServer() {
        this(free_port);
    }

    public SingleThreadServer(int n) {
        port = n;
    }

    public SingleThreadServer maxConnections(int n) {
        stopCondition = new NConnectionsReceived(n);
        return this;
    }

    @Override
    public SingleThreadServer set(EngineFactory factory) {
        this.factory = factory;
        return this;
    }

    @Override
    public SingleThreadServer set(Check check) {
        this.check = check;
        return this;
    }

    @Override
    public SingleThreadServer stopWhen(StopCondition condition) {
        stopCondition = condition;
        return this;
    }

    @Override
    public boolean failed() {
        return failed;
    }

    @Override
    public Engine[] engines() {
        return engines.toArray(new Engine[0]);
    }

    @Override
    public int port() {
        return port;
    }

    @Override
    public EngineFactory engineFactory() {
        return factory;
    }

    @Override
    public Status status() {
        synchronized (this) {
            return status;
        }
    }

    @Override
    public void run() {
        if (factory == null) {
            throw whatTheHell("engine factory is not set! (null)");
        }

        try (ServerSocket socket = new ServerSocket(port)) {
            serverSocket = socket;
            port = serverSocket.getLocalPort();
            logger.info("started on port {}", port());
            while (shouldRun()) {
                accept(socket);
            }
        } catch (IOException e) {
            if (serverSocket != null && serverSocket.isClosed()) {
                logger.info(e.getMessage());
            } else {
                logger.warn("unexpected i/o exception", e);
                failed = true;
            }
        } catch (Exception e) {
            logger.warn("unexpected exception", e);
            failed = true;
        } finally {
            synchronized (this) {
                status = Status.done;
            }
        }

        logger.info("stopped");
    }

    private boolean shouldRun() {
        if (serverSocket != null && serverSocket.isClosed()) {
            return false;
        }

        return stopCondition.shouldRun();
    }

    private void accept(ServerSocket serverSocket)
            throws IOException, EngineException, NegotiatorException, ActionFailed,
            AEADException {

        synchronized (this) {
            status = Status.ready;
        }

        try (Connection connection = Connection.create(serverSocket.accept())) {
            synchronized (this) {
                status = Status.accepted;
            }
            logger.info("accepted");

            Engine engine = factory.create();
            engines.add(engine);

            engine.set(connection);

            try {
                engine.run(); // TODO: rename connect -> run
            } catch (Exception e) {
                logger.warn("unexpected exception, sending alert", e);
                connection.send(generateAlert(engine));
                failed = true;
            }

            if (check != null) {
                logger.info("run check: {}", check.name());
                check.set(engine);
                check.run();
                failed &= check.failed();
            }

            logger.info("done");
        }
    }

    @Override
    public SingleThreadServer stop() {
        if (!serverSocket.isClosed()) {
            try {
                serverSocket.close();
            } catch (IOException e) {
                logger.warn("exception occurred while stopping the server", e);
            }
        }

        return this;
    }

    @Override
    public void close() {
        stop();
    }

    private ByteBuffer generateAlert(Engine engine) throws IOException, NegotiatorException,
            ActionFailed, AEADException {

        ByteBuffer buffer = new GeneratingAlert()
                .level(fatal)
                .description(handshake_failure)
                .set(engine.context())

                .run()
                .out();
        return new WrappingIntoTLSPlaintexts()
                .type(alert)
                .set(engine.context())

                .in(buffer)
                .run()
                .out();
    }

}
