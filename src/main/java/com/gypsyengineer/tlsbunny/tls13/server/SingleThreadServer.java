package com.gypsyengineer.tlsbunny.tls13.server;

import com.gypsyengineer.tlsbunny.output.Output;
import com.gypsyengineer.tlsbunny.tls13.connection.EngineException;
import com.gypsyengineer.tlsbunny.tls13.connection.action.ActionFailed;
import com.gypsyengineer.tlsbunny.tls13.connection.action.simple.GeneratingAlert;
import com.gypsyengineer.tlsbunny.tls13.connection.action.simple.WrappingIntoTLSPlaintexts;
import com.gypsyengineer.tlsbunny.tls13.connection.check.Check;
import com.gypsyengineer.tlsbunny.tls13.connection.Engine;
import com.gypsyengineer.tlsbunny.tls13.connection.EngineFactory;
import com.gypsyengineer.tlsbunny.tls13.crypto.AEADException;
import com.gypsyengineer.tlsbunny.tls13.handshake.NegotiatorException;
import com.gypsyengineer.tlsbunny.utils.*;

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

public class SingleThreadServer implements Server {

    public static final int free_port = 0;

    private ServerSocket serverSocket;

    // TODO: add synchronization
    private Config config = SystemPropertiesConfig.load();
    private EngineFactory factory;
    private StopCondition stopCondition = new NonStop();
    private Output output = Output.local("server");
    private Check check;
    private boolean failed = false;
    private Status status = Status.not_started;

    private final List<Engine> engines = Collections.synchronizedList(new ArrayList<>());

    public SingleThreadServer() {
        this(free_port);
    }

    public SingleThreadServer(int n) {
        if (config == null) {
            throw whatTheHell("can't set a port because config is null");
        }
        config.port(n);
    }

    @Override
    public Output output() {
        return output;
    }

    public SingleThreadServer maxConnections(int n) {
        stopCondition = new NConnectionsReceived(n);
        return this;
    }

    @Override
    public SingleThreadServer set(Config config) {
        this.config = config;
        return this;
    }

    @Override
    public SingleThreadServer set(EngineFactory factory) {
        this.factory = factory;
        return this;
    }

    @Override
    public SingleThreadServer set(Output output) {
        this.output = output;
        return this;
    }

    @Override
    public SingleThreadServer set(Check check) {
        this.check = check;
        return this;
    }

    @Override
    public Server set(Sync sync) {
        // do nothing
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
        return config.port();
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

        output.info("started on port %d", port());
        try (ServerSocket socket = new ServerSocket(config.port())) {
            serverSocket = socket;
            while (shouldRun()) {
                accept(socket);
            }
        } catch (IOException e) {
            if (serverSocket != null && serverSocket.isClosed()) {
                output.info(e.getMessage());
            } else {
                output.achtung("unexpected i/o exception", e);
                failed = true;
            }
        } catch (Exception e) {
            output.achtung("unexpected exception", e);
            failed = true;
        } finally {
            synchronized (this) {
                status = Status.done;
            }
        }

        output.info("stopped");
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
            output.info("accepted");

            Engine engine = factory.create();
            engines.add(engine);

            engine.set(output);
            engine.set(connection);

            try {
                engine.connect(); // TODO: rename connect -> run
            } catch (Exception e) {
                connection.send(generateAlert(engine));
                failed = true;
            }

            if (check != null) {
                output.info("run check: %s", check.name());
                check.set(engine);
                check.set(engine.context());
                check.run();
                failed &= check.failed();
            }

            output.info("done");
        }
    }

    @Override
    public SingleThreadServer stop() {
        if (!serverSocket.isClosed()) {
            try {
                serverSocket.close();
            } catch (IOException e) {
                output.achtung("exception occurred while stopping the server", e);
            }
        }

        return this;
    }

    @Override
    public void close() {
        stop();

        if (output != null) {
            output.flush();
        }
    }

    private ByteBuffer generateAlert(Engine engine) throws IOException, NegotiatorException,
            ActionFailed, AEADException {

        ByteBuffer buffer = new GeneratingAlert()
                .level(fatal)
                .description(handshake_failure)
                .set(engine.context())
                .set(output)
                .run()
                .out();
        return new WrappingIntoTLSPlaintexts()
                .type(alert)
                .set(engine.context())
                .set(output)
                .in(buffer)
                .run()
                .out();
    }

}
