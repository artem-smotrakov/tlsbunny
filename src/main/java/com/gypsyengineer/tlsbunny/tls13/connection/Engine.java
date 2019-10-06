package com.gypsyengineer.tlsbunny.tls13.connection;

import com.gypsyengineer.tlsbunny.tls13.connection.action.Action;
import com.gypsyengineer.tlsbunny.tls13.connection.action.ActionFailed;
import com.gypsyengineer.tlsbunny.tls13.connection.action.EmptyAction;
import com.gypsyengineer.tlsbunny.tls13.connection.check.Check;
import com.gypsyengineer.tlsbunny.tls13.crypto.HKDF;
import com.gypsyengineer.tlsbunny.tls13.handshake.Context;
import com.gypsyengineer.tlsbunny.tls13.handshake.ECDHENegotiator;
import com.gypsyengineer.tlsbunny.tls13.handshake.Negotiator;
import com.gypsyengineer.tlsbunny.tls13.handshake.NegotiatorException;
import com.gypsyengineer.tlsbunny.tls13.struct.CipherSuite;
import com.gypsyengineer.tlsbunny.tls13.struct.NamedGroup;
import com.gypsyengineer.tlsbunny.tls13.struct.SignatureScheme;
import com.gypsyengineer.tlsbunny.tls13.struct.StructFactory;
import com.gypsyengineer.tlsbunny.utils.Connection;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

import static com.gypsyengineer.tlsbunny.utils.WhatTheHell.whatTheHell;

public class Engine {

    private static final Logger logger = LogManager.getLogger(Engine.class);

    private static final ByteBuffer nothing = ByteBuffer.allocate(0);

    private enum ActionType {
        run, send, receive, store, restore, receive_till
    }

    public enum Status {
        not_started, running, unexpected_error, success
    }

    private final List<ActionHolder> actions = new ArrayList<>();

    private Connection connection;
    private boolean createdConnection = false;

    private String host = "localhost";
    private int port = 443;
    private Status status = Status.not_started;
    private ByteBuffer buffer = nothing;
    private ByteBuffer applicationData = nothing;
    private Context context = new Context();

    private Throwable exception;

    // timeout for reading incoming data (in millis)
    private long timeout = Connection.default_read_timeout;

    // if true, then stop if an alert occurred
    private boolean stopIfAlert = true;

    // if true, then an exception is thrown in case of error
    private boolean strict = true;

    // this is a label to mark a particular connection
    private String label = String.format("connection:%d", System.currentTimeMillis());

    private final List<byte[]> storedData = new ArrayList<>();

    private Engine() {
        context.set(SignatureScheme.ecdsa_secp256r1_sha256);
        context.set(CipherSuite.TLS_AES_128_GCM_SHA256);
        context.set(StructFactory.getDefault());
    }

    public Context context() {
        return context;
    }

    public Engine set(String host, int port) {
        return target(host).target(port);
    }

    public Engine target(String host) {
        Objects.requireNonNull(host, "Hey! Host can't be null!");
        if (host.isEmpty()) {
            throw whatTheHell("Hey! Host can't be empty!");
        }
        this.host = host;
        return this;
    }

    public Engine target(int port) {
        if (port < 0 || port > 65535) {
            throw whatTheHell("Hey! Give me a valid port number but not %d!", port);
        }
        this.port = port;
        return this;
    }

    public Throwable exception() {
        return exception;
    }

    public Engine strict() {
        strict = true;
        return this;
    }

    public Engine label(String label) {
        if (label == null || label.trim().isEmpty()) {
            throw whatTheHell("empty label!");
        }
        this.label = label;
        return this;
    }

    public String label() {
        return label;
    }

    public Engine set(Connection connection) {
        this.connection = connection;
        return this;
    }

    public Engine set(StructFactory factory) {
        this.context.set(factory);
        return this;
    }

    public Engine set(SignatureScheme scheme) {
        this.context.set(scheme);
        return this;
    }

    public Engine set(Negotiator negotiator) {
        this.context.set(negotiator);
        return this;
    }

    public Engine store() {
        actions.add(new ActionHolder()
                .set(this)
                .set(EmptyAction::new)
                .type(ActionType.store));
        return this;
    }

    public Engine restore() {
        actions.add(new ActionHolder()
                .set(this)
                .set(EmptyAction::new)
                .type(ActionType.restore));
        return this;
    }

    public Engine send(Action action) {
        actions.add(new ActionHolder()
                .set(this)
                .set(() -> action)
                .type(ActionType.send));
        return this;
    }

    public Engine send(int n, ActionFactory factory) {
        for (int i=0; i<n; i++) {
            send(factory.create());
        }
        return this;
    }

    public Engine send(ActionFactory factory) {
        actions.add(new ActionHolder()
                .set(this)
                .set(factory)
                .type(ActionType.send));
        return this;
    }

    public Engine receive(Action action) {
        actions.add(new ActionHolder()
                .set(this)
                .set(() -> action)
                .type(ActionType.receive));
        return this;
    }

    public ActionHolder receive(ActionFactory factory) {
        return new ActionHolder().set(this).set(factory);
    }

    public ActionHolder until(Condition condition) {
        return new ActionHolder()
                .set(this)
                .type(ActionType.receive_till)
                .set(condition);
    }

    public Engine run(ActionFactory factory) {
        actions.add(new ActionHolder()
                .set(this)
                .set(factory)
                .type(ActionType.run));
        return this;
    }

    public Engine run(Action action) {
        actions.add(new ActionHolder()
                .set(this)
                .set(() -> action)
                .type(ActionType.run));
        return this;
    }

    public Engine run() throws EngineException {
        context.negotiator().set(context.factory());
        status = Status.running;

        initConnection();
        try {
            buffer = nothing;

            loop: for (ActionHolder holder : actions) {
                if (connection.isClosed()) {
                    logger.warn("connection is closed, stop");
                    break;
                }

                ActionFactory actionFactory = holder.factory;

                Action action;
                switch (holder.type) {
                    case send:
                        action = actionFactory.create();
                        logger.info("send: {}", action.name());
                        init(action).run();
                        connection.send(action.out());
                        if (connection.failed()) {
                            logger.warn("could not send data, stop", connection.exception());
                            break loop;
                        }
                        break;
                    case receive:
                        action = actionFactory.create();
                        logger.info("receive: {}", action.name());
                        read(connection, action);
                        if (connection.failed()) {
                            logger.warn("could not read data, stop", connection.exception());
                            break loop;
                        }
                        init(action).run();
                        combineData(action);
                        break;
                    case receive_till:
                        action = actionFactory.create();
                        while (holder.condition.met(context)) {
                            logger.info("receive (conditional): {}", action.name());
                            read(connection, action);
                            if (connection.failed()) {
                                logger.warn("could not read data, stop", connection.exception());
                                break loop;
                            }
                            init(action).run();
                            combineData(action);
                        }
                        break;
                    case run:
                        action = actionFactory.create();
                        logger.info("run: {}", action.name());
                        init(action).run();
                        combineData(action);
                        break;
                    case store:
                        storeImpl();
                        break;
                    case restore:
                        restoreImpl();
                        break;
                    default:
                        throw new IllegalStateException(
                                String.format("unknown action type: %s", holder.type));
                }

                if (context.hasAlert()) {
                    if (context.getAlert().isFatal()) {
                        logger.info("stop, fatal alert occurred: {}", context.getAlert());
                        break;
                    }

                    if (stopIfAlert) {
                        logger.info("stop, alert occurred: {}", context.getAlert());
                        break;
                    }
                }
            }
        } catch (Exception e) {
            status = Status.unexpected_error;
            return reportError(e);
        } finally {
            if (createdConnection && !connection.isClosed()) {
                try {
                    connection.close();
                } catch (IOException e) {
                    logger.warn("could not close connection", e);
                }
            }
        }

        if (status == Status.running) {
            status = Status.success;
        }

        return this;
    }

    public Engine requireOne(Check... checks) throws ActionFailed {
        return requireOne(List.of(checks));
    }

    public Engine requireOne(List<Check> checks) throws ActionFailed {
        for (Check check : checks) {
            check.set(this);

            check.run();
            if (!check.failed()) {
                logger.info("check passed: {}", check.name());
                return this;
            }

            logger.info("check failed: {}", check.name());
        }

        throw new ActionFailed("all checks failed");
    }

    public Engine require(List<Check> checks) throws ActionFailed {
        for (Check check : checks) {
            check.set(this);

            check.run();
            if (check.failed()) {
                throw new ActionFailed(String.format("check failed: %s", check.name()));
            }
            logger.info("check passed: {}", check.name());
        }

        return this;
    }

    public Engine require(Check... checks) throws ActionFailed {
        return require(List.of(checks));
    }

    public Engine apply(Analyzer analyzer) {
        if (analyzer != null) {
            analyzer.add(this);
        }
        return this;
    }

    public Status status() {
        return status;
    }

    private Engine reportError(Throwable e) throws EngineException {
        exception = e;
        if (strict) {
            throw new EngineException("unexpected exception", e);
        }

        logger.warn("error: {}", e.toString());
        return this;
    }

    private void storeImpl() {
        byte[] data = new byte[buffer.remaining()];
        buffer.get(data);
        storedData.add(data);
        buffer = nothing;
        logger.info("stored {} bytes", data.length);
    }

    private void restoreImpl() {
        buffer.flip();
        byte[] data = new byte[buffer.remaining()];
        buffer.get(data);

        int n = data.length;
        for (byte[] bytes : storedData) {
            n += bytes.length;
        }

        buffer = ByteBuffer.allocate(n);

        for (byte[] bytes : storedData) {
            buffer.put(bytes);
        }

        buffer.put(data);
        buffer.flip();

        logger.info("restored {} bytes", n);
    }

    private void combineData(Action action) {
        ByteBuffer out = action.out();
        if (out != null && out.remaining() > 0) {
            ByteBuffer combined = ByteBuffer.allocate(buffer.remaining() + out.remaining());
            combined.put(out);
            combined.put(buffer);
            buffer = combined;
            buffer.flip();
        }

        ByteBuffer data = action.applicationData();
        if (data != null && data.remaining() > 0) {
            applicationData = data;
        }
    }

    private void read(Connection connection, Action action) throws IOException {
        if (connection.isClosed()) {
            throw new IOException("connection was closed");
        }

        while (buffer.remaining() == 0) {
            buffer = ByteBuffer.wrap(connection.read());
            if (buffer.remaining() == 0) {
                throw new IOException("no data received");
            }
        }

        action.in(buffer);
    }

    public static Engine init() throws NoSuchAlgorithmException, NegotiatorException {
        Engine engine = new Engine();
        engine.context.set(ECDHENegotiator.create(
                NamedGroup.secp256r1, engine.context.factory()));
        engine.context.set(HKDF.create(
                engine.context.suite().hash(), engine.context.factory()));

        return engine;
    }

    private Action init(Action action) {
        action.set(context);
        action.in(buffer);
        action.applicationData(applicationData);

        return action;
    }

    private void initConnection() throws EngineException {
        if (connection != null) {
            return;
        }

        if (host != null && port > 0) {
            try {
                connection = Connection.create(host, port, timeout);
                createdConnection = true;
                return;
            } catch (IOException e) {
                throw new EngineException("could not init connection", e);
            }
        }

        throw whatTheHell("connection can't be initialized!");
    }

    public interface ActionFactory {
        Action create();
    }

    public static class ActionHolder {

        private Engine engine;
        private ActionType type;
        private ActionFactory factory;
        private Condition condition;

        public Engine receive(ActionFactory factory) {
            set(factory);
            engine.actions.add(this);
            return engine;
        }

        private ActionHolder set(Engine engine) {
            this.engine = engine;
            return this;
        }

        private ActionHolder set(ActionFactory factory) {
            this.factory = factory;
            return this;
        }

        private ActionHolder type(ActionType type) {
            this.type = type;
            return this;
        }

        private ActionHolder set(Condition condition) {
            this.condition = condition;
            return this;
        }
    }

}
