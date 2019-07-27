package com.gypsyengineer.tlsbunny.tls13.fuzzer;

import com.gypsyengineer.tlsbunny.tls13.connection.Engine;
import com.gypsyengineer.tlsbunny.tls13.connection.EngineException;
import com.gypsyengineer.tlsbunny.tls13.connection.EngineFactory;
import com.gypsyengineer.tlsbunny.tls13.connection.check.Check;
import com.gypsyengineer.tlsbunny.tls13.server.Server;
import com.gypsyengineer.tlsbunny.tls13.server.StopCondition;
import com.gypsyengineer.tlsbunny.tls13.struct.StructFactory;
import com.gypsyengineer.tlsbunny.tls13.utils.FuzzerConfig;
import com.gypsyengineer.tlsbunny.utils.Config;
import com.gypsyengineer.tlsbunny.utils.Connection;
import com.gypsyengineer.tlsbunny.output.Output;
import com.gypsyengineer.tlsbunny.utils.Sync;

import java.io.IOException;
import java.net.ServerSocket;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.stream.Collectors;

import static com.gypsyengineer.tlsbunny.utils.WhatTheHell.whatTheHell;

public class MutatedServer implements Server {

    private static final int free_port = 0;

    private final ServerSocket ssocket;
    private final EngineFactory engineFactory;
    private final List<Engine> engines = Collections.synchronizedList(new ArrayList<>());

    // TODO: synchronization
    private Status status = Status.not_started;
    private boolean failed = false;
    private Output output;
    private FuzzerConfig[] fuzzerConfigs;
    private Sync sync = Sync.dummy();

    private long test = 0;

    public static MutatedServer from(Server server) throws IOException {
        return mutatedServer(server);
    }

    public static MutatedServer from(Server server, FuzzerConfig... fuzzerConfigs)
            throws IOException {

        return mutatedServer(server, fuzzerConfigs);
    }

    public static MutatedServer mutatedServer(
            Server server, FuzzerConfig... fuzzerConfigs) throws IOException {

        ServerSocket socket = new ServerSocket(free_port);
        socket.setReuseAddress(true);
        return new MutatedServer(socket, server, fuzzerConfigs);
    }

    private MutatedServer(ServerSocket ssocket,
                          Server server, FuzzerConfig... fuzzerConfigs) {

        this.engineFactory = server.engineFactory();
        this.fuzzerConfigs = check(fuzzerConfigs);
        this.ssocket = ssocket;
    }

    public MutatedServer set(FuzzerConfig... fuzzerConfigs) {
        this.fuzzerConfigs = check(fuzzerConfigs);
        return this;
    }

    private FuzzerConfig[] check(FuzzerConfig... fuzzerConfigs) {
        for (FuzzerConfig fuzzerConfig : fuzzerConfigs) {
            if (fuzzerConfig.noFactory()) {
                throw whatTheHell("no factory specified!");
            }

            StructFactory factory = fuzzerConfig.factory();
            if (factory instanceof FuzzyStructFactory == false) {
                throw whatTheHell("expected %s",
                        FuzzyStructFactory.class.getSimpleName());
            }
        }

        return fuzzerConfigs;
    }

    @Override
    public MutatedServer set(Config config) {
        if (config instanceof FuzzerConfig == false) {
            throw whatTheHell("expected FuzzerConfig!");
        }
        this.fuzzerConfigs = new FuzzerConfig[] { (FuzzerConfig) config };
        return this;
    }

    @Override
    public MutatedServer set(EngineFactory engineFactory) {
        throw whatTheHell("you can't set an engine factory for me!");
    }

    @Override
    public MutatedServer set(Check check) {
        throw whatTheHell("you can't set a check for me!");
    }

    @Override
    public MutatedServer set(Sync sync) {
        this.sync = sync;
        return this;
    }

    @Override
    public MutatedServer stopWhen(StopCondition condition) {
        throw whatTheHell("I know when I should stop!");
    }

    @Override
    public MutatedServer stop() {
        if (!ssocket.isClosed()) {
            try {
                ssocket.close();
            } catch (IOException e) {
                output.achtung("exception occurred while stopping the server", e);
            }
        }

        return this;
    }

    @Override
    public int port() {
        return ssocket.getLocalPort();
    }

    @Override
    public Engine[] engines() {
        return engines.toArray(new Engine[0]);
    }

    @Override
    public boolean failed() {
        return failed;
    }

    @Override
    public MutatedServer set(Output output) {
        this.output = output;
        return this;
    }

    @Override
    public Output output() {
        return output;
    }

    @Override
    public EngineFactory engineFactory() {
        throw whatTheHell("no engine factories for you!");
    }

    @Override
    public Status status() {
        synchronized (this) {
            return status;
        }
    }

    @Override
    public void close() {
        stop();

        if (output != null) {
            output.flush();
        }
    }

    synchronized public Sync sync() {
        return sync;
    }

    @Override
    public void run() {
        for (FuzzerConfig fuzzerConfig : fuzzerConfigs) {
            run(fuzzerConfig);
        }
    }

    private void run(FuzzerConfig fuzzerConfig) {
        FuzzyStructFactory fuzzer = (FuzzyStructFactory) fuzzerConfig.factory();
        fuzzer.set(output);

        engineFactory.set(fuzzer);

        if (fuzzerConfig.hasState()) {
            fuzzer.state(fuzzerConfig.state());
        }

        output.info("run fuzzer config:");
        output.increaseIndent();
        output.info("targets     = %s",
                Arrays.stream(fuzzer.targets())
                        .map(Object::toString)
                        .collect(Collectors.joining(", ")));
        output.info("fuzzer      = %s",
                fuzzer.fuzzer() != null
                        ? fuzzer.fuzzer().toString()
                        : "null");
        output.info("total tests = %d", fuzzerConfig.total());
        output.info("state       = %s",
                fuzzerConfig.hasState() ? fuzzerConfig.state() : "not specified");
        output.decreaseIndent();

        try {
            test = 0;
            output.info("started on port %d", port());
            while (shouldRun(fuzzer, fuzzerConfig)) {
                sync().start();
                synchronized (this) {
                    status = Status.ready;
                }
                try (Connection connection = Connection.create(ssocket.accept())) {
                    synchronized (this) {
                        status = Status.accepted;
                    }
                    run(connection, fuzzer);
                } finally {
                    output.flush();
                    sync().end();
                    fuzzer.moveOn();
                    test++;
                }
            }
        } catch (Exception e) {
            output.achtung("what the hell? unexpected exception", e);
            failed = true;
        } finally {
            status = Status.done;
            output.info("stopped");
            output.flush();
        }
    }

    private void run(Connection connection, FuzzyStructFactory fuzzyStructFactory)
            throws EngineException {

        String message = String.format("test #%d (accepted), %s/%s, targets: [%s]",
                test,
                getClass().getSimpleName(),
                fuzzyStructFactory.fuzzer().getClass().getSimpleName(),
                Arrays.stream(fuzzyStructFactory.targets)
                        .map(Enum::toString)
                        .collect(Collectors.joining(", ")));
        output.info(message);

        Engine engine = engineFactory.create()
                .set(output)
                .set(connection)
                .connect();

        engines.add(engine);
    }

    private boolean shouldRun(
            FuzzyStructFactory mutatedStructFactory, FuzzerConfig fuzzerConfig) {

        return mutatedStructFactory.canFuzz() && test < fuzzerConfig.total();
    }
}
