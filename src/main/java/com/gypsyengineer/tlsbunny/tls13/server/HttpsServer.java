package com.gypsyengineer.tlsbunny.tls13.server;

import com.gypsyengineer.tlsbunny.tls13.connection.BaseEngineFactory;
import com.gypsyengineer.tlsbunny.tls13.connection.Engine;
import com.gypsyengineer.tlsbunny.tls13.connection.EngineFactory;
import com.gypsyengineer.tlsbunny.tls13.connection.action.Side;
import com.gypsyengineer.tlsbunny.tls13.connection.action.composite.IncomingMessages;
import com.gypsyengineer.tlsbunny.tls13.connection.action.composite.OutgoingMainServerFlight;
import com.gypsyengineer.tlsbunny.tls13.connection.action.simple.*;
import com.gypsyengineer.tlsbunny.tls13.connection.check.Check;
import com.gypsyengineer.tlsbunny.tls13.handshake.Negotiator;
import com.gypsyengineer.tlsbunny.tls13.handshake.NegotiatorException;
import com.gypsyengineer.tlsbunny.tls13.struct.NamedGroup;
import com.gypsyengineer.tlsbunny.tls13.struct.StructFactory;
import com.gypsyengineer.tlsbunny.utils.Config;
import com.gypsyengineer.tlsbunny.output.Output;
import com.gypsyengineer.tlsbunny.utils.Sync;

import static com.gypsyengineer.tlsbunny.tls13.struct.NamedGroup.secp256r1;
import static com.gypsyengineer.tlsbunny.utils.WhatTheHell.whatTheHell;

public class HttpsServer implements Server {

    private final EngineFactoryImpl engineFactory;
    private final SingleThreadServer server;

    public static HttpsServer httpsServer() throws NegotiatorException {
        return httpsServer(SingleThreadServer.free_port);
    }

    public static HttpsServer httpsServer(int port) throws NegotiatorException {
        EngineFactoryImpl factory = new EngineFactoryImpl()
                .set(secp256r1)
                .set(StructFactory.getDefault());

        return new HttpsServer(new SingleThreadServer(port), factory);
    }

    private HttpsServer(SingleThreadServer server, EngineFactoryImpl engineFactory) {
        this.engineFactory = engineFactory;
        this.server = server;
        server.set(engineFactory);
    }

    @Override
    public HttpsServer set(Config config) {
        engineFactory.set(config);
        server.set(config);
        return this;
    }

    @Override
    public HttpsServer set(EngineFactory engineFactory) {
        throw whatTheHell("you can't set an engine engineFactory for me!");
    }

    @Override
    public HttpsServer set(Check check) {
        server.set(check);
        return this;
    }

    @Override
    public Server set(Sync sync) {
        // do nothing
        return this;
    }

    @Override
    public HttpsServer stopWhen(StopCondition condition) {
        server.stopWhen(condition);
        return this;
    }

    public HttpsServer neverStop() {
        server.stopWhen(new NonStop());
        return this;
    }

    @Override
    public HttpsServer stop() {
        server.stop();
        return this;
    }

    @Override
    public boolean running() {
        return server.running();
    }

    @Override
    public int port() {
        return server.port();
    }

    @Override
    public Engine[] engines() {
        return server.engines();
    }

    @Override
    public boolean failed() {
        return server.failed();
    }

    @Override
    public EngineFactory engineFactory() {
        return engineFactory;
    }

    @Override
    public Status status() {
        return server.status();
    }

    @Override
    public HttpsServer set(Output output) {
        engineFactory.set(output);
        server.set(output);
        return this;
    }

    @Override
    public Output output() {
        return server.output();
    }

    @Override
    public void close() {
        server.close();
    }

    @Override
    public void run() {
        server.run();
    }

    public HttpsServer maxConnections(int n) {
        server.maxConnections(n);
        return this;
    }

    public HttpsServer set(NamedGroup group) throws NegotiatorException {
        engineFactory.set(group);
        return this;
    }

    public HttpsServer set(StructFactory structFactory) {
        engineFactory.set(structFactory);
        return this;
    }

    private static class EngineFactoryImpl extends BaseEngineFactory {

        private Negotiator negotiator;

        public EngineFactoryImpl set(NamedGroup group) throws NegotiatorException {
            negotiator = Negotiator.create(group, structFactory());
            return this;
        }

        @Override
        public EngineFactoryImpl set(StructFactory structFactory) {
            super.set(structFactory);
            negotiator.set(structFactory);
            return this;
        }

        @Override
        protected Engine createImpl() throws Exception {
            return Engine.init()
                    .set(structFactory)
                    .set(output)
                    .set(negotiator)

                    .receive(new IncomingData())

                    // process ClientHello
                    .loop(context -> !context.hasFirstClientHello() && !context.hasAlert())
                        .receive(() -> new IncomingMessages(Side.server))

                    // send messages
                    .send(new OutgoingMainServerFlight()
                            .apply(config))

                    // receive Finished and application data
                    .loop(context -> !context.receivedApplicationData() && !context.hasAlert())
                        .receive(() -> new IncomingMessages(Side.server))

                    // send application data
                    .run(new PreparingHttpResponse())
                    .run(new WrappingApplicationDataIntoTLSCiphertext())
                    .send(new OutgoingData());
        }
    }
}
