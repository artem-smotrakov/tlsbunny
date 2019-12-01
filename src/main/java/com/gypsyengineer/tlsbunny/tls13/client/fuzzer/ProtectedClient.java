package com.gypsyengineer.tlsbunny.tls13.client.fuzzer;

import com.gypsyengineer.tlsbunny.tls13.client.Client;
import com.gypsyengineer.tlsbunny.tls13.connection.Analyzer;
import com.gypsyengineer.tlsbunny.tls13.connection.Engine;
import com.gypsyengineer.tlsbunny.tls13.connection.check.Check;
import com.gypsyengineer.tlsbunny.tls13.handshake.Negotiator;
import com.gypsyengineer.tlsbunny.tls13.server.Server;
import com.gypsyengineer.tlsbunny.tls13.struct.StructFactory;

import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

public class ProtectedClient implements Client {

    private enum ProtectedElement {
        struct_factory
    }

    private final Client client;
    private final List<ProtectedElement> protectedElements = new ArrayList<>();

    public static ProtectedClient from(Client client) {
        return new ProtectedClient(client);
    }

    private ProtectedClient(Client client) {
        Objects.requireNonNull(client, "Hey! Client can't be null!");
        this.client = client;
    }

    public ProtectedClient withUnmodifiableStructFactory() {
        protectedElements.add(ProtectedElement.struct_factory);
        return this;
    }

    private boolean allowed(ProtectedElement element) {
        return !protectedElements.contains(element);
    }

    @Override
    public Client to(String host) {
        client.to(host);
        return this;
    }

    @Override
    public Client to(int port) {
        client.to(port);
        return this;
    }

    @Override
    public Client to(Server server) {
        client.to(server);
        return this;
    }

    @Override
    public Client set(StructFactory factory) {
        if (allowed(ProtectedElement.struct_factory)) {
            client.set(factory);
        }
        return this;
    }

    @Override
    public Client set(Negotiator negotiator) {
        client.set(negotiator);
        return this;
    }

    @Override
    public Client set(Check... checks) {
        client.set(checks);
        return this;
    }

    @Override
    public Client set(Analyzer analyzer) {
        client.set(analyzer);
        return this;
    }

    @Override
    public Client connect() throws Exception {
        client.connect();
        return this;
    }

    @Override
    public Status status() {
        return client.status();
    }

    @Override
    public Engine[] engines() {
        return client.engines();
    }

    @Override
    public Client stop() {
        client.stop();
        return this;
    }

    @Override
    public void close() throws Exception {
        client.close();
    }

    @Override
    public void run() {
        client.run();
    }

    @Override
    public Thread start() {
        return client.start();
    }

    @Override
    public Client apply(Analyzer analyzer) {
        client.apply(analyzer);
        return this;
    }

    @Override
    public boolean running() {
        return client.running();
    }

    @Override
    public boolean done() {
        return client.done();
    }
}
