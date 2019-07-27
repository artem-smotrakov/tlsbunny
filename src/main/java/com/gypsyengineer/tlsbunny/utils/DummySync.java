package com.gypsyengineer.tlsbunny.utils;

import com.gypsyengineer.tlsbunny.output.Output;
import com.gypsyengineer.tlsbunny.tls13.client.Client;
import com.gypsyengineer.tlsbunny.tls13.server.Server;

public class DummySync implements Sync {

    private final Output output = Output.local("dummy_sync");

    @Override
    public Sync set(Client client) {
        return this;
    }

    @Override
    public Sync set(Server server) {
        return this;
    }

    @Override
    public Sync logPrefix(String prefix) {
        return this;
    }

    @Override
    public Sync logs(String path) {
        return this;
    }

    @Override
    public Sync printToFile() {
        return this;
    }

    @Override
    public Sync init() {
        return this;
    }

    @Override
    public Sync start() {
        return this;
    }

    @Override
    public Sync end() {
        return this;
    }

    @Override
    public Output output() {
        return output;
    }

    @Override
    public void close() {
        // do nothing
    }
}
