package com.gypsyengineer.tlsbunny.utils;

import com.gypsyengineer.tlsbunny.output.Output;
import com.gypsyengineer.tlsbunny.tls13.client.Client;
import com.gypsyengineer.tlsbunny.tls13.server.Server;

public interface Sync extends AutoCloseable {

    static Sync dummy() {
        return new DummySync();
    }

    static Sync between(Client client, Server server) {
        Sync sync = new SyncImpl()
                .set(client)
                .set(server);

        client.set(sync);
        server.set(sync);

        return sync;
    }

    Sync set(Client client);
    Sync set(Server server);
    Sync logPrefix(String prefix);
    Sync logs(String path);
    Sync printToFile();
    Sync init();
    Sync start();
    Sync end();
    Output output();
}
