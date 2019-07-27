package com.gypsyengineer.tlsbunny.tls13.client;

import com.gypsyengineer.tlsbunny.tls13.connection.Engine;

public abstract class SingleConnectionClient extends AbstractClient {

    @Override
    public final Client connectImpl() throws Exception {
        sync().start();
        try {
            output.info("connect to %s:%d", config.host(), config.port());
            Engine engine = createEngine();
            engines.add(engine);
            engine.connect();
            engine.run(checks);
            return this;
        } finally {
            sync().end();
        }
    }

    protected abstract Engine createEngine() throws Exception;
}
