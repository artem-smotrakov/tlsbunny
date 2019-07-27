package com.gypsyengineer.tlsbunny.tls13.client;

import com.gypsyengineer.tlsbunny.tls13.connection.Engine;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public abstract class SingleConnectionClient extends AbstractClient {

    private static final Logger logger = LogManager.getLogger(SingleConnectionClient.class);

    @Override
    public final Client connectImpl() throws Exception {
            logger.info("connect to {}:%d", config.host(), config.port());
            Engine engine = createEngine();
            engines.add(engine);
            engine.connect();
            engine.run(checks);
            return this;
    }

    protected abstract Engine createEngine() throws Exception;
}
