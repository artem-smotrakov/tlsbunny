package com.gypsyengineer.tlsbunny.tls13.server;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public abstract class AbstractServer implements Server {

    private static final Logger logger = LogManager.getLogger(AbstractServer.class);

    @Override
    public Thread start() {
        Thread thread = new Thread(this, "server");
        thread.start();

        try {
            Thread.sleep(1000); // one second
        } catch (InterruptedException e) {
            logger.warn("something wrong happened", e);
        }

        return thread;
    }

}
