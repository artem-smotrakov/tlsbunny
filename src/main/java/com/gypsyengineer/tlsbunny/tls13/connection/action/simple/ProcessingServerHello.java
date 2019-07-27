package com.gypsyengineer.tlsbunny.tls13.connection.action.simple;

import com.gypsyengineer.tlsbunny.tls13.connection.action.AbstractAction;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class ProcessingServerHello extends AbstractAction<ProcessingServerHello> {

    private static final Logger logger = LogManager.getLogger(ProcessingServerHello.class);

    @Override
    public String name() {
        return "processing a ServerHello";
    }

    @Override
    public ProcessingServerHello run() {
        context.factory().parser().parseServerHello(in);
        logger.info("received a ServerHello message");

        return this;
    }

}
