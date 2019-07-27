package com.gypsyengineer.tlsbunny.tls13.connection.action.simple;

import com.gypsyengineer.tlsbunny.tls13.connection.action.AbstractAction;
import com.gypsyengineer.tlsbunny.tls13.struct.ClientHello;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class ProcessingClientHello extends AbstractAction<ProcessingClientHello> {

    private static final Logger logger = LogManager.getLogger(ProcessingClientHello.class);

    private ClientHello hello;

    public ClientHello get() {
        return hello;
    }

    @Override
    public String name() {
        return "processing a ClientHello";
    }

    @Override
    public ProcessingClientHello run() {
        hello = context.factory().parser().parseClientHello(in);
        logger.info("received a ClientHello message");

        return this;
    }

}
