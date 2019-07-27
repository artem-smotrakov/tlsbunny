package com.gypsyengineer.tlsbunny.tls13.connection.action.simple;

import com.gypsyengineer.tlsbunny.tls13.connection.action.AbstractAction;

public class ProcessingServerHello extends AbstractAction<ProcessingServerHello> {

    @Override
    public String name() {
        return "processing a ServerHello";
    }

    @Override
    public ProcessingServerHello run() {
        context.factory().parser().parseServerHello(in);
        output.info("received a ServerHello message");

        return this;
    }

}
