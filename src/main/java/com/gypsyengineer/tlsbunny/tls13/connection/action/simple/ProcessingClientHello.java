package com.gypsyengineer.tlsbunny.tls13.connection.action.simple;

import com.gypsyengineer.tlsbunny.tls13.connection.action.AbstractAction;
import com.gypsyengineer.tlsbunny.tls13.struct.ClientHello;

public class ProcessingClientHello extends AbstractAction<ProcessingClientHello> {

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
        output.info("received a ClientHello message");

        return this;
    }

}
