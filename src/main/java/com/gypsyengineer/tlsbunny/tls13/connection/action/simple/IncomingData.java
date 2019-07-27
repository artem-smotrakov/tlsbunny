package com.gypsyengineer.tlsbunny.tls13.connection.action.simple;

import com.gypsyengineer.tlsbunny.tls13.connection.action.AbstractAction;
import com.gypsyengineer.tlsbunny.tls13.connection.action.Action;

import java.nio.ByteBuffer;

public class IncomingData extends AbstractAction {

    @Override
    public String name() {
        return String.format("incoming data");
    }

    @Override
    public Action run() {
        out = ByteBuffer.allocate(in.remaining());
        out.put(in);
        out.position(0);
        output.info("received %d bytes", out.remaining());

        return this;
    }

}
