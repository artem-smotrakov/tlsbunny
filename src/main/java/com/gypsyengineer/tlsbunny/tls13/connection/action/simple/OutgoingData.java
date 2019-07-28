package com.gypsyengineer.tlsbunny.tls13.connection.action.simple;

import com.gypsyengineer.tlsbunny.tls13.connection.action.AbstractAction;
import com.gypsyengineer.tlsbunny.tls13.connection.action.Action;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.nio.ByteBuffer;

public class OutgoingData extends AbstractAction {

    private static final Logger logger = LogManager.getLogger(OutgoingData.class);

    @Override
    public String name() {
        return "outgoing data";
    }

    @Override
    public Action run() {
        out = ByteBuffer.allocate(in.remaining());
        out.put(in);
        out.position(0);
        logger.info("sent {} bytes", out.remaining());

        return this;
    }

}
