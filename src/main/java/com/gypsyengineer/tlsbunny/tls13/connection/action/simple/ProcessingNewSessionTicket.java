package com.gypsyengineer.tlsbunny.tls13.connection.action.simple;

import com.gypsyengineer.tlsbunny.tls13.connection.action.AbstractAction;
import com.gypsyengineer.tlsbunny.tls13.connection.action.Action;
import com.gypsyengineer.tlsbunny.tls13.struct.NewSessionTicket;
import com.gypsyengineer.tlsbunny.utils.HexDump;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.io.IOException;

public class ProcessingNewSessionTicket extends AbstractAction<ProcessingNewSessionTicket> {

    private static final Logger logger = LogManager.getLogger(ProcessingNewSessionTicket.class);

    @Override
    public String name() {
        return "processing NewSessionTicket";
    }

    @Override
    public Action run() throws IOException {
        NewSessionTicket ticket = context.factory().parser().parseNewSessionTicket(in);
        context.add(ticket);

        logger.info("received a NewSessionTicket message");
        logger.info("NewSessionTicket encoding length: {}", ticket.encodingLength());
        logger.info("NewSessionTicket content:\n{}", HexDump.printHex(ticket.encoding()));

        return this;
    }

}
