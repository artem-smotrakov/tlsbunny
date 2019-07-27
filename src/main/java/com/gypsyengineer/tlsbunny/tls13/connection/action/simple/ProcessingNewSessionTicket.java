package com.gypsyengineer.tlsbunny.tls13.connection.action.simple;

import com.gypsyengineer.tlsbunny.tls13.connection.action.AbstractAction;
import com.gypsyengineer.tlsbunny.tls13.connection.action.Action;
import com.gypsyengineer.tlsbunny.tls13.struct.NewSessionTicket;
import com.gypsyengineer.tlsbunny.utils.HexDump;

import java.io.IOException;

public class ProcessingNewSessionTicket extends AbstractAction<ProcessingNewSessionTicket> {

    @Override
    public String name() {
        return "processing NewSessionTicket";
    }

    @Override
    public Action run() throws IOException {
        NewSessionTicket ticket = context.factory().parser().parseNewSessionTicket(in);
        output.info("NewSessionTicket encoding length: %d", ticket.encodingLength());
        output.info("NewSessionTicket content: %n%s", HexDump.printHex(ticket.encoding()));
        output.info("received a NewSessionTicket message");

        return this;
    }
}
