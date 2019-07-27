package com.gypsyengineer.tlsbunny.tls13.struct.impl;

import com.gypsyengineer.tlsbunny.tls.UInt32;
import com.gypsyengineer.tlsbunny.tls.Vector;
import com.gypsyengineer.tlsbunny.tls13.struct.NewSessionTicket;
import com.gypsyengineer.tlsbunny.tls13.struct.StructFactory;
import org.junit.Test;

import java.io.IOException;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;

public class NewSessionTicketImplTest {

    @Test
    public void encoding() throws IOException {
        NewSessionTicketImpl ticket = new NewSessionTicketImpl(
                UInt32.create(1),
                UInt32.create(2),
                Vector.wrap(NewSessionTicket.nonce_length_bytes, new byte[4]),
                Vector.wrap(NewSessionTicket.ticket_length_bytes, new byte[8]),
                Vector.wrap(NewSessionTicket.extensions_length_bytes));

        assertEquals(UInt32.encoding_length
                        + UInt32.encoding_length
                        + NewSessionTicket.nonce_length_bytes + 4
                        + NewSessionTicket.ticket_length_bytes + 8
                        + NewSessionTicket.extensions_length_bytes,
                ticket.encodingLength());

        assertEquals(ticket.encodingLength(), ticket.encoding().length);
    }

    @Test
    public void copy() throws IOException {
        NewSessionTicketImpl ticket = new NewSessionTicketImpl(
                UInt32.create(1),
                UInt32.create(2),
                Vector.wrap(NewSessionTicket.nonce_length_bytes, new byte[4]),
                Vector.wrap(NewSessionTicket.ticket_length_bytes, new byte[8]),
                Vector.wrap(NewSessionTicket.extensions_length_bytes));

        NewSessionTicketImpl clone = ticket.copy();

        assertEquals(clone, ticket);
        assertEquals(clone.hashCode(), ticket.hashCode());
        assertArrayEquals(clone.encoding(), ticket.encoding());
    }

    @Test
    public void parse() throws IOException {
        StructFactory factory = StructFactory.getDefault();

        NewSessionTicketImpl ticket = new NewSessionTicketImpl(
                UInt32.create(1),
                UInt32.create(2),
                Vector.wrap(NewSessionTicket.nonce_length_bytes, new byte[4]),
                Vector.wrap(NewSessionTicket.ticket_length_bytes, new byte[8]),
                Vector.wrap(NewSessionTicket.extensions_length_bytes));

        NewSessionTicket clone = factory.parser().parseNewSessionTicket(ticket.encoding());

        assertEquals(ticket, clone);
    }
}
