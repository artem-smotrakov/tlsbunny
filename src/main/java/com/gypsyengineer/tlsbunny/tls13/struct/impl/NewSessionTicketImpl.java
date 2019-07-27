package com.gypsyengineer.tlsbunny.tls13.struct.impl;

import com.gypsyengineer.tlsbunny.tls.UInt32;
import com.gypsyengineer.tlsbunny.tls.Vector;
import com.gypsyengineer.tlsbunny.tls13.struct.Extension;
import com.gypsyengineer.tlsbunny.tls13.struct.NewSessionTicket;
import com.gypsyengineer.tlsbunny.utils.Utils;

import java.io.IOException;
import java.util.Objects;

public class NewSessionTicketImpl implements NewSessionTicket {

    private final UInt32 ticket_lifetime;
    private final UInt32 ticket_age_add;
    private final Vector<Byte> ticket_nonce;
    private final Vector<Byte> ticket;
    private final Vector<Extension> extensions;

    NewSessionTicketImpl(UInt32 ticket_lifetime,
                                UInt32 ticket_age_add,
                                Vector<Byte> ticket_nonce,
                                Vector<Byte> ticket,
                                Vector<Extension> extensions) {

        this.ticket_lifetime = ticket_lifetime;
        this.ticket_age_add = ticket_age_add;
        this.ticket_nonce = ticket_nonce;
        this.ticket = ticket;
        this.extensions = extensions;
    }

    @Override
    public int encodingLength() {
        return Utils.getEncodingLength(
                ticket_lifetime, ticket_age_add, ticket_nonce, ticket, extensions);
    }

    @Override
    public byte[] encoding() throws IOException {
        return Utils.encoding(
                ticket_lifetime, ticket_age_add, ticket_nonce, ticket, extensions);
    }

    @Override
    public NewSessionTicketImpl copy() {
        return new NewSessionTicketImpl(
                ticket_lifetime.copy(),
                ticket_age_add.copy(),
                (Vector<Byte>) ticket_nonce.copy(),
                (Vector<Byte>) ticket.copy(),
                (Vector<Extension>) extensions.copy());
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) {
            return true;
        }
        if (o == null || getClass() != o.getClass()) {
            return false;
        }
        NewSessionTicketImpl that = (NewSessionTicketImpl) o;
        return Objects.equals(ticket_lifetime, that.ticket_lifetime) &&
                Objects.equals(ticket_age_add, that.ticket_age_add) &&
                Objects.equals(ticket_nonce, that.ticket_nonce) &&
                Objects.equals(ticket, that.ticket) &&
                Objects.equals(extensions, that.extensions);
    }

    @Override
    public int hashCode() {
        return Objects.hash(
                ticket_lifetime, ticket_age_add, ticket_nonce, ticket, extensions);
    }
}
