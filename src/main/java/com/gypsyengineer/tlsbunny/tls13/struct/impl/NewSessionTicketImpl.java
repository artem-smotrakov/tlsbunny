package com.gypsyengineer.tlsbunny.tls13.struct.impl;

import com.gypsyengineer.tlsbunny.tls.Struct;
import com.gypsyengineer.tlsbunny.tls.UInt32;
import com.gypsyengineer.tlsbunny.tls.Vector;
import com.gypsyengineer.tlsbunny.tls13.struct.Extension;
import com.gypsyengineer.tlsbunny.tls13.struct.HandshakeType;
import com.gypsyengineer.tlsbunny.tls13.struct.NewSessionTicket;
import com.gypsyengineer.tlsbunny.utils.Utils;

import java.io.IOException;
import java.util.Objects;

import static com.gypsyengineer.tlsbunny.utils.Utils.cast;
import static com.gypsyengineer.tlsbunny.utils.WhatTheHell.whatTheHell;

public class NewSessionTicketImpl implements NewSessionTicket {

    private UInt32 ticket_lifetime;
    private UInt32 ticket_age_add;
    private Vector<Byte> ticket_nonce;
    private Vector<Byte> ticket;
    private Vector<Extension> extensions;

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
    public Vector<Byte> ticket() {
        return ticket;
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
    public HandshakeType type() {
        return HandshakeType.new_session_ticket;
    }

    @Override
    public boolean composite() {
        return true;
    }

    @Override
    public int total() {
        return 5;
    }

    @Override
    public Struct element(int index) {
        switch (index) {
            case 0:
                return ticket_lifetime;
            case 1:
                return ticket_age_add;
            case 2:
                return ticket_nonce;
            case 3:
                return ticket;
            case 4:
                return extensions;
            default:
                throw whatTheHell("incorrect index %d!", index);
        }
    }

    @Override
    public void element(int index, Struct element) {
        if (element == null) {
            throw whatTheHell("element can't be null!");
        }
        switch (index) {
            case 0:
                ticket_lifetime = cast(element, UInt32.class);
                break;
            case 1:
                ticket_age_add = cast(element, UInt32.class);
                break;
            case 2:
                ticket_nonce = cast(element, Vector.class);
                break;
            case 3:
                ticket = cast(element, Vector.class);
                break;
            case 4:
                extensions = cast(element, Vector.class);
                break;
            default:
                throw whatTheHell("incorrect index %d!", index);
        }
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
