package com.gypsyengineer.tlsbunny.tls13.struct.impl;

import com.gypsyengineer.tlsbunny.tls.Struct;
import com.gypsyengineer.tlsbunny.tls.UInt32;
import com.gypsyengineer.tlsbunny.tls.Vector;
import com.gypsyengineer.tlsbunny.tls13.struct.PskIdentity;
import com.gypsyengineer.tlsbunny.utils.Utils;

import java.io.IOException;
import java.util.Objects;

import static com.gypsyengineer.tlsbunny.utils.Utils.cast;
import static com.gypsyengineer.tlsbunny.utils.WhatTheHell.whatTheHell;

public class PskIdentityImpl implements PskIdentity {

    private Vector<Byte> identity;
    private UInt32 obfuscated_ticket_age;

    PskIdentityImpl(Vector<Byte> identity, UInt32 obfuscated_ticket_age) {
        this.identity = identity;
        this.obfuscated_ticket_age = obfuscated_ticket_age;
    }

    @Override
    public Vector<Byte> identity() {
        return identity;
    }

    @Override
    public UInt32 obfuscatedTicketAge() {
        return obfuscated_ticket_age;
    }

    @Override
    public int encodingLength() {
        return Utils.getEncodingLength(identity, obfuscated_ticket_age);
    }

    @Override
    public byte[] encoding() throws IOException {
        return Utils.encoding(identity, obfuscated_ticket_age);
    }

    @Override
    public Struct copy() {
        return new PskIdentityImpl(identity, obfuscated_ticket_age);
    }

    @Override
    public boolean composite() {
        return true;
    }

    @Override
    public int total() {
        return 2;
    }

    @Override
    public Struct element(int index) {
        switch (index) {
            case 0:
                return identity;
            case 1:
                return obfuscated_ticket_age;
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
                identity = cast(element, Vector.class);
                break;
            case 1:
                obfuscated_ticket_age = cast(element, UInt32.class);
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
        PskIdentityImpl that = (PskIdentityImpl) o;
        return Objects.equals(identity, that.identity) &&
                Objects.equals(obfuscated_ticket_age, that.obfuscated_ticket_age);
    }

    @Override
    public int hashCode() {
        return Objects.hash(identity, obfuscated_ticket_age);
    }
}
