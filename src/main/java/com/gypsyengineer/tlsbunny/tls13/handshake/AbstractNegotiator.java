package com.gypsyengineer.tlsbunny.tls13.handshake;

import com.gypsyengineer.tlsbunny.tls13.struct.NamedGroup;
import com.gypsyengineer.tlsbunny.tls13.struct.StructFactory;

abstract class AbstractNegotiator implements Negotiator {

    final NamedGroup group;
    StructFactory factory;

    AbstractNegotiator(NamedGroup group, StructFactory factory) {
        this.group = group;
        this.factory = factory;
    }

    @Override
    public NamedGroup group() {
        return group;
    }

    @Override
    public Negotiator set(StructFactory factory) {
        this.factory = factory;
        return this;
    }

}
