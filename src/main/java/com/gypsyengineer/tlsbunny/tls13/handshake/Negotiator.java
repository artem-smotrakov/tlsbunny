package com.gypsyengineer.tlsbunny.tls13.handshake;

import com.gypsyengineer.tlsbunny.tls13.struct.KeyShareEntry;
import com.gypsyengineer.tlsbunny.tls13.struct.NamedGroup;
import com.gypsyengineer.tlsbunny.tls13.struct.StructFactory;
import com.gypsyengineer.tlsbunny.output.Output;

public interface Negotiator {

    NamedGroup group();
    Negotiator set(Output output);
    Negotiator set(StructFactory factory);
    KeyShareEntry createKeyShareEntry() throws NegotiatorException;
    void processKeyShareEntry(KeyShareEntry entry) throws NegotiatorException;
    byte[] generateSecret() throws NegotiatorException;

    static Negotiator create(NamedGroup group, StructFactory factory)
            throws NegotiatorException {
        
        if (group instanceof NamedGroup.FFDHE) {
            return FFDHENegotiator.create((NamedGroup.FFDHE) group, factory);
        }

        if (group instanceof NamedGroup.Secp ) {
            return ECDHENegotiator.create((NamedGroup.Secp) group, factory);
        }

        throw new IllegalArgumentException();
    }

}
