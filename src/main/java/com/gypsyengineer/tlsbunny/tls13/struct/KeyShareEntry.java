package com.gypsyengineer.tlsbunny.tls13.struct;

import com.gypsyengineer.tlsbunny.tls.Struct;
import com.gypsyengineer.tlsbunny.tls.Vector;

public interface KeyShareEntry extends Struct {

    int key_exchange_length_bytes = 2;

    NamedGroup namedGroup();
    Vector<Byte> keyExchange();

    KeyShareEntry namedGroup(NamedGroup group);
    KeyShareEntry keyExchange(Vector<Byte> bytes);
}
