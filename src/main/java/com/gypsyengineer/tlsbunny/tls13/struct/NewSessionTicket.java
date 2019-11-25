package com.gypsyengineer.tlsbunny.tls13.struct;

import com.gypsyengineer.tlsbunny.tls.Vector;

public interface NewSessionTicket extends HandshakeMessage {

    int nonce_length_bytes = 1;
    int ticket_length_bytes = 2;
    int extensions_length_bytes = 2;

    Vector<Byte> ticket();
}
