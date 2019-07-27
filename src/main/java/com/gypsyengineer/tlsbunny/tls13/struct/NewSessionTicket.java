package com.gypsyengineer.tlsbunny.tls13.struct;

import com.gypsyengineer.tlsbunny.tls.Struct;

public interface NewSessionTicket extends Struct {

    int nonce_length_bytes = 1;
    int ticket_length_bytes = 2;
    int extensions_length_bytes = 2;
}
