package com.gypsyengineer.tlsbunny.tls13.connection.action.simple;

import com.gypsyengineer.tlsbunny.tls13.connection.action.Phase;

public class ProcessingHandshakeTLSCiphertext extends ProcessingTLSCiphertext {

    public ProcessingHandshakeTLSCiphertext() {
        super(Phase.handshake);
    }
    
}
