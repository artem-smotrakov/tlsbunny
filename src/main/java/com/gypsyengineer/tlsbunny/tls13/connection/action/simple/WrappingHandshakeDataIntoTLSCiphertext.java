package com.gypsyengineer.tlsbunny.tls13.connection.action.simple;

import com.gypsyengineer.tlsbunny.tls13.connection.action.Phase;
import com.gypsyengineer.tlsbunny.tls13.struct.ContentType;

public class WrappingHandshakeDataIntoTLSCiphertext extends WrappingIntoTLSCiphertext {

    public WrappingHandshakeDataIntoTLSCiphertext() {
        super(Phase.handshake);
        type(ContentType.handshake);
    }

}
