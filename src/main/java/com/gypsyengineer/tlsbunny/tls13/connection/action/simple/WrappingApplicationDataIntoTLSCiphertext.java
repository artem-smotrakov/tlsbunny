package com.gypsyengineer.tlsbunny.tls13.connection.action.simple;

import com.gypsyengineer.tlsbunny.tls13.connection.action.Phase;
import com.gypsyengineer.tlsbunny.tls13.struct.ContentType;

public class WrappingApplicationDataIntoTLSCiphertext extends WrappingIntoTLSCiphertext {

    public WrappingApplicationDataIntoTLSCiphertext() {
        super(Phase.application_data);
        type(ContentType.application_data);
    }

}
