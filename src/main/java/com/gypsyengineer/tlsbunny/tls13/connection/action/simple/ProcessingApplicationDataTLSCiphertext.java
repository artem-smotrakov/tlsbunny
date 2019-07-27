package com.gypsyengineer.tlsbunny.tls13.connection.action.simple;

import com.gypsyengineer.tlsbunny.tls13.connection.action.Phase;

public class ProcessingApplicationDataTLSCiphertext extends ProcessingTLSCiphertext {

    public ProcessingApplicationDataTLSCiphertext() {
        super(Phase.application_data);
    }
    
}
