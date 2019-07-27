package com.gypsyengineer.tlsbunny.tls13.handshake;

public class NegotiatorException extends Exception {

    public NegotiatorException(String message) {
        super(message);
    }

    public NegotiatorException(Throwable e) {
        super(e);
    }
}
