package com.gypsyengineer.tlsbunny.tls13.server;

public class OneConnectionReceived extends NConnectionsReceived {

    public static OneConnectionReceived oneConnectionReceived() {
        return new OneConnectionReceived();
    }

    public OneConnectionReceived() {
        super(1);
    }
}
