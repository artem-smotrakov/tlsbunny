package com.gypsyengineer.tlsbunny.tls13.connection;

public class EngineException extends Exception {

    public EngineException(String message) {
        super(message);
    }

    public EngineException(Throwable e) {
        super(e);
    }

    public EngineException(String message, Throwable e) {
        super(message, e);
    }
}
