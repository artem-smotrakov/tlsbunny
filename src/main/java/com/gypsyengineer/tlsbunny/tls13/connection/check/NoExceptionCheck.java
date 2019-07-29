package com.gypsyengineer.tlsbunny.tls13.connection.check;

public class NoExceptionCheck extends AbstractCheck {

    @Override
    public Check run() {
        if (engine.exception() != null) {
            markFailed();
        }
        return this;
    }

    @Override
    public String name() {
        return "if no exception received";
    }

}
