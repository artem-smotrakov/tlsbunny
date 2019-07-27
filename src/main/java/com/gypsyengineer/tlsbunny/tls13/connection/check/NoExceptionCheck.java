package com.gypsyengineer.tlsbunny.tls13.connection.check;

public class NoExceptionCheck extends AbstractCheck {

    @Override
    public Check run() {
        failed = engine.exception() != null;
        return this;
    }

    @Override
    public String name() {
        return "no exception received";
    }

}
