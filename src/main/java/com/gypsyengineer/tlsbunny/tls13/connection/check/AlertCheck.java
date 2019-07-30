package com.gypsyengineer.tlsbunny.tls13.connection.check;

public class AlertCheck extends AbstractCheck {

    @Override
    public Check run() {
        if (!engine.context().hasAlert()) {
            markFailed();
        }
        return this;
    }

    @Override
    public String name() {
        return "alert received";
    }

}
