package com.gypsyengineer.tlsbunny.tls13.connection.check;

import com.gypsyengineer.tlsbunny.tls13.connection.Engine;

public class FailureCheck extends AbstractCheck {

    @Override
    public Check run() {
        if(engine.status() == Engine.Status.success) {
            markFailed();
        }
        return this;
    }

    @Override
    public String name() {
        return "if the connection failed";
    }

}
