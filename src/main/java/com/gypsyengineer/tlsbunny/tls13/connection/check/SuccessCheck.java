package com.gypsyengineer.tlsbunny.tls13.connection.check;

import com.gypsyengineer.tlsbunny.tls13.connection.Engine;

public class SuccessCheck extends AbstractCheck {

    public static SuccessCheck successCheck() {
        return new SuccessCheck();
    }

    @Override
    public Check run() {
        failed = engine.status() != Engine.Status.success;
        return this;
    }

    @Override
    public String name() {
        return "check if a connection succeeded";
    }

}
