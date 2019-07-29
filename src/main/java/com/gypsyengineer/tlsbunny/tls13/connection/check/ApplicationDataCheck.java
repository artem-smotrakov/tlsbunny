package com.gypsyengineer.tlsbunny.tls13.connection.check;

public class ApplicationDataCheck extends AbstractCheck {

    public static ApplicationDataCheck applicationDataCheck() {
        return new ApplicationDataCheck();
    }

    @Override
    public String name() {
        return "if application data was transferred";
    }

    @Override
    public Check run() {
        engine.context().receivedApplicationData();
        return this;
    }
}
