package com.gypsyengineer.tlsbunny.tls13.server;

public class NonStop implements StopCondition {

    @Override
    public boolean shouldRun() {
        return true;
    }
}
