package com.gypsyengineer.tlsbunny.tls13.client.fuzzer;

import com.gypsyengineer.tlsbunny.tls13.client.Client;
import com.gypsyengineer.tlsbunny.tls13.connection.check.Check;
import com.gypsyengineer.tlsbunny.utils.Config;

public abstract class AbstractFuzzyClient implements Client, AutoCloseable {

    protected static final Check[] no_checks = {};

    private Status status = Status.not_started;
    private boolean stopped = false;
    protected String state = Config.instance.getString("state");

    @Override
    public final void run() {
        synchronized (this) {
            status = Status.running;
            stopped = false;
        }

        try {
            runImpl();
        } finally {
            synchronized (this) {
                status = Status.done;
            }
        }
    }

    @Override
    public Status status() {
        synchronized (this) {
            return status;
        }
    }

    @Override
    public Client stop() {
        synchronized (this) {
            stopped = true;
        }
        return this;
    }

    protected boolean stopped() {
        synchronized (this) {
            return stopped;
        }
    }

    protected abstract void runImpl();
}
