package com.gypsyengineer.tlsbunny.tls13.fuzzer;

import com.gypsyengineer.tlsbunny.tls13.client.Client;
import com.gypsyengineer.tlsbunny.utils.Sync;

import java.util.Objects;

public abstract class AbstractFuzzyClient implements Client, AutoCloseable {

    private Status status = Status.not_started;
    private boolean stopped = false;
    private Sync sync = Sync.dummy();

    @Override
    synchronized public AbstractFuzzyClient set(Sync sync) {
        Objects.requireNonNull(sync, "sync can't be null!");
        synchronized (this) {
            this.sync = sync;
        }
        return this;
    }

    public Sync sync() {
        synchronized (this) {
            return sync;
        }
    }

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
