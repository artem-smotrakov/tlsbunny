package com.gypsyengineer.tlsbunny.tls13.connection.check;

import com.gypsyengineer.tlsbunny.tls13.connection.Engine;

import java.util.Objects;

public abstract class AbstractCheck implements Check {

    protected Engine engine;
    private boolean failed = false;

    @Override
    public Check set(Engine engine) {
        this.engine = engine;
        return this;
    }

    @Override
    public boolean failed() {
        return failed;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) {
            return true;
        }
        if (o == null || getClass() != o.getClass()) {
            return false;
        }
        AbstractCheck that = (AbstractCheck) o;
        return failed == that.failed &&
                Objects.equals(engine, that.engine);
    }

    @Override
    public int hashCode() {
        return Objects.hash(engine, failed);
    }

    void markFailed() {
        failed = true;
    }
}
