package com.gypsyengineer.tlsbunny.tls13.connection.check;

import com.gypsyengineer.tlsbunny.tls13.connection.Engine;
import com.gypsyengineer.tlsbunny.tls13.handshake.Context;

import java.util.Objects;

public abstract class AbstractCheck implements Check {

    protected Engine engine;
    protected Context context;

    protected boolean failed = true;

    @Override
    public Check set(Engine engine) {
        this.engine = engine;
        return this;
    }

    @Override
    public Check set(Context context) {
        this.context = context;
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
                Objects.equals(engine, that.engine) &&
                Objects.equals(context, that.context);
    }

    @Override
    public int hashCode() {
        return Objects.hash(engine, context, failed);
    }
}
