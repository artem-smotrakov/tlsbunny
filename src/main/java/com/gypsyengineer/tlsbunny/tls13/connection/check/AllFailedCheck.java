package com.gypsyengineer.tlsbunny.tls13.connection.check;

import com.gypsyengineer.tlsbunny.tls13.connection.Engine;
import com.gypsyengineer.tlsbunny.tls13.handshake.Context;

import java.util.ArrayList;
import java.util.List;

public class AllFailedCheck implements Check {

    private List<Check> checks = new ArrayList<>();

    public AllFailedCheck add(Check check) {
        checks.add(check);
        return this;
    }

    @Override
    public String name() {
        return String.format("all %d checks failed", checks.size());
    }

    @Override
    public Check set(Engine engine) {
        for (Check check : checks) {
            check.set(engine);
        }

        return this;
    }

    @Override
    public Check set(Context context) {
        for (Check check : checks) {
            check.set(context);
        }

        return this;
    }

    @Override
    public boolean failed() {
        for (Check check : checks) {
            if (!check.failed()) {
                return false;
            }
        }

        return true;
    }

    @Override
    public Check run() {
        for (Check check : checks) {
            check.run();
        }

        return this;
    }

}
