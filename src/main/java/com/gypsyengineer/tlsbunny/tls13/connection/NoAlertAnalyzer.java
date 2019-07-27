package com.gypsyengineer.tlsbunny.tls13.connection;

import com.gypsyengineer.tlsbunny.output.Output;

import java.util.ArrayList;
import java.util.List;

public class NoAlertAnalyzer implements Analyzer {

    private Output output;
    private final List<Engine> engines = new ArrayList<>();

    @Override
    public Analyzer set(Output output) {
        this.output = output;
        return this;
    }

    @Override
    public Analyzer add(Engine... engines) {
        this.engines.addAll(List.of(engines));
        return this;
    }

    @Override
    public Analyzer run() {
        output.info("let's look for connections with no alerts");

        if (engines.isEmpty()) {
            output.info("there is nothing to analyze!");
            return this;
        }

        int count = 0;
        for (Engine engine : engines) {
            if (!engine.context().hasAlert()) {
                output.info("connection '%s' didn't result to an alert:", engine.label());
                count++;
            }
        }

        if (count == 0) {
            output.info("all connections resulted to an alert");
        } else if (count == 1) {
            output.info("found 1 connection which didn't result to an alert");
        } else {
            output.info("found %d connections which didn't result to an alert", count);
        }

        return this;
    }

    @Override
    public Engine[] engines() {
        return engines.toArray(new Engine[engines.size()]);
    }

}
