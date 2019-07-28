package com.gypsyengineer.tlsbunny.tls13.connection;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.util.ArrayList;
import java.util.List;

public class NoAlertAnalyzer implements Analyzer {

    private static final Logger logger = LogManager.getLogger(NoAlertAnalyzer.class);

    private final List<Engine> engines = new ArrayList<>();

    @Override
    public Analyzer add(Engine... engines) {
        this.engines.addAll(List.of(engines));
        return this;
    }

    @Override
    public Analyzer run() {
        logger.info("let's look for connections with no alerts");

        if (engines.isEmpty()) {
            logger.info("there is nothing to analyze!");
            return this;
        }

        int count = 0;
        for (Engine engine : engines) {
            if (!engine.context().hasAlert()) {
                logger.info("connection '{}' didn't result to an alert:", engine.label());
                count++;
            }
        }

        if (count == 0) {
            logger.info("all connections resulted to an alert");
        } else if (count == 1) {
            logger.info("found 1 connection which didn't result to an alert");
        } else {
            logger.info("found {} connections which didn't result to an alert", count);
        }

        return this;
    }

    @Override
    public Engine[] engines() {
        return engines.toArray(new Engine[engines.size()]);
    }

}
