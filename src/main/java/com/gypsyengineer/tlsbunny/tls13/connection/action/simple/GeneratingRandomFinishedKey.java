package com.gypsyengineer.tlsbunny.tls13.connection.action.simple;

import com.gypsyengineer.tlsbunny.tls13.connection.action.AbstractAction;
import com.gypsyengineer.tlsbunny.tls13.connection.action.Action;

import java.util.Random;

import static com.gypsyengineer.tlsbunny.utils.Utils.SEED;

public class GeneratingRandomFinishedKey extends AbstractAction {

    @Override
    public String name() {
        return "generating random finished key";
    }

    @Override
    public Action run() {
        Random generator = new Random(SEED);
        context.finished_key(new byte[context.suite().hashLength()]);
        generator.nextBytes(context.finished_key());

        return this;
    }
}
