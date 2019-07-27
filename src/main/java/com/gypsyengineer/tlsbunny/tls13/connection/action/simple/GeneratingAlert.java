package com.gypsyengineer.tlsbunny.tls13.connection.action.simple;

import com.gypsyengineer.tlsbunny.tls13.connection.action.AbstractAction;
import com.gypsyengineer.tlsbunny.tls13.struct.*;

import java.io.IOException;
import java.nio.ByteBuffer;

public class GeneratingAlert extends AbstractAction<GeneratingAlert> {

    private AlertLevel level = AlertLevel.fatal;
    private AlertDescription description = AlertDescription.close_notify;

    public GeneratingAlert level(AlertLevel level) {
        this.level = level;
        return this;
    }

    public GeneratingAlert description(AlertDescription description) {
        this.description = description;
        return this;
    }

    @Override
    public String name() {
        return String.format("generating Alert (%s, %s)", level, description);
    }

    @Override
    public GeneratingAlert run() throws IOException {
        Alert alert = context.factory().createAlert(level, description);
        out = ByteBuffer.wrap(alert.encoding());
        return this;
    }

}
