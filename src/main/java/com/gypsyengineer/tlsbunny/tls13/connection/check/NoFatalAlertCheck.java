package com.gypsyengineer.tlsbunny.tls13.connection.check;

import com.gypsyengineer.tlsbunny.tls13.handshake.Context;
import com.gypsyengineer.tlsbunny.tls13.struct.AlertDescription;
import com.gypsyengineer.tlsbunny.tls13.struct.AlertLevel;

/**
 * The check fails if an alert with a error received.
 */
public class NoFatalAlertCheck extends AbstractCheck {

    @Override
    public Check run() {
        Context context = engine.context();
        if (context.hasAlert() && context.getAlert().getLevel().equals(AlertLevel.fatal)) {
            markFailed();
        }
        return this;
    }

    @Override
    public String name() {
        return "check if no fatal alert received";
    }

}
