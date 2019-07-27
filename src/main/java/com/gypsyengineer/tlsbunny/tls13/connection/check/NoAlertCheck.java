package com.gypsyengineer.tlsbunny.tls13.connection.check;

import com.gypsyengineer.tlsbunny.tls13.struct.AlertDescription;

// the check fails if an alert with a error received
public class NoAlertCheck extends AbstractCheck {

    @Override
    public Check run() {
        failed = context.hasAlert()
                && !context.getAlert().getDescription().equals(
                        AlertDescription.close_notify);
        return this;
    }

    @Override
    public String name() {
        return "no fatal alert received";
    }

}
