package com.gypsyengineer.tlsbunny.tls13.connection.action.simple;

import com.gypsyengineer.tlsbunny.tls13.connection.action.AbstractAction;
import com.gypsyengineer.tlsbunny.tls13.connection.action.Action;
import com.gypsyengineer.tlsbunny.tls13.struct.Alert;

public class ProcessingAlert extends AbstractAction<ProcessingAlert> {

    @Override
    public String name() {
        return "processing an alert";
    }

    @Override
    public Action run() {
        Alert alert = context.factory().parser().parseAlert(in);
        context.setAlert(alert);

        output.info("received an alert: %s", alert);

        return this;
    }

    
}
