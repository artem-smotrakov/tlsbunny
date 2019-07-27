package com.gypsyengineer.tlsbunny.tls13.connection.action.simple;

import com.gypsyengineer.tlsbunny.tls13.connection.action.AbstractAction;
import com.gypsyengineer.tlsbunny.tls13.connection.action.ActionFailed;
import com.gypsyengineer.tlsbunny.tls13.struct.Alert;
import com.gypsyengineer.tlsbunny.tls13.struct.TLSPlaintext;

import java.io.IOException;

public class ProcessingTLSPlaintextWithAlert extends AbstractAction<ProcessingTLSPlaintextWithAlert> {

    @Override
    public String name() {
        return "processing TLSPlaintext with alert";
    }

    @Override
    public ProcessingTLSPlaintextWithAlert run() throws ActionFailed, IOException {
        TLSPlaintext tlsPlaintext = context.factory().parser().parseTLSPlaintext(in);

        if (!tlsPlaintext.containsAlert()) {
            throw new ActionFailed("expected an alert");
        }

        Alert alert = context.factory().parser().parseAlert(tlsPlaintext.getFragment());
        context.setAlert(alert);

        output.info("received an alert: %s", alert);

        return this;
    }

    
}
