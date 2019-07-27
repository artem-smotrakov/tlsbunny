package com.gypsyengineer.tlsbunny.tls13.connection.action.simple;

import com.gypsyengineer.tlsbunny.tls13.connection.action.AbstractAction;
import com.gypsyengineer.tlsbunny.tls13.connection.action.ActionFailed;
import com.gypsyengineer.tlsbunny.tls13.struct.Alert;
import com.gypsyengineer.tlsbunny.tls13.struct.TLSPlaintext;

import java.io.IOException;
import java.nio.ByteBuffer;

public class CheckingForAlert extends AbstractAction<CheckingForAlert> {

    @Override
    public String name() {
        return "checking for an alert";
    }

    @Override
    public CheckingForAlert run() throws ActionFailed, IOException {
        TLSPlaintext tlsPlaintext = context.factory().parser().parseTLSPlaintext(in);

        if (tlsPlaintext.containsAlert()) {
            Alert alert = context.factory().parser().parseAlert(tlsPlaintext.getFragment());
            context.setAlert(alert);
            output.info("received an alert: %s", alert);
        } else {
            out = ByteBuffer.wrap(tlsPlaintext.getFragment());
            output.info("received a TLSPlaintext");
        }

        return this;
    }

}
