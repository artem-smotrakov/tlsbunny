package com.gypsyengineer.tlsbunny.tls13.connection.action.composite;

import com.gypsyengineer.tlsbunny.tls13.connection.action.AbstractAction;
import com.gypsyengineer.tlsbunny.tls13.connection.action.ActionFailed;
import com.gypsyengineer.tlsbunny.tls13.crypto.AEADException;
import com.gypsyengineer.tlsbunny.tls13.struct.*;

import java.io.IOException;

public class IncomingAlert extends AbstractAction<IncomingAlert> {

    @Override
    public String name() {
        return "Alert";
    }

    @Override
    public IncomingAlert run() throws ActionFailed, AEADException, IOException {
        TLSPlaintext tlsPlaintext = context.factory().parser().parseTLSPlaintext(in);

        Alert alert;
        if (tlsPlaintext.containsAlert()) {
            alert = context.factory().parser().parseAlert(tlsPlaintext.getFragment());
        } else if (tlsPlaintext.containsApplicationData()) {
            TLSInnerPlaintext tlsInnerPlaintext = context.factory().parser().parseTLSInnerPlaintext(
                    context.applicationDataDecryptor().decrypt(tlsPlaintext));

            if (!tlsInnerPlaintext.containsAlert()) {
                throw new ActionFailed("expected an alert");
            }

            alert = context.factory().parser().parseAlert(tlsInnerPlaintext.getContent());
        } else {
            throw new ActionFailed("expected an alert");
        }

        if (alert != null) {
            context.setAlert(alert);
        }

        output.info("received an alert: %s", alert);

        return this;
    }
    
}
