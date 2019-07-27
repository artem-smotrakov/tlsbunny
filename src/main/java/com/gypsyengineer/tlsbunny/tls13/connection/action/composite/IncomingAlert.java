package com.gypsyengineer.tlsbunny.tls13.connection.action.composite;

import com.gypsyengineer.tlsbunny.tls13.connection.action.AbstractAction;
import com.gypsyengineer.tlsbunny.tls13.connection.action.ActionFailed;
import com.gypsyengineer.tlsbunny.tls13.crypto.AEADException;
import com.gypsyengineer.tlsbunny.tls13.struct.Alert;
import com.gypsyengineer.tlsbunny.tls13.struct.TLSInnerPlaintext;
import com.gypsyengineer.tlsbunny.tls13.struct.TLSPlaintext;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.io.IOException;

public class IncomingAlert extends AbstractAction<IncomingAlert> {

    private static final Logger logger = LogManager.getLogger(IncomingAlert.class);

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

        logger.info("received an alert: {}", alert);

        return this;
    }
    
}
