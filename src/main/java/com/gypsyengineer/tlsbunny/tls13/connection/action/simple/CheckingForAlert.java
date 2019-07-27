package com.gypsyengineer.tlsbunny.tls13.connection.action.simple;

import com.gypsyengineer.tlsbunny.tls13.connection.action.AbstractAction;
import com.gypsyengineer.tlsbunny.tls13.connection.action.ActionFailed;
import com.gypsyengineer.tlsbunny.tls13.struct.Alert;
import com.gypsyengineer.tlsbunny.tls13.struct.TLSPlaintext;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.io.IOException;
import java.nio.ByteBuffer;

public class CheckingForAlert extends AbstractAction<CheckingForAlert> {

    private static final Logger logger = LogManager.getLogger(CheckingForAlert.class);

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
            logger.info("received an alert: {}", alert);
        } else {
            out = ByteBuffer.wrap(tlsPlaintext.getFragment());
            logger.info("received a TLSPlaintext");
        }

        return this;
    }

}
