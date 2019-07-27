package com.gypsyengineer.tlsbunny.tls13.connection.action.simple;

import com.gypsyengineer.tlsbunny.tls13.connection.action.AbstractAction;
import com.gypsyengineer.tlsbunny.tls13.connection.action.Action;
import com.gypsyengineer.tlsbunny.tls13.struct.Alert;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class ProcessingAlert extends AbstractAction<ProcessingAlert> {

    private static final Logger logger = LogManager.getLogger(ProcessingAlert.class);

    @Override
    public String name() {
        return "processing an alert";
    }

    @Override
    public Action run() {
        Alert alert = context.factory().parser().parseAlert(in);
        context.setAlert(alert);

        logger.info("received an alert: {}", alert);

        return this;
    }

    
}
