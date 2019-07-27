package com.gypsyengineer.tlsbunny.tls13.connection.action.simple;

import com.gypsyengineer.tlsbunny.tls13.connection.action.AbstractAction;
import com.gypsyengineer.tlsbunny.tls13.connection.action.Action;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class ProcessingEncryptedExtensions extends AbstractAction<ProcessingEncryptedExtensions> {

    private static final Logger logger = LogManager.getLogger(ProcessingEncryptedExtensions.class);

    @Override
    public String name() {
        return "processing an EncryptedExtensions";
    }

    @Override
    public Action run() {
        context.factory().parser().parseEncryptedExtensions(in);
        logger.info("received an EncryptedExtensions message");

        return this;
    }

}
