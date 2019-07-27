package com.gypsyengineer.tlsbunny.tls13.connection.action.simple;

import com.gypsyengineer.tlsbunny.tls13.connection.action.AbstractAction;
import com.gypsyengineer.tlsbunny.tls13.connection.action.Action;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class ProcessingCertificateVerify
        extends AbstractAction<ProcessingCertificateVerify> {

    private static final Logger logger = LogManager.getLogger(ProcessingCertificateVerify.class);

    @Override
    public String name() {
        return "processing a CertificateVerify";
    }

    @Override
    public Action run() {
        context.factory().parser().parseCertificateVerify(in);
        logger.info("received a CertificateVerify message");

        return this;
    }

}
