package com.gypsyengineer.tlsbunny.tls13.connection.action.simple;

import com.gypsyengineer.tlsbunny.tls13.connection.action.AbstractAction;
import com.gypsyengineer.tlsbunny.tls13.connection.action.Action;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class ProcessingCertificate extends AbstractAction<ProcessingCertificate> {

    private static final Logger logger = LogManager.getLogger(ProcessingCertificate.class);

    @Override
    public String name() {
        return "processing a Certificate";
    }

    @Override
    public Action run() {
        context.factory().parser().parseCertificate(
                in, buf -> context.factory().parser().parseX509CertificateEntry(buf));
        logger.info("received a Certificate message");

        return this;
    }

}
