package com.gypsyengineer.tlsbunny.tls13.connection.action.simple;

import com.gypsyengineer.tlsbunny.tls13.connection.action.AbstractAction;
import com.gypsyengineer.tlsbunny.tls13.connection.action.Action;
import com.gypsyengineer.tlsbunny.tls13.struct.CertificateRequest;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class ProcessingCertificateRequest
        extends AbstractAction<ProcessingCertificateRequest> {

    private static final Logger logger = LogManager.getLogger(ProcessingCertificateRequest.class);

    @Override
    public String name() {
        return "processing CertificateRequest";
    }

    @Override
    public Action run() {
        CertificateRequest request = context.factory().parser().parseCertificateRequest(in);
        context.certificateRequestContext(request.certificateRequestContext());
        logger.info("received a CertificateRequest message");

        return this;
    }

}
