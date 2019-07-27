package com.gypsyengineer.tlsbunny.tls13.connection.action.simple;

import com.gypsyengineer.tlsbunny.tls13.connection.action.AbstractAction;
import com.gypsyengineer.tlsbunny.tls13.connection.action.Action;
import com.gypsyengineer.tlsbunny.tls13.struct.CertificateRequest;

public class ProcessingCertificateRequest
        extends AbstractAction<ProcessingCertificateRequest> {

    @Override
    public String name() {
        return "processing CertificateRequest";
    }

    @Override
    public Action run() {
        CertificateRequest request = context.factory().parser().parseCertificateRequest(in);
        context.certificateRequestContext(request.certificateRequestContext());
        output.info("received a CertificateRequest message");

        return this;
    }

}
