package com.gypsyengineer.tlsbunny.tls13.connection.action.simple;

import com.gypsyengineer.tlsbunny.tls13.connection.action.AbstractAction;
import com.gypsyengineer.tlsbunny.tls13.connection.action.Action;

public class ProcessingCertificate extends AbstractAction<ProcessingCertificate> {

    @Override
    public String name() {
        return "processing a Certificate";
    }

    @Override
    public Action run() {
        context.factory().parser().parseCertificate(
                in, buf -> context.factory().parser().parseX509CertificateEntry(buf));
        output.info("received a Certificate message");

        return this;
    }

}
