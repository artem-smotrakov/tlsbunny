package com.gypsyengineer.tlsbunny.tls13.connection.action.simple;

import com.gypsyengineer.tlsbunny.tls13.connection.action.AbstractAction;
import com.gypsyengineer.tlsbunny.tls13.connection.action.Action;
import com.gypsyengineer.tlsbunny.tls13.crypto.AEADException;
import com.gypsyengineer.tlsbunny.tls13.struct.*;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.file.Files;
import java.nio.file.Paths;

public class GeneratingCertificate extends AbstractAction {

    private byte[] certificate_request_context = new byte[0];
    private byte[] cert_data;

    public Action certificate(String path) throws IOException {
        if (path == null || path.trim().isEmpty()) {
            throw  new IllegalArgumentException("no certificate specified");
        }

        cert_data = Files.readAllBytes(Paths.get(path));

        return this;
    }

    public Action context(byte[] certificate_request_context) {
        this.certificate_request_context = certificate_request_context;
        return this;
    }

    @Override
    public String name() {
        return "generating Certificate";
    }

    @Override
    public Action run() throws IOException, AEADException {
        Certificate certificate = context.factory().createCertificate(
                certificate_request_context,
                context.factory().createX509CertificateEntry(cert_data));

        // TODO: should it save context to context.certificate_request_context?

        out = ByteBuffer.wrap(certificate.encoding());

        return this;
    }

}
