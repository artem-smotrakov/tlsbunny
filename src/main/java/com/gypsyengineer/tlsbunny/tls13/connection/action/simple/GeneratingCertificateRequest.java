package com.gypsyengineer.tlsbunny.tls13.connection.action.simple;

import com.gypsyengineer.tlsbunny.tls13.connection.action.AbstractAction;
import com.gypsyengineer.tlsbunny.tls13.connection.action.Action;
import com.gypsyengineer.tlsbunny.tls13.crypto.AEADException;
import com.gypsyengineer.tlsbunny.tls13.struct.CertificateRequest;
import com.gypsyengineer.tlsbunny.tls13.struct.Extension;
import com.gypsyengineer.tlsbunny.tls13.struct.SignatureScheme;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.List;

public class GeneratingCertificateRequest
        extends AbstractAction<GeneratingCertificateRequest> {

    private byte[] certificate_request_context = new byte[0];
    private SignatureScheme[] schemes = new SignatureScheme[0];

    public GeneratingCertificateRequest context(byte[] certificate_request_context) {
        this.certificate_request_context = certificate_request_context;
        return this;
    }

    public GeneratingCertificateRequest signatures(SignatureScheme... schemes) {
        this.schemes = schemes;
        return this;
    }

    @Override
    public String name() {
        return "generating CertificateRequest";
    }

    @Override
    public Action run() throws IOException, AEADException {
        List<Extension> extensions = new ArrayList<>();

        for (SignatureScheme scheme : schemes) {
            extensions.add(wrap(context.factory().createSignatureSchemeList(scheme)));
        }

        CertificateRequest certificateRequest = context.factory().createCertificateRequest(
                certificate_request_context, extensions);

        // TODO: should it save context to context.certificate_request_context?

        out = ByteBuffer.wrap(certificateRequest.encoding());

        return this;
    }

}
