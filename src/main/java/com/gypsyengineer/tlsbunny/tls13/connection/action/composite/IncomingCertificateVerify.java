package com.gypsyengineer.tlsbunny.tls13.connection.action.composite;

import com.gypsyengineer.tlsbunny.tls13.connection.action.AbstractAction;
import com.gypsyengineer.tlsbunny.tls13.connection.action.Action;
import com.gypsyengineer.tlsbunny.tls13.connection.action.ActionFailed;
import com.gypsyengineer.tlsbunny.tls13.crypto.AEADException;
import com.gypsyengineer.tlsbunny.tls13.struct.Handshake;

import java.io.IOException;

public class IncomingCertificateVerify extends AbstractAction {

    @Override
    public String name() {
        return "CertificateVerify";
    }

    @Override
    public Action run() throws ActionFailed, AEADException, IOException {
        Handshake handshake = processEncryptedHandshake();
        if (!handshake.containsCertificateVerify()) {
            throw new ActionFailed("expected a CertificateVerify message");
        }

        processCertificateVerify(handshake);

        return this;
    }

    private void processCertificateVerify(Handshake handshake) {
        context.factory().parser().parseCertificateVerify(handshake.getBody());
        context.setServerCertificateVerify(handshake);
    }
}
