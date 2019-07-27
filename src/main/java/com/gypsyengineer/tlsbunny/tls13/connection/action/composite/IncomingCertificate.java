package com.gypsyengineer.tlsbunny.tls13.connection.action.composite;

import com.gypsyengineer.tlsbunny.tls13.connection.action.AbstractAction;
import com.gypsyengineer.tlsbunny.tls13.connection.action.Action;
import com.gypsyengineer.tlsbunny.tls13.connection.action.ActionFailed;
import com.gypsyengineer.tlsbunny.tls13.crypto.AEADException;
import com.gypsyengineer.tlsbunny.tls13.struct.Handshake;

import java.io.IOException;

public class IncomingCertificate extends AbstractAction {

    @Override
    public String name() {
        return "Certificate";
    }

    @Override
    public Action run() throws ActionFailed, AEADException, IOException {
        Handshake handshake = processEncryptedHandshake();
        if (!handshake.containsCertificate()) {
            throw new ActionFailed("expected a Certificate message");
        }

        processCertificate(handshake);

        return this;
    }

    private void processCertificate(Handshake handshake) {
        context.factory().parser().parseCertificate(
                handshake.getBody(),
                buf -> context.factory().parser().parseX509CertificateEntry(buf));
        context.setServerCertificate(handshake);
    }
}
