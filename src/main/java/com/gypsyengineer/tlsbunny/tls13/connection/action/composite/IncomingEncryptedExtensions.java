package com.gypsyengineer.tlsbunny.tls13.connection.action.composite;

import com.gypsyengineer.tlsbunny.tls13.connection.action.AbstractAction;
import com.gypsyengineer.tlsbunny.tls13.connection.action.Action;
import com.gypsyengineer.tlsbunny.tls13.connection.action.ActionFailed;
import com.gypsyengineer.tlsbunny.tls13.crypto.AEADException;
import com.gypsyengineer.tlsbunny.tls13.struct.Handshake;

import java.io.IOException;

public class IncomingEncryptedExtensions extends AbstractAction {

    @Override
    public String name() {
        return "EncryptedExtensions";
    }

    @Override
    public Action run() throws ActionFailed, AEADException, IOException {
        Handshake handshake = processEncryptedHandshake();
        if (!handshake.containsEncryptedExtensions()) {
            throw new ActionFailed("expected a EncryptedExtensions message");
        }

        processEncryptedExtensions(handshake);

        return this;
    }

    private void processEncryptedExtensions(Handshake handshake) {
        context.factory().parser().parseEncryptedExtensions(handshake.getBody());
        context.setEncryptedExtensions(handshake);
    }
}
