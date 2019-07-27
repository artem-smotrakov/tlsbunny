package com.gypsyengineer.tlsbunny.tls13.connection.action.simple;

import com.gypsyengineer.tlsbunny.tls13.connection.action.AbstractAction;
import com.gypsyengineer.tlsbunny.tls13.connection.action.Action;
import com.gypsyengineer.tlsbunny.tls13.connection.action.ActionFailed;
import com.gypsyengineer.tlsbunny.tls13.connection.action.Phase;
import com.gypsyengineer.tlsbunny.tls13.crypto.AEAD;
import com.gypsyengineer.tlsbunny.tls13.crypto.AEADException;
import com.gypsyengineer.tlsbunny.tls13.struct.Alert;
import com.gypsyengineer.tlsbunny.tls13.struct.TLSInnerPlaintext;
import com.gypsyengineer.tlsbunny.tls13.struct.TLSPlaintext;

import java.io.IOException;
import java.nio.ByteBuffer;

public class ProcessingEncryptedAlert extends AbstractAction<ProcessingEncryptedAlert> {

    private final Phase phase;

    public ProcessingEncryptedAlert(Phase phase) {
        this.phase = phase;
    }

    @Override
    public String name() {
        return String.format("encrypted alert (%s)", phase);
    }

    @Override
    public ProcessingEncryptedAlert run() throws ActionFailed, AEADException, IOException {
        TLSPlaintext tlsPlaintext = context.factory().parser().parseTLSPlaintext(in);

        if (!tlsPlaintext.containsApplicationData()) {
            throw new ActionFailed("expected encrypted data");
        }

        AEAD decryptor;
        switch (phase) {
            case handshake:
                decryptor = context.handshakeDecryptor();
                break;
            case application_data:
                decryptor = context.applicationDataDecryptor();
                break;
            default:
                throw new IllegalArgumentException();
        }

        byte[] plaintext = decryptor.decrypt(tlsPlaintext);
        try {
            TLSInnerPlaintext tlsInnerPlaintext = context.factory().parser()
                    .parseTLSInnerPlaintext(plaintext);

            if (!tlsInnerPlaintext.containsAlert()) {
                throw new ActionFailed("expected an alert");
            }

            Alert alert = context.factory().parser().parseAlert(tlsInnerPlaintext.getContent());
            context.setAlert(alert);
            output.info("received an alert: %s", alert);
        } catch (ActionFailed e) {
            out = ByteBuffer.wrap(plaintext);
            throw e;
        }

        return this;
    }

    
}
