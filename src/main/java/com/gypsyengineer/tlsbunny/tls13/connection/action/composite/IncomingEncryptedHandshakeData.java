package com.gypsyengineer.tlsbunny.tls13.connection.action.composite;

import com.gypsyengineer.tlsbunny.tls13.connection.action.AbstractAction;
import com.gypsyengineer.tlsbunny.tls13.connection.action.ActionFailed;
import com.gypsyengineer.tlsbunny.tls13.crypto.AEADException;
import com.gypsyengineer.tlsbunny.tls13.struct.TLSInnerPlaintext;
import com.gypsyengineer.tlsbunny.tls13.struct.TLSPlaintext;

import java.io.IOException;
import java.nio.ByteBuffer;

public class IncomingEncryptedHandshakeData extends AbstractAction<IncomingEncryptedHandshakeData> {

    @Override
    public String name() {
        return "encrypted handshake data";
    }

    @Override
    public IncomingEncryptedHandshakeData run()
            throws ActionFailed, AEADException, IOException {

        TLSPlaintext tlsPlaintext = context.factory().parser().parseTLSPlaintext(in);

        if (!tlsPlaintext.containsApplicationData()) {
            throw new ActionFailed("expected encrypted data");
        }

        TLSInnerPlaintext tlsInnerPlaintext = context.factory().parser().parseTLSInnerPlaintext(
                context.handshakeDecryptor().decrypt(tlsPlaintext));

        out = ByteBuffer.wrap(tlsInnerPlaintext.getContent());

        output.info("received encrypted handshake data (%d bytes)",
                tlsInnerPlaintext.getContent().length);

        return this;
    }

    
}
