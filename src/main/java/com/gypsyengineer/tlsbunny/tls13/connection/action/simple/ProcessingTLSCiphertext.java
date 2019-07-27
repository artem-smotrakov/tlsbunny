package com.gypsyengineer.tlsbunny.tls13.connection.action.simple;

import com.gypsyengineer.tlsbunny.tls13.connection.action.AbstractAction;
import com.gypsyengineer.tlsbunny.tls13.connection.action.ActionFailed;
import com.gypsyengineer.tlsbunny.tls13.connection.action.Phase;
import com.gypsyengineer.tlsbunny.tls13.crypto.AEAD;
import com.gypsyengineer.tlsbunny.tls13.crypto.AEADException;
import com.gypsyengineer.tlsbunny.tls13.struct.ContentType;
import com.gypsyengineer.tlsbunny.tls13.struct.TLSInnerPlaintext;
import com.gypsyengineer.tlsbunny.tls13.struct.TLSPlaintext;

import java.io.IOException;
import java.nio.ByteBuffer;

public class ProcessingTLSCiphertext extends AbstractAction<ProcessingTLSCiphertext> {

    public static final ContentType NO_TYPE_SPECIFIED = null;
    public static final TLSPlaintext NO_TLS_CIPHERTEXT_SPECIFIED = null;

    private final Phase phase;
    private ContentType expectedType = NO_TYPE_SPECIFIED;
    private TLSPlaintext tlsCiphertext = NO_TLS_CIPHERTEXT_SPECIFIED;
    private TLSInnerPlaintext tlsInnerPlaintext;

    public ProcessingTLSCiphertext set(TLSPlaintext tlsCiphertext) {
        this.tlsCiphertext = tlsCiphertext;
        return this;
    }

    public ProcessingTLSCiphertext(Phase phase) {
        this.phase = phase;
    }

    public ProcessingTLSCiphertext expect(ContentType type) {
        expectedType = type;
        return this;
    }

    @Override
    public String name() {
        return String.format("processing TLSCiphertext (%s), expect %s",
                phase, expectedType);
    }

    public TLSInnerPlaintext tlsInnerPlaintext() {
        return tlsInnerPlaintext;
    }

    @Override
    public ProcessingTLSCiphertext run() throws IOException, ActionFailed, AEADException {
        if (tlsCiphertext == NO_TLS_CIPHERTEXT_SPECIFIED) {
            tlsCiphertext = context.factory().parser().parseTLSPlaintext(in);
        }

        if (!tlsCiphertext.containsApplicationData()) {
            throw new ActionFailed(String.format(
                    "expected application_data, but received %s", tlsCiphertext.getType()));
        }

        AEAD decryptor = getDecryptor();
        if (decryptor == null) {
            throw new ActionFailed("what the hell! decryptor is not available! (null)");
        }

        byte[] plaintext = decryptor.decrypt(tlsCiphertext);
        tlsInnerPlaintext = context.factory().parser()
                .parseTLSInnerPlaintext(plaintext);

        ContentType type = tlsInnerPlaintext.getType();
        if (expectedType != NO_TYPE_SPECIFIED && !expectedType.equals(type)) {
            throw new IOException(
                    String.format("expected %s, but found %s", expectedType, type));
        }

        out = ByteBuffer.wrap(tlsInnerPlaintext.getContent());
        output.info("decrypted a TLSCiphertext");

        return this;
    }

    private AEAD getDecryptor() {
        switch (phase) {
            case handshake:
                return context.handshakeDecryptor();
            case application_data:
                return context.applicationDataDecryptor();
            default:
                throw new IllegalArgumentException();
        }
    }

    
}
