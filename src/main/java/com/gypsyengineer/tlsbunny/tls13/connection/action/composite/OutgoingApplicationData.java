package com.gypsyengineer.tlsbunny.tls13.connection.action.composite;

import com.gypsyengineer.tlsbunny.tls13.connection.action.AbstractAction;
import com.gypsyengineer.tlsbunny.tls13.connection.action.Action;
import com.gypsyengineer.tlsbunny.tls13.crypto.AEAD;
import com.gypsyengineer.tlsbunny.tls13.crypto.AEADException;
import com.gypsyengineer.tlsbunny.tls13.crypto.AesGcm;
import com.gypsyengineer.tlsbunny.tls13.struct.ContentType;
import com.gypsyengineer.tlsbunny.tls13.struct.ProtocolVersion;
import com.gypsyengineer.tlsbunny.tls13.struct.TLSInnerPlaintext;
import com.gypsyengineer.tlsbunny.tls13.struct.TLSPlaintext;
import com.gypsyengineer.tlsbunny.tls13.utils.TLS13Utils;

import java.io.IOException;

import static com.gypsyengineer.tlsbunny.tls13.struct.TLSInnerPlaintext.no_padding;

public class OutgoingApplicationData extends AbstractAction {

    public static final byte[] NOTHING = new byte[0];

    private byte[] data = NOTHING;

    public OutgoingApplicationData(byte[] data) {
        this.data = data;
    }

    public OutgoingApplicationData(String string) {
        this(string.getBytes());
    }

    @Override
    public String name() {
        return "application data";
    }

    @Override
    public Action run() throws IOException, AEADException {
        TLSPlaintext[] tlsPlaintexts = context.factory().createTLSPlaintexts(
                ContentType.application_data,
                ProtocolVersion.TLSv12,
                encrypt(data));

        out = TLS13Utils.store(tlsPlaintexts);

        return this;
    }

    private byte[] encrypt(byte[] data) throws IOException, AEADException {
        TLSInnerPlaintext tlsInnerPlaintext = context.factory().createTLSInnerPlaintext(
                ContentType.application_data, data, no_padding);
        byte[] plaintext = tlsInnerPlaintext.encoding();

        context.applicationDataEncryptor().start();
        context.applicationDataEncryptor().updateAAD(
                AEAD.getAdditionalData(plaintext.length + AesGcm.tag_length_in_bytes));
        context.applicationDataEncryptor().update(plaintext);

        return context.applicationDataEncryptor().finish();
    }
}
