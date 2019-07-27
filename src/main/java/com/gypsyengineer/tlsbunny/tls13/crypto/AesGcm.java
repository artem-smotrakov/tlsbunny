package com.gypsyengineer.tlsbunny.tls13.crypto;

import com.gypsyengineer.tlsbunny.tls.UInt16;
import com.gypsyengineer.tlsbunny.tls13.struct.ContentType;
import com.gypsyengineer.tlsbunny.tls13.struct.ProtocolVersion;
import com.gypsyengineer.tlsbunny.tls13.struct.TLSPlaintext;
import com.gypsyengineer.tlsbunny.utils.Utils;

import javax.crypto.Cipher;
import java.io.IOException;
import java.security.Key;

public abstract class AesGcm extends AbstractAEAD {

    public static final String algorithm = "AES";
    public static final String transform = "AES/GCM/NoPadding";
    public static final int tag_length_in_bits = 128;
    public static final int tag_length_in_bytes = 16;
    public static final int n_min = 12;

    final Cipher cipher;
    final Key key;

    public AesGcm(Cipher cipher, Key key, byte[] iv) {
        super(iv);
        this.cipher = cipher;
        this.key = key;
    }

    @Override
    public int getNMin() {
        return n_min;
    }

    @Override
    public byte[] decrypt(TLSPlaintext tlsCiphertext) throws AEADException {
        throw new UnsupportedOperationException("what the hell? I can't decrypt!");
    }

    byte[] getAdditionalData(ContentType type, ProtocolVersion version, UInt16 length)
            throws IOException {

        return Utils.concatenate(type.encoding(), version.encoding(), length.encoding());
    }

    byte[] getAdditionalData(TLSPlaintext tlsPlaintext) throws IOException {
        return getAdditionalData(
                tlsPlaintext.getType(),
                tlsPlaintext.getLegacyRecordVersion(),
                tlsPlaintext.getFragmentLength());
    }
}
