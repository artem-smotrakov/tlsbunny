package com.gypsyengineer.tlsbunny.tls13.crypto;

import com.gypsyengineer.tlsbunny.utils.Converter;
import com.gypsyengineer.tlsbunny.utils.Utils;

public abstract class AbstractAEAD implements AEAD {

    private long sequenceNumber = 0;
    private final byte[] iv;

    AbstractAEAD(byte[] iv) {
        this.iv = iv;
    }
    
    public abstract int getNMin();

    byte[] nextNonce() {
        return Utils.xor(Converter.long2bytes(sequenceNumber++, iv.length), iv);
    }

    @Override
    public byte[] update(byte[] plaintext) {
        throw new UnsupportedOperationException(
                "What the hell? I can't do encryption or decryption");
    }

}
