package com.gypsyengineer.tlsbunny.tls13.crypto;

import javax.crypto.SecretKey;

public class RawKey implements SecretKey {

    private final String algorithm;
    private final byte[] key;

    public RawKey(byte[] key, String algorithm) {
        this.algorithm = algorithm;
        this.key = key.clone();
    }

    @Override
    public String getAlgorithm() {
        return algorithm;
    }

    @Override
    public String getFormat() {
        return "RAW";
    }

    @Override
    public byte[] getEncoded() {
        return key.clone();
    }
    
}
