package com.gypsyengineer.tlsbunny.tls13.crypto;

import com.gypsyengineer.tlsbunny.TestUtils;
import org.junit.Test;

public class AesGcmEncryptorTest {

    @Test
    public void badKey() {
        TestUtils.expectException(() -> {
            AEAD encryptor = AEAD.createEncryptor(
                    AEAD.Method.aes_128_gcm, new byte[0], new byte[16]);
            encryptor.start();
        }, IllegalArgumentException.class);

        TestUtils.expectException(() -> {
            AEAD encryptor = AEAD.createEncryptor(
                    AEAD.Method.aes_128_gcm, new byte[5], new byte[16]);
            encryptor.start();
        }, AEADException.class);
    }
}
