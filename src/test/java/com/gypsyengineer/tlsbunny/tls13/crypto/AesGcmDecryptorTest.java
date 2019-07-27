package com.gypsyengineer.tlsbunny.tls13.crypto;

import com.gypsyengineer.tlsbunny.TestUtils;
import org.junit.Test;

public class AesGcmDecryptorTest {

    @Test
    public void badKey() {
        TestUtils.expectException(() -> {
            AEAD decryptor = AEAD.createDecryptor(
                    AEAD.Method.aes_128_gcm, new byte[0], new byte[16]);
            decryptor.start();
        }, IllegalArgumentException.class);

        TestUtils.expectException(() -> {
            AEAD decryptor = AEAD.createDecryptor(
                    AEAD.Method.aes_128_gcm, new byte[5], new byte[16]);
            decryptor.start();
        }, AEADException.class);
    }
}
