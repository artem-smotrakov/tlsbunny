package com.gypsyengineer.tlsbunny.tls13.crypto;

import com.gypsyengineer.tlsbunny.TestUtils;
import org.junit.Test;

public class AEADTest {

    @Test
    public void createDecryptor() {
        TestUtils.expectException(
                () -> AEAD.createDecryptor(
                        AEAD.Method.chacha20_poly1305,
                        new byte[16],
                        new byte[16]),
                IllegalArgumentException.class);

        TestUtils.expectException(
                () -> AEAD.createDecryptor(
                        AEAD.Method.aes_128_ccm,
                        new byte[16],
                        new byte[16]),
                IllegalArgumentException.class);

        TestUtils.expectException(
                () -> AEAD.createDecryptor(
                        AEAD.Method.aes_128_ccm_8,
                        new byte[16],
                        new byte[16]),
                IllegalArgumentException.class);

        TestUtils.expectException(
                () -> AEAD.createDecryptor(
                        AEAD.Method.unknown,
                        new byte[16],
                        new byte[16]),
                IllegalArgumentException.class);
    }

    @Test
    public void createEncryptor() {
        TestUtils.expectException(
                () -> AEAD.createEncryptor(
                        AEAD.Method.chacha20_poly1305,
                        new byte[16],
                        new byte[16]),
                IllegalArgumentException.class);

        TestUtils.expectException(
                () -> AEAD.createEncryptor(
                        AEAD.Method.aes_128_ccm,
                        new byte[16],
                        new byte[16]),
                IllegalArgumentException.class);

        TestUtils.expectException(
                () -> AEAD.createEncryptor(
                        AEAD.Method.aes_128_ccm_8,
                        new byte[16],
                        new byte[16]),
                IllegalArgumentException.class);

        TestUtils.expectException(
                () -> AEAD.createEncryptor(
                        AEAD.Method.unknown,
                        new byte[16],
                        new byte[16]),
                IllegalArgumentException.class);
    }
}
