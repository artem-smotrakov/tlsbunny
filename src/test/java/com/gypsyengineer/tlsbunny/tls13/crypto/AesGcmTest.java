package com.gypsyengineer.tlsbunny.tls13.crypto;

import com.gypsyengineer.tlsbunny.TestUtils;
import com.gypsyengineer.tlsbunny.tls13.struct.ContentType;
import com.gypsyengineer.tlsbunny.tls13.struct.ProtocolVersion;
import com.gypsyengineer.tlsbunny.tls13.struct.StructFactory;
import org.junit.Test;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;
import java.security.Key;
import java.security.NoSuchAlgorithmException;

import static junit.framework.TestCase.assertEquals;

public class AesGcmTest {

    @Test
    public void nMin() throws NoSuchAlgorithmException, NoSuchPaddingException {
        assertEquals(12, AesGcmImpl.create().getNMin());
    }

    @Test
    public void update() throws Exception {
        TestUtils.expectUnsupported(() -> AesGcmImpl.create()
                .update(new byte[] {1 ,2, 3}));
    }

    @Test
    public void decrypt() throws Exception {
        TestUtils.expectUnsupported(() -> AesGcmImpl.create()
                .decrypt(StructFactory.getDefault().createTLSPlaintext(
                        ContentType.application_data,
                        ProtocolVersion.TLSv12,
                        new byte[] {1 ,2, 3})));
    }

    private static class AesGcmImpl extends AesGcm {

        private static AesGcmImpl create()
                throws NoSuchPaddingException, NoSuchAlgorithmException {

            return new AesGcmImpl(Cipher.getInstance("AES"),
                    new SecretKeySpec(new byte[16], "AES"), new byte[16]);
        }

        AesGcmImpl(Cipher cipher, Key key, byte[] iv) {
            super(cipher, key, iv);
        }

        @Override
        public void start() {
            // do nothing
        }

        @Override
        public void updateAAD(byte[] data) {
            // do nothing
        }

        @Override
        public byte[] finish() {
            return new byte[0];
        }
    }
}
