package com.gypsyengineer.tlsbunny.tls13.struct.impl;

import com.gypsyengineer.tlsbunny.tls.Vector;
import com.gypsyengineer.tlsbunny.tls13.struct.CertificateVerify;
import com.gypsyengineer.tlsbunny.tls13.struct.SignatureScheme;
import com.gypsyengineer.tlsbunny.tls13.struct.StructFactory;
import org.junit.Test;

import static com.gypsyengineer.tlsbunny.TestUtils.expectWhatTheHell;
import static junit.framework.TestCase.assertEquals;
import static junit.framework.TestCase.assertTrue;
import static org.junit.Assert.assertSame;

public class CertificateVerifyImplTest {

    @Test
    public void getAndSet() throws Exception {
        StructFactory factory = StructFactory.getDefault();
        CertificateVerify verify = factory.createCertificateVerify(
                SignatureScheme.ecdsa_secp256r1_sha256, new byte[] {1, 2, 3});

        assertEquals(SignatureScheme.ecdsa_secp256r1_sha256, verify.algorithm());
        assertEquals(
                Vector.wrap(2, new byte[] {1, 2, 3}),
                verify.signature());

        assertTrue(verify.composite());
        assertEquals(2, verify.total());

        verify.element(0, SignatureScheme.rsa_pkcs1_sha256);
        assertEquals(SignatureScheme.rsa_pkcs1_sha256, verify.element(0));

        Vector<Byte> vector = Vector.wrap(2, new byte[] {3, 4});
        verify.element(1, vector);
        assertSame(vector, verify.element(1));

        expectWhatTheHell(() -> verify.element(7));
        expectWhatTheHell(() -> verify.element(7, vector));
    }
}
