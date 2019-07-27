package com.gypsyengineer.tlsbunny.tls13.struct.impl;

import com.gypsyengineer.tlsbunny.tls.Vector;
import com.gypsyengineer.tlsbunny.tls13.struct.*;
import org.junit.Test;

import java.io.IOException;
import java.util.Arrays;

import static com.gypsyengineer.tlsbunny.TestUtils.expectWhatTheHell;
import static junit.framework.TestCase.assertEquals;
import static junit.framework.TestCase.assertTrue;
import static org.junit.Assert.*;

public class SignatureSchemeListImplTest {

    @Test
    public void main() throws IOException {
        StructFactory factory = StructFactory.getDefault();
        SignatureSchemeList one = factory.createSignatureSchemeList(
                SignatureScheme.ecdsa_secp256r1_sha256);
        SignatureSchemeList two = factory.createSignatureSchemeList(
                SignatureScheme.ecdsa_secp256r1_sha256);

        assertEquals(one, two);
        assertEquals(one.hashCode(), two.hashCode());
        assertEquals(one.encodingLength(), two.encodingLength());
        assertArrayEquals(one.encoding(), two.encoding());

        SignatureSchemeList three = factory.createSignatureSchemeList(
                SignatureScheme.rsa_pkcs1_sha256);

        assertNotEquals(one, three);
        assertNotEquals(one.hashCode(), three.hashCode());
        assertEquals(one.encodingLength(), three.encodingLength());
        assertFalse(Arrays.equals(one.encoding(), three.encoding()));

        assertEquals(one, one.copy());
    }

    @Test
    public void getAndSet() throws Exception {
        StructFactory factory = StructFactory.getDefault();
        SignatureSchemeList list = factory.createSignatureSchemeList(
                SignatureScheme.ecdsa_secp256r1_sha256);

        assertTrue(list.composite());
        assertEquals(1, list.total());

        Vector<SignatureScheme> schemes = Vector.wrap(2, SignatureScheme.ecdsa_secp384r1_sha384);
        list.element(0, schemes);
        assertSame(schemes, list.element(0));

        expectWhatTheHell(() -> list.element(7));
        expectWhatTheHell(() -> list.element(7, schemes));
    }
}
