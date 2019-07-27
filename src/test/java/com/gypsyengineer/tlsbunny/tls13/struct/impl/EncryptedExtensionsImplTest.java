package com.gypsyengineer.tlsbunny.tls13.struct.impl;

import com.gypsyengineer.tlsbunny.tls.Vector;
import com.gypsyengineer.tlsbunny.tls13.struct.*;
import org.junit.Test;

import static com.gypsyengineer.tlsbunny.TestUtils.expectWhatTheHell;
import static junit.framework.TestCase.assertEquals;
import static junit.framework.TestCase.assertTrue;
import static org.junit.Assert.assertSame;

public class EncryptedExtensionsImplTest {

    @Test
    public void setAndGet() throws Exception {
        StructFactory factory = StructFactory.getDefault();
        EncryptedExtensions encrypted = factory.createEncryptedExtensions(
                factory.createExtension(
                        ExtensionType.client_certificate_type,
                        new byte[] {1, 2, 3}));

        assertTrue(encrypted.composite());
        assertEquals(1, encrypted.total());

        assertEquals(
                Vector.wrap(2, factory.createExtension(
                        ExtensionType.client_certificate_type,
                        new byte[] {1, 2, 3})),
                encrypted.extensions());

        assertEquals(HandshakeType.encrypted_extensions, encrypted.type());

        Vector<Extension> extensions = Vector.wrap(2, factory.createExtension(
                ExtensionType.key_share, new byte[] {4, 5}));
        encrypted.element(0, extensions);
        assertSame(extensions, encrypted.element(0));

        expectWhatTheHell(() -> encrypted.element(7));
        expectWhatTheHell(() -> encrypted.element(7, extensions));
    }
}
