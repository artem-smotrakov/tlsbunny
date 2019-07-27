package com.gypsyengineer.tlsbunny.tls13.struct.impl;

import com.gypsyengineer.tlsbunny.tls.Random;
import com.gypsyengineer.tlsbunny.tls.RandomImpl;
import com.gypsyengineer.tlsbunny.tls.Vector;
import com.gypsyengineer.tlsbunny.tls13.struct.*;
import org.junit.Test;

import static com.gypsyengineer.tlsbunny.TestUtils.createClientHello;
import static com.gypsyengineer.tlsbunny.TestUtils.expectWhatTheHell;
import static junit.framework.TestCase.assertEquals;
import static org.junit.Assert.assertSame;
import static org.junit.Assert.assertTrue;

public class ClientHelloImplTest {

    @Test
    public void getAndSet() {
        ClientHello hello = createClientHello();

        assertTrue(hello.composite());
        assertEquals(hello.total(), 6);
        assertEquals(hello.protocolVersion(), hello.element(0));
        assertEquals(hello.random(), hello.element(1));
        assertEquals(hello.legacySessionId(), hello.element(2));
        assertEquals(hello.cipherSuites(), hello.element(3));
        assertEquals(hello.legacyCompressionMethods(), hello.element(4));
        assertEquals(hello.extensions(), hello.element(5));

        hello.element(0, ProtocolVersion.TLSv12);
        assertEquals(hello.protocolVersion(), hello.element(0));
        assertEquals(ProtocolVersion.TLSv12, hello.element(0));

        Random random = Random.create();
        hello.element(1, random);
        assertSame(random, hello.element(1));

        Vector<Byte> session_id = Vector.wrap(1, new byte[] {1, 2, 3});
        hello.element(2, session_id);
        assertSame(session_id, hello.element(2));

        Vector<CipherSuite> cipherSuites = Vector.wrap(
                1, CipherSuite.TLS_AES_128_GCM_SHA256);
        hello.element(3, cipherSuites);
        assertSame(cipherSuites, hello.element(3));

        Vector<CompressionMethod> compressionMethods = Vector.wrap(
                1, CompressionMethod.None);
        hello.element(4, compressionMethods);
        assertSame(compressionMethods, hello.element(4));

        Vector<Extension> extensions = Vector.wrap(
                2, StructFactory.getDefault().createExtension(ExtensionType.supported_versions, new byte[15]));
        hello.element(5, extensions);
        assertSame(extensions, hello.element(5));
    }

    @Test
    public void wrongIndex() throws Exception {
        ClientHello hello = createClientHello();

        expectWhatTheHell(() -> hello.element(7));
        expectWhatTheHell(() -> hello.element(-1));
        expectWhatTheHell(() -> hello.element(42, ProtocolVersion.TLSv12));
        expectWhatTheHell(() -> hello.element(-5, ProtocolVersion.TLSv12));
    }

}
