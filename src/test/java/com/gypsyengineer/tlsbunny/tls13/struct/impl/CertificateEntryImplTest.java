package com.gypsyengineer.tlsbunny.tls13.struct.impl;

import com.gypsyengineer.tlsbunny.tls.Vector;
import com.gypsyengineer.tlsbunny.tls13.struct.CertificateEntry;
import com.gypsyengineer.tlsbunny.tls13.struct.Extension;
import com.gypsyengineer.tlsbunny.tls13.struct.StructFactory;
import org.junit.Test;

import static com.gypsyengineer.tlsbunny.TestUtils.expectWhatTheHell;
import static org.junit.Assert.*;

public class CertificateEntryImplTest {

    @Test
    public void x509GetAndSet() throws Exception {
        CertificateEntry.X509 x509entry = StructFactory.getDefault()
                .createX509CertificateEntry(new byte[256]);
        assertTrue(x509entry.composite());
        assertEquals(2, x509entry.total());

        Vector<Extension> extensions = Vector.wrap(2);
        x509entry.element(0, extensions);
        assertSame(extensions, x509entry.element(0));

        Vector<Byte> data = Vector.wrap(3, new byte[123]);
        x509entry.element(1, data);
        assertSame(data, x509entry.element(1));

        expectWhatTheHell(() -> x509entry.element(7));
        expectWhatTheHell(() -> x509entry.element(7, extensions));
    }
}
