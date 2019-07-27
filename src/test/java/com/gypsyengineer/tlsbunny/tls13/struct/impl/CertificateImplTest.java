package com.gypsyengineer.tlsbunny.tls13.struct.impl;

import com.gypsyengineer.tlsbunny.tls.Vector;
import com.gypsyengineer.tlsbunny.tls13.struct.Certificate;
import com.gypsyengineer.tlsbunny.tls13.struct.CertificateEntry;
import com.gypsyengineer.tlsbunny.tls13.struct.StructFactory;
import org.junit.Test;

import static com.gypsyengineer.tlsbunny.TestUtils.expectWhatTheHell;
import static junit.framework.TestCase.assertEquals;
import static junit.framework.TestCase.assertTrue;
import static org.junit.Assert.assertSame;

public class CertificateImplTest {

    @Test
    public void getAndSet() throws Exception {
        StructFactory factory = StructFactory.getDefault();
        Certificate certificate = factory.createCertificate(
                new byte[] {1 ,2 ,3}, factory.createX509CertificateEntry(new byte[16]));

        assertTrue(certificate.composite());
        assertEquals(2, certificate.total());

        assertEquals(
                Vector.wrap(1, new byte[] {1, 2, 3}),
                certificate.certificateRequestContext());

        assertEquals(
                Vector.wrap(3, factory.createX509CertificateEntry(new byte[16])),
                certificate.certificateList());

        Vector<Byte> context = Vector.wrap(1, new byte[10]);
        certificate.element(0, context);
        assertSame(context, certificate.element(0));

        Vector<CertificateEntry> list = Vector.wrap(
                3, factory.createX509CertificateEntry(new byte[8]));
        certificate.element(1, list);
        assertSame(list, certificate.element(1));

        expectWhatTheHell(() -> certificate.element(7));
        expectWhatTheHell(() -> certificate.element(7, list));
    }
}
