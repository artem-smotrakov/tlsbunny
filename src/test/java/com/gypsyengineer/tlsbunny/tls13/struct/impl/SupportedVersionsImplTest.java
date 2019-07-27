package com.gypsyengineer.tlsbunny.tls13.struct.impl;

import com.gypsyengineer.tlsbunny.tls.Vector;
import com.gypsyengineer.tlsbunny.tls13.struct.ProtocolVersion;
import com.gypsyengineer.tlsbunny.tls13.struct.StructFactory;
import com.gypsyengineer.tlsbunny.tls13.struct.SupportedVersions;
import org.junit.Test;

import static com.gypsyengineer.tlsbunny.TestUtils.expectWhatTheHell;
import static junit.framework.TestCase.assertEquals;
import static junit.framework.TestCase.assertTrue;
import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertSame;

public class SupportedVersionsImplTest {

    @Test
    public void mainClientHello() {
        StructFactory factory = StructFactory.getDefault();
        SupportedVersions.ClientHello ext
                = factory.createSupportedVersionForClientHello(ProtocolVersion.TLSv13);

        assertEquals(Vector.wrap(1, ProtocolVersion.TLSv13), ext.getVersions());

        SupportedVersions.ClientHello same
                = factory.createSupportedVersionForClientHello(ProtocolVersion.TLSv13);

        assertEquals(ext, same);
        assertEquals(ext.hashCode(), same.hashCode());

        SupportedVersions.ClientHello another
                = factory.createSupportedVersionForClientHello(ProtocolVersion.TLSv12);

        assertNotEquals(ext, another);
        assertNotEquals(ext.hashCode(), another.hashCode());
    }

    @Test
    public void setAndGetWithClientHello() throws Exception {
        StructFactory factory = StructFactory.getDefault();
        SupportedVersions.ClientHello ext
                = factory.createSupportedVersionForClientHello(ProtocolVersion.TLSv13);

        assertTrue(ext.composite());
        assertEquals(1, ext.total());

        Vector<ProtocolVersion> versions = Vector.wrap(1, ProtocolVersion.TLSv11);
        ext.element(0, versions);
        assertSame(versions, ext.element(0));

        expectWhatTheHell(() -> ext.element(7));
        expectWhatTheHell(() -> ext.element(7, versions));
    }

    @Test
    public void mainServerHello() {
        StructFactory factory = StructFactory.getDefault();
        SupportedVersions.ServerHello ext
                = factory.createSupportedVersionForServerHello(ProtocolVersion.TLSv13);

        assertEquals(ProtocolVersion.TLSv13, ext.getSelectedVersion());

        SupportedVersions.ServerHello same
                = factory.createSupportedVersionForServerHello(ProtocolVersion.TLSv13);

        assertEquals(ext, same);
        assertEquals(ext.hashCode(), same.hashCode());

        SupportedVersions.ServerHello another
                = factory.createSupportedVersionForServerHello(ProtocolVersion.TLSv12);

        assertNotEquals(ext, another);
        assertNotEquals(ext.hashCode(), another.hashCode());
    }

    @Test
    public void setAndGetWithServerHello() throws Exception {
        StructFactory factory = StructFactory.getDefault();
        SupportedVersions.ServerHello ext
                = factory.createSupportedVersionForServerHello(ProtocolVersion.TLSv13);

        assertTrue(ext.composite());
        assertEquals(1, ext.total());

        ext.element(0, ProtocolVersion.TLSv12);
        assertEquals(ProtocolVersion.TLSv12, ext.element(0));

        expectWhatTheHell(() -> ext.element(7));
        expectWhatTheHell(() -> ext.element(7, ProtocolVersion.TLSv12));
    }
}
