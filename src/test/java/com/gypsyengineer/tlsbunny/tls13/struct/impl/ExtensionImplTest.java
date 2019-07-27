package com.gypsyengineer.tlsbunny.tls13.struct.impl;

import com.gypsyengineer.tlsbunny.tls13.struct.Extension;
import com.gypsyengineer.tlsbunny.tls13.struct.ExtensionType;
import org.junit.Test;

import static com.gypsyengineer.tlsbunny.TestUtils.createExtension;
import static com.gypsyengineer.tlsbunny.TestUtils.expectWhatTheHell;
import static junit.framework.TestCase.assertEquals;
import static org.junit.Assert.assertTrue;

public class ExtensionImplTest {

    @Test
    public void getAndSet() {
        Extension ext = createExtension();

        assertTrue(ext.composite());
        assertEquals(ext.total(), 2);
        assertEquals(ext.extensionType(), ext.element(0));
        assertEquals(ext.extensionData(), ext.element(1));

        ext.element(0, ExtensionType.key_share);
        assertEquals(ext.extensionType(), ext.element(0));
        assertEquals(ExtensionType.key_share, ext.element(0));
    }

    @Test
    public void wrongIndex() throws Exception {
        Extension ext = createExtension();

        expectWhatTheHell(() -> ext.element(3));
        expectWhatTheHell(() -> ext.element(-1));
        expectWhatTheHell(() -> ext.element(42, ExtensionType.key_share));
        expectWhatTheHell(() -> ext.element(-5, ExtensionType.key_share));
    }
}
