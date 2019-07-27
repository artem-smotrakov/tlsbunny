package com.gypsyengineer.tlsbunny.tls13.struct.impl;

import com.gypsyengineer.tlsbunny.tls.Vector;
import com.gypsyengineer.tlsbunny.tls13.struct.KeyShareEntry;
import com.gypsyengineer.tlsbunny.tls13.struct.NamedGroup;
import com.gypsyengineer.tlsbunny.tls13.struct.StructFactory;
import org.junit.Test;

import static com.gypsyengineer.tlsbunny.TestUtils.expectWhatTheHell;
import static junit.framework.TestCase.assertEquals;
import static junit.framework.TestCase.assertTrue;
import static org.junit.Assert.assertNotEquals;

public class KeyShareEntryImplTest {

    @Test
    public void basic() {
        StructFactory factory = StructFactory.getDefault();
        KeyShareEntry one = factory.createKeyShareEntry(
                NamedGroup.secp256r1, new byte[] {1, 2, 3});
        KeyShareEntry two = factory.createKeyShareEntry(
                NamedGroup.secp256r1, new byte[] {1, 2, 3});

        assertEquals(one, two);
        assertEquals(one.hashCode(), two.hashCode());

        KeyShareEntry three = factory.createKeyShareEntry(
                NamedGroup.secp256r1, new byte[] {1, 2});
        assertNotEquals(one, three);
        assertNotEquals(one.hashCode(), three.hashCode());
    }

    @Test
    public void getAndSet() throws Exception {
        StructFactory factory = StructFactory.getDefault();
        KeyShareEntry entry = factory.createKeyShareEntry(
                NamedGroup.secp256r1, new byte[] {1, 2, 3});

        assertTrue(entry.composite());
        assertEquals(2, entry.total());

        entry.element(0, NamedGroup.ffdhe2048);
        assertEquals(NamedGroup.ffdhe2048, entry.element(0));
        assertEquals(NamedGroup.ffdhe2048, entry.namedGroup());

        Vector<Byte> keyExchange = Vector.wrap(2, new byte[] {3, 4});
        entry.element(1, keyExchange);
        assertEquals(keyExchange, entry.element(1));
        assertEquals(keyExchange, entry.keyExchange());

        expectWhatTheHell(() -> entry.element(7));
        expectWhatTheHell(() -> entry.element(7, keyExchange));
    }
}
