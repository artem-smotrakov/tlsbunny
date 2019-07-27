package com.gypsyengineer.tlsbunny.tls13.struct.impl;

import com.gypsyengineer.tlsbunny.tls.Vector;
import com.gypsyengineer.tlsbunny.tls13.struct.NamedGroup;
import com.gypsyengineer.tlsbunny.tls13.struct.NamedGroupList;
import com.gypsyengineer.tlsbunny.tls13.struct.StructFactory;
import org.junit.Test;

import java.io.IOException;
import java.util.Arrays;

import static com.gypsyengineer.tlsbunny.TestUtils.expectWhatTheHell;
import static junit.framework.TestCase.assertEquals;
import static junit.framework.TestCase.assertTrue;
import static org.junit.Assert.*;

public class NamedGroupListImplTest {

    @Test
    public void main() throws IOException {
        StructFactory factory = StructFactory.getDefault();
        NamedGroupList one = factory.createNamedGroupList(NamedGroup.secp256r1);
        NamedGroupList two = factory.createNamedGroupList(NamedGroup.secp256r1);

        assertEquals(one, two);
        assertEquals(one.hashCode(), two.hashCode());
        assertEquals(one.encodingLength(), two.encodingLength());
        assertArrayEquals(one.encoding(), two.encoding());

        NamedGroupList three = factory.createNamedGroupList(NamedGroup.ffdhe2048);

        assertNotEquals(one, three);
        assertNotEquals(one.hashCode(), three.hashCode());
        assertEquals(one.encodingLength(), three.encodingLength());
        assertFalse(Arrays.equals(one.encoding(), three.encoding()));

        assertEquals(one, one.copy());
    }

    @Test
    public void getAndSet() throws Exception {
        StructFactory factory = StructFactory.getDefault();
        NamedGroupList list = factory.createNamedGroupList(NamedGroup.secp256r1);

        assertTrue(list.composite());
        assertEquals(1, list.total());

        Vector<NamedGroup> groups = Vector.wrap(2, NamedGroup.ffdhe4096);
        list.element(0, groups);
        assertSame(groups, list.element(0));

        expectWhatTheHell(() -> list.element(7));
        expectWhatTheHell(() -> list.element(7, groups));
    }
}
