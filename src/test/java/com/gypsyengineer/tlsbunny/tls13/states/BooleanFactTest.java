package com.gypsyengineer.tlsbunny.tls13.states;

import com.gypsyengineer.tlsbunny.TestUtils;
import com.gypsyengineer.tlsbunny.tls13.state.BooleanFact;
import org.junit.Test;

import static com.gypsyengineer.tlsbunny.tls13.state.BooleanFact.booleanFact;
import static org.junit.Assert.*;

public class BooleanFactTest {

    @Test
    public void checkEqual() {
        BooleanFact first = booleanFact("foo", true);
        BooleanFact second = booleanFact("foo", true);
        assertEquals(first, second);
        assertEquals(first.hashCode(), second.hashCode());
        assertEquals(first.name(), second.name());
        assertEquals(first.value(), second.value());

        first = booleanFact("foo", false);
        second = booleanFact("foo", false);
        assertEquals(first, second);
        assertEquals(first.hashCode(), second.hashCode());
        assertEquals(first.name(), second.name());
        assertEquals(first.value(), second.value());
    }

    @Test
    public void checkNotEqual() {
        BooleanFact first = booleanFact("foo", true);
        BooleanFact second = booleanFact("foo", false);
        assertNotEquals(first, second);
        assertNotEquals(first.hashCode(), second.hashCode());
        assertEquals(first.name(), second.name());
        assertNotEquals(first.value(), second.value());

        first = booleanFact("foo", false);
        second = booleanFact("bar", false);
        assertNotEquals(first, second);
        assertNotEquals(first.hashCode(), second.hashCode());
        assertNotEquals(first.name(), second.name());
        assertEquals(first.value(), second.value());
    }

    @Test
    public void invalid() {
        TestUtils.expectException(() -> booleanFact(null, true), NullPointerException.class);
    }

    @Test
    public void checkValues() {
        Boolean[] values = booleanFact("bar", true).values();
        assertNotNull(values);
        assertEquals(2, values.length);
        TestUtils.assertContains(Boolean.TRUE, values);
        TestUtils.assertContains(Boolean.FALSE, values);
    }
}
