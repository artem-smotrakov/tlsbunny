package com.gypsyengineer.tlsbunny.tls13.states;

import com.gypsyengineer.tlsbunny.TestUtils;
import com.gypsyengineer.tlsbunny.tls13.state.Fact;
import com.gypsyengineer.tlsbunny.tls13.state.State;
import org.junit.Test;

import static com.gypsyengineer.tlsbunny.TestUtils.assertContains;
import static com.gypsyengineer.tlsbunny.tls13.state.BooleanFact.booleanFact;
import static com.gypsyengineer.tlsbunny.tls13.state.State.state;
import static org.junit.Assert.*;

public class StateTest {

    @Test
    public void invalid() throws Exception {
        Fact[] nullFacts = null;
        TestUtils.expectException(() -> state(nullFacts), NullPointerException.class);
        TestUtils.expectWhatTheHell(State::state);
    }

    @Test
    public void basic() {
        State state = state(
                booleanFact("foo", true),
                booleanFact("bar", false));
        assertNotNull(state);
        assertEquals(2, state.facts().length);
        assertContains(booleanFact("foo", true), state.facts());
        assertContains(booleanFact("bar", false), state.facts());
        assertTrue(state.contains("foo"));
        assertTrue(state.contains("bar"));
        assertFalse(state.contains("nope"));
        assertEquals(Boolean.TRUE, state.get("foo").value());
        assertEquals(Boolean.FALSE, state.get("bar").value());
    }

    @Test
    public void checkEquals() {
        State first = state(
                booleanFact("foo", true),
                booleanFact("bar", false));
        State second = state(
                booleanFact("foo", true),
                booleanFact("bar", false));
        assertEquals(first, second);
        assertEquals(first.hashCode(), second.hashCode());

        // order doesn't matter
        State third = state(
                booleanFact("bar", false),
                booleanFact("foo", true));
        assertEquals(first, third);
        assertEquals(second, third);
        assertEquals(first.hashCode(), third.hashCode());
        assertEquals(second.hashCode(), third.hashCode());
    }
}
