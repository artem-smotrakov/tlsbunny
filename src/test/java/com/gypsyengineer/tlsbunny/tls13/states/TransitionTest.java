package com.gypsyengineer.tlsbunny.tls13.states;

import com.gypsyengineer.tlsbunny.tls13.state.State;
import com.gypsyengineer.tlsbunny.tls13.state.Transition;
import org.junit.Test;

import static com.gypsyengineer.tlsbunny.TestUtils.expectException;
import static com.gypsyengineer.tlsbunny.tls13.state.BooleanFact.booleanFact;
import static com.gypsyengineer.tlsbunny.tls13.state.State.state;
import static com.gypsyengineer.tlsbunny.tls13.state.Transition.transition;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertNotNull;

public class TransitionTest {

    @Test
    public void basic() {
        State from = state(booleanFact("foo", true));
        State to = state(booleanFact("foo", false));
        Transition t = transition(from, to);
        assertNotNull(t);
        assertEquals(state(booleanFact("foo", true)), t.from());
        assertEquals(state(booleanFact("foo", false)), t.to());
    }

    @Test
    public void invalid() {
        expectException(
                () -> transition(null, state(booleanFact("foo", true))),
                NullPointerException.class);
        expectException(
                () -> transition(state(booleanFact("bar", false)), null),
                NullPointerException.class);
    }

    @Test
    public void chechEquals() {
        Transition first = transition(
                state(booleanFact("foo", true)),
                state(booleanFact("foo", false))
        );
        Transition second = transition(
                state(booleanFact("foo", true)),
                state(booleanFact("foo", false))
        );
        assertEquals(first, second);
        assertEquals(first.hashCode(), second.hashCode());
        Transition third = transition(
                state(booleanFact("foo", false)),
                state(booleanFact("foo", true))
        );
        assertNotEquals(first, third);
        assertNotEquals(second, third);
        assertNotEquals(first.hashCode(), third.hashCode());
        assertNotEquals(second.hashCode(), third.hashCode());
    }

}
