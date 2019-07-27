package com.gypsyengineer.tlsbunny.tls13.state;

import java.util.Objects;

public class Transition {

    private final State from;
    private final State to;

    public static Transition transition(State from, State to) {
        Objects.requireNonNull(from, "from can't be null!");
        Objects.requireNonNull(to, "to can't be null!");
        return new Transition(from, to);
    }

    private Transition(State from, State to) {
        this.from = from;
        this.to = to;
    }

    public State from() {
        return from;
    }

    public State to() {
        return to;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) {
            return true;
        }
        if (o == null || getClass() != o.getClass()) {
            return false;
        }

        Transition that = (Transition) o;
        return Objects.equals(from, that.from) &&
                Objects.equals(to, that.to);
    }

    @Override
    public int hashCode() {
        return Objects.hash(from, to);
    }
}
