package com.gypsyengineer.tlsbunny.tls13.state;

import java.util.HashMap;
import java.util.Map;
import java.util.Objects;

import static com.gypsyengineer.tlsbunny.utils.WhatTheHell.whatTheHell;

public class State {

    private final Map<String, Fact> facts = new HashMap<>();

    public static State state(Fact... facts) {
        Objects.requireNonNull(facts, "facts can't be null!");
        if (facts.length == 0) {
            throw whatTheHell("no facts provided!");
        }

        State state = new State();
        for (Fact fact : facts) {
            state.add(fact);
        }

        return state;
    }

    private State() {}

    private State add(Fact fact) {
        Objects.requireNonNull(fact.name(), "hey! name can't be null!");
        facts.put(fact.name(), fact);
        return this;
    }

    public boolean contains(String name) {
        Objects.requireNonNull(name, "hey! name can't be null!");
        return facts.containsKey(name);
    }

    public Fact get(String name) {
        Objects.requireNonNull(name, "hey! name can't be null!");
        return facts.get(name);
    }

    public Fact[] facts() {
        Fact[] array = new Fact[facts.size()];

        int i = 0;
        for (Map.Entry<String, Fact> entry : facts.entrySet()) {
            array[i++] = entry.getValue();
        }

        return array;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) {
            return true;
        }
        if (o == null || getClass() != o.getClass()) {
            return false;
        }

        State state = (State) o;
        return Objects.equals(facts, state.facts);
    }

    @Override
    public int hashCode() {
        return Objects.hash(facts);
    }
}
