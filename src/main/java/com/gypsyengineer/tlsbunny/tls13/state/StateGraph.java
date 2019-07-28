package com.gypsyengineer.tlsbunny.tls13.state;

import java.util.*;

import static com.gypsyengineer.tlsbunny.tls13.state.Transition.transition;
import static com.gypsyengineer.tlsbunny.utils.WhatTheHell.whatTheHell;

public class StateGraph {

    private final Set<State> states = new HashSet<>();
    private final List<Transition> transitions = new ArrayList<>();
    private State current;

    public static StateGraph stateGraph() {
        return new StateGraph();
    }

    private StateGraph() {}

    public StateGraph add(State state) {
        check(state);
        states.add(state);
        transitions.add(transition(current, state));
        current = state;
        return this;
    }

    private void check(State state) {
        Objects.requireNonNull(state, "hey! state can't be null");

        Fact[] facts = state.facts();
        if (facts.length == 0) {
            throw whatTheHell("state has to have at least one fact!");
        }

        // all states should have the same set of facts
        // take one state in the graph, and compare the state with it
        if (states.isEmpty()) {
            return;
        }

        Fact[] requiredFacts = states.iterator().next().facts();
        if (requiredFacts.length != facts.length) {
            throw whatTheHell("states have to have the same number of facts!");
        }

        for (Fact requiredFact : requiredFacts) {
            boolean found = false;
            for (Fact fact : facts) {
                if (requiredFact.name().equals(fact.name())) {
                    found = true;
                    break;
                }
            }

            if (!found) {
                throw whatTheHell("required fact '%s' not found!", requiredFact.name());
            }
        }
    }
}
