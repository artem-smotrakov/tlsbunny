package com.gypsyengineer.tlsbunny.tls13.fuzzer;

import com.gypsyengineer.tlsbunny.fuzzer.Fuzzer;
import com.gypsyengineer.tlsbunny.tls13.struct.*;
import com.gypsyengineer.tlsbunny.output.Output;

import java.util.Arrays;
import java.util.Scanner;
import java.util.stream.Collectors;

public abstract class FuzzyStructFactory<T> extends StructFactoryWrapper
        implements StructFactory, Fuzzer<T> {

    protected Target[] targets;
    protected Output output;
    protected Fuzzer<T> fuzzer;

    public FuzzyStructFactory(StructFactory factory, Output output) {
        super(factory);
        this.output = output;
    }

    @Override
    public String toString() {
        return String.format("%s (targets = %s, fuzzer = %s)",
                getClass().getSimpleName(),
                Arrays.stream(targets)
                        .map(Object::toString)
                        .collect(Collectors.joining(",")),
                fuzzer.getClass().getSimpleName());
    }

    synchronized public FuzzyStructFactory targets(Target... targets) {
        this.targets = targets.clone();
        return this;
    }

    synchronized public FuzzyStructFactory targets(String... targets) {
        this.targets = new Target[targets.length];
        for (int i = 0; i < targets.length; i++) {
            this.targets[i] = Target.valueOf(targets[i]);
        }
        return this;
    }

    synchronized public Target[] targets() {
        return targets.clone();
    }

    synchronized public FuzzyStructFactory<T> fuzzer(Fuzzer<T> fuzzer) {
        this.fuzzer = fuzzer;
        return this;
    }

    synchronized public Fuzzer<T> fuzzer() {
        return fuzzer;
    }

    // implement methods from Fuzzer

    @Override
    synchronized public FuzzyStructFactory set(Output output) {
        this.output = output;
        return this;
    }

    @Override
    synchronized public Output output() {
        return output;
    }

    @Override
    synchronized public String state() {
        return String.format("%s:%s",
                Arrays.stream(targets)
                        .map(Enum::toString)
                        .collect(Collectors.joining( "-")),
                fuzzer.state());
    }

    @Override
    synchronized public void state(String string) {
        try (Scanner scanner = new Scanner(string)) {
            scanner.useDelimiter(":");
            targets(scanner.next().split("-"));
            scanner.skip(":");
            fuzzer.state(scanner.nextLine());
        }
    }

    @Override
    synchronized public boolean canFuzz() {
        return fuzzer.canFuzz();
    }

    @Override
    synchronized public void moveOn() {
        fuzzer.moveOn();
    }

    protected boolean targeted(Target target) {
        for (Target t : targets) {
            if (t == target) {
                return true;
            }
        }

        return false;
    }

}
