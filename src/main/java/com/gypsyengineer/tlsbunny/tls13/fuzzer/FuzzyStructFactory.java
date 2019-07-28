package com.gypsyengineer.tlsbunny.tls13.fuzzer;

import com.gypsyengineer.tlsbunny.fuzzer.Fuzzer;
import com.gypsyengineer.tlsbunny.tls13.struct.StructFactory;

import java.util.Arrays;
import java.util.Scanner;
import java.util.stream.Collectors;

public abstract class FuzzyStructFactory<T> extends StructFactoryWrapper
        implements StructFactory, Fuzzer<T> {

    protected Target[] targets;
    protected Fuzzer<T> fuzzer;

    public FuzzyStructFactory(StructFactory factory) {
        super(factory);
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

    public synchronized FuzzyStructFactory targets(Target... targets) {
        this.targets = targets.clone();
        return this;
    }

    public synchronized FuzzyStructFactory targets(String... targets) {
        this.targets = new Target[targets.length];
        for (int i = 0; i < targets.length; i++) {
            this.targets[i] = Target.valueOf(targets[i]);
        }
        return this;
    }

    public synchronized Target[] targets() {
        return targets.clone();
    }

    public synchronized FuzzyStructFactory<T> fuzzer(Fuzzer<T> fuzzer) {
        this.fuzzer = fuzzer;
        return this;
    }

    public synchronized Fuzzer<T> fuzzer() {
        return fuzzer;
    }

    // implement methods from Fuzzer

    @Override
    public synchronized String state() {
        return String.format("%s:%s",
                Arrays.stream(targets)
                        .map(Enum::toString)
                        .collect(Collectors.joining( "-")),
                fuzzer.state());
    }

    @Override
    public synchronized void state(String string) {
        try (Scanner scanner = new Scanner(string)) {
            scanner.useDelimiter(":");
            targets(scanner.next().split("-"));
            scanner.skip(":");
            fuzzer.state(scanner.nextLine());
        }
    }

    @Override
    public synchronized boolean canFuzz() {
        return fuzzer.canFuzz();
    }

    @Override
    public synchronized void moveOn() {
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
