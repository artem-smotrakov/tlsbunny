package com.gypsyengineer.tlsbunny.tls13.state;

import java.util.Objects;

public class BooleanFact implements Fact<Boolean> {

    private static Boolean[] values = { Boolean.TRUE, Boolean.FALSE };

    private final String name;
    private final Boolean value;

    public static BooleanFact booleanFact(String name, Boolean value) {
        Objects.requireNonNull(name, "name can't be null!");
        return new BooleanFact(name, value);
    }

    private BooleanFact(String name, Boolean value) {
        this.name = name;
        this.value = value;
    }

    @Override
    public String name() {
        return name;
    }

    @Override
    public Boolean value() {
        return value;
    }

    @Override
    public Boolean[] values() {
        return values.clone();
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) {
            return true;
        }

        if (o == null || getClass() != o.getClass()) {
            return false;
        }

        BooleanFact that = (BooleanFact) o;
        return Objects.equals(name, that.name) &&
                Objects.equals(value, that.value);
    }

    @Override
    public int hashCode() {
        return Objects.hash(name, value);
    }
}
