package com.gypsyengineer.tlsbunny.output;

import java.util.Objects;

public class Line {

    private final Level level;
    private final String value;

    public Line(Level level, String value) {
        this.level = level;
        this.value = value;
    }

    public Level level() {
        return level;
    }

    public String value() {
        return value;
    }

    boolean has(Level level) {
        return this.level.compareTo(level) >= 0;
    }

    public boolean contains(String string) {
        return value.contains(string);
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) {
            return true;
        }
        if (o == null || getClass() != o.getClass()) {
            return false;
        }
        Line line = (Line) o;
        return level == line.level &&
                Objects.equals(value, line.value);
    }

    @Override
    public int hashCode() {
        return Objects.hash(level, value);
    }
}
