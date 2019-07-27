package com.gypsyengineer.tlsbunny.tls13.state;

public interface Fact<T> {
    String name();
    T value();
    T[] values();
}
