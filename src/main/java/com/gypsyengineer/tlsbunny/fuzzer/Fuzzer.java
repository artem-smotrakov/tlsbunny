package com.gypsyengineer.tlsbunny.fuzzer;

// TODO: setting seed(long)
// TODO: add total()
public interface Fuzzer<T> {

    boolean canFuzz();
    T fuzz(T object);
    void moveOn();
    String state();
    void state(String string);
}
