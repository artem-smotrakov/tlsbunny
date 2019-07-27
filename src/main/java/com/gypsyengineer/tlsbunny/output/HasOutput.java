package com.gypsyengineer.tlsbunny.output;

/**
 * Indicates that an object can take an Output instance.
 */
public interface HasOutput<T> {
    T set(Output output);
    Output output();
}
