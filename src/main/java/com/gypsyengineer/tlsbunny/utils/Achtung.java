package com.gypsyengineer.tlsbunny.utils;

/**
 * One of your favorite exceptions.
 */
public class Achtung extends RuntimeException {

    public static final String prefix = "achtung! ";

    public Achtung(String message) {
        super(prefix + message);
    }

    public Achtung(String message, Throwable e) {
        super(prefix + message, e);
    }

    // a couple of factory methods

    public static Achtung achtung(String template, Object... objects) {
        return new Achtung(String.format(template, objects));
    }

    public static Achtung achtung(Throwable e, String template, Object... objects) {
        return new Achtung(String.format(template, objects), e);
    }
}
