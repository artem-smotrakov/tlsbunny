package com.gypsyengineer.tlsbunny.utils;

/**
 * One of your favorite exceptions.
 * It usually means that something unexpectedly went wrong.
 */
public class WhatTheHell extends RuntimeException {

    public static final String prefix = "what the hell? ";

    public WhatTheHell(String message) {
        super(prefix + message);
    }

    public WhatTheHell(String message, Throwable e) {
        super(prefix + message, e);
    }

    // a couple of factory methods

    public static WhatTheHell whatTheHell(String template, Object... objects) {
        return new WhatTheHell(String.format(template, objects));
    }

    public static WhatTheHell whatTheHell(Throwable e, String template, Object... objects) {
        return new WhatTheHell(String.format(template, objects), e);
    }

    public static WhatTheHell whatTheHell(String message, Throwable e) {
        return new WhatTheHell(message, e);
    }
}
