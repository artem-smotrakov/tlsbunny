package com.gypsyengineer.tlsbunny.utils;

public class UncaughtExceptionHandlerImpl implements Thread.UncaughtExceptionHandler {

    private Throwable exception;

    @Override
    synchronized public void uncaughtException(Thread thread, Throwable exception) {
        this.exception = exception;
    }

    synchronized public Throwable exception() {
        return exception;
    }

    synchronized public boolean knowsSomething() {
        return exception != null;
    }
}
