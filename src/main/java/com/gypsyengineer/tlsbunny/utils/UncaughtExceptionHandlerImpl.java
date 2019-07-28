package com.gypsyengineer.tlsbunny.utils;

public class UncaughtExceptionHandlerImpl implements Thread.UncaughtExceptionHandler {

    private Throwable exception;

    @Override
    public synchronized void uncaughtException(Thread thread, Throwable exception) {
        this.exception = exception;
    }

    public synchronized Throwable exception() {
        return exception;
    }

    public synchronized boolean knowsSomething() {
        return exception != null;
    }
}
