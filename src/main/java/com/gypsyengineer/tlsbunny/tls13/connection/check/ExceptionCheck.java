package com.gypsyengineer.tlsbunny.tls13.connection.check;

public class ExceptionCheck extends AbstractCheck {

    private Class clazz;
    private String message;

    public ExceptionCheck set(Class clazz) {
        this.clazz = clazz;
        return this;
    }

    public ExceptionCheck set(String message) {
        this.message = message;
        return this;
    }

    @Override
    public Check run() {
        failed = runImpl();
        return this;
    }

    @Override
    public String name() {
        return "no exception received";
    }

    private boolean runImpl() {
        Throwable exception = engine.exception();
        if (exception == null) {
            return true;
        }

        if (clazz != null && !clazz.equals(exception.getClass())) {
            return true;
        }

        if (message != null && !message.equals(exception.getMessage())) {
            return true;
        }

        return false;
    }

}
