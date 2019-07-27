package com.gypsyengineer.tlsbunny.tls13.connection.action;

public class ActionFailed extends Exception {

    public ActionFailed(String message) {
        super(message);
    }

    public ActionFailed(Throwable e) {
        super(e);
    }
}
