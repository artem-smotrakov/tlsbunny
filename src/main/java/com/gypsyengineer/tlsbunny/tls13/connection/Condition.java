package com.gypsyengineer.tlsbunny.tls13.connection;

import com.gypsyengineer.tlsbunny.tls13.handshake.Context;

public interface Condition {

    boolean met(Context context);

    static boolean serverNotDone(Context context) {
        return !context.receivedServerFinished() && !context.hasAlert();
    }

    static boolean applicationDataNotReceived(Context context) {
        return !context.receivedApplicationData() && !context.hasAlert();
    }
}
