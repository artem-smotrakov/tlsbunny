package com.gypsyengineer.tlsbunny.tls13.connection.check;

import com.gypsyengineer.tlsbunny.tls13.connection.Engine;
import com.gypsyengineer.tlsbunny.tls13.handshake.Context;

/**
 * Note: a check is expected to be stateless.
 */
public interface Check {
    String name();
    Check set(Engine engine);
    Check set(Context context); // TODO: this method doesn't seem to be necessary since Engine provides the context
    Check run();
    boolean failed();
}
