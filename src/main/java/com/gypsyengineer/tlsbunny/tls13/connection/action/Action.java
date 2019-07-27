package com.gypsyengineer.tlsbunny.tls13.connection.action;

import com.gypsyengineer.tlsbunny.tls13.crypto.AEADException;
import com.gypsyengineer.tlsbunny.tls13.handshake.Context;
import com.gypsyengineer.tlsbunny.tls13.handshake.NegotiatorException;
import com.gypsyengineer.tlsbunny.output.Output;

import java.io.IOException;
import java.nio.ByteBuffer;

public interface Action {
    String name();
    Action set(Output output);
    Action set(Context context);
    Action run() throws ActionFailed, AEADException, NegotiatorException, IOException;

    Action in(byte[] bytes);
    Action in(ByteBuffer buffer);
    ByteBuffer out();

    Action applicationData(ByteBuffer buffer);
    ByteBuffer applicationData();
}
