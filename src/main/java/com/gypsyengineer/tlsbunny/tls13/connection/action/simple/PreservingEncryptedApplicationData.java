package com.gypsyengineer.tlsbunny.tls13.connection.action.simple;

import com.gypsyengineer.tlsbunny.tls13.connection.action.AbstractAction;

import java.nio.ByteBuffer;

public class PreservingEncryptedApplicationData extends AbstractAction<PreservingEncryptedApplicationData> {

    @Override
    public String name() {
        return "preserving encrypted application data";
    }

    @Override
    public PreservingEncryptedApplicationData run() {
        byte[] data = new byte[in.remaining()];
        in.get(data);
        applicationDataOut = ByteBuffer.wrap(data);
        output.info("preserved %d bytes of encrypted application data", data.length);

        return this;
    }

}
