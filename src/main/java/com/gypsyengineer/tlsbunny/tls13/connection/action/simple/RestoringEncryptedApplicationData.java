package com.gypsyengineer.tlsbunny.tls13.connection.action.simple;

import com.gypsyengineer.tlsbunny.tls13.connection.action.AbstractAction;

import java.nio.ByteBuffer;

public class RestoringEncryptedApplicationData
        extends AbstractAction<RestoringEncryptedApplicationData> {

    @Override
    public String name() {
        return "restoring encrypted application data";
    }

    @Override
    public RestoringEncryptedApplicationData run() {
        if (applicationDataIn.remaining() == 0) {
            return this;
        }

        byte[] data = new byte[applicationDataIn.remaining()];
        applicationDataIn.get(data);
        out = ByteBuffer.wrap(data);
        output.info("restored %d bytes of encrypted application data", data.length);

        return this;
    }

}
