package com.gypsyengineer.tlsbunny.tls13.connection.action.simple;

import com.gypsyengineer.tlsbunny.tls13.connection.action.AbstractAction;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.nio.ByteBuffer;

public class PreservingEncryptedApplicationData extends AbstractAction<PreservingEncryptedApplicationData> {

    private static final Logger logger = LogManager.getLogger(PreservingEncryptedApplicationData.class);

    @Override
    public String name() {
        return "preserving encrypted application data";
    }

    @Override
    public PreservingEncryptedApplicationData run() {
        byte[] data = new byte[in.remaining()];
        in.get(data);
        applicationDataOut = ByteBuffer.wrap(data);
        logger.info("preserved {} bytes of encrypted application data", data.length);

        return this;
    }

}
