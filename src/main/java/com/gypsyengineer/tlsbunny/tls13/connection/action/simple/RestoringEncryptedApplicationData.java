package com.gypsyengineer.tlsbunny.tls13.connection.action.simple;

import com.gypsyengineer.tlsbunny.tls13.connection.action.AbstractAction;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.nio.ByteBuffer;

public class RestoringEncryptedApplicationData
        extends AbstractAction<RestoringEncryptedApplicationData> {

    private static final Logger logger = LogManager.getLogger(RestoringEncryptedApplicationData.class);

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
        logger.info("restored {} bytes of encrypted application data", data.length);

        return this;
    }

}
