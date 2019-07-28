package com.gypsyengineer.tlsbunny.tls13.connection.action.composite;

import com.gypsyengineer.tlsbunny.tls13.connection.action.AbstractAction;
import com.gypsyengineer.tlsbunny.tls13.connection.action.Action;
import com.gypsyengineer.tlsbunny.tls13.connection.action.ActionFailed;
import com.gypsyengineer.tlsbunny.tls13.crypto.AEADException;
import com.gypsyengineer.tlsbunny.tls13.struct.ContentType;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.io.IOException;

public class IncomingApplicationData extends AbstractAction {

    private static final Logger logger = LogManager.getLogger(IncomingApplicationData.class);

    @Override
    public String name() {
        return "application data";
    }

    @Override
    public Action run() throws AEADException, ActionFailed, IOException {
        byte[] data = processEncrypted(
                context.applicationDataDecryptor(), ContentType.application_data);
        logger.info("received data ({} bytes): {}", data.length, new String(data));

        return this;
    }

}
