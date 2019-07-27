package com.gypsyengineer.tlsbunny.tls13.connection.action.composite;

import com.gypsyengineer.tlsbunny.tls13.connection.action.AbstractAction;
import com.gypsyengineer.tlsbunny.tls13.connection.action.Action;
import com.gypsyengineer.tlsbunny.tls13.connection.action.ActionFailed;
import com.gypsyengineer.tlsbunny.tls13.crypto.AEADException;
import com.gypsyengineer.tlsbunny.tls13.struct.ContentType;

import java.io.IOException;

public class IncomingApplicationData extends AbstractAction {

    @Override
    public String name() {
        return "application data";
    }

    @Override
    public Action run() throws AEADException, ActionFailed, IOException {
        byte[] data = processEncrypted(
                context.applicationDataDecryptor(), ContentType.application_data);
        output.info("received data (%d bytes)%n%s", data.length, new String(data));

        return this;
    }

}
