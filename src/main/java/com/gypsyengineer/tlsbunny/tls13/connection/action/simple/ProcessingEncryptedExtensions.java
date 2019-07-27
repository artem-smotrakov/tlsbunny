package com.gypsyengineer.tlsbunny.tls13.connection.action.simple;

import com.gypsyengineer.tlsbunny.tls13.connection.action.AbstractAction;
import com.gypsyengineer.tlsbunny.tls13.connection.action.Action;

public class ProcessingEncryptedExtensions extends AbstractAction<ProcessingEncryptedExtensions> {

    @Override
    public String name() {
        return "processing an EncryptedExtensions";
    }

    @Override
    public Action run() {
        context.factory().parser().parseEncryptedExtensions(in);
        output.info("received an EncryptedExtensions message");

        return this;
    }

}
