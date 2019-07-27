package com.gypsyengineer.tlsbunny.tls13.connection.action.simple;

import com.gypsyengineer.tlsbunny.tls13.connection.action.AbstractAction;
import com.gypsyengineer.tlsbunny.tls13.struct.EncryptedExtensions;

import java.io.IOException;
import java.nio.ByteBuffer;

public class GeneratingEncryptedExtensions
        extends AbstractAction<GeneratingEncryptedExtensions> {

    @Override
    public String name() {
        return "generating EncryptedExtensions";
    }

    @Override
    public GeneratingEncryptedExtensions run() throws IOException {
        EncryptedExtensions extensions = context.factory().createEncryptedExtensions();

        out = ByteBuffer.wrap(extensions.encoding());

        return this;
    }
}
