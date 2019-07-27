package com.gypsyengineer.tlsbunny.tls13.connection.action.simple;

import com.gypsyengineer.tlsbunny.tls13.connection.action.AbstractAction;
import com.gypsyengineer.tlsbunny.tls13.struct.ChangeCipherSpec;

import java.io.IOException;
import java.nio.ByteBuffer;

public class GeneratingChangeCipherSpec extends AbstractAction {

    private int value = ChangeCipherSpec.valid_value;

    public GeneratingChangeCipherSpec set(int value) {
        this.value = value;
        return this;
    }

    @Override
    public String name() {
        return String.format("generating ChangeCipherSpec (%d)", value);
    }

    @Override
    public GeneratingChangeCipherSpec run() throws IOException {
        ChangeCipherSpec ccs = context.factory().createChangeCipherSpec(value);
        out = ByteBuffer.wrap(ccs.encoding());

        return this;
    }

}
