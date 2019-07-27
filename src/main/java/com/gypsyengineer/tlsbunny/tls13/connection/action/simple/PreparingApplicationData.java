package com.gypsyengineer.tlsbunny.tls13.connection.action.simple;

import com.gypsyengineer.tlsbunny.tls13.connection.action.AbstractAction;
import com.gypsyengineer.tlsbunny.tls13.connection.action.Action;

import java.nio.ByteBuffer;

public class PreparingApplicationData extends AbstractAction {

    private byte[] data;

    public PreparingApplicationData(byte[] data) {
        this.data = data;
    }

    public PreparingApplicationData() {
        this(new byte[0]);
    }

    @Override
    public String name() {
        return "generating application data";
    }

    public PreparingApplicationData data(String string) {
        data = string.getBytes();
        return this;
    }

    @Override
    public Action run() {
        out = ByteBuffer.wrap(data);
        return this;
    }

}
