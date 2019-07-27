package com.gypsyengineer.tlsbunny.tls13.connection.action.simple;

import com.gypsyengineer.tlsbunny.tls13.connection.action.AbstractAction;

public class PrintingData extends AbstractAction<PrintingData> {

    @Override
    public String name() {
        return "printing data";
    }

    @Override
    public PrintingData run() {
        byte[] data = new byte[in.remaining()];
        in.get(data);
        output.info("received application data:%n%s", new String(data));

        return this;
    }

}
