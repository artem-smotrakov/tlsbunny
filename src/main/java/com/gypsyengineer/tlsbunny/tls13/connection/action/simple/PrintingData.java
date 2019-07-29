package com.gypsyengineer.tlsbunny.tls13.connection.action.simple;

import com.gypsyengineer.tlsbunny.tls13.connection.action.AbstractAction;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class PrintingData extends AbstractAction<PrintingData> {

    private static final Logger logger = LogManager.getLogger(PrintingData.class);

    @Override
    public String name() {
        return "printing data";
    }

    @Override
    public PrintingData run() {
        byte[] data = new byte[in.remaining()];
        in.get(data);
        logger.info("received application data:\n{}", new String(data));

        return this;
    }

}
