package com.gypsyengineer.tlsbunny.tls13.connection.action.simple;

import com.gypsyengineer.tlsbunny.tls13.connection.action.AbstractAction;
import com.gypsyengineer.tlsbunny.tls13.connection.action.ActionFailed;
import com.gypsyengineer.tlsbunny.tls13.struct.ContentType;
import com.gypsyengineer.tlsbunny.tls13.struct.TLSPlaintext;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.io.IOException;
import java.nio.ByteBuffer;

public class ProcessingTLSPlaintext extends AbstractAction<ProcessingTLSPlaintext> {

    private static final Logger logger = LogManager.getLogger(ProcessingTLSPlaintext.class);

    public static final ContentType NO_TYPE_SPECIFIED = null;

    private ContentType expectedType = NO_TYPE_SPECIFIED;
    private TLSPlaintext tlsPlaintext;

    public ProcessingTLSPlaintext expect(ContentType type) {
        expectedType = type;
        return this;
    }

    @Override
    public String name() {
        return "processing a TLSPlaintext";
    }

    @Override
    public ProcessingTLSPlaintext run() throws ActionFailed, IOException {
        tlsPlaintext = context.factory().parser().parseTLSPlaintext(in);

        ContentType type = tlsPlaintext.getType();
        if (expectedType != NO_TYPE_SPECIFIED && !expectedType.equals(type)) {
            throw new ActionFailed(
                    String.format("expected {}, but found {}", expectedType, type));
        }

        out = ByteBuffer.wrap(tlsPlaintext.getFragment());
        logger.info("received a TLSPlaintext");

        return this;
    }

    public TLSPlaintext tlsPlaintext() {
        return tlsPlaintext;
    }

}
