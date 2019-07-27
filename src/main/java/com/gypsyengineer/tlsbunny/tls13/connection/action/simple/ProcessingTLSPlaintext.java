package com.gypsyengineer.tlsbunny.tls13.connection.action.simple;

import com.gypsyengineer.tlsbunny.tls13.connection.action.AbstractAction;
import com.gypsyengineer.tlsbunny.tls13.connection.action.ActionFailed;
import com.gypsyengineer.tlsbunny.tls13.struct.ContentType;
import com.gypsyengineer.tlsbunny.tls13.struct.TLSPlaintext;

import java.io.IOException;
import java.nio.ByteBuffer;

public class ProcessingTLSPlaintext extends AbstractAction<ProcessingTLSPlaintext> {

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
                    String.format("expected %s, but found %s", expectedType, type));
        }

        out = ByteBuffer.wrap(tlsPlaintext.getFragment());
        output.info("received a TLSPlaintext");

        return this;
    }

    public TLSPlaintext tlsPlaintext() {
        return tlsPlaintext;
    }

}
