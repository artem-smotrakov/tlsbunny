package com.gypsyengineer.tlsbunny.tls13.connection.action.simple;

import com.gypsyengineer.tlsbunny.tls13.connection.action.AbstractAction;
import com.gypsyengineer.tlsbunny.tls13.connection.action.Action;
import com.gypsyengineer.tlsbunny.tls13.handshake.Context;
import com.gypsyengineer.tlsbunny.tls13.struct.*;

import java.io.IOException;
import java.nio.ByteBuffer;

public class WrappingIntoHandshake extends AbstractAction {

    public static final ContextUpdater NOT_SPECIFIED = null;

    private HandshakeType type;
    private ContextUpdater contextUpdater;
    private Context.Element element;

    public WrappingIntoHandshake type(HandshakeType type) {
        this.type = type;
        return this;
    }

    public WrappingIntoHandshake run(ContextUpdater contextUpdater) {
        this.contextUpdater = contextUpdater;
        return this;
    }

    @Override
    public String name() {
        return String.format("wrapping into Handshake (%s)", type);
    }

    public WrappingIntoHandshake updateContext(Context.Element element) {
        this.element = element;
        return this;
    }

    @Override
    public Action run() throws IOException {
        byte[] content = new byte[in.remaining()];
        in.get(content);

        Handshake handshake = context.factory().createHandshake(type, content);

        if (contextUpdater != NOT_SPECIFIED) {
            contextUpdater.run(context, handshake);
        }

        if (element != null) {
            context.set(element, handshake);
        }

        out = ByteBuffer.wrap(handshake.encoding());

        return this;
    }

    public interface ContextUpdater {
        void run(Context context, Handshake handshake);
    }
}
