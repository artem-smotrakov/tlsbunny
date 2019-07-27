package com.gypsyengineer.tlsbunny.tls13.connection.action.simple;

import com.gypsyengineer.tlsbunny.tls13.connection.action.AbstractAction;
import com.gypsyengineer.tlsbunny.tls13.struct.ContentType;
import com.gypsyengineer.tlsbunny.tls13.struct.ProtocolVersion;
import com.gypsyengineer.tlsbunny.tls13.utils.TLS13Utils;

import java.io.IOException;

public class GeneratingEmptyTLSPlaintext extends AbstractAction<GeneratingEmptyTLSPlaintext> {

    private static final byte[] EMPTY = new byte[0];

    private ContentType type;
    private ProtocolVersion version;

    public GeneratingEmptyTLSPlaintext type(ContentType type) {
        this.type = type;
        return this;
    }

    public GeneratingEmptyTLSPlaintext version(ProtocolVersion version) {
        this.version = version;
        return this;
    }

    @Override
    public String name() {
        return String.format("generating am empty TLSPlaintext (%s, %s)", type, version);
    }

    @Override
    public GeneratingEmptyTLSPlaintext run() throws IOException {
        out = TLS13Utils.store(context.factory().createTLSPlaintexts(type, version, EMPTY));
        return this;
    }

}
