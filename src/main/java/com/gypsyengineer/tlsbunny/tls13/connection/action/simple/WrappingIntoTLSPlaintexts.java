package com.gypsyengineer.tlsbunny.tls13.connection.action.simple;

import com.gypsyengineer.tlsbunny.tls13.connection.action.AbstractAction;
import com.gypsyengineer.tlsbunny.tls13.connection.action.Action;
import com.gypsyengineer.tlsbunny.tls13.struct.*;
import com.gypsyengineer.tlsbunny.tls13.utils.TLS13Utils;

import java.io.IOException;

import static com.gypsyengineer.tlsbunny.utils.WhatTheHell.whatTheHell;

public class WrappingIntoTLSPlaintexts extends AbstractAction {

    private ContentType type;
    private ProtocolVersion version = ProtocolVersion.TLSv12;

    public WrappingIntoTLSPlaintexts type(ContentType type) {
        this.type = type;
        return this;
    }

    public WrappingIntoTLSPlaintexts version(ProtocolVersion version) {
        this.version = version;
        return this;
    }

    @Override
    public String name() {
        return String.format("wrapping into TLSPlaintext (%s, %s)", type, version);
    }

    @Override
    public Action run() throws IOException {
        if (version == null) {
            throw whatTheHell("version is null!");
        }

        if (type == null) {
            throw whatTheHell("content type is null!");
        }

        byte[] content = new byte[in.remaining()];
        in.get(content);

        out = TLS13Utils.store(context.factory().createTLSPlaintexts(type, version, content));

        return this;
    }

}
