package com.gypsyengineer.tlsbunny.tls13.connection.action.composite;

import com.gypsyengineer.tlsbunny.tls13.connection.action.AbstractAction;
import com.gypsyengineer.tlsbunny.tls13.struct.ChangeCipherSpec;
import com.gypsyengineer.tlsbunny.tls13.struct.ContentType;
import com.gypsyengineer.tlsbunny.tls13.struct.ProtocolVersion;
import com.gypsyengineer.tlsbunny.tls13.struct.TLSPlaintext;
import com.gypsyengineer.tlsbunny.tls13.utils.TLS13Utils;

import java.io.IOException;

public class OutgoingChangeCipherSpec extends AbstractAction {

    private int value = ChangeCipherSpec.valid_value;

    public OutgoingChangeCipherSpec set(int value) {
        this.value = value;
        return this;
    }

    @Override
    public String name() {
        return String.format("generating ChangeCipherSpec (%d)", value);
    }

    @Override
    public OutgoingChangeCipherSpec run() throws IOException {
        ChangeCipherSpec ccs = context.factory().createChangeCipherSpec(value);

        TLSPlaintext[] tlsPlaintexts = context.factory().createTLSPlaintexts(
                ContentType.change_cipher_spec,
                ProtocolVersion.TLSv12,
                ccs.encoding());

        out = TLS13Utils.store(tlsPlaintexts);

        return this;
    }

}
