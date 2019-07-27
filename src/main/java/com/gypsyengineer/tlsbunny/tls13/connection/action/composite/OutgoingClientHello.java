package com.gypsyengineer.tlsbunny.tls13.connection.action.composite;

import com.gypsyengineer.tlsbunny.tls13.connection.action.AbstractAction;
import com.gypsyengineer.tlsbunny.tls13.connection.action.Action;
import com.gypsyengineer.tlsbunny.tls13.handshake.NegotiatorException;
import com.gypsyengineer.tlsbunny.tls13.struct.*;
import com.gypsyengineer.tlsbunny.tls13.utils.TLS13Utils;

import java.io.IOException;
import java.util.List;

public class OutgoingClientHello extends AbstractAction {

    private static final byte[] empty_session_id = new byte[0];

    @Override
    public String name() {
        return "ClientHello";
    }

    @Override
    public Action run() throws IOException, NegotiatorException {
        List<Extension> extensions = List.of(
                wrap(context.factory().createSupportedVersionForClientHello(
                        ProtocolVersion.TLSv13)),
                wrap(context.factory().createSignatureSchemeList(context.scheme())),
                wrap(context.factory().createNamedGroupList(context.negotiator().group())),
                wrap(context.factory().createKeyShareForClientHello(
                        context.negotiator().createKeyShareEntry())));

        ClientHello hello = context.factory().createClientHello(ProtocolVersion.TLSv12,
                createRandom(),
                empty_session_id,
                List.of(CipherSuite.TLS_AES_128_GCM_SHA256),
                List.of(context.factory().createCompressionMethod(0)),
                extensions);

        Handshake handshake = toHandshake(hello);
        TLSPlaintext[] tlsPlaintexts = context.factory().createTLSPlaintexts(
                ContentType.handshake,
                ProtocolVersion.TLSv10,
                handshake.encoding());

        out = TLS13Utils.store(tlsPlaintexts);

        if (context.hasFirstClientHello() && context.hasSecondClientHello()) {
            throw new IOException("already received two ClientHello messages");
        }

        if (context.hasFirstClientHello()) {
            context.setSecondClientHello(handshake);
        } else {
            context.setFirstClientHello(handshake);
        }

        return this;
    }
}
