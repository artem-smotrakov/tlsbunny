package com.gypsyengineer.tlsbunny.tls13.connection.action.simple;

import com.gypsyengineer.tlsbunny.tls13.connection.action.AbstractAction;
import com.gypsyengineer.tlsbunny.tls13.connection.action.Action;
import com.gypsyengineer.tlsbunny.tls13.handshake.Context;
import com.gypsyengineer.tlsbunny.tls13.handshake.NegotiatorException;
import com.gypsyengineer.tlsbunny.tls13.struct.*;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.List;

public class GeneratingClientHello extends AbstractAction<GeneratingClientHello> {

    private static byte[] empty_session_id = new byte[0];

    private static final byte[] no_cookie = null;
    private static final NewSessionTicket no_ticket = null;
    public static final MaxFragmentLength no_max_fragment_length = null;

    private ProtocolVersion legacyVersion = ProtocolVersion.TLSv12;
    private ProtocolVersion[] versions = new ProtocolVersion[0];
    private SignatureScheme[] schemes = new SignatureScheme[0];
    private NamedGroup[] groups = new NamedGroup[0];
    private KeyShareEntryFactory[] keyShareEntryFactories = new KeyShareEntryFactory[0];
    private KeyShareFactory[] keyShareFactories = new KeyShareFactory[0];
    private byte[] cookie = no_cookie;
    private MaxFragmentLength maxFragmentLength = no_max_fragment_length;
    private CipherSuite[] cipherSuites = { CipherSuite.TLS_AES_128_GCM_SHA256 };
    private NewSessionTicket ticket;
    private PskKeyExchangeMode[] pskKeyExchangeModes;

    public static GeneratingClientHello generatingClientHello() {
        return new GeneratingClientHello();
    }

    @Override
    public String name() {
        return "generating ClientHello";
    }

    public GeneratingClientHello legacyVersion(ProtocolVersion legacyVersion) {
        this.legacyVersion = legacyVersion;
        return this;
    }

    public GeneratingClientHello supportedVersions(ProtocolVersion... versions) {
        this.versions = versions;
        return this;
    }

    public GeneratingClientHello signatureSchemes(SignatureScheme... schemes) {
        this.schemes = schemes;
        return this;
    }

    public GeneratingClientHello groups(NamedGroup... groups) {
        this.groups = groups;
        return this;
    }

    public GeneratingClientHello keyShareEntries(
            KeyShareEntryFactory... keyShareEntryFactories) {

        this.keyShareEntryFactories = keyShareEntryFactories;
        return this;
    }

    public GeneratingClientHello keyShares(KeyShareFactory... keyShareFactories) {
        this.keyShareFactories = keyShareFactories;
        return this;
    }

    public GeneratingClientHello cookie(byte[] cookie) {
        this.cookie = cookie.clone();
        return this;
    }

    public GeneratingClientHello maxFragmentLength(int code) {
        this.maxFragmentLength = context.factory().createMaxFragmentLength(code);
        return this;
    }

    public GeneratingClientHello use(NewSessionTicket ticket) {
        this.ticket = ticket;
        return this;
    }

    public GeneratingClientHello pskKeyExchangeModes(PskKeyExchangeMode... modes) {
        pskKeyExchangeModes = modes;
        return this;
    }

    public GeneratingClientHello set(MaxFragmentLength maxFragmentLength) {
        this.maxFragmentLength = maxFragmentLength;
        return this;
    }

    public GeneratingClientHello cipherSuites(CipherSuite... cipherSuites) {
        this.cipherSuites = cipherSuites;
        return this;
    }

    @Override
    public Action run() throws IOException, NegotiatorException {
        List<Extension> extensions = new ArrayList<>();

        for (ProtocolVersion version : versions) {
            extensions.add(wrap(context.factory().createSupportedVersionForClientHello(version)));
        }

        for (SignatureScheme scheme : schemes) {
            extensions.add(wrap(context.factory().createSignatureSchemeList(scheme)));
        }

        if (groups.length > 0) {
            extensions.add(wrap(context.factory().createNamedGroupList(groups)));
        }

        for (KeyShareFactory factory : keyShareFactories) {
            extensions.add(wrap(factory.create(context)));
        }

        for (KeyShareEntryFactory factory : keyShareEntryFactories) {
            extensions.add(wrap(context.factory().createKeyShareForClientHello(
                    factory.create(context))));
        }

        if (cookie != no_cookie) {
            extensions.add(wrap(context.factory().createCookie(cookie)));
        }

        if (maxFragmentLength != no_max_fragment_length) {
            extensions.add(wrap(maxFragmentLength));
        }

        if (pskKeyExchangeModes != null) {
            extensions.add(wrap(pskKeyExchangeModes));
        }

        if (ticket != no_ticket) {
            // TODO: implement
        }

        ClientHello hello = context.factory().createClientHello(
                legacyVersion,
                createRandom(),
                empty_session_id,
                List.of(cipherSuites),
                List.of(CompressionMethod.None),
                extensions);

        out = ByteBuffer.wrap(hello.encoding());

        return this;
    }

    public interface KeyShareEntryFactory {
        KeyShareEntry create(Context context) throws IOException, NegotiatorException;
    }

    public interface KeyShareFactory {
        KeyShare create(Context context) throws IOException, NegotiatorException;
    }
}
