package com.gypsyengineer.tlsbunny.tls13.connection.action.simple;

import com.gypsyengineer.tlsbunny.tls13.connection.action.AbstractAction;
import com.gypsyengineer.tlsbunny.tls13.connection.action.Action;
import com.gypsyengineer.tlsbunny.tls13.handshake.NegotiatorException;
import com.gypsyengineer.tlsbunny.tls13.struct.KeyShare;
import com.gypsyengineer.tlsbunny.tls13.struct.KeyShareEntry;
import com.gypsyengineer.tlsbunny.tls13.struct.NamedGroup;
import com.gypsyengineer.tlsbunny.tls13.struct.ServerHello;

import java.io.IOException;

import static com.gypsyengineer.tlsbunny.tls13.utils.TLS13Utils.findKeyShare;

public class NegotiatingClientDHSecret extends AbstractAction<NegotiatingClientDHSecret> {

    @Override
    public String name() {
        return "negotiating client DH secret";
    }

    @Override
    public Action run() throws IOException, NegotiatorException {
        ServerHello serverHello = context.factory().parser().parseServerHello(
                context.getServerHello().getBody());

        // TODO: we look for only first key share, but there may be multiple key shares
        KeyShare.ServerHello keyShare = findKeyShare(context.factory(), serverHello);

        KeyShareEntry keyShareEntry = keyShare.getServerShare();

        NamedGroup group = context.negotiator().group();
        if (!group.equals(keyShareEntry.namedGroup())) {
            output.info("expected groups: %s", group);
            output.info("received groups: %s", keyShareEntry.namedGroup());
            throw new NegotiatorException("unexpected groups");
        }
        context.negotiator().processKeyShareEntry(keyShareEntry);
        context.dh_shared_secret(context.negotiator().generateSecret());

        return this;
    }

}
