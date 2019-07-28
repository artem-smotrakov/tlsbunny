package com.gypsyengineer.tlsbunny.tls13.connection.action.simple;

import com.gypsyengineer.tlsbunny.tls13.connection.action.AbstractAction;
import com.gypsyengineer.tlsbunny.tls13.connection.action.Action;
import com.gypsyengineer.tlsbunny.tls13.handshake.NegotiatorException;
import com.gypsyengineer.tlsbunny.tls13.struct.ClientHello;
import com.gypsyengineer.tlsbunny.tls13.struct.KeyShare;
import com.gypsyengineer.tlsbunny.tls13.struct.KeyShareEntry;

import java.io.IOException;

import static com.gypsyengineer.tlsbunny.tls13.utils.TLS13Utils.findKeyShare;

public class NegotiatingServerDHSecret extends AbstractAction<NegotiatingServerDHSecret> {

    @Override
    public String name() {
        return "negotiating server DH secret";
    }

    @Override
    public Action run() throws IOException, NegotiatorException {
        // TODO: we only care about first client hello but there may be a second one
        ClientHello clientHello = context.factory().parser().parseClientHello(
                context.getFirstClientHello().getBody());

        // TODO: we look for only first key share, but there may be multiple key shares
        KeyShare.ClientHello keyShare = findKeyShare(context.factory(), clientHello);

        KeyShareEntry selectedKeyShareEntry = null;
        for (KeyShareEntry keyShareEntry : keyShare.getClientShares().toList()) {
            if (context.negotiator().group().equals(keyShareEntry.namedGroup())) {
                selectedKeyShareEntry = keyShareEntry;
            }
        }

        if (selectedKeyShareEntry == null) {
            throw new NegotiatorException(
                    String.format("could not find a key share with %s",
                            context.negotiator().group()));
        }

        context.negotiator().processKeyShareEntry(selectedKeyShareEntry);
        context.dh_shared_secret(context.negotiator().generateSecret());

        return this;
    }

}
