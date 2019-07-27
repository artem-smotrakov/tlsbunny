package com.gypsyengineer.tlsbunny.tls13.connection.action.composite;

import com.gypsyengineer.tlsbunny.tls13.connection.action.AbstractAction;
import com.gypsyengineer.tlsbunny.tls13.connection.action.Action;
import com.gypsyengineer.tlsbunny.tls13.connection.action.ActionFailed;
import com.gypsyengineer.tlsbunny.tls13.crypto.AEAD;
import com.gypsyengineer.tlsbunny.tls13.crypto.AEADException;
import com.gypsyengineer.tlsbunny.tls13.handshake.NegotiatorException;
import com.gypsyengineer.tlsbunny.tls13.handshake.Constants;
import com.gypsyengineer.tlsbunny.tls13.struct.*;

import static com.gypsyengineer.tlsbunny.tls13.handshake.Constants.zero_hash_value;
import static com.gypsyengineer.tlsbunny.tls13.handshake.Constants.zero_salt;
import static com.gypsyengineer.tlsbunny.tls13.utils.TLS13Utils.findKeyShare;
import static com.gypsyengineer.tlsbunny.tls13.utils.TLS13Utils.findSupportedVersion;
import static com.gypsyengineer.tlsbunny.utils.Utils.concatenate;
import static com.gypsyengineer.tlsbunny.utils.Utils.zeroes;

import java.io.IOException;

public class IncomingServerHello extends AbstractAction {

    @Override
    public String name() {
        return "ServerHello";
    }

    @Override
    public Action run()
            throws ActionFailed, NegotiatorException, IOException, AEADException {

        TLSPlaintext tlsPlaintext = context.factory().parser().parseTLSPlaintext(in);

        if (tlsPlaintext.containsAlert()) {
            Alert alert = context.factory().parser().parseAlert(tlsPlaintext.getFragment());
            context.setAlert(alert);
            throw new ActionFailed(String.format("received an alert: %s", alert));
        }

        if (!tlsPlaintext.containsHandshake()) {
            throw new ActionFailed("expected a handshake message");
        }

        Handshake handshake = context.factory().parser()
                .parseHandshake(tlsPlaintext.getFragment());

        if (!handshake.containsServerHello()) {
            throw new ActionFailed("expected a ServerHello message");
        }

        processServerHello(handshake);

        return this;
    }

    private void processServerHello(Handshake handshake)
            throws ActionFailed, IOException, NegotiatorException, AEADException {

        ServerHello serverHello = context.factory().parser()
                .parseServerHello(handshake.getBody());

        if (!context.suite().equals(serverHello.cipherSuite())) {
            output.info("expected cipher suite: %s", context.suite());
            output.info("received cipher suite: %s", serverHello.cipherSuite());
            throw new ActionFailed("unexpected ciphersuite");
        }

        SupportedVersions.ServerHello selected_version = findSupportedVersion(
                context.factory(), serverHello);
        output.info("selected version: %s", selected_version);

        // TODO: we look for only first key share, but there may be multiple key shares
        KeyShare.ServerHello keyShare = findKeyShare(context.factory(), serverHello);
        NamedGroup group = context.negotiator().group();
        if (!group.equals(keyShare.getServerShare().namedGroup())) {
            output.info("expected groups: %s", group);
            output.info("received groups: %s", keyShare.getServerShare().namedGroup());
            throw new RuntimeException("unexpected groups");
        }

        context.negotiator().processKeyShareEntry(keyShare.getServerShare());
        context.dh_shared_secret(context.negotiator().generateSecret());

        context.setServerHello(handshake);

        byte[] psk = zeroes(context.hkdf().getHashLength());

        Handshake wrappedClientHello = context.getFirstClientHello();

        context.early_secret(context.hkdf().extract(zero_salt, psk));
        context.binder_key(context.hkdf().deriveSecret(
                context.early_secret(),
                concatenate(Constants.ext_binder(), Constants.res_binder())));
        context.client_early_traffic_secret(context.hkdf().deriveSecret(
                context.early_secret(),
                Constants.c_e_traffic(),
                wrappedClientHello));
        context.early_exporter_master_secret(context.hkdf().deriveSecret(
                context.early_secret(),
                Constants.e_exp_master(),
                wrappedClientHello));

        context.handshake_secret_salt(context.hkdf().deriveSecret(
                context.early_secret(), Constants.derived()));

        context.handshake_secret(context.hkdf().extract(
                context.handshake_secret_salt(), context.dh_shared_secret()));
        context.client_handshake_traffic_secret(context.hkdf().deriveSecret(
                context.handshake_secret(),
                Constants.c_hs_traffic(),
                wrappedClientHello, handshake));
        context.server_handshake_traffic_secret(context.hkdf().deriveSecret(
                context.handshake_secret(),
                Constants.s_hs_traffic(),
                wrappedClientHello, handshake));
        context.master_secret(context.hkdf().extract(
                context.hkdf().deriveSecret(
                        context.handshake_secret(),
                        Constants.derived()),
                zeroes(context.hkdf().getHashLength())));

        context.client_handshake_write_key(context.hkdf().expandLabel(
                context.client_handshake_traffic_secret(),
                Constants.key(),
                zero_hash_value,
                context.suite().keyLength()));
        context.client_handshake_write_iv(context.hkdf().expandLabel(
                context.client_handshake_traffic_secret(),
                Constants.iv(),
                zero_hash_value,
                context.suite().ivLength()));
        context.server_handshake_write_key(context.hkdf().expandLabel(
                context.server_handshake_traffic_secret(),
                Constants.key(),
                zero_hash_value,
                context.suite().keyLength()));
        context.server_handshake_write_iv(context.hkdf().expandLabel(
                context.server_handshake_traffic_secret(),
                Constants.iv(),
                zero_hash_value,
                context.suite().ivLength()));
        context.finished_key(context.hkdf().expandLabel(
                context.client_handshake_traffic_secret(),
                Constants.finished(),
                zero_hash_value,
                context.hkdf().getHashLength()));

        context.handshakeEncryptor(AEAD.createEncryptor(
                context.suite().cipher(),
                context.client_handshake_write_key(),
                context.client_handshake_write_iv()));
        context.handshakeDecryptor(AEAD.createDecryptor(
                context.suite().cipher(),
                context.server_handshake_write_key(),
                context.server_handshake_write_iv()));
    }

}
