package com.gypsyengineer.tlsbunny.tls13.connection.action.composite;

import com.gypsyengineer.tlsbunny.tls13.connection.action.AbstractAction;
import com.gypsyengineer.tlsbunny.tls13.connection.action.Action;
import com.gypsyengineer.tlsbunny.tls13.connection.action.ActionFailed;
import com.gypsyengineer.tlsbunny.tls13.crypto.AEAD;
import com.gypsyengineer.tlsbunny.tls13.crypto.AEADException;
import com.gypsyengineer.tlsbunny.tls13.crypto.AesGcm;
import com.gypsyengineer.tlsbunny.tls13.crypto.TranscriptHash;
import com.gypsyengineer.tlsbunny.tls13.handshake.Constants;
import com.gypsyengineer.tlsbunny.tls13.struct.ContentType;
import com.gypsyengineer.tlsbunny.tls13.struct.Finished;
import com.gypsyengineer.tlsbunny.tls13.struct.Handshake;
import com.gypsyengineer.tlsbunny.tls13.struct.ProtocolVersion;
import com.gypsyengineer.tlsbunny.tls13.struct.TLSInnerPlaintext;

import static com.gypsyengineer.tlsbunny.tls13.handshake.Constants.zero_hash_value;
import static com.gypsyengineer.tlsbunny.tls13.struct.TLSInnerPlaintext.no_padding;

import com.gypsyengineer.tlsbunny.tls13.struct.TLSPlaintext;
import com.gypsyengineer.tlsbunny.tls13.utils.TLS13Utils;

import java.io.IOException;
import java.security.NoSuchAlgorithmException;

public class OutgoingFinished extends AbstractAction {

    @Override
    public String name() {
        return "Finished";
    }

    @Override
    public Action run() throws IOException, AEADException, ActionFailed {
        Finished finished = createFinished();
        Handshake handshake = toHandshake(finished);
        context.setClientFinished(handshake);

        context.resumption_master_secret(context.hkdf().deriveSecret(
                context.master_secret(),
                Constants.res_master(),
                context.allMessages()));
        context.client_application_write_key(context.hkdf().expandLabel(
                context.client_application_traffic_secret_0(),
                Constants.key(),
                zero_hash_value,
                context.suite().keyLength()));
        context.client_application_write_iv(context.hkdf().expandLabel(
                context.client_application_traffic_secret_0(),
                Constants.iv(),
                zero_hash_value,
                context.suite().ivLength()));
        context.server_application_write_key(context.hkdf().expandLabel(
                context.server_application_traffic_secret_0(),
                Constants.key(),
                zero_hash_value,
                context.suite().keyLength()));
        context.server_application_write_iv(context.hkdf().expandLabel(
                context.server_application_traffic_secret_0(),
                Constants.iv(),
                zero_hash_value,
                context.suite().ivLength()));

        out = TLS13Utils.store(encrypt(handshake));

        context.applicationDataEncryptor(AEAD.createEncryptor(
                context.suite().cipher(),
                context.client_application_write_key(),
                context.client_application_write_iv()));
        context.applicationDataDecryptor(AEAD.createDecryptor(
                context.suite().cipher(),
                context.server_application_write_key(),
                context.server_application_write_iv()));

        return this;
    }

    private Finished createFinished() throws IOException, ActionFailed {
        try {
            byte[] verify_data = context.hkdf().hmac(
                    context.finished_key(),
                    TranscriptHash.compute(context.suite().hash(), context.allMessages()));

            return context.factory().createFinished(verify_data);
        } catch (NoSuchAlgorithmException e) {
            throw new ActionFailed(e);
        }
    }

    TLSPlaintext[] encrypt(Handshake message) throws AEADException, IOException {
        return context.factory().createTLSPlaintexts(
                ContentType.application_data,
                ProtocolVersion.TLSv12,
                encrypt(message.encoding()));
    }

    private byte[] encrypt(byte[] data) throws AEADException, IOException {
        TLSInnerPlaintext tlsInnerPlaintext = context.factory().createTLSInnerPlaintext(
                ContentType.handshake, data, no_padding);
        byte[] plaintext = tlsInnerPlaintext.encoding();

        context.handshakeEncryptor().start();
        context.handshakeEncryptor().updateAAD(
                AEAD.getAdditionalData(plaintext.length + AesGcm.tag_length_in_bytes));
        context.handshakeEncryptor().update(plaintext);

        return context.handshakeEncryptor().finish();
    }

}
