package com.gypsyengineer.tlsbunny.tls13.connection.action.composite;

import com.gypsyengineer.tlsbunny.tls13.connection.action.AbstractAction;
import com.gypsyengineer.tlsbunny.tls13.connection.action.Action;
import com.gypsyengineer.tlsbunny.tls13.crypto.AEAD;
import com.gypsyengineer.tlsbunny.tls13.crypto.AEADException;
import com.gypsyengineer.tlsbunny.tls13.crypto.AesGcm;
import com.gypsyengineer.tlsbunny.tls13.struct.*;
import com.gypsyengineer.tlsbunny.tls13.utils.TLS13Utils;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;

import static com.gypsyengineer.tlsbunny.tls13.struct.TLSInnerPlaintext.no_padding;

public class OutgoingClientCertificate extends AbstractAction {

    private byte[] cert_data;

    public Action certificate(String path) throws IOException {
        if (path == null || path.trim().isEmpty()) {
            throw  new IllegalArgumentException("no certificate specified");
        }

        cert_data = Files.readAllBytes(Paths.get(path));

        return this;
    }

    @Override
    public String name() {
        return "Certificate";
    }

    @Override
    public Action run() throws IOException, AEADException {
        Certificate certificate = createCertificate();
        Handshake handshake = toHandshake(certificate);
        context.setClientCertificate(handshake);
        out = TLS13Utils.store(encrypt(handshake));

        return this;
    }

    private Certificate createCertificate() throws IOException {
        // TODO: looks like this class can't be used on server side
        //       on server side, certificate_request_context should be empty
        byte[] certificate_request_context = new byte[0];
        if (context.certificateRequestContext() != null) {
            certificate_request_context = context.certificateRequestContext().bytes();
        }

        return context.factory().createCertificate(
                certificate_request_context,
                context.factory().createX509CertificateEntry(cert_data));
    }


    TLSPlaintext[] encrypt(Handshake message) throws IOException, AEADException {
        return context.factory().createTLSPlaintexts(
                ContentType.application_data,
                ProtocolVersion.TLSv12,
                encrypt(message.encoding()));
    }

    private byte[] encrypt(byte[] data) throws IOException, AEADException {
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
