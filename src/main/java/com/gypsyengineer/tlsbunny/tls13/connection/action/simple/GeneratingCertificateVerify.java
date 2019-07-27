package com.gypsyengineer.tlsbunny.tls13.connection.action.simple;

import com.gypsyengineer.tlsbunny.tls13.connection.action.AbstractAction;
import com.gypsyengineer.tlsbunny.tls13.connection.action.ActionFailed;
import com.gypsyengineer.tlsbunny.tls13.connection.action.Side;
import com.gypsyengineer.tlsbunny.tls13.crypto.AEADException;
import com.gypsyengineer.tlsbunny.tls13.crypto.TranscriptHash;
import com.gypsyengineer.tlsbunny.tls13.struct.*;
import com.gypsyengineer.tlsbunny.utils.Utils;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;

import static com.gypsyengineer.tlsbunny.utils.WhatTheHell.whatTheHell;

public class GeneratingCertificateVerify extends AbstractAction<GeneratingCertificateVerify> {

    private static final byte[] CERTIFICATE_VERIFY_PREFIX = new byte[64];
    static {
        for (int i=0; i<CERTIFICATE_VERIFY_PREFIX.length; i++) {
            CERTIFICATE_VERIFY_PREFIX[i] = 0x20;
        }
    }

    private static final byte[] ZERO = new byte[] { 0 };

    private static final byte[] CLIENT_CERTIFICATE_VERIFY_CONTEXT_STRING =
            "TLS 1.3, client CertificateVerify".getBytes();

    private static final byte[] SERVER_CERTIFICATE_VERIFY_CONTEXT_STRING =
            "TLS 1.3, server CertificateVerify".getBytes();

    private Side side;
    private byte[] key_data;

    public GeneratingCertificateVerify server() {
        side = Side.server;
        return this;
    }

    public GeneratingCertificateVerify client() {
        side = Side.client;
        return this;
    }

    public GeneratingCertificateVerify key(String path) throws IOException {
        if (path == null || path.trim().isEmpty()) {
            throw  new IllegalArgumentException("no certificate key specified");
        }

        key_data = Files.readAllBytes(Paths.get(path));

        return this;
    }

    @Override
    public String name() {
        return String.format("generating CertificateVerify (%s)", side);
    }

    @Override
    public GeneratingCertificateVerify run() throws IOException, AEADException, ActionFailed {
        try {
            byte[] content = Utils.concatenate(
                    CERTIFICATE_VERIFY_PREFIX,
                    contextString(),
                    ZERO,
                    TranscriptHash.compute(context.suite().hash(), context.allMessages()));

            Signature signature = Signature.getInstance("SHA256withECDSA");
            signature.initSign(
                    KeyFactory.getInstance("EC").generatePrivate(
                            new PKCS8EncodedKeySpec(key_data)));
            signature.update(content);

            CertificateVerify certificateVerify = context.factory().createCertificateVerify(
                    SignatureScheme.ecdsa_secp256r1_sha256, signature.sign());

            out = ByteBuffer.wrap(certificateVerify.encoding());
        } catch (NoSuchAlgorithmException | SignatureException
                | InvalidKeyException | InvalidKeySpecException e) {

            // TODO: can we get rid of these exceptions?
            throw new ActionFailed(e);
        }

        return this;
    }

    private byte[] contextString() {
        if (side == null) {
            throw whatTheHell("side not specified! (null)");
        }

        switch (side) {
            case client:
                return CLIENT_CERTIFICATE_VERIFY_CONTEXT_STRING;
            case server:
                return SERVER_CERTIFICATE_VERIFY_CONTEXT_STRING;
            default:
                throw whatTheHell("unexpected side: %s", side);
        }
    }
}
