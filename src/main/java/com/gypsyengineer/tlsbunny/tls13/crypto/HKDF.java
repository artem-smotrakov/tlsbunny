package com.gypsyengineer.tlsbunny.tls13.crypto;

import com.gypsyengineer.tlsbunny.tls13.struct.Handshake;
import com.gypsyengineer.tlsbunny.tls13.struct.HkdfLabel;
import com.gypsyengineer.tlsbunny.tls13.struct.StructFactory;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import javax.crypto.Mac;
import static com.gypsyengineer.tlsbunny.utils.Utils.concatenate;
import static com.gypsyengineer.tlsbunny.utils.WhatTheHell.whatTheHell;

import javax.crypto.spec.SecretKeySpec;

public class HKDF {

    private final int hashLen;
    private final Mac mac;
    private final TranscriptHash transcriptHash;
    private final StructFactory factory;

    private HKDF(int hashLength, Mac mac, TranscriptHash transcriptHash, 
            StructFactory factory) {
        
        this.hashLen = hashLength;
        this.mac = mac;
        this.transcriptHash = transcriptHash;
        this.factory = factory;
    }

    public int getHashLength() {
        return hashLen;
    }

    // HKDF-Extract(salt, IKM) -> PRK
    public byte[] extract(byte[] salt, byte[] IKM) {
        if (salt == null) {
            throw new IllegalArgumentException("salt is null");
        }

        if (IKM == null) {
            throw new IllegalArgumentException("IKM is null");
        }

        return hmac(salt, IKM);
    }

    // HKDF-Expand(PRK, info, L) -> OKM
    public byte[] expand(byte[] PRK, byte[] info, int L) {
        if (PRK == null) {
            throw new IllegalArgumentException("PRK is null");
        }

        if (info == null) {
            throw new IllegalArgumentException("info is null");
        }

        int maxLen = 255 * hashLen;
        if (L > maxLen) {
            throw new IllegalArgumentException("L > maxLen");
        }

        int N = (int) Math.ceil((double) L / hashLen);
        ByteBuffer T = ByteBuffer.allocate(N * hashLen);
        byte[] t = new byte[0];
        mac.reset();

        try {
            mac.init(new SecretKeySpec(PRK, mac.getAlgorithm()));
        } catch (InvalidKeyException e) {
            throw whatTheHell("InvalidKeyException should not occur!", e);
        }

        for (int i = 1; i <= N; i++) {
            t = mac.doFinal(concatenate(t, info, new byte[] { (byte) i }));
            T.put(t);
        }

        return Arrays.copyOf(T.array(), L);
    }

    // HKDF-Expand-Label(Secret, Label, Context, Length) =
    //     HKDF-Expand(Secret, HkdfLabel, Length)
    public byte[] expandLabel(byte[] secret, byte[] label, byte[] context, int length)
            throws IOException {

        return expand(secret, 
                createHkdfLabel(length, label, context).encoding(),
                length);
    }

    // Derive-Secret(Secret, Label, Messages) =
    //        HKDF-Expand-Label(Secret, Label,
    //                          Transcript-Hash(Messages), Hash.length)
    public byte[] deriveSecret(byte[] secret, byte[] label, Handshake... messages)
            throws IOException {

        return expandLabel(secret, label, transcriptHash.compute(messages), hashLen);
    }

    // HMAC-Hash() function
    public byte[] hmac(byte[] key, byte[] input) {
        if (key == null) {
            throw new IllegalArgumentException("key is null");
        }

        if (input == null) {
            throw new IllegalArgumentException("input is null");
        }

        mac.reset();

        try {
            mac.init(new RawKey(key, mac.getAlgorithm()));
        } catch (InvalidKeyException e) {
            throw whatTheHell("InvalidKeyException should not occur!", e);
        }
        return mac.doFinal(input);
    }

    public static HKDF create(String algorithm, StructFactory factory) 
            throws NoSuchAlgorithmException {

        return new HKDF(
                MessageDigest.getInstance(algorithm).getDigestLength(),
                getHmac(algorithm),
                TranscriptHash.create(algorithm), 
                factory);
    }

    private static Mac getHmac(String hashAlgorithm) throws NoSuchAlgorithmException {
        return Mac.getInstance("Hmac" + hashAlgorithm.replace("-", ""));
    }

    private HkdfLabel createHkdfLabel(int length, byte[] label, byte[] context) {
        byte[] tls13_label = concatenate("tls13 ".getBytes(), label);
        if (tls13_label.length > HkdfLabel.max_label_length) {
            throw new IllegalArgumentException();
        }

        if (context.length > HkdfLabel.max_context_length) {
            throw new IllegalArgumentException();
        }

        return factory.createHkdfLabel(length, tls13_label, context);
    }

}
