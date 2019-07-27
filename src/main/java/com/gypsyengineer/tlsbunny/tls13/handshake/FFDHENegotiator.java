package com.gypsyengineer.tlsbunny.tls13.handshake;

import com.gypsyengineer.tlsbunny.tls13.struct.KeyShareEntry;
import com.gypsyengineer.tlsbunny.tls13.struct.NamedGroup;
import com.gypsyengineer.tlsbunny.tls13.struct.StructFactory;
import com.gypsyengineer.tlsbunny.utils.Converter;

import java.io.IOException;
import java.math.BigInteger;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import javax.crypto.KeyAgreement;
import javax.crypto.interfaces.DHPublicKey;
import javax.crypto.spec.DHPublicKeySpec;

import static com.gypsyengineer.tlsbunny.utils.WhatTheHell.whatTheHell;

public class FFDHENegotiator extends AbstractNegotiator {

    private final FFDHEParameters ffdheParameters;
    private final KeyAgreement keyAgreement;
    private final KeyPairGenerator generator;

    private FFDHENegotiator(NamedGroup.FFDHE group,
                            FFDHEParameters ffdheParameters,
                            KeyAgreement keyAgreement,
                            KeyPairGenerator generator,
                            StructFactory factory) {

        super(group, factory);
        this.ffdheParameters = ffdheParameters;
        this.keyAgreement = keyAgreement;
        this.generator = generator;
    }

    public static FFDHENegotiator create(NamedGroup.FFDHE group, StructFactory factory) 
            throws NegotiatorException {

        try {
            KeyPairGenerator generator = KeyPairGenerator.getInstance("DiffieHellman");
            FFDHEParameters parameters = FFDHEParameters.create(group);
            generator.initialize(parameters.spec);

            return new FFDHENegotiator(
                    group,
                    parameters,
                    KeyAgreement.getInstance("DiffieHellman"),
                    generator, factory);
        } catch (NoSuchAlgorithmException | InvalidAlgorithmParameterException e) {
            throw new NegotiatorException(e);
        }
    }

    @Override
    public KeyShareEntry createKeyShareEntry() throws NegotiatorException {
        try {
            KeyPair kp = generator.generateKeyPair();
            keyAgreement.init(kp.getPrivate(), ffdheParameters.spec);

            BigInteger y = ((DHPublicKey) kp.getPublic()).getY();
            if (y.compareTo(BigInteger.ONE) <= 0 || y.compareTo(ffdheParameters.spec.getP()) >= 0) {
                throw whatTheHell("wrong y! (%s)", y.toString());
            }

            byte[] publicPart = Converter.leftPadding(
                    y.toByteArray(), ffdheParameters.spec.getP().toByteArray().length);

            return factory.createKeyShareEntry(group, publicPart);
        } catch (InvalidAlgorithmParameterException | InvalidKeyException e) {
            throw new NegotiatorException(e);
        }
    }

    @Override
    public void processKeyShareEntry(KeyShareEntry  entry) throws NegotiatorException {
        if (!group.equals(entry.namedGroup())) {
            throw whatTheHell("expected a key share entry with group %s but received %s",
                    group, entry.namedGroup());
        }

        try {
            PublicKey key = KeyFactory.getInstance("DiffieHellman").generatePublic(
                    new DHPublicKeySpec(
                            new BigInteger(1, entry.keyExchange().bytes()),
                            ffdheParameters.spec.getP(),
                            ffdheParameters.spec.getG()));

            keyAgreement.doPhase(key, true);
        } catch (NoSuchAlgorithmException | IOException | InvalidKeyException
                | InvalidKeySpecException e) {
            throw new NegotiatorException(e);
        }
    }

    @Override
    public byte[] generateSecret() {
        return keyAgreement.generateSecret();
    }

}
