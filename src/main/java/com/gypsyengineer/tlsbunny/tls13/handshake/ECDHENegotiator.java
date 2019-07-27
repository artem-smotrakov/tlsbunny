package com.gypsyengineer.tlsbunny.tls13.handshake;

import com.gypsyengineer.tlsbunny.tls13.struct.KeyShareEntry;
import com.gypsyengineer.tlsbunny.tls13.struct.NamedGroup;
import com.gypsyengineer.tlsbunny.tls13.struct.StructFactory;
import com.gypsyengineer.tlsbunny.tls13.struct.UncompressedPointRepresentation;
import com.gypsyengineer.tlsbunny.utils.ECException;
import com.gypsyengineer.tlsbunny.utils.ECUtils;

import java.io.IOException;
import java.math.BigInteger;
import java.security.*;
import java.security.interfaces.ECPublicKey;
import java.security.spec.*;
import javax.crypto.KeyAgreement;

import static com.gypsyengineer.tlsbunny.tls13.utils.TLS13Utils.getCoordinateLength;
import static com.gypsyengineer.tlsbunny.utils.MathUtils.toBytes;
import static com.gypsyengineer.tlsbunny.utils.MathUtils.toPositiveBigInteger;

public class ECDHENegotiator extends AbstractNegotiator {

    private final SecpParameters secpParameters;
    private final KeyAgreement keyAgreement;
    private final KeyPairGenerator generator;

    // if true, the negotiator throws an exception if validation fails
    private boolean strictValidation = false;

    private ECDHENegotiator(NamedGroup.Secp group, SecpParameters secpParameters, 
            KeyAgreement keyAgreement, KeyPairGenerator generator, StructFactory factory) {
        
        super(group, factory);
        this.secpParameters = secpParameters;
        this.keyAgreement = keyAgreement;
        this.generator = generator;
    }

    public ECDHENegotiator strictValidation() {
        this.strictValidation = true;
        return this;
    }

    @Override
    public KeyShareEntry  createKeyShareEntry() throws NegotiatorException {
        try {
            KeyPair kp = generator.generateKeyPair();
            keyAgreement.init(kp.getPrivate());
            ECPoint W = ((ECPublicKey) kp.getPublic()).getW();

            // TODO: consider adding a self-check to make sure that the key
            //       passes checks defined by NIST and Section 5.2.2 of X9.62
            //       in other words:
            //
            //   validate(w);

            return factory.createKeyShareEntry(
                    group,
                    createUPR(W).encoding());
        } catch (InvalidKeyException | IOException e) {
            throw new NegotiatorException(e);
        }
    }
    
    @Override
    public void processKeyShareEntry(KeyShareEntry entry) throws NegotiatorException {
        if (!group.equals(entry.namedGroup())) {
            output.achtung("expected groups: %s", group);
            output.achtung("received groups: %s", entry.namedGroup());
            throw new NegotiatorException("unexpected groups");
        }

        try {
            ECPoint point = convertToECPoint(entry);
            validate(point);

            PublicKey key = KeyFactory.getInstance("EC").generatePublic(
                    new ECPublicKeySpec(
                            point,
                            secpParameters.ecParameterSpec));

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
    
    private ECPoint convertToECPoint(KeyShareEntry entry) 
            throws IOException {
        
        UncompressedPointRepresentation upr = 
                factory.parser().parseUncompressedPointRepresentation(
                        entry.keyExchange().bytes(),
                        getCoordinateLength(group));

        return new ECPoint(
                toPositiveBigInteger(upr.getX()),
                toPositiveBigInteger(upr.getY()));
    }

    private UncompressedPointRepresentation createUPR(ECPoint point) {
        int coordinate_length = getCoordinateLength(group);
        return factory.createUncompressedPointRepresentation(
                toBytes(point.getAffineX(), coordinate_length), 
                toBytes(point.getAffineY(), coordinate_length));
    }

    // validates an EC public key as defined in TLS 1.3 spec
    // https://tools.ietf.org/html/draft-ietf-tls-tls13-26#section-4.2.8.2
    //
    // See details in section 5.6.2.3.2 of NIST SP 56A and section 5.2.2 of X9.62:
    // - https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-56Ar2.pdf
    // - http://citeseerx.ist.psu.edu/viewdoc/download?doi=10.1.1.202.2977&rep=rep1&type=pdf
    private void validate(ECPoint point) throws NegotiatorException {
        try {
            EllipticCurve curve = secpParameters.ecParameterSpec.getCurve();
            BigInteger x = point.getAffineX();
            BigInteger y = point.getAffineY();
            BigInteger p = ECUtils.getP(curve);
            BigInteger a = curve.getA();
            BigInteger b = curve.getB();

            output.info("p = %s", p.toString());
            output.info("x = %s", x.toString());
            output.info("y = %s", y.toString());
            output.info("a = %s", a.toString());
            output.info("b = %s", b.toString());

            ECUtils.checkPointOnCurve(point, curve);
        } catch (ECException e) {
            reportError(e);
        }
    }

    private void reportError(Exception e) throws NegotiatorException {
        if (strictValidation) {
            throw new NegotiatorException(e);
        }

        output.achtung("%s", e.getMessage());
    }
    
    public static ECDHENegotiator create(NamedGroup.Secp group, StructFactory factory) 
            throws NegotiatorException {

        try {
            KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
            ECGenParameterSpec spec = new ECGenParameterSpec(group.getCurve());
            generator.initialize(spec);

            return new ECDHENegotiator(
                    group,
                    SecpParameters.create(group),
                    KeyAgreement.getInstance("ECDH"),
                    generator, factory);
        } catch (NoSuchAlgorithmException | InvalidAlgorithmParameterException e) {
            throw new NegotiatorException(e);
        }
    }

}
