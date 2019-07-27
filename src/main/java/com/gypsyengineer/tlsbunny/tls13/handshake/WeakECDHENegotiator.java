package com.gypsyengineer.tlsbunny.tls13.handshake;

import com.gypsyengineer.tlsbunny.tls13.struct.KeyShareEntry;
import com.gypsyengineer.tlsbunny.tls13.struct.NamedGroup;
import com.gypsyengineer.tlsbunny.tls13.struct.StructFactory;
import com.gypsyengineer.tlsbunny.tls13.struct.UncompressedPointRepresentation;
import com.gypsyengineer.tlsbunny.utils.ECException;
import com.gypsyengineer.tlsbunny.utils.ECUtils;
import com.gypsyengineer.tlsbunny.utils.MathException;

import javax.crypto.KeyAgreement;
import java.io.IOException;
import java.math.BigInteger;
import java.security.*;
import java.security.interfaces.ECPublicKey;
import java.security.spec.*;

import static com.gypsyengineer.tlsbunny.tls13.utils.TLS13Utils.getCoordinateLength;
import static com.gypsyengineer.tlsbunny.utils.MathUtils.*;

public class WeakECDHENegotiator extends AbstractNegotiator {

    private final SecpParameters secpParameters;
    private final KeyAgreement keyAgreement;
    private final KeyPairGenerator generator;

    private WeakECDHENegotiator(NamedGroup.Secp group, SecpParameters secpParameters,
                                KeyAgreement keyAgreement, KeyPairGenerator generator, StructFactory factory) {
        
        super(group, factory);
        this.secpParameters = secpParameters;
        this.keyAgreement = keyAgreement;
        this.generator = generator;
    }

    /*
     * (borrowed from wycheproof)
     *
     * Returns a weak public key of order 3 such that the public key point is on the curve specified
     * in ecParams. This method is used to check ECC implementations for missing step in the
     * verification of the public key. E.g. implementations of ECDH must verify that the public key
     * contains a point on the curve as well as public and secret key are using the same curve.
     */
    @Override
    public KeyShareEntry  createKeyShareEntry() throws NegotiatorException {
        try {
            EllipticCurve curve = secpParameters.ecParameterSpec.getCurve();
            BigInteger p = ECUtils.getP(curve);

            while (true) {
                // generate a point on the original curve
                KeyPair keyPair = generator.generateKeyPair();
                ECPublicKey pub = (ECPublicKey) keyPair.getPublic();
                ECPoint w = pub.getW();
                BigInteger x = w.getAffineX();
                BigInteger y = w.getAffineY();

                // Find the curve parameters a,b such that 3*w = infinity.
                // This is the case if the following equations are satisfied:
                //    3x == l^2 (mod p)
                //    l == (3x^2 + a) / 2*y (mod p)
                //    y^2 == x^3 + ax + b (mod p)
                BigInteger l;
                try {
                    l = modSqrt(x.multiply(THREE), p);
                } catch (MathException ex) {
                    continue;
                }
                BigInteger xSqr = x.multiply(x).mod(p);
                BigInteger a = l.multiply(y.add(y)).subtract(xSqr.multiply(THREE)).mod(p);
                BigInteger b = y.multiply(y).subtract(x.multiply(xSqr.add(a))).mod(p);
                EllipticCurve newCurve = new EllipticCurve(curve.getField(), a, b);

                // just a sanity check
                ECUtils.checkPointOnCurve(w, newCurve);

                // cofactor and order are of course wrong
                ECParameterSpec spec = new ECParameterSpec(newCurve, w, p, 1);

                return factory.createKeyShareEntry(
                        group,
                        createUPR(w).encoding());
            }
        } catch (IOException | ECException e) {
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

            throw new NegotiatorException("I can't really process key share entry!");
        } catch (NoSuchAlgorithmException | IOException | InvalidKeySpecException e) {
            throw new NegotiatorException(e);
        }
    }

    @Override
    public byte[] generateSecret() throws NegotiatorException {
        throw new NegotiatorException("I can't really generate secret!");
    }
    
    private NamedGroup.Secp getGroup() {
        return (NamedGroup.Secp) group;
    }
    
    private ECPoint convertToECPoint(KeyShareEntry entry) 
            throws IOException {
        
        UncompressedPointRepresentation upr = 
                factory.parser().parseUncompressedPointRepresentation(
                        entry.keyExchange().bytes(),
                        getCoordinateLength(getGroup()));

        return new ECPoint(
                toPositiveBigInteger(upr.getX()),
                toPositiveBigInteger(upr.getY()));
    }

    private UncompressedPointRepresentation createUPR(ECPoint point) {
        int coordinate_length = getCoordinateLength(getGroup());
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

            output.achtung("p = %s", p.toString());
            output.info("x = %s", x.toString());
            output.info("y = %s", y.toString());
            output.achtung("a = %s", a.toString());
            output.achtung("b = %s", b.toString());

            ECUtils.checkPointOnCurve(point, curve);
        } catch (ECException e) {
            throw new NegotiatorException(e);
        }
    }
    
    public static WeakECDHENegotiator create(NamedGroup.Secp group, StructFactory factory)
            throws NegotiatorException {

        try {
            KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
            ECGenParameterSpec spec = new ECGenParameterSpec(group.getCurve());
            generator.initialize(spec);

            return new WeakECDHENegotiator(
                    group,
                    SecpParameters.create(group),
                    KeyAgreement.getInstance("ECDH"),
                    generator, factory);
        } catch (NoSuchAlgorithmException | InvalidAlgorithmParameterException e) {
            throw new NegotiatorException(e);
        }
    }

}
