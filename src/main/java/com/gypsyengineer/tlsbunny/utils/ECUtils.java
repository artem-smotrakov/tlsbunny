package com.gypsyengineer.tlsbunny.utils;

import java.math.BigInteger;
import java.security.spec.ECField;
import java.security.spec.ECFieldFp;
import java.security.spec.ECPoint;
import java.security.spec.EllipticCurve;

public class ECUtils {

    /**
     * (borrowed from wycheproof)
     *
     * Returns the modulus of the field used by the curve specified in ecParams.
     *
     * @param curve must be a prime order elliptic curve
     * @return the order of the finite field over which curve is defined.
     */
    public static BigInteger getP(EllipticCurve curve) throws ECException {
        ECField field = curve.getField();
        if (field instanceof ECFieldFp) {
            return ((ECFieldFp) field).getP();
        }

        throw new ECException(
                "only curves over prime order fields are supported");
    }

    /**
     * (borrowed from wycheproof)
     *
     * Checks that a point is on a given elliptic curve. This method implements the partial public key
     * validation routine from Section 5.6.2.6 of NIST SP 800-56A
     * http://csrc.nist.gov/publications/nistpubs/800-56A/SP800-56A_Revision1_Mar08-2007.pdf A partial
     * public key validation is sufficient for curves with cofactor 1. See Section B.3 of
     * http://www.nsa.gov/ia/_files/SuiteB_Implementer_G-113808.pdf The point validations above are
     * taken from recommendations for ECDH, because parameter checks in ECDH are much more important
     * than for the case of ECDSA. Performing this test for ECDSA keys is mainly a sanity check.
     *
     * @param point the point that needs verification
     * @param ec the elliptic curve. This must be a curve over a prime order field.
     * @throws ECException if the field is binary or if the point is not on the curve.
     */
    public static void checkPointOnCurve(ECPoint point, EllipticCurve ec)
            throws ECException {

        BigInteger p = getP(ec);
        BigInteger x = point.getAffineX();
        BigInteger y = point.getAffineY();

        if (x == null || y == null) {
            throw new ECException("point is at infinity");
        }

        // Check 0 <= x < p and 0 <= y < p.
        if (x.signum() == -1 || x.compareTo(p) >= 0) {
            throw new ECException("x is out of range [0, p-1]");
        }
        if (y.signum() == -1 || y.compareTo(p) >= 0) {
            throw new ECException("y is out of range [0, p-1]");
        }

        // Check y^2 == x^3 + a x + b (mod p)
        BigInteger lhs = y.multiply(y).mod(p);
        BigInteger rhs = x.multiply(x).add(ec.getA()).multiply(x).add(ec.getB()).mod(p);
        if (!lhs.equals(rhs)) {
            throw new ECException("point is not on curve");
        }
    }
}
