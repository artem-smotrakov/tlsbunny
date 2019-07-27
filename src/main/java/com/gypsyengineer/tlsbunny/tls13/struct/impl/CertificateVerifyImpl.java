package com.gypsyengineer.tlsbunny.tls13.struct.impl;

import com.gypsyengineer.tlsbunny.tls.Struct;
import com.gypsyengineer.tlsbunny.tls.Vector;
import com.gypsyengineer.tlsbunny.tls13.struct.CertificateVerify;
import com.gypsyengineer.tlsbunny.tls13.struct.HandshakeType;
import com.gypsyengineer.tlsbunny.tls13.struct.SignatureScheme;
import com.gypsyengineer.tlsbunny.utils.Utils;
import java.io.IOException;
import java.util.Objects;

import static com.gypsyengineer.tlsbunny.utils.Utils.cast;
import static com.gypsyengineer.tlsbunny.utils.WhatTheHell.whatTheHell;

public class CertificateVerifyImpl implements CertificateVerify {

    private SignatureScheme algorithm;
    private Vector<Byte> signature;

    CertificateVerifyImpl(SignatureScheme algorithm, Vector<Byte> signature) {
        this.algorithm = algorithm;
        this.signature = signature;
    }

    @Override
    public int encodingLength() {
        return Utils.getEncodingLength(algorithm, signature);
    }

    @Override
    public byte[] encoding() throws IOException {
        return Utils.encoding(algorithm, signature);
    }

    @Override
    public CertificateVerifyImpl copy() {
        return new CertificateVerifyImpl(
                (SignatureScheme) algorithm.copy(),
                (Vector<Byte>) signature.copy());
    }

    @Override
    public boolean composite() {
        return true;
    }

    @Override
    public int total() {
        return 2;
    }

    @Override
    public Struct element(int index) {
        switch (index) {
            case 0:
                return algorithm;
            case 1:
                return signature;
            default:
                throw whatTheHell("incorrect index %d!", index);
        }
    }

    @Override
    public void element(int index, Struct element) {
        if (element == null) {
            throw whatTheHell("element can't be null!");
        }
        switch (index) {
            case 0:
                algorithm = cast(element, SignatureScheme.class);
                break;
            case 1:
                signature = cast(element, Vector.class);
                break;
            default:
                throw whatTheHell("incorrect index %d!", index);
        }
    }

    @Override
    public SignatureScheme algorithm() {
        return algorithm;
    }

    @Override
    public Vector<Byte> signature() {
        return signature;
    }

    @Override
    public HandshakeType type() {
        return HandshakeTypeImpl.certificate_verify;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) {
            return true;
        }
        if (o == null || getClass() != o.getClass()) {
            return false;
        }
        CertificateVerifyImpl that = (CertificateVerifyImpl) o;
        return Objects.equals(algorithm, that.algorithm) &&
                Objects.equals(signature, that.signature);
    }

    @Override
    public int hashCode() {
        return Objects.hash(algorithm, signature);
    }
}
