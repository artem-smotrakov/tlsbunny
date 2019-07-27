package com.gypsyengineer.tlsbunny.tls13.struct.impl;

import com.gypsyengineer.tlsbunny.tls.Struct;
import com.gypsyengineer.tlsbunny.tls.Vector;
import com.gypsyengineer.tlsbunny.tls13.struct.SignatureScheme;
import com.gypsyengineer.tlsbunny.tls13.struct.SignatureSchemeList;
import java.io.IOException;
import java.util.Objects;

import static com.gypsyengineer.tlsbunny.utils.Utils.cast;
import static com.gypsyengineer.tlsbunny.utils.WhatTheHell.whatTheHell;

public class SignatureSchemeListImpl implements SignatureSchemeList {

    private Vector<SignatureScheme> supported_signature_algorithms;

    SignatureSchemeListImpl(Vector<SignatureScheme> supported_signature_algorithms) {
        this.supported_signature_algorithms = supported_signature_algorithms;
    }

    @Override
    public Vector<SignatureScheme> getSupportedSignatureAlgorithms() {
        return supported_signature_algorithms;
    }

    @Override
    public int encodingLength() {
        return supported_signature_algorithms.encodingLength();
    }

    @Override
    public byte[] encoding() throws IOException {
        return supported_signature_algorithms.encoding();
    }

    @Override
    public SignatureSchemeListImpl copy() {
        return new SignatureSchemeListImpl(
                (Vector<SignatureScheme>) supported_signature_algorithms.copy());
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) {
            return true;
        }
        if (o == null || getClass() != o.getClass()) {
            return false;
        }
        SignatureSchemeListImpl that = (SignatureSchemeListImpl) o;
        return Objects.equals(supported_signature_algorithms, that.supported_signature_algorithms);
    }

    @Override
    public int hashCode() {
        return Objects.hash(supported_signature_algorithms);
    }

    @Override
    public boolean composite() {
        return true;
    }

    @Override
    public int total() {
        return 1;
    }

    @Override
    public Struct element(int index) {
        switch (index) {
            case 0:
                return supported_signature_algorithms;
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
                supported_signature_algorithms = cast(element, Vector.class);
                break;
            default:
                throw whatTheHell("incorrect index %d!", index);
        }
    }
}
