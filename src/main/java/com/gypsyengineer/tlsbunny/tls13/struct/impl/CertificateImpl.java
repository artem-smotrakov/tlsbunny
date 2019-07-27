package com.gypsyengineer.tlsbunny.tls13.struct.impl;

import com.gypsyengineer.tlsbunny.tls.Struct;
import com.gypsyengineer.tlsbunny.tls.Vector;
import com.gypsyengineer.tlsbunny.tls13.struct.Certificate;
import com.gypsyengineer.tlsbunny.tls13.struct.CertificateEntry;
import com.gypsyengineer.tlsbunny.tls13.struct.HandshakeType;
import com.gypsyengineer.tlsbunny.utils.Utils;
import java.io.IOException;
import java.util.Objects;

import static com.gypsyengineer.tlsbunny.utils.Utils.cast;
import static com.gypsyengineer.tlsbunny.utils.WhatTheHell.whatTheHell;

public class CertificateImpl implements Certificate {

    private Vector<Byte> certificate_request_context;
    private Vector<CertificateEntry> certificate_list;

    CertificateImpl(Vector<Byte> certificate_request_context,
            Vector<CertificateEntry> certificate_list) {

        this.certificate_request_context = certificate_request_context;
        this.certificate_list = certificate_list;
    }

    @Override
    public int encodingLength() {
        return Utils.getEncodingLength(certificate_request_context, certificate_list);
    }

    @Override
    public byte[] encoding() throws IOException {
        return Utils.encoding(certificate_request_context, certificate_list);
    }

    @Override
    public CertificateImpl copy() {
        return new CertificateImpl(
                (Vector<Byte>) certificate_request_context.copy(),
                (Vector<CertificateEntry>) certificate_list.copy());
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
                return certificate_request_context;
            case 1:
                return certificate_list;
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
                certificate_request_context = cast(element, Vector.class);
                break;
            case 1:
                certificate_list = cast(element, Vector.class);
                break;
            default:
                throw whatTheHell("incorrect index %d!", index);
        }
    }

    @Override
    public Vector<Byte> certificateRequestContext() {
        return certificate_request_context;
    }

    @Override
    public Vector<CertificateEntry> certificateList() {
        return certificate_list;
    }

    @Override
    public HandshakeType type() {
        return HandshakeTypeImpl.certificate;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) {
            return true;
        }
        if (o == null || getClass() != o.getClass()) {
            return false;
        }
        CertificateImpl that = (CertificateImpl) o;
        return Objects.equals(certificate_request_context, that.certificate_request_context) &&
                Objects.equals(certificate_list, that.certificate_list);
    }

    @Override
    public int hashCode() {
        return Objects.hash(certificate_request_context, certificate_list);
    }
}
