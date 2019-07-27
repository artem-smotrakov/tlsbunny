package com.gypsyengineer.tlsbunny.tls13.struct.impl;

import com.gypsyengineer.tlsbunny.tls13.struct.CertificateStatusType;

import static com.gypsyengineer.tlsbunny.utils.WhatTheHell.whatTheHell;

public class CertificateStatusTypeImpl implements CertificateStatusType {

    private final int code;

    CertificateStatusTypeImpl(int code) {
        check(code);
        this.code = code;
    }

    @Override
    public int getCode() {
        return code;
    }

    @Override
    public int encodingLength() {
        return encoding_length;
    }

    @Override
    public byte[] encoding() {
        return new byte[] { (byte) code };
    }

    @Override
    public CertificateStatusTypeImpl copy() {
        return new CertificateStatusTypeImpl(code);
    }

    @Override
    public int hashCode() {
        int hash = 7;
        hash = 59 * hash + this.code;
        return hash;
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj == null) {
            return false;
        }
        if (getClass() != obj.getClass()) {
            return false;
        }
        final CertificateStatusTypeImpl other = (CertificateStatusTypeImpl) obj;
        return this.code == other.code;
    }

    @Override
    public String toString() {
        return String.format("certificate status type (%d)", code);
    }

    private static void check(int code) {
        if (code < 0 || code > 255) {
            throw whatTheHell("code is wrong: %s", code);
        }
    }

}
