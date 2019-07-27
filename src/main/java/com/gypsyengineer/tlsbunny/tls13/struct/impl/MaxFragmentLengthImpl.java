package com.gypsyengineer.tlsbunny.tls13.struct.impl;

import com.gypsyengineer.tlsbunny.tls13.struct.MaxFragmentLength;

import static com.gypsyengineer.tlsbunny.utils.WhatTheHell.whatTheHell;

public class MaxFragmentLengthImpl implements MaxFragmentLength {

    private final int code;

    MaxFragmentLengthImpl(int code) {
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
    public MaxFragmentLengthImpl copy() {
        return new MaxFragmentLengthImpl(code);
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
        final MaxFragmentLengthImpl other = (MaxFragmentLengthImpl) obj;
        return this.code == other.code;
    }

    @Override
    public String toString() {
        return String.format("max fragment length (%d)", code);
    }

    private static void check(int code) {
        if (code < 0 || code > 255) {
            throw whatTheHell("code is wrong: %d", code);
        }
    }

}
