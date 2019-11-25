package com.gypsyengineer.tlsbunny.tls13.struct.impl;

import com.gypsyengineer.tlsbunny.tls.Struct;
import com.gypsyengineer.tlsbunny.tls13.struct.PskKeyExchangeMode;

import java.util.Objects;

import static com.gypsyengineer.tlsbunny.utils.WhatTheHell.whatTheHell;

public class PskKeyExchangeModeImpl implements PskKeyExchangeMode {

    private int code;

    PskKeyExchangeModeImpl(int code) {
        this.code = check(code);
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
    public Struct copy() {
        return new PskKeyExchangeModeImpl(code);
    }

    @Override
    public boolean composite() {
        return false;
    }

    @Override
    public int total() {
        return 0;
    }

    @Override
    public Struct element(int index) {
        throw whatTheHell("Hey! PskKeyExchangeMode is not a composite struct!");
    }

    @Override
    public void element(int index, Struct element) {
        throw whatTheHell("Hey! PskKeyExchangeMode is not a composite struct!");
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) {
            return true;
        }
        if (o == null || getClass() != o.getClass()) {
            return false;
        }
        PskKeyExchangeModeImpl that = (PskKeyExchangeModeImpl) o;
        return code == that.code;
    }

    @Override
    public int hashCode() {
        return Objects.hash(code);
    }

    private static int check(int code) {
        if (code < min || code > max) {
            throw whatTheHell("Invalid PskKeyExchangeMode: %d", code);
        }
        return code;
    }
}
