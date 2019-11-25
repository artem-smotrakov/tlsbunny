package com.gypsyengineer.tlsbunny.tls13.struct.impl;

import com.gypsyengineer.tlsbunny.tls.Struct;
import com.gypsyengineer.tlsbunny.tls.Vector;
import com.gypsyengineer.tlsbunny.tls13.struct.PskKeyExchangeMode;
import com.gypsyengineer.tlsbunny.tls13.struct.PskKeyExchangeModes;

import java.io.IOException;

import static com.gypsyengineer.tlsbunny.utils.Utils.cast;
import static com.gypsyengineer.tlsbunny.utils.WhatTheHell.whatTheHell;

public class PskKeyExchangeModesImpl implements PskKeyExchangeModes {

    private Vector<PskKeyExchangeMode> ke_modes;

    PskKeyExchangeModesImpl(Vector<PskKeyExchangeMode> ke_modes) {
        this.ke_modes = ke_modes;
    }

    @Override
    public Vector<PskKeyExchangeMode> keModes() {
        return ke_modes;
    }

    @Override
    public int encodingLength() {
        return ke_modes.encodingLength();
    }

    @Override
    public byte[] encoding() throws IOException {
        return ke_modes.encoding();
    }

    @Override
    public Struct copy() {
        return new PskKeyExchangeModesImpl(
                cast(ke_modes.copy(), Vector.class));
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
        if (index == 0) {
            return ke_modes;
        }
        throw whatTheHell("incorrect index %d!", index);
    }

    @Override
    public void element(int index, Struct element) {
        if (index == 0) {
            ke_modes = cast(element, Vector.class);
        }
        throw whatTheHell("incorrect index %d!", index);
    }
}
