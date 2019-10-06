package com.gypsyengineer.tlsbunny.tls13.struct.impl;

import com.gypsyengineer.tlsbunny.tls.Struct;
import com.gypsyengineer.tlsbunny.tls.Vector;
import com.gypsyengineer.tlsbunny.tls13.struct.OfferedPsks;
import com.gypsyengineer.tlsbunny.tls13.struct.PskBinderEntry;
import com.gypsyengineer.tlsbunny.tls13.struct.PskIdentity;
import com.gypsyengineer.tlsbunny.utils.Utils;

import java.io.IOException;
import java.util.Objects;

import static com.gypsyengineer.tlsbunny.utils.Utils.cast;
import static com.gypsyengineer.tlsbunny.utils.WhatTheHell.whatTheHell;

public class OfferedPsksImpl implements OfferedPsks {

    private Vector<PskIdentity> identities;
    private Vector<PskBinderEntry> binders;

    OfferedPsksImpl(Vector<PskIdentity> identities, Vector<PskBinderEntry> binders) {
        this.identities = identities;
        this.binders = binders;
    }

    @Override
    public Vector<PskIdentity> identities() {
        return identities;
    }

    @Override
    public Vector<PskBinderEntry> binders() {
        return binders;
    }

    @Override
    public int encodingLength() {
        return Utils.getEncodingLength(identities, binders);
    }

    @Override
    public byte[] encoding() throws IOException {
        return Utils.encoding(identities, binders);
    }

    @Override
    public Struct copy() {
        return new OfferedPsksImpl(identities, binders);
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
                return identities;
            case 1:
                return binders;
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
                identities = cast(element, Vector.class);
                break;
            case 1:
                binders = cast(element, Vector.class);
                break;
            default:
                throw whatTheHell("incorrect index %d!", index);
        }
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) {
            return true;
        }
        if (o == null || getClass() != o.getClass()) {
            return false;
        }
        OfferedPsksImpl that = (OfferedPsksImpl) o;
        return Objects.equals(identities, that.identities) &&
                Objects.equals(binders, that.binders);
    }

    @Override
    public int hashCode() {
        return Objects.hash(identities, binders);
    }
}
