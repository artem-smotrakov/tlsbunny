package com.gypsyengineer.tlsbunny.tls13.struct.impl;

import com.gypsyengineer.tlsbunny.tls.Struct;
import com.gypsyengineer.tlsbunny.tls.Vector;
import com.gypsyengineer.tlsbunny.tls13.struct.PskBinderEntry;

import java.io.IOException;
import java.util.Objects;

import static com.gypsyengineer.tlsbunny.utils.Utils.cast;
import static com.gypsyengineer.tlsbunny.utils.WhatTheHell.whatTheHell;

public class PskBinderEntryImpl implements PskBinderEntry {

    private Vector<Byte> content;

    PskBinderEntryImpl(Vector<Byte> content) {
        this.content = content;
    }

    @Override
    public Vector<Byte> content() {
        return content;
    }

    @Override
    public int encodingLength() {
        return content.encodingLength();
    }

    @Override
    public byte[] encoding() throws IOException {
        return content.encoding();
    }

    @Override
    public Struct copy() {
        return new PskBinderEntryImpl(content);
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
            return content;
        }
        throw whatTheHell("incorrect index %d!", index);
    }

    @Override
    public void element(int index, Struct element) {
        if (index == 0) {
            content = cast(element, Vector.class);
        }
        throw whatTheHell("incorrect index %d!", index);
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) {
            return true;
        }
        if (o == null || getClass() != o.getClass()) {
            return false;
        }
        PskBinderEntryImpl that = (PskBinderEntryImpl) o;
        return Objects.equals(content, that.content);
    }

    @Override
    public int hashCode() {
        return Objects.hash(content);
    }
}
