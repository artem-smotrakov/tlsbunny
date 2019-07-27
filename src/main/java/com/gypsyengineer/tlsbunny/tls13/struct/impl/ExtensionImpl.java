package com.gypsyengineer.tlsbunny.tls13.struct.impl;

import com.gypsyengineer.tlsbunny.tls.Struct;
import com.gypsyengineer.tlsbunny.tls.Vector;
import com.gypsyengineer.tlsbunny.tls13.struct.Extension;
import com.gypsyengineer.tlsbunny.tls13.struct.ExtensionType;
import com.gypsyengineer.tlsbunny.utils.Utils;
import java.io.IOException;
import java.util.Objects;

import static com.gypsyengineer.tlsbunny.utils.Utils.cast;
import static com.gypsyengineer.tlsbunny.utils.WhatTheHell.whatTheHell;

public class ExtensionImpl implements Extension {

    private ExtensionType extension_type;
    private Vector<Byte> extension_data;
    
    ExtensionImpl(ExtensionType extension_type, Vector<Byte> extension_data) {
        this.extension_type = extension_type;
        this.extension_data = extension_data;
    }
    
    @Override
    public ExtensionType extensionType() {
        return extension_type;
    }

    @Override
    public Extension extensionData(Vector<Byte> data) {
        extension_data = data;
        return this;
    }

    @Override
    public Extension extensionType(ExtensionType type) {
        extension_type = type;
        return this;
    }

    @Override
    public Vector<Byte> extensionData() {
        return extension_data;
    }
    
    @Override
    public final int encodingLength() {
        return Utils.getEncodingLength(extension_type, extension_data);
    }

    @Override
    public final byte[] encoding() throws IOException {     
        return Utils.encoding(extension_type, extension_data);
    }

    @Override
    public ExtensionImpl copy() {
        return new ExtensionImpl(
                (ExtensionType) extension_type.copy(),
                (Vector<Byte>) extension_data.copy());
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) {
            return true;
        }

        if (o == null || getClass() != o.getClass()) {
            return false;
        }

        ExtensionImpl extension = (ExtensionImpl) o;
        return Objects.equals(extension_type, extension.extension_type) &&
                Objects.equals(extension_data, extension.extension_data);
    }

    @Override
    public int hashCode() {
        return Objects.hash(extension_type, extension_data);
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
                return extension_type;
            case 1:
                return extension_data;
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
                extension_type = cast(element, ExtensionType.class);
                break;
            case 1:
                extension_data = cast(element, Vector.class);
                break;
            default:
                throw whatTheHell("incorrect index %d!", index);
        }
    }
}
