package com.gypsyengineer.tlsbunny.tls13.struct.impl;

import com.gypsyengineer.tlsbunny.tls.Struct;
import com.gypsyengineer.tlsbunny.tls.Vector;
import com.gypsyengineer.tlsbunny.tls.UInt16;
import com.gypsyengineer.tlsbunny.tls13.struct.HkdfLabel;
import com.gypsyengineer.tlsbunny.utils.Utils;
import java.io.IOException;
import java.util.Objects;

public class HkdfLabelImpl implements HkdfLabel {

    private final UInt16 length;
    private final Vector<Byte> label;
    private final Vector<Byte> hash_value;

    HkdfLabelImpl(UInt16 length, Vector<Byte> label, Vector<Byte> hash_value) {
        this.length = length;
        this.label = label;
        this.hash_value = hash_value;
    }

    @Override
    public UInt16 getLength() {
        return length;
    }

    @Override
    public Vector<Byte> getLabel() {
        return label;
    }

    @Override
    public Vector<Byte> getContext() {
        return hash_value;
    }

    @Override
    public int encodingLength() {
        return Utils.getEncodingLength(length, label, hash_value);
    }

    @Override
    public byte[] encoding() throws IOException {
        return Utils.encoding(length, label, hash_value);
    }

    @Override
    public Struct copy() {
        return new HkdfLabelImpl(
                length.copy(),
                (Vector<Byte>) label.copy(),
                (Vector<Byte>) hash_value.copy());
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) {
            return true;
        }
        if (o == null || getClass() != o.getClass()) {
            return false;
        }
        HkdfLabelImpl hkdfLabel = (HkdfLabelImpl) o;
        return Objects.equals(length, hkdfLabel.length) &&
                Objects.equals(label, hkdfLabel.label) &&
                Objects.equals(hash_value, hkdfLabel.hash_value);
    }

    @Override
    public int hashCode() {
        return Objects.hash(length, label, hash_value);
    }
}
