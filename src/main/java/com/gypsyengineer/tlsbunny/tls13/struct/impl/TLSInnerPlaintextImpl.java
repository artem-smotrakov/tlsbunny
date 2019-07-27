package com.gypsyengineer.tlsbunny.tls13.struct.impl;

import com.gypsyengineer.tlsbunny.tls.Bytes;
import com.gypsyengineer.tlsbunny.utils.Utils;
import com.gypsyengineer.tlsbunny.tls13.struct.ContentType;
import com.gypsyengineer.tlsbunny.tls13.struct.TLSInnerPlaintext;
import java.io.IOException;
import java.util.Objects;

public class TLSInnerPlaintextImpl implements TLSInnerPlaintext {

    private final Bytes content;
    private final ContentType type;
    private final Bytes zeros;

    TLSInnerPlaintextImpl(Bytes content, ContentType type, Bytes zeros) {
        this.content = content;
        this.type = type;
        this.zeros = zeros;
    }
    
    @Override
    public byte[] getContent() {
        return content.encoding();
    }

    @Override
    public ContentType getType() {
        return type;
    }

    @Override
    public Bytes getZeros() {
        return zeros;
    }

    @Override
    public boolean containsHandshake() {
        return type.isHandshake();
    }

    @Override
    public boolean containsApplicationData() {
        return type.isApplicationData();
    }

    @Override
    public boolean containsAlert() {
        return type.isAlert();
    }
    
    @Override
    public int encodingLength() {
        return Utils.getEncodingLength(content, type, zeros);
    }

    @Override
    public byte[] encoding() throws IOException {
        return Utils.encoding(content, type, zeros);
    }

    @Override
    public TLSInnerPlaintextImpl copy() {
        return new TLSInnerPlaintextImpl(
                content.copy(), (ContentType) type.copy(), zeros.copy());
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) {
            return true;
        }
        if (o == null || getClass() != o.getClass()) {
            return false;
        }
        TLSInnerPlaintextImpl that = (TLSInnerPlaintextImpl) o;
        return Objects.equals(content, that.content) &&
                Objects.equals(type, that.type) &&
                Objects.equals(zeros, that.zeros);
    }

    @Override
    public int hashCode() {
        return Objects.hash(content, type, zeros);
    }
}
