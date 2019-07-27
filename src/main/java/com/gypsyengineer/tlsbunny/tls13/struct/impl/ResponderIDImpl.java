package com.gypsyengineer.tlsbunny.tls13.struct.impl;

import com.gypsyengineer.tlsbunny.tls.Vector;
import com.gypsyengineer.tlsbunny.tls13.struct.ResponderID;

import java.io.IOException;
import java.util.Objects;

public class ResponderIDImpl implements ResponderID {

    private Vector<Byte> content;

    ResponderIDImpl(Vector<Byte> content) {
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
    public ResponderIDImpl copy() {
        return new ResponderIDImpl((Vector<Byte>) content.copy());
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) {
            return true;
        }
        if (o == null || getClass() != o.getClass()) {
            return false;
        }
        ResponderIDImpl that = (ResponderIDImpl) o;
        return Objects.equals(content, that.content);
    }

    @Override
    public int hashCode() {
        return Objects.hash(content);
    }
}
