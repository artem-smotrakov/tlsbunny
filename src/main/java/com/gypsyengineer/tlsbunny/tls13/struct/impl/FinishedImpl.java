package com.gypsyengineer.tlsbunny.tls13.struct.impl;

import com.gypsyengineer.tlsbunny.tls.Bytes;
import com.gypsyengineer.tlsbunny.tls.Struct;
import com.gypsyengineer.tlsbunny.tls13.struct.Finished;
import com.gypsyengineer.tlsbunny.tls13.struct.HandshakeType;

import java.util.Objects;

public class FinishedImpl implements Finished {

    private final Bytes verify_data;

    FinishedImpl(Bytes verify_data) {
        this.verify_data = verify_data;
    }

    @Override
    public byte[] getVerifyData() {
        return verify_data.encoding();
    }

    @Override
    public int encodingLength() {
        return verify_data.encodingLength();
    }

    @Override
    public byte[] encoding() {
        return verify_data.encoding();
    }

    @Override
    public Struct copy() {
        return new FinishedImpl(verify_data.copy());
    }

    @Override
    public HandshakeType type() {
        return HandshakeType.finished;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) {
            return true;
        }
        if (o == null || getClass() != o.getClass()) {
            return false;
        }
        FinishedImpl finished = (FinishedImpl) o;
        return Objects.equals(verify_data, finished.verify_data);
    }

    @Override
    public int hashCode() {
        return Objects.hash(verify_data);
    }
}
