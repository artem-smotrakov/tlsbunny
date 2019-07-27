package com.gypsyengineer.tlsbunny.tls13.struct.impl;

import com.gypsyengineer.tlsbunny.tls13.struct.EndOfEarlyData;
import com.gypsyengineer.tlsbunny.tls13.struct.HandshakeType;
import java.io.IOException;

public class EndOfEarlyDataImpl implements EndOfEarlyData {

    @Override
    public int encodingLength() {
        throw new UnsupportedOperationException("no encoding length for you!");
    }

    @Override
    public byte[] encoding() throws IOException {
        throw new UnsupportedOperationException("no encodings for you!");
    }

    @Override
    public EndOfEarlyDataImpl copy() {
        throw new UnsupportedOperationException("no copies for you!");
    }

    @Override
    public HandshakeType type() {
        return HandshakeType.end_of_early_data;
    }

}
