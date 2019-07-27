package com.gypsyengineer.tlsbunny.tls13.struct;

import com.gypsyengineer.tlsbunny.tls.Struct;

public interface HandshakeMessage extends Struct {
    HandshakeType type();
}
