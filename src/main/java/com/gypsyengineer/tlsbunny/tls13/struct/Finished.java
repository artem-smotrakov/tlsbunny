package com.gypsyengineer.tlsbunny.tls13.struct;

public interface Finished extends HandshakeMessage {

    byte[] getVerifyData();
}
