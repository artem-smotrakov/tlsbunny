package com.gypsyengineer.tlsbunny.tls13.struct;

import com.gypsyengineer.tlsbunny.tls.Vector;

public interface EncryptedExtensions extends HandshakeMessage {

    int length_bytes = 2;

    Vector<Extension> extensions();
}
