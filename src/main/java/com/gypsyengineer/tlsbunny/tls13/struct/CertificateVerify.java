package com.gypsyengineer.tlsbunny.tls13.struct;

import com.gypsyengineer.tlsbunny.tls.Vector;

public interface CertificateVerify extends HandshakeMessage {

    int signature_length_bytes = 2;

    SignatureScheme algorithm();
    Vector<Byte> signature();
}
