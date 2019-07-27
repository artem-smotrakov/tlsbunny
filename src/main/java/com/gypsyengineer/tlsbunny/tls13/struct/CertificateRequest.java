package com.gypsyengineer.tlsbunny.tls13.struct;

import com.gypsyengineer.tlsbunny.tls.Vector;

public interface CertificateRequest extends HandshakeMessage {

    int certificate_request_context_length_bytes = 1;
    int extensions_length_bytes = 2;

    Vector<Byte> certificateRequestContext();
    Vector<Extension> extensions();
}
