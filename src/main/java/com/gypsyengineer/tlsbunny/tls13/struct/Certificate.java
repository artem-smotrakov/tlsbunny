package com.gypsyengineer.tlsbunny.tls13.struct;

import com.gypsyengineer.tlsbunny.tls.Vector;

public interface Certificate extends HandshakeMessage {

    int certificate_list_length_bytes = 3;
    int context_length_bytes = 1;

    Vector<CertificateEntry> certificateList();
    Vector<Byte> certificateRequestContext();
}
