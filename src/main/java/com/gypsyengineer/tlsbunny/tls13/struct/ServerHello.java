package com.gypsyengineer.tlsbunny.tls13.struct;

import com.gypsyengineer.tlsbunny.tls.Random;
import com.gypsyengineer.tlsbunny.tls.Vector;

public interface ServerHello extends HandshakeMessage {

    int extensions_length_bytes = 2;
    int legacy_session_id_echo_length_bytes = 1;

    ProtocolVersion protocolVersion();
    Random random();
    Vector<Byte> legacySessionIdEcho();
    CipherSuite cipherSuite();
    CompressionMethod legacyCompressionMethod();
    Vector<Extension> extensions();

    void extensions(Vector<Extension> extensions);
    void legacySessionIdEcho(Vector<Byte> echo);

    Extension find(ExtensionType type);
}
