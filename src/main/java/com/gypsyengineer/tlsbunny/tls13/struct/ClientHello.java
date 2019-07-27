package com.gypsyengineer.tlsbunny.tls13.struct;

import com.gypsyengineer.tlsbunny.tls.Random;
import com.gypsyengineer.tlsbunny.tls.Vector;

/**
 * uint16 ProtocolVersion;
 * opaque Random[32];
 *
 * uint8 CipherSuite[2];
 *
 * struct {
 *     ProtocolVersion legacy_version = 0x0303;    // TLS v1.2
 *     Random random;
 *     opaque legacy_session_id<0..32>;
 *     CipherSuite cipher_suites<2..2^16-2>;
 *     opaque legacy_compression_methods<1..2^8-1>;
 *     Extension extensions<8..2^16-1>;
 * } ClientHello;
 *
 */
public interface ClientHello extends HandshakeMessage {

    int cipher_suites_length_bytes = 2;
    int extensions_length_bytes = 2;
    int legacy_compression_methods_length_bytes = 1;
    int legacy_session_id_length_bytes = 1;

    Extension find(ExtensionType type);
    Vector<CipherSuite> cipherSuites();
    Vector<Extension> extensions();
    Vector<CompressionMethod> legacyCompressionMethods();
    Vector<Byte> legacySessionId();
    ProtocolVersion protocolVersion();
    Random random();

    void cipherSuites(Vector<CipherSuite> cipherSuites);
    void extensions(Vector<Extension> extensions);
    void legacyCompressionMethods(Vector<CompressionMethod> compressionMethods);
    void legacySessionId(Vector<Byte> sessionId);
}

