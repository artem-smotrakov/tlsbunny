package com.gypsyengineer.tlsbunny.tls13.struct;

import com.gypsyengineer.tlsbunny.tls.Struct;
import com.gypsyengineer.tlsbunny.tls.UInt24;

public interface Handshake extends Struct {

    boolean containsCertificate();
    boolean containsCertificateRequest();
    boolean containsCertificateVerify();
    boolean containsClientHello();
    boolean containsEncryptedExtensions();
    boolean containsFinished();
    boolean containsHelloRetryRequest();
    boolean containsNewSessionTicket();
    boolean containsServerHello();
    byte[] getBody();
    UInt24 getBodyLength();
    HandshakeType getMessageType();

    Handshake bodyLength(UInt24 length);
}
