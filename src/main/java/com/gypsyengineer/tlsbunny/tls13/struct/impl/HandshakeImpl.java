package com.gypsyengineer.tlsbunny.tls13.struct.impl;

import com.gypsyengineer.tlsbunny.tls.Bytes;
import com.gypsyengineer.tlsbunny.tls.Struct;
import com.gypsyengineer.tlsbunny.tls.UInt24;
import com.gypsyengineer.tlsbunny.utils.Utils;
import com.gypsyengineer.tlsbunny.tls13.struct.Handshake;
import com.gypsyengineer.tlsbunny.tls13.struct.HandshakeType;
import java.io.IOException;
import java.util.Objects;

public class HandshakeImpl implements Handshake {

    private HandshakeType msg_type;
    private UInt24 length;
    private Bytes body;

    HandshakeImpl(HandshakeType msg_type, UInt24 length, Bytes body) {
        this.msg_type = msg_type;
        this.length = length;
        this.body = body;
    }

    @Override
    public int encodingLength() {
        return Utils.getEncodingLength(msg_type, length, body);
    }

    @Override
    public byte[] encoding() throws IOException {
        return Utils.encoding(msg_type, length, body);
    }

    @Override
    public Struct copy() {
        return new HandshakeImpl(
                (HandshakeType) msg_type.copy(),
                length.copy(),
                body.copy());
    }

    @Override
    public HandshakeType getMessageType() {
        return msg_type;
    }

    @Override
    public Handshake bodyLength(UInt24 length) {
        this.length = length;
        return this;
    }

    @Override
    public UInt24 getBodyLength() {
        return length;
    }

    @Override
    public byte[] getBody() {
        return body.encoding();
    }

    @Override
    public boolean containsClientHello() {
        return HandshakeTypeImpl.client_hello.equals(msg_type);
    }

    @Override
    public boolean containsHelloRetryRequest() {
        return HandshakeTypeImpl.hello_retry_request.equals(msg_type);
    }

    @Override
    public boolean containsServerHello() {
        return HandshakeTypeImpl.server_hello.equals(msg_type);
    }

    @Override
    public boolean containsEncryptedExtensions(){
        return HandshakeTypeImpl.encrypted_extensions.equals(msg_type);
    }

    @Override
    public boolean containsCertificateRequest() {
        return HandshakeTypeImpl.certificate_request.equals(msg_type);
    }

    @Override
    public boolean containsCertificate() {
        return HandshakeTypeImpl.certificate.equals(msg_type);
    }

    @Override
    public boolean containsCertificateVerify() {
        return HandshakeTypeImpl.certificate_verify.equals(msg_type);
    }

    @Override
    public boolean containsFinished() {
        return HandshakeTypeImpl.finished.equals(msg_type);
    }

    @Override
    public boolean containsNewSessionTicket() {
        return HandshakeTypeImpl.new_session_ticket.equals(msg_type);
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) {
            return true;
        }
        if (o == null || getClass() != o.getClass()) {
            return false;
        }
        HandshakeImpl handshake = (HandshakeImpl) o;
        return Objects.equals(msg_type, handshake.msg_type) &&
                Objects.equals(length, handshake.length) &&
                Objects.equals(body, handshake.body);
    }

    @Override
    public int hashCode() {
        return Objects.hash(msg_type, length, body);
    }
}
