package com.gypsyengineer.tlsbunny.tls13.struct.impl;

import java.nio.ByteBuffer;

import com.gypsyengineer.tlsbunny.tls13.struct.HandshakeType;

public class HandshakeTypeImpl implements HandshakeType {

    private final int value;

    HandshakeTypeImpl(int value) {
        this.value = value;
    }

    @Override
    public int encodingLength() {
        return encoding_length;
    }

    @Override
    public byte[] encoding() {
        return ByteBuffer.allocate(encoding_length).put((byte) value).array();
    }

    @Override
    public HandshakeTypeImpl copy() {
        return new HandshakeTypeImpl(value);
    }

    @Override
    public int getValue() {
        return value;
    }

    @Override
    public int hashCode() {
        int hash = 7;
        hash = 31 * hash + this.value;
        return hash;
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj == null) {
            return false;
        }
        if (getClass() != obj.getClass()) {
            return false;
        }
        final HandshakeTypeImpl other = (HandshakeTypeImpl) obj;
        return this.value == other.value;
    }

    @Override
    public String toString() {
        // yes, the multiple ifs below look just terrible
        // although it's not clear how to avoid them:
        // - "switch" doesn't work because we can't use HandshakeType.getCode() for "case"
        // - creating a map {code, description} doesn't work because standard types in HandshakeType
        //   are not initialized at the moment of initializing of the map
        String template = "handshake type (%d)";
        if (client_hello.getValue() == value) {
            template = "client_hello (%s)";
        }
        if (server_hello.getValue() == value) {
            template = "server_hello (%s)";
        }
        if (encrypted_extensions.getValue() == value) {
            template = "encrypted_extensions (%s)";
        }
        if (certificate.getValue() == value) {
            template = "certificate (%s)";
        }
        if (certificate_verify.getValue() == value) {
            template = "certificate_verify (%s)";
        }
        if (certificate_request.getValue() == value) {
            template = "certificate_request (%s)";
        }
        if (finished.getValue() == value) {
            template = "finished (%s)";
        }
        if (end_of_early_data.getValue() == value) {
            template = "end_of_early_data (%s)";
        }
        if (key_update.getValue() == value) {
            template = "key_update (%s)";
        }
        if (hello_retry_request.getValue() == value) {
            template = "hello_retry_request (%s)";
        }
        if (message_hash.getValue() == value) {
            template = "message_hash (%s)";
        }
        if (new_session_ticket.getValue() == value) {
            template = "new_session_ticket (%s)";
        }
        return String.format(template, value);
    }

}
