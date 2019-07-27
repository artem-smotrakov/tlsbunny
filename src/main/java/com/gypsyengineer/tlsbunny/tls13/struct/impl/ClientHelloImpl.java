package com.gypsyengineer.tlsbunny.tls13.struct.impl;

import com.gypsyengineer.tlsbunny.tls.Random;
import com.gypsyengineer.tlsbunny.tls.Struct;
import com.gypsyengineer.tlsbunny.tls.Vector;
import com.gypsyengineer.tlsbunny.tls13.struct.CipherSuite;
import com.gypsyengineer.tlsbunny.tls13.struct.ClientHello;
import com.gypsyengineer.tlsbunny.tls13.struct.CompressionMethod;
import com.gypsyengineer.tlsbunny.tls13.struct.Extension;
import com.gypsyengineer.tlsbunny.tls13.struct.ExtensionType;
import com.gypsyengineer.tlsbunny.tls13.struct.HandshakeType;
import com.gypsyengineer.tlsbunny.tls13.struct.ProtocolVersion;
import com.gypsyengineer.tlsbunny.utils.Utils;
import java.io.IOException;
import java.util.Objects;

import static com.gypsyengineer.tlsbunny.utils.WhatTheHell.whatTheHell;
import static com.gypsyengineer.tlsbunny.utils.Utils.cast;

public class ClientHelloImpl implements ClientHello {
    
    private ProtocolVersion legacy_version;
    private Random random;
    private Vector<Byte> legacy_session_id;
    private Vector<CipherSuite> cipher_suites;
    private Vector<CompressionMethod> legacy_compression_methods;
    private Vector<Extension> extensions;

    ClientHelloImpl(
            ProtocolVersion legacy_version,
            Random random,
            Vector<Byte> legacy_session_id,
            Vector<CipherSuite> cipher_suites,
            Vector<CompressionMethod> legacy_compression_methods,
            Vector<Extension> extensions) {

        this.legacy_version = legacy_version;
        this.random = random;
        this.legacy_session_id = legacy_session_id;
        this.cipher_suites = cipher_suites;
        this.legacy_compression_methods = legacy_compression_methods;
        this.extensions = extensions;
    }

    @Override
    public int encodingLength() {
        return Utils.getEncodingLength(
                legacy_version,
                random,
                legacy_session_id,
                cipher_suites,
                legacy_compression_methods,
                extensions);
    }

    @Override
    public byte[] encoding() throws IOException {
        return Utils.encoding(
                legacy_version,
                random,
                legacy_session_id,
                cipher_suites,
                legacy_compression_methods,
                extensions);
    }

    @Override
    public ClientHelloImpl copy() {
        return new ClientHelloImpl(
                cast(legacy_version.copy(), ProtocolVersion.class),
                cast(random.copy(), Random.class),
                cast(legacy_session_id.copy(), Vector.class),
                cast(cipher_suites.copy(), Vector.class),
                cast(legacy_compression_methods.copy(), Vector.class),
                cast(extensions.copy(), Vector.class)
        );
    }

    @Override
    public Vector<Byte> legacySessionId() {
        return legacy_session_id;
    }

    @Override
    public Vector<CompressionMethod> legacyCompressionMethods() {
        return legacy_compression_methods;
    }

    @Override
    public Vector<CipherSuite> cipherSuites() {
        return cipher_suites;
    }

    @Override
    public ProtocolVersion protocolVersion() {
        return legacy_version;
    }

    @Override
    public Random random() {
        return random;
    }

    @Override
    public void cipherSuites(Vector<CipherSuite> cipherSuites) {
        this.cipher_suites = cipherSuites;
    }

    @Override
    public void extensions(Vector<Extension> extensions) {
        this.extensions = extensions;
    }

    @Override
    public void legacyCompressionMethods(Vector<CompressionMethod> compressionMethods) {
        this.legacy_compression_methods = compressionMethods;
    }

    @Override
    public void legacySessionId(Vector<Byte> sessionId) {
        this.legacy_session_id = sessionId;
    }

    @Override
    public Vector<Extension> extensions() {
        return extensions;
    }

    @Override
    public Extension find(ExtensionType type) {
        for (Extension extension : extensions.toList()) {
            if (type.equals(extension.extensionType())) {
                return extension;
            }
        }

        return null;
    }

    @Override
    public HandshakeType type() {
        return HandshakeTypeImpl.client_hello;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) {
            return true;
        }
        if (o == null || getClass() != o.getClass()) {
            return false;
        }
        ClientHelloImpl that = (ClientHelloImpl) o;
        return Objects.equals(legacy_version, that.legacy_version) &&
                Objects.equals(random, that.random) &&
                Objects.equals(legacy_session_id, that.legacy_session_id) &&
                Objects.equals(cipher_suites, that.cipher_suites) &&
                Objects.equals(legacy_compression_methods, that.legacy_compression_methods) &&
                Objects.equals(extensions, that.extensions);
    }

    @Override
    public int hashCode() {
        return Objects.hash(legacy_version, random, legacy_session_id,
                cipher_suites, legacy_compression_methods, extensions);
    }

    @Override
    public boolean composite() {
        return true;
    }

    @Override
    public int total() {
        return 6;
    }

    @Override
    public Struct element(int index) {
        switch (index) {
            case 0:
                return legacy_version;
            case 1:
                return random;
            case 2:
                return legacy_session_id;
            case 3:
                return cipher_suites;
            case 4:
                return legacy_compression_methods;
            case 5:
                return extensions;
            default:
                throw whatTheHell("incorrect index %d!", index);
        }
    }

    @Override
    public void element(int index, Struct element) {
        if (element == null) {
            throw whatTheHell("element can't be null!");
        }
        switch (index) {
            case 0:
                legacy_version = cast(element, ProtocolVersion.class);
                break;
            case 1:
                random = cast(element, Random.class);
                break;
            case 2:
                legacy_session_id = cast(element, Vector.class);
                break;
            case 3:
                cipher_suites = cast(element, Vector.class);
                break;
            case 4:
                legacy_compression_methods = cast(element, Vector.class);
                break;
            case 5:
                extensions = cast(element, Vector.class);
                break;
            default:
                throw whatTheHell("incorrect index %d!", index);
        }
    }

}
