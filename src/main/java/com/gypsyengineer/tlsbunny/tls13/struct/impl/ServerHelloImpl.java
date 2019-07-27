package com.gypsyengineer.tlsbunny.tls13.struct.impl;

import com.gypsyengineer.tlsbunny.tls.Random;
import com.gypsyengineer.tlsbunny.tls.Vector;
import com.gypsyengineer.tlsbunny.tls13.struct.CipherSuite;
import com.gypsyengineer.tlsbunny.tls13.struct.CompressionMethod;
import com.gypsyengineer.tlsbunny.tls13.struct.Extension;
import com.gypsyengineer.tlsbunny.tls13.struct.ExtensionType;
import com.gypsyengineer.tlsbunny.tls13.struct.HandshakeType;
import com.gypsyengineer.tlsbunny.tls13.struct.ProtocolVersion;
import com.gypsyengineer.tlsbunny.tls13.struct.ServerHello;
import com.gypsyengineer.tlsbunny.utils.Utils;
import java.io.IOException;
import java.util.Objects;

import static com.gypsyengineer.tlsbunny.utils.Utils.cast;

public class ServerHelloImpl implements ServerHello {

    protected ProtocolVersion version;
    protected Random random;
    protected Vector<Byte> legacy_session_id_echo;
    protected CipherSuite cipher_suite;
    protected CompressionMethod legacy_compression_method;
    protected Vector<Extension> extensions;

    ServerHelloImpl(ProtocolVersion version, Random random,
            Vector<Byte> legacy_session_id_echo,
            CipherSuite cipher_suite,
            CompressionMethod legacy_compression_method,
            Vector<Extension> extensions) {

        this.version = version;
        this.random = random;
        this.legacy_session_id_echo = legacy_session_id_echo;
        this.cipher_suite = cipher_suite;
        this.legacy_compression_method = legacy_compression_method;
        this.extensions = extensions;
    }

    @Override
    public int encodingLength() {
        return Utils.getEncodingLength(
                version,
                random,
                legacy_session_id_echo,
                cipher_suite,
                legacy_compression_method,
                extensions);
    }

    @Override
    public byte[] encoding() throws IOException {
        return Utils.encoding(
                version,
                random,
                legacy_session_id_echo,
                cipher_suite,
                legacy_compression_method,
                extensions);
    }

    @Override
    public ProtocolVersion protocolVersion() {
        return version;
    }

    @Override
    public Random random() {
        return random;
    }

    @Override
    public Vector<Byte> legacySessionIdEcho() {
        return legacy_session_id_echo;
    }

    @Override
    public CipherSuite cipherSuite() {
        return cipher_suite;
    }

    @Override
    public CompressionMethod legacyCompressionMethod() {
        return legacy_compression_method;
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
    public Vector<Extension> extensions() {
        return extensions;
    }

    @Override
    public void extensions(Vector<Extension> extensions) {
        this.extensions = extensions;
    }

    @Override
    public void legacySessionIdEcho(Vector<Byte> legacy_session_id_echo) {
        this.legacy_session_id_echo = legacy_session_id_echo;
    }

    @Override
    public HandshakeType type() {
        return HandshakeType.server_hello;
    }

    @Override
    public ServerHelloImpl copy() {
        return new ServerHelloImpl(
                cast(version.copy(), ProtocolVersion.class),
                cast(random.copy(), Random.class),
                cast(legacy_session_id_echo.copy(), Vector.class),
                cast(cipher_suite.copy(), CipherSuite.class),
                cast(legacy_compression_method.copy(), CompressionMethod.class),
                cast(extensions.copy(), Vector.class));
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) {
            return true;
        }
        if (o == null || getClass() != o.getClass()) {
            return false;
        }
        ServerHelloImpl that = (ServerHelloImpl) o;
        return Objects.equals(version, that.version) &&
                Objects.equals(random, that.random) &&
                Objects.equals(legacy_session_id_echo, that.legacy_session_id_echo) &&
                Objects.equals(cipher_suite, that.cipher_suite) &&
                Objects.equals(legacy_compression_method, that.legacy_compression_method) &&
                Objects.equals(extensions, that.extensions);
    }

    @Override
    public int hashCode() {
        return Objects.hash(version, random, legacy_session_id_echo,
                cipher_suite, legacy_compression_method, extensions);
    }
}
