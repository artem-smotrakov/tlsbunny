package com.gypsyengineer.tlsbunny.tls13.struct.impl;

import com.gypsyengineer.tlsbunny.tls.Random;
import com.gypsyengineer.tlsbunny.tls.Vector;
import com.gypsyengineer.tlsbunny.tls13.struct.CipherSuite;
import com.gypsyengineer.tlsbunny.tls13.struct.CompressionMethod;
import com.gypsyengineer.tlsbunny.tls13.struct.Extension;
import com.gypsyengineer.tlsbunny.tls13.struct.HandshakeType;
import com.gypsyengineer.tlsbunny.tls13.struct.HelloRetryRequest;
import com.gypsyengineer.tlsbunny.tls13.struct.ProtocolVersion;

public class HelloRetryRequestImpl extends ServerHelloImpl implements HelloRetryRequest {

    HelloRetryRequestImpl(ProtocolVersion version,
                          Random random,
                          Vector<Byte> legacy_session_id_echo,
                          CipherSuite cipher_suite,
                          CompressionMethod legacy_compression_method,
                          Vector<Extension> extensions) {

        super(version, random, legacy_session_id_echo, cipher_suite,
                legacy_compression_method, extensions);
    }

    @Override
    public HandshakeType type() {
        return HandshakeType.hello_retry_request;
    }

    @Override
    public HelloRetryRequestImpl copy() {
        return new HelloRetryRequestImpl(
                (ProtocolVersion) version.copy(),
                (Random) random.copy(),
                (Vector<Byte>) legacy_session_id_echo.copy(),
                (CipherSuite) cipher_suite.copy(),
                (CompressionMethod) legacy_compression_method.copy(),
                (Vector<Extension>) extensions.copy());
    }
}
