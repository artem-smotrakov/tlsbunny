package com.gypsyengineer.tlsbunny.tls13.fuzzer;

import com.gypsyengineer.tlsbunny.tls.*;
import com.gypsyengineer.tlsbunny.tls13.struct.*;

import static com.gypsyengineer.tlsbunny.utils.Utils.cantDoThat;

public class MutatedStruct implements TLSPlaintext, Handshake, ChangeCipherSpec,
        ClientHello, ServerHello, EncryptedExtensions, Finished, Certificate,
        CertificateVerify {

    private static final HandshakeType NO_HANDSHAKE_TYPE = null;

    private final int mutatedEncodingLength;
    private final byte[] mutatedEncoding;
    private final HandshakeType handshakeType;

    public MutatedStruct(byte[] mutatedEncoding) {
        this(mutatedEncoding.length, mutatedEncoding, NO_HANDSHAKE_TYPE);
    }

    public MutatedStruct(int mutatedEncodingLength, byte[] mutatedEncoding) {
        this(mutatedEncodingLength, mutatedEncoding, NO_HANDSHAKE_TYPE);
    }

    public MutatedStruct(int mutatedEncodingLength, byte[] mutatedEncoding,
            HandshakeType handshakeType) {

        this.mutatedEncodingLength = mutatedEncodingLength;
        this.mutatedEncoding = mutatedEncoding;
        this.handshakeType = handshakeType;
    }

    // Struct

    @Override
    public int encodingLength() {
        return mutatedEncodingLength;
    }

    @Override
    public byte[] encoding() {
        return mutatedEncoding;
    }

    @Override
    public Struct copy() {
        throw cantDoThat();
    }

    // TLSPlaintext

    @Override
    public boolean containsAlert() {
        throw cantDoThat();
    }

    @Override
    public boolean containsApplicationData() {
        throw cantDoThat();
    }

    @Override
    public boolean containsHandshake() {
        throw cantDoThat();
    }

    @Override
    public boolean containsChangeCipherSpec() {
        throw new UnsupportedOperationException();
    }

    @Override
    public byte[] getFragment() {
        throw cantDoThat();
    }

    @Override
    public ProtocolVersion getLegacyRecordVersion() {
        throw cantDoThat();
    }

    @Override
    public ContentType getType() {
        throw cantDoThat();
    }

    @Override
    public boolean containsCertificate() {
        throw new UnsupportedOperationException();
    }

    @Override
    public boolean containsCertificateRequest() {
        throw new UnsupportedOperationException();
    }

    @Override
    public boolean containsCertificateVerify() {
        throw new UnsupportedOperationException();
    }

    @Override
    public boolean containsClientHello() {
        throw new UnsupportedOperationException();
    }

    @Override
    public boolean containsEncryptedExtensions() {
        throw new UnsupportedOperationException();
    }

    @Override
    public boolean containsFinished() {
        throw new UnsupportedOperationException();
    }

    @Override
    public boolean containsHelloRetryRequest() {
        throw new UnsupportedOperationException();
    }

    @Override
    public boolean containsNewSessionTicket() {
        throw new UnsupportedOperationException();
    }

    @Override
    public boolean containsServerHello() {
        throw new UnsupportedOperationException();
    }

    @Override
    public byte[] getBody() {
        throw new UnsupportedOperationException();
    }

    @Override
    public HandshakeType getMessageType() {
        throw new UnsupportedOperationException();
    }

    @Override
    public Handshake bodyLength(UInt24 length) {
        throw new UnsupportedOperationException();
    }

    @Override
    public UInt16 getFragmentLength() {
        throw new UnsupportedOperationException();
    }

    @Override
    public UInt24 getBodyLength() {
        throw new UnsupportedOperationException();
    }

    @Override
    public HandshakeType type() {
        return handshakeType;
    }

    @Override
    public Vector<CipherSuite> cipherSuites() {
        throw new UnsupportedOperationException();
    }

    @Override
    public Vector<CompressionMethod> legacyCompressionMethods() {
        throw new UnsupportedOperationException();
    }

    @Override
    public Vector<Byte> legacySessionId() {
        throw new UnsupportedOperationException();
    }

    @Override
    public ProtocolVersion protocolVersion() {
        throw new UnsupportedOperationException();
    }

    @Override
    public Random random() {
        throw new UnsupportedOperationException();
    }

    @Override
    public void cipherSuites(Vector<CipherSuite> cipherSuites) {
        throw new UnsupportedOperationException();
    }

    @Override
    public void extensions(Vector<Extension> extensions) {
        throw new UnsupportedOperationException();
    }

    @Override
    public void legacySessionIdEcho(Vector<Byte> echo) {
        throw new UnsupportedOperationException();
    }

    @Override
    public void legacyCompressionMethods(Vector<CompressionMethod> compressionMethods) {
        throw new UnsupportedOperationException();
    }

    @Override
    public void legacySessionId(Vector<Byte> sessionId) {
        throw new UnsupportedOperationException();
    }

    @Override
    public Vector<Byte> legacySessionIdEcho() {
        throw new UnsupportedOperationException();
    }

    @Override
    public CipherSuite cipherSuite() {
        throw new UnsupportedOperationException();
    }

    @Override
    public CompressionMethod legacyCompressionMethod() {
        throw new UnsupportedOperationException();
    }

    @Override
    public Vector<Extension> extensions() {
        throw new UnsupportedOperationException();
    }

    @Override
    public Extension find(ExtensionType type) {
        throw new UnsupportedOperationException();
    }

    @Override
    public byte[] getVerifyData() {
        throw new UnsupportedOperationException();
    }

    @Override
    public Vector<CertificateEntry> certificateList() {
        throw new UnsupportedOperationException();
    }

    @Override
    public Vector<Byte> certificateRequestContext() {
        throw new UnsupportedOperationException();
    }

    @Override
    public SignatureScheme algorithm() {
        throw new UnsupportedOperationException();
    }

    @Override
    public Vector<Byte> signature() {
        throw new UnsupportedOperationException();
    }

    // ChangeCipherSpec

    @Override
    public int getValue() {
        throw new UnsupportedOperationException();
    }

    @Override
    public boolean isValid() {
        throw new UnsupportedOperationException();
    }
}
