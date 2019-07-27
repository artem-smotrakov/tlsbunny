package com.gypsyengineer.tlsbunny.tls13.fuzzer;

import com.gypsyengineer.tlsbunny.tls.Random;
import com.gypsyengineer.tlsbunny.tls.Struct;
import com.gypsyengineer.tlsbunny.tls.Vector;
import com.gypsyengineer.tlsbunny.tls13.crypto.AEAD;
import com.gypsyengineer.tlsbunny.tls13.struct.*;

import java.util.List;

import static com.gypsyengineer.tlsbunny.utils.Utils.cantDoThat;

public class FuzzedStruct implements ClientHello, ServerHello, 
        HelloRetryRequest, EncryptedExtensions, EndOfEarlyData, Certificate, 
        CertificateRequest, CertificateVerify, Finished, 
        ProtocolVersion, CipherSuite, Vector, CompressionMethod, 
        Extension, ExtensionType, Random {

    private final int encodingLength;
    private final byte[] encoding;

    public static FuzzedStruct fuzzedHandshakeMessage(byte[] encoding) {
        return new FuzzedStruct(encoding.length, encoding);
    }

    public static FuzzedStruct fuzzedHandshakeMessage(
            int encodingLength, byte[] encoding) {

        return new FuzzedStruct(encodingLength, encoding);
    }

    private FuzzedStruct(int encodingLength, byte[] encoding) {
        this.encodingLength = encodingLength;
        this.encoding = encoding.clone();
    }

    @Override
    public int encodingLength() {
        return encodingLength;
    }

    @Override
    public byte[] encoding() {
        return encoding.clone();
    }

    @Override
    public Struct copy() {
        return new FuzzedStruct(encodingLength, encoding);
    }

    @Override
    public HandshakeType type() {
        throw cantDoThat();
    }

    // implement interfaces of handshake messages
    
    @Override
    public Vector<CertificateEntry> certificateList() {
        throw cantDoThat();
    }

    @Override
    public Vector<Byte> certificateRequestContext() {
        throw cantDoThat();
    }

    @Override
    public SignatureScheme algorithm() {
        throw cantDoThat();
    }

    @Override
    public Vector<Byte> signature() {
        throw cantDoThat();
    }

    @Override
    public Vector<CipherSuite> cipherSuites() {
        throw cantDoThat();
    }

    @Override
    public Vector<CompressionMethod> legacyCompressionMethods() {
        throw cantDoThat();
    }

    @Override
    public Vector<Byte> legacySessionId() {
        throw cantDoThat();
    }

    @Override
    public ProtocolVersion protocolVersion() {
        throw cantDoThat();
    }

    @Override
    public Random random() {
        throw cantDoThat();
    }

    @Override
    public void cipherSuites(Vector<CipherSuite> cipherSuites) {
        throw cantDoThat();
    }

    @Override
    public void extensions(Vector<Extension> extensions) {
        throw cantDoThat();
    }

    @Override
    public void legacySessionIdEcho(Vector<Byte> echo) {
        throw cantDoThat();
    }

    @Override
    public void legacyCompressionMethods(Vector<CompressionMethod> compressionMethods) {
        throw cantDoThat();
    }

    @Override
    public void legacySessionId(Vector<Byte> sessionId) {
        throw cantDoThat();
    }

    @Override
    public Vector<Byte> legacySessionIdEcho() {
        throw cantDoThat();
    }

    @Override
    public CipherSuite cipherSuite() {
        throw cantDoThat();
    }

    @Override
    public CompressionMethod legacyCompressionMethod() {
        throw cantDoThat();
    }

    @Override
    public Vector<Extension> extensions() {
        throw cantDoThat();
    }

    @Override
    public Extension find(ExtensionType type) {
        throw cantDoThat();
    }

    @Override
    public byte[] getVerifyData() {
        throw cantDoThat();
    }

    @Override
    public int size() {
        throw cantDoThat();
    }

    @Override
    public boolean isEmpty() {
        throw cantDoThat();
    }

    @Override
    public Object get(int index) {
        throw cantDoThat();
    }

    @Override
    public Object first() {
        throw cantDoThat();
    }

    @Override
    public void add(Object object) {
        throw cantDoThat();
    }

    @Override
    public void set(int index, Object object) {
        throw cantDoThat();
    }

    @Override
    public void clear() {
        throw cantDoThat();
    }

    @Override
    public List toList() {
        throw cantDoThat();
    }

    @Override
    public int lengthBytes() {
        throw cantDoThat();
    }

    @Override
    public byte[] bytes() {
        throw cantDoThat();
    }

    @Override
    public AEAD.Method cipher() {
        throw cantDoThat();
    }

    @Override
    public int getFirst() {
        throw cantDoThat();
    }

    @Override
    public int getSecond() {
        throw cantDoThat();
    }

    @Override
    public String hash() {
        throw cantDoThat();
    }

    @Override
    public int hashLength() {
        throw cantDoThat();
    }

    @Override
    public int ivLength() {
        throw cantDoThat();
    }

    @Override
    public int keyLength() {
        throw cantDoThat();
    }

    @Override
    public int code() {
        throw cantDoThat();
    }

    @Override
    public Vector<Byte> extensionData() {
        throw cantDoThat();
    }

    @Override
    public ExtensionType extensionType() {
        throw cantDoThat();
    }

    @Override
    public Extension extensionData(Vector<Byte> data) {
        throw cantDoThat();
    }

    @Override
    public Extension extensionType(ExtensionType type) {
        throw cantDoThat();
    }

    @Override
    public int getMinor() {
        throw cantDoThat();
    }

    @Override
    public int getMajor() {
        throw cantDoThat();
    }

    @Override
    public byte[] getBytes() {
        throw cantDoThat();
    }

    @Override
    public void setBytes(byte[] bytes) {
        throw cantDoThat();
    }

    @Override
    public void setLastBytes(byte[] lastBytes) {
        throw cantDoThat();
    }
}
