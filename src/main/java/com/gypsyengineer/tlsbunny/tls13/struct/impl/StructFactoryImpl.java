package com.gypsyengineer.tlsbunny.tls13.struct.impl;

import com.gypsyengineer.tlsbunny.tls.Bytes;
import com.gypsyengineer.tlsbunny.tls.Random;
import com.gypsyengineer.tlsbunny.tls.UInt16;
import com.gypsyengineer.tlsbunny.tls.UInt24;
import com.gypsyengineer.tlsbunny.tls.Vector;
import com.gypsyengineer.tlsbunny.tls13.struct.*;
import com.gypsyengineer.tlsbunny.utils.Utils;

import java.util.List;

// TODO: all implementations should return immutable vectors
public class StructFactoryImpl implements StructFactory {

    @Override
    public TLSPlaintext createTLSPlaintext(
            ContentType type, ProtocolVersion version, byte[] content) {
        
        return new TLSPlaintextImpl(type, version, 
                new UInt16(content.length), new Bytes(content));
    }
    
    @Override
    public TLSPlaintext[] createTLSPlaintexts(
            ContentType type, ProtocolVersion version, byte[] content) {
        
        if (content.length <= TLSPlaintext.max_allowed_length) {
            return new TLSPlaintext[] {
                createTLSPlaintext(type, version, content)
            };
        }

        byte[][] fragments = Utils.split(content, TLSPlaintext.max_allowed_length);
        TLSPlaintext[] tlsPlaintexts = new TLSPlaintext[fragments.length];
        for (int i=0; i < fragments.length; i++) {
            tlsPlaintexts[i] = createTLSPlaintext(type, version, fragments[i]);
        }

        return tlsPlaintexts;
    }
    
    @Override
    public TLSInnerPlaintext createTLSInnerPlaintext(
            ContentType type, byte[] content, byte[] zeros) {
        
        return new TLSInnerPlaintextImpl(new Bytes(content), type, new Bytes(zeros));
    }
    
    @Override
    public Handshake createHandshake(HandshakeType type, byte[] content) {
        return new HandshakeImpl(type, new UInt24(content.length), new Bytes(content));
    }

    @Override
    public Certificate createCertificate(byte[] certificate_request_context,
                                         CertificateEntry... certificate_list) {
        return new CertificateImpl(
                Vector.wrap(Certificate.context_length_bytes, certificate_request_context),
                Vector.wrap(Certificate.certificate_list_length_bytes, certificate_list));
    }

    @Override
    public Alert createAlert(AlertLevel level, AlertDescription description) {
        return new AlertImpl(level, description);
    }
    
    // handshake messages below

    @Override
    public ClientHello createClientHello(ProtocolVersion legacy_version,
                                         Random random,
                                         byte[] legacy_session_id,
                                         List<CipherSuite> cipher_suites,
                                         List<CompressionMethod> legacy_compression_methods,
                                         List<Extension> extensions) {
        return new ClientHelloImpl(
                legacy_version,
                random,
                Vector.wrap(
                        ClientHello.legacy_session_id_length_bytes,
                        legacy_session_id),
                Vector.wrap(
                        ClientHello.cipher_suites_length_bytes,
                        cipher_suites),
                Vector.wrap(
                        ClientHello.legacy_compression_methods_length_bytes,
                        legacy_compression_methods),
                Vector.wrap(
                        ClientHello.extensions_length_bytes,
                        extensions));
    }

    @Override
    public ChangeCipherSpec createChangeCipherSpec(int value) {
        return new ChangeCipherSpecImpl(value);
    }

    @Override
    public ServerHello createServerHello(ProtocolVersion version,
                                         Random random,
                                         byte[] legacy_session_id_echo,
                                         CipherSuite cipher_suite,
                                         CompressionMethod legacy_compression_method,
                                         List<Extension> extensions) {

        return new ServerHelloImpl(
                version,
                random,
                Vector.wrap(
                        ServerHello.legacy_session_id_echo_length_bytes,
                        legacy_session_id_echo),
                cipher_suite,
                legacy_compression_method,
                Vector.wrap(
                        ServerHello.extensions_length_bytes,
                        extensions));
    }

    @Override
    public HelloRetryRequest createHelloRetryRequest() {
        throw new UnsupportedOperationException("I don't know how to do it yet!");
    }
    
    @Override
    public EncryptedExtensions createEncryptedExtensions(Extension... extensions) {
        return new EncryptedExtensionsImpl(
                Vector.wrap(EncryptedExtensions.length_bytes, extensions));
    }
    
    @Override
    public EndOfEarlyData createEndOfEarlyData() {
        throw new UnsupportedOperationException("I don't know how to do it yet!");
    }
    
    @Override
    public CertificateVerify createCertificateVerify(
            SignatureScheme algorithm, byte[] signature) {
        
        return new CertificateVerifyImpl(
                algorithm,
                Vector.wrap(CertificateVerifyImpl.signature_length_bytes, signature));
    }

    @Override
    public CertificateRequest createCertificateRequest(byte[] certificate_request_context,
                                                       List<Extension> extensions) {
        return new CertificateRequestImpl(
                Vector.wrap(
                        CertificateRequest.certificate_request_context_length_bytes,
                        certificate_request_context),
                Vector.wrap(
                        CertificateRequest.extensions_length_bytes,
                        extensions));
    }

    @Override
    public Finished createFinished(byte[] verify_data) {
        return new FinishedImpl(new Bytes(verify_data));
    }

    @Override
    public SupportedVersions.ClientHello createSupportedVersionForClientHello(
            ProtocolVersion version) {

        return new SupportedVersionsImpl.ClientHelloImpl(
                Vector.wrap(SupportedVersions.ClientHello.versions_length_bytes, version));
    }

    @Override
    public SupportedVersions.ServerHello createSupportedVersionForServerHello(
            ProtocolVersion version) {

        return new SupportedVersionsImpl.ServerHelloImpl(version);
    }
    
    @Override
    public Extension createExtension(ExtensionType type, byte[] bytes) {
        return new ExtensionImpl(
                type, 
                Vector.wrap(Extension.extension_data_length_bytes, bytes));
    }

    @Override
    public Cookie createCookie(Vector<Byte> cookie) {
        return new CookieImpl(cookie);
    }

    @Override
    public Cookie createCookie(byte[] cookie) {
        return createCookie(Vector.wrap(Cookie.length_bytes, cookie));
    }

    @Override
    public CompressionMethod createCompressionMethod(int code) {
        return new CompressionMethodImpl(code);
    }

    @Override
    public KeyShare.ClientHello createKeyShareForClientHello(KeyShareEntry... entries) {
        if (entries.length > 0) {
            return new KeyShareImpl.ClientHelloImpl(
                    Vector.wrap(
                            KeyShare.ClientHello.length_bytes,
                            entries));
        }

        return new KeyShareImpl.ClientHelloImpl();
    }

    @Override
    public KeyShare.ServerHello createKeyShareForServerHello(KeyShareEntry entry) {
        return new KeyShareImpl.ServerHelloImpl(entry);
    }

    @Override
    public SignatureSchemeList createSignatureSchemeList(SignatureScheme scheme) {
        return new SignatureSchemeListImpl(
                Vector.wrap(SignatureSchemeList.length_bytes, scheme));
    }

    @Override
    public NamedGroupList createNamedGroupList(NamedGroup... groups) {
        return new NamedGroupListImpl(
                Vector.wrap(NamedGroupList.length_bytes, groups));
    }

    @Override
    public AlertLevel createAlertLevel(int code) {
        return new AlertLevelImpl(code);
    }

    @Override
    public AlertDescription createAlertDescription(int code) {
        return new AlertDescriptionImpl(code);
    }

    @Override
    public HkdfLabel createHkdfLabel(int length, byte[] label, byte[] hashValue) {
        return new HkdfLabelImpl(
                new UInt16(length),
                Vector.wrap(HkdfLabel.label_length_bytes, label),
                Vector.wrap(HkdfLabel.context_length_bytes, hashValue));
    }

    @Override
    public CipherSuite createCipherSuite(int first, int second) {
        return new CipherSuiteImpl(first, second);
    }

    @Override
    public UncompressedPointRepresentation createUncompressedPointRepresentation(
            byte[] X, byte[] Y) {
        
        return new UncompressedPointRepresentationImpl(X, Y);
    }

    @Override
    public HandshakeType createHandshakeType(int code) {
        return new HandshakeTypeImpl(code);
    }

    @Override
    public ProtocolVersion createProtocolVersion(int minor, int major) {
        return new ProtocolVersionImpl(minor, major);
    }

    @Override
    public ExtensionType createExtensionType(int code) {
        return new ExtensionTypeImpl(code);
    }

    @Override
    public ContentType createContentType(int code) {
        return new ContentTypeImpl(code);
    }

    @Override
    public SignatureScheme createSignatureScheme(int code) {
        return new SignatureSchemeImpl(code);
    }

    @Override
    public NamedGroup.FFDHE createFFDHENamedGroup(int code) {
        return new NamedGroupImpl.FFDHEImpl(code);
    }

    @Override
    public NamedGroup.Secp createSecpNamedGroup(int code, String curve) {
        return new NamedGroupImpl.SecpImpl(code, curve);
    }

    @Override
    public NamedGroup.X createXNamedGroup(int code) {
        return new NamedGroupImpl.XImpl(code);
    }

    @Override
    public KeyShareEntry createKeyShareEntry(NamedGroup group, byte[] bytes) {
        return new KeyShareEntryImpl(
                group, 
                Vector.wrap(KeyShareEntry.key_exchange_length_bytes, bytes));
    }

    @Override
    public MaxFragmentLength createMaxFragmentLength(int code) {
        return new MaxFragmentLengthImpl(code);
    }

    @Override
    public CertificateStatusType createCertificateStatusType(int code) {
        return new CertificateStatusTypeImpl(code);
    }

    @Override
    public OCSPStatusRequest createOCSPStatusRequest(Vector<ResponderID> responder_id_list,
                                                     Vector<Byte> extensions) {
        return new OCSPStatusRequestImpl(responder_id_list, extensions);
    }

    @Override
    public CertificateStatusRequest createCertificateStatusRequest(CertificateStatusType status_type,
                                                                   OCSPStatusRequest request) {
        return new CertificateStatusRequestImpl(status_type, request);
    }

    @Override
    public CertificateEntry.X509 createX509CertificateEntry(byte[] bytes) {
        return new CertificateEntryImpl.X509Impl(
                    Vector.wrap(CertificateEntry.X509.length_bytes, bytes),
                    Vector.wrap(CertificateEntry.X509.extensions_length_bytes));
    }

    @Override
    public StructParser parser() {
        return new StructParserImpl();
    }
    
}
