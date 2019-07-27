package com.gypsyengineer.tlsbunny.tls13.struct;

import com.gypsyengineer.tlsbunny.tls.Random;
import com.gypsyengineer.tlsbunny.tls.Vector;
import com.gypsyengineer.tlsbunny.tls13.struct.impl.StructFactoryImpl;
import java.util.List;

public interface StructFactory {
    
    static StructFactory getDefault() {
        return new StructFactoryImpl();
    }

    CompressionMethod createCompressionMethod(int code);
    CipherSuite createCipherSuite(int first, int second);
    HkdfLabel createHkdfLabel(int length, byte[] label, byte[] hashValue);
    UncompressedPointRepresentation createUncompressedPointRepresentation(byte[] X,
                                                                          byte[] Y);
    HandshakeType createHandshakeType(int code);
    ProtocolVersion createProtocolVersion(int minor, int major);
    ExtensionType createExtensionType(int code);
    ContentType createContentType(int code);
    SignatureScheme createSignatureScheme(int code);
    NamedGroup.FFDHE createFFDHENamedGroup(int code);
    NamedGroup.Secp createSecpNamedGroup(int code, String curve);
    NamedGroup.X createXNamedGroup(int code);
    KeyShareEntry createKeyShareEntry(NamedGroup group, byte[] bytes);
    
    TLSInnerPlaintext createTLSInnerPlaintext(ContentType type,
                                              byte[] content,
                                              byte[] zeros);
    TLSPlaintext createTLSPlaintext(ContentType type,
                                    ProtocolVersion version,
                                    byte[] content);
    TLSPlaintext[] createTLSPlaintexts(ContentType type,
                                       ProtocolVersion version,
                                       byte[] content);

    AlertLevel createAlertLevel(int code);
    AlertDescription createAlertDescription(int code);
    Alert createAlert(AlertLevel level, AlertDescription description);

    ChangeCipherSpec createChangeCipherSpec(int value);
    
    // handshake messages
    Handshake createHandshake(HandshakeType type, byte[] content);

    Certificate createCertificate(byte[] certificate_request_context,
                                          CertificateEntry... certificate_list);

    CertificateRequest createCertificateRequest(byte[] certificate_request_context,
                                                List<Extension> extensions);

    CertificateVerify createCertificateVerify(SignatureScheme algorithm,
                                              byte[] signature);

    ClientHello createClientHello(ProtocolVersion legacy_version,
                                  Random random,
                                  byte[] legacy_session_id,
                                  List<CipherSuite> cipher_suites,
                                  List<CompressionMethod> legacy_compression_methods,
                                  List<Extension> extensions);

    EndOfEarlyData createEndOfEarlyData();
    Finished createFinished(byte[] verify_data);
    HelloRetryRequest createHelloRetryRequest();

    EncryptedExtensions createEncryptedExtensions(Extension... extensions);

    ServerHello createServerHello(ProtocolVersion version,
                                  Random random,
                                  byte[] legacy_session_id_echo,
                                  CipherSuite cipher_suite,
                                  CompressionMethod legacy_compression_method,
                                  List<Extension> extensions);

    // create extensions
    KeyShare.ClientHello createKeyShareForClientHello(KeyShareEntry... entries);
    KeyShare.ServerHello createKeyShareForServerHello(KeyShareEntry entry);
    SupportedVersions.ClientHello createSupportedVersionForClientHello(ProtocolVersion version);
    SupportedVersions.ServerHello createSupportedVersionForServerHello(ProtocolVersion version);
    SignatureSchemeList createSignatureSchemeList(SignatureScheme scheme);
    NamedGroupList createNamedGroupList(NamedGroup... groups);
    CertificateEntry.X509 createX509CertificateEntry(byte[] bytes);
    Extension createExtension(ExtensionType type, byte[] bytes);
    Cookie createCookie(Vector<Byte> cookie);
    Cookie createCookie(byte[] cookie);
    MaxFragmentLength createMaxFragmentLength(int code);
    CertificateStatusType createCertificateStatusType(int code);
    OCSPStatusRequest createOCSPStatusRequest(Vector<ResponderID> responder_id_list,
                                              Vector<Byte> extensions);
    CertificateStatusRequest createCertificateStatusRequest(CertificateStatusType status_type,
                                                            OCSPStatusRequest request);
    
    StructParser parser();
}
