package com.gypsyengineer.tlsbunny.tls13.fuzzer;

import com.gypsyengineer.tlsbunny.fuzzer.Fuzzer;
import com.gypsyengineer.tlsbunny.tls.Random;
import com.gypsyengineer.tlsbunny.tls.UInt16;
import com.gypsyengineer.tlsbunny.tls.UInt32;
import com.gypsyengineer.tlsbunny.tls.Vector;
import com.gypsyengineer.tlsbunny.tls13.struct.*;

import java.util.Arrays;
import java.util.List;
import java.util.Objects;
import java.util.Scanner;
import java.util.stream.Collectors;

public abstract class FuzzyStructFactory<T> implements StructFactory, Fuzzer<T> {

    protected final StructFactory factory;
    protected Target[] targets;
    protected Fuzzer<T> fuzzer;

    public FuzzyStructFactory(StructFactory factory) {
        Objects.requireNonNull(factory, "Hey! Factory can't be null!");
        this.factory = factory;
    }

    @Override
    public String toString() {
        return String.format("%s (targets = %s, fuzzer = %s)",
                getClass().getSimpleName(),
                Arrays.stream(targets)
                        .map(Object::toString)
                        .collect(Collectors.joining(",")),
                fuzzer.getClass().getSimpleName());
    }

    public synchronized FuzzyStructFactory targets(Target... targets) {
        this.targets = targets.clone();
        return this;
    }

    public synchronized FuzzyStructFactory targets(String... targets) {
        this.targets = new Target[targets.length];
        for (int i = 0; i < targets.length; i++) {
            this.targets[i] = Target.valueOf(targets[i]);
        }
        return this;
    }

    public synchronized Target[] targets() {
        return targets.clone();
    }

    public synchronized FuzzyStructFactory<T> fuzzer(Fuzzer<T> fuzzer) {
        this.fuzzer = fuzzer;
        return this;
    }

    public synchronized Fuzzer<T> fuzzer() {
        return fuzzer;
    }

    // implement methods from Fuzzer

    @Override
    public synchronized String state() {
        return String.format("%s:%s",
                Arrays.stream(targets)
                        .map(Enum::toString)
                        .collect(Collectors.joining( "-")),
                fuzzer.state());
    }

    @Override
    public synchronized void state(String string) {
        try (Scanner scanner = new Scanner(string)) {
            scanner.useDelimiter(":");
            targets(scanner.next().split("-"));
            scanner.skip(":");
            fuzzer.state(scanner.nextLine());
        }
    }

    @Override
    public synchronized boolean canFuzz() {
        return fuzzer.canFuzz();
    }

    @Override
    public synchronized void moveOn() {
        fuzzer.moveOn();
    }

    protected boolean targeted(Target target) {
        for (Target t : targets) {
            if (t == target) {
                return true;
            }
        }

        return false;
    }

    // implement StructFactory

    @Override
    public CompressionMethod createCompressionMethod(int code) {
        return factory.createCompressionMethod(code);
    }

    @Override
    public CipherSuite createCipherSuite(int first, int second) {
        return factory.createCipherSuite(first, second);
    }

    @Override
    public HkdfLabel createHkdfLabel(int length, byte[] label, byte[] hashValue) {
        return factory.createHkdfLabel(length, label, hashValue);
    }

    @Override
    public UncompressedPointRepresentation createUncompressedPointRepresentation(
            byte[] X, byte[] Y) {

        return factory.createUncompressedPointRepresentation(X, Y);
    }

    @Override
    public HandshakeType createHandshakeType(int code) {
        return factory.createHandshakeType(code);
    }

    @Override
    public ProtocolVersion createProtocolVersion(int minor, int major) {
        return factory.createProtocolVersion(minor, major);
    }

    @Override
    public ExtensionType createExtensionType(int code) {
        return factory.createExtensionType(code);
    }

    @Override
    public Cookie createCookie(byte[] cookie) {
        return factory.createCookie(cookie);
    }

    @Override
    public ContentType createContentType(int code) {
        return factory.createContentType(code);
    }

    @Override
    public SignatureScheme createSignatureScheme(int code) {
        return factory.createSignatureScheme(code);
    }

    @Override
    public NamedGroup.FFDHE createFFDHENamedGroup(int code) {
        return factory.createFFDHENamedGroup(code);
    }

    @Override
    public NamedGroup.Secp createSecpNamedGroup(int code, String curve) {
        return factory.createSecpNamedGroup(code, curve);
    }

    @Override
    public NamedGroup.X createXNamedGroup(int code) {
        return factory.createXNamedGroup(code);
    }

    @Override
    public KeyShareEntry createKeyShareEntry(NamedGroup group, byte[] bytes) {
        return factory.createKeyShareEntry(group, bytes);
    }

    @Override
    public TLSInnerPlaintext createTLSInnerPlaintext(
            ContentType type, byte[] content, byte[] zeros) {

        return factory.createTLSInnerPlaintext(type, content, zeros);
    }

    @Override
    public TLSPlaintext createTLSPlaintext(
            ContentType type, ProtocolVersion version, byte[] content) {

        return factory.createTLSPlaintext(type, version, content);
    }

    @Override
    public TLSPlaintext[] createTLSPlaintexts(
            ContentType type, ProtocolVersion version, byte[] content) {

        return factory.createTLSPlaintexts(type, version, content);
    }

    @Override
    public AlertLevel createAlertLevel(int code) {
        return factory.createAlertLevel(code);
    }

    @Override
    public AlertDescription createAlertDescription(int code) {
        return factory.createAlertDescription(code);
    }

    @Override
    public Alert createAlert(AlertLevel level, AlertDescription description) {
        return factory.createAlert(level, description);
    }

    @Override
    public ChangeCipherSpec createChangeCipherSpec(int value) {
        return factory.createChangeCipherSpec(value);
    }

    @Override
    public Handshake createHandshake(HandshakeType type, byte[] content) {
        return factory.createHandshake(type, content);
    }

    @Override
    public Certificate createCertificate(byte[] certificate_request_context,
                                         CertificateEntry... certificate_list) {

        return factory.createCertificate(certificate_request_context, certificate_list);
    }

    @Override
    public CertificateRequest createCertificateRequest(byte[] certificate_request_context,
                                                       List<Extension> extensions) {
        return factory.createCertificateRequest(certificate_request_context, extensions);
    }

    @Override
    public CertificateVerify createCertificateVerify(
            SignatureScheme algorithm, byte[] signature) {

        return factory.createCertificateVerify(algorithm, signature);
    }

    @Override
    public ClientHello createClientHello(ProtocolVersion legacy_version,
                                         Random random,
                                         byte[] legacy_session_id,
                                         List<CipherSuite> cipher_suites,
                                         List<CompressionMethod> legacy_compression_methods,
                                         List<Extension> extensions) {

        return factory.createClientHello(legacy_version, random,
                legacy_session_id, cipher_suites, legacy_compression_methods, extensions);
    }

    @Override
    public EncryptedExtensions createEncryptedExtensions(Extension... extensions) {
        return factory.createEncryptedExtensions(extensions);
    }

    @Override
    public EndOfEarlyData createEndOfEarlyData() {
        return factory.createEndOfEarlyData();
    }

    @Override
    public Finished createFinished(byte[] verify_data) {
        return factory.createFinished(verify_data);
    }

    @Override
    public HelloRetryRequest createHelloRetryRequest() {
        return factory.createHelloRetryRequest();
    }

    @Override
    public ServerHello createServerHello(ProtocolVersion version,
                                         Random random,
                                         byte[] legacy_session_id_echo,
                                         CipherSuite cipher_suite,
                                         CompressionMethod legacy_compression_method,
                                         List<Extension> extensions) {

        return factory.createServerHello(version, random, legacy_session_id_echo,
                cipher_suite, legacy_compression_method, extensions);
    }

    @Override
    public KeyShare.ClientHello createKeyShareForClientHello(KeyShareEntry... entries) {
        return factory.createKeyShareForClientHello(entries);
    }

    @Override
    public KeyShare.ServerHello createKeyShareForServerHello(KeyShareEntry entry) {
        return factory.createKeyShareForServerHello(entry);
    }

    @Override
    public SupportedVersions.ClientHello createSupportedVersionForClientHello(
            ProtocolVersion version) {

        return factory.createSupportedVersionForClientHello(version);
    }

    @Override
    public SupportedVersions.ServerHello createSupportedVersionForServerHello(
            ProtocolVersion version) {

        return factory.createSupportedVersionForServerHello(version);
    }

    @Override
    public SignatureSchemeList createSignatureSchemeList(SignatureScheme scheme) {
        return factory.createSignatureSchemeList(scheme);
    }

    @Override
    public NamedGroupList createNamedGroupList(NamedGroup... groups) {
        return factory.createNamedGroupList(groups);
    }

    @Override
    public CertificateEntry.X509 createX509CertificateEntry(byte[] bytes) {
        return factory.createX509CertificateEntry(bytes);
    }

    @Override
    public Extension createExtension(ExtensionType type, byte[] bytes) {
        return factory.createExtension(type, bytes);
    }

    @Override
    public MaxFragmentLength createMaxFragmentLength(int code) {
        return factory.createMaxFragmentLength(code);
    }

    @Override
    public CertificateStatusType createCertificateStatusType(int code) {
        return factory.createCertificateStatusType(code);
    }

    @Override
    public OCSPStatusRequest createOCSPStatusRequest(Vector<ResponderID> responder_id_list,
                                                     Vector<Byte> extensions) {
        return factory.createOCSPStatusRequest(responder_id_list, extensions);
    }

    @Override
    public CertificateStatusRequest createCertificateStatusRequest(CertificateStatusType status_type,
                                                                   OCSPStatusRequest request) {
        return factory.createCertificateStatusRequest(status_type, request);
    }

    @Override
    public PreSharedKeyExtension.ClientHello createPreSharedKeyExtensionForClientHello(OfferedPsks offeredPsks) {
        return factory.createPreSharedKeyExtensionForClientHello(offeredPsks);
    }

    @Override
    public PreSharedKeyExtension.ServerHello createPreSharedKeyExtensionForServerHello(UInt16 selected_identity) {
        return factory.createPreSharedKeyExtensionForServerHello(selected_identity);
    }

    @Override
    public OfferedPsks createOfferedPsks(Vector<PskIdentity> identities, Vector<PskBinderEntry> binders) {
        return factory.createOfferedPsks(identities, binders);
    }

    @Override
    public PskIdentity createPskIdentity(Vector<Byte> identity, UInt32 obfuscated_ticket_age) {
        return factory.createPskIdentity(identity, obfuscated_ticket_age);
    }

    @Override
    public PskBinderEntry createPskBinderEntry(Vector<Byte> content) {
        return factory.createPskBinderEntry(content);
    }

    @Override
    public PskKeyExchangeMode createPskKeyExchangeMode(int code) {
        return factory.createPskKeyExchangeMode(code);
    }

    @Override
    public PskKeyExchangeModes createPskKeyExchangeModes(Vector<PskKeyExchangeMode> ke_modes) {
        return factory.createPskKeyExchangeModes(ke_modes);
    }

    @Override
    public NewSessionTicket createNewSessionTicket(UInt32 ticket_lifetime,
                                                   UInt32 ticket_age_add,
                                                   Vector<Byte> ticket_nonce,
                                                   Vector<Byte> ticket,
                                                   Vector<Extension> extensions) {
        return factory.createNewSessionTicket(
                ticket_lifetime, ticket_age_add, ticket_nonce, ticket, extensions);
    }

    @Override
    public StructParser parser() {
        return factory.parser();
    }

}
