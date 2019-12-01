package com.gypsyengineer.tlsbunny.tls13.fuzzer;

import com.gypsyengineer.tlsbunny.fuzzer.Fuzzer;
import com.gypsyengineer.tlsbunny.tls.*;
import com.gypsyengineer.tlsbunny.tls.Random;
import com.gypsyengineer.tlsbunny.tls.Vector;
import com.gypsyengineer.tlsbunny.tls13.struct.*;
import com.gypsyengineer.tlsbunny.utils.HexDump;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.io.IOException;
import java.util.*;

import static com.gypsyengineer.tlsbunny.fuzzer.ByteFlipFuzzer.byteFlipFuzzer;
import static com.gypsyengineer.tlsbunny.tls13.fuzzer.FuzzedStruct.fuzzedHandshakeMessage;
import static com.gypsyengineer.tlsbunny.utils.HexDump.printHexDiff;
import static com.gypsyengineer.tlsbunny.utils.Utils.cast;
import static com.gypsyengineer.tlsbunny.utils.WhatTheHell.whatTheHell;

public class DeepHandshakeFuzzer implements Fuzzer<HandshakeMessage>, StructFactory {

    private static final Logger logger = LogManager.getLogger(DeepHandshakeFuzzer.class);

    private final StructFactory factory;
    private Fuzzer<byte[]> fuzzer = byteFlipFuzzer();
    private Mode mode;
    private final List<Holder> recorded = new ArrayList<>();
    private int currentHolderIndex = 0;
    private int currentPathIndex = 0;
    private int round = 0;
    private int rounds = 10;

    public static DeepHandshakeFuzzer deepHandshakeFuzzer() {
        return deepHandshakeFuzzer(StructFactory.getDefault());
    }

    public static DeepHandshakeFuzzer deepHandshakeFuzzer(StructFactory factory) {
        return new DeepHandshakeFuzzer(factory);
    }

    private DeepHandshakeFuzzer(StructFactory factory) {
        Objects.requireNonNull(factory, "Hey! Factory can't be null!");
        this.factory = factory;
    }

    @Override
    public String toString() {
        return String.format("%s (fuzzer = %s, mode = %s)",
                getClass().getSimpleName(),
                fuzzer.getClass().getSimpleName(),
                mode);
    }

    public Fuzzer<byte[]> fuzzer() {
        return fuzzer;
    }

    public DeepHandshakeFuzzer set(Fuzzer<byte[]> fuzzer) {
        this.fuzzer = fuzzer;
        return this;
    }

    public synchronized HandshakeType[] targeted() {
        HandshakeType[] targeted = new HandshakeType[recorded.size()];

        int i = 0;
        for (Holder holder : recorded) {
            targeted[i++] = holder.message.type();
        }

        return targeted;
    }

    private boolean shouldFuzz(HandshakeMessage message) {
        if (mode != Mode.fuzzing || recorded.isEmpty()) {
            return false;
        }

        return currentHolder().match(message);
    }

    private Holder currentHolder() {
        return recorded.get(currentHolderIndex);
    }

    private Path currentPath() {
        return currentHolder().paths[currentPathIndex];
    }

    // switch to recording mode
    public synchronized DeepHandshakeFuzzer recording() {
        mode = Mode.recording;
        recorded.clear();
        return this;
    }

    // switch to fuzzing mode
    public synchronized DeepHandshakeFuzzer fuzzing() {
        mode = Mode.fuzzing;
        return this;
    }

    @Override
    public HandshakeMessage fuzz(HandshakeMessage message) {
        message = (HandshakeMessage) message.copy();

        if (mode != Mode.fuzzing) {
            throw whatTheHell(
                    "could not start fuzzing in mode '%s'", mode);
        }

        if (recorded.isEmpty()) {
            throw whatTheHell(
                    "could not start fuzzing since no messages were targeted!");
        }

        if (!currentHolder().match(message)) {
            return message;
        }

        Path path = currentPath();
        Struct target = get(message, path);

        byte[] encoding;
        try {
             encoding = target.encoding();
        } catch (IOException e) {
            throw whatTheHell("could not encode", e);
        }

        byte[] fuzzed = fuzzer.fuzz(encoding);
        HandshakeMessage fuzzedMessage = set(
                message, currentPath(), fuzzedHandshakeMessage(fuzzed));

        logger.info(HexDump.explain(target.getClass().getSimpleName(), encoding, fuzzed));

        return fuzzedMessage;
    }

    @Override
    public boolean canFuzz() {
        return fuzzer.canFuzz();
    }

    @Override
    public void moveOn() {
        boolean finished = incrementRound();
        if (finished) {
            finished = incrementPath();
            if (finished) {
                nextTarget();
            }
        }

        fuzzer.moveOn();
    }

    @Override
    public String state() {
        return String.format("%d:%d:%d:%d:%s",
                currentHolderIndex, currentPathIndex,
                rounds, round,
                fuzzer.state());
    }

    @Override
    public void state(String string) {
        try (Scanner scanner = new Scanner(string)) {
            scanner.useDelimiter(":");
            currentHolderIndex = scanner.nextInt();
            currentPathIndex = scanner.nextInt();
            rounds = scanner.nextInt();
            round = scanner.nextInt();
            scanner.skip(":");
            fuzzer.state(scanner.nextLine());
        }
    }

    List<Holder> recorded() {
        return recorded;
    }

    DeepHandshakeFuzzer rounds(int rounds) {
        this.rounds = rounds;
        return this;
    }

    private boolean incrementRound() {
        if (round == rounds - 1) {
            round = 0;
            return true;
        }

        round++;
        return false;
    }

    private boolean incrementPath() {
        if (currentPathIndex == recorded.get(currentHolderIndex).paths.length - 1) {
            currentPathIndex = 0;
            return true;
        }

        currentPathIndex++;
        return false;
    }

    private void nextTarget() {
        currentHolderIndex++;
        currentHolderIndex %= recorded.size();
    }

    private DeepHandshakeFuzzer record(HandshakeMessage message) {
        recorded.add(new Holder(message));
        return this;
    }

    private MessageAction with(HandshakeMessage message) {
        return new MessageAction(this, message);
    }

    private <T> T handle(HandshakeMessage message) {
        return with(message)
                .record()
                .fuzz()
                .get();
    }

    private enum Mode { recording, fuzzing }

    private static class MessageAction {

        private final DeepHandshakeFuzzer fuzzer;
        private HandshakeMessage message;

        MessageAction(DeepHandshakeFuzzer fuzzer, HandshakeMessage message) {
            this.fuzzer = fuzzer;
            this.message = message;
        }

        public MessageAction fuzz() {
            if (fuzzer.shouldFuzz(message)) {
                message = fuzzer.fuzz(message);
            }
            return this;
        }

        public MessageAction record() {
            if (fuzzer.mode == Mode.recording) {
                fuzzer.record(message);
            }
            return this;
        }

        public <T> T get() {
            if (!HandshakeMessage.class.isAssignableFrom(message.getClass())) {
                throw whatTheHell("expected %s but received %s",
                        HandshakeMessage.class.getSimpleName(),
                        message.getClass().getSimpleName());
            }
            return (T) message;
        }

    }

    static class Path {

        private final List<Integer> indexes;

        private Path() {
            this.indexes = new ArrayList<>();
        }

        Path copy() {
            Path clone = new Path();
            for (int index : indexes) {
                clone.indexes.add(index);
            }
            return clone;
        }

        Path add(int index) {
            indexes.add(index);
            return this;
        }

        Integer[] indexes() {
            return indexes.toArray(new Integer[indexes.size()]);
        }

        boolean empty() {
            return indexes.isEmpty();
        }

        Path reduced() {
            if (indexes.isEmpty()) {
                throw whatTheHell("path is empty!");
            }

            Path reduced = copy();
            reduced.indexes.remove(indexes.size() - 1);
            return reduced;
        }

        int lastIndex() {
            return indexes.get(indexes.size() - 1);
        }
    }

    private static Path[] browse(HandshakeMessage message) {
        List<Path> paths = new ArrayList<>();
        browse(message, new Path(), paths);
        return paths.toArray(new Path[paths.size()]);
    }

    private static void browse(Struct struct, Path path, List<Path> paths) {
        paths.add(path);
        for (int index = 0; index < struct.total(); index++) {
             browse(struct.element(index), path.copy().add(index), paths);
        }
    }

    private static Struct get(Struct message, Path path) {
        for (int index : path.indexes) {
            message = message.element(index);
        }
        return message;
    }

    private static HandshakeMessage set(
            HandshakeMessage message, Path path, Struct replacement) {

        if (path.empty()) {
            return cast(replacement, HandshakeMessage.class);
        }

        Struct target = get(message, path.reduced());
        target.element(path.lastIndex(), replacement);
        return message;
    }

    static class Holder {

        private final HandshakeMessage message;
        private final Path[] paths;

        Holder(HandshakeMessage message) {
            this.message = message;
            this.paths = browse(message);
        }

        boolean match(HandshakeMessage message) {
            return this.message.type().equals(message.type());
        }

        HandshakeMessage message() {
            return message;
        }

        Path[] paths() {
            return paths;
        }
    }

    // override methods which create Handshake messages
    // handle created handshake messages

    @Override
    public synchronized Certificate createCertificate(byte[] certificate_request_context,
                                                      CertificateEntry... certificate_list) {

        return handle(factory.createCertificate(certificate_request_context, certificate_list));
    }

    @Override
    public CertificateRequest createCertificateRequest(byte[] certificate_request_context,
                                                       List<Extension> extensions) {
        return handle(factory.createCertificateRequest(certificate_request_context, extensions));
    }

    @Override
    public synchronized CertificateVerify createCertificateVerify(SignatureScheme algorithm,
                                                                  byte[] signature) {

        return handle(factory.createCertificateVerify(algorithm, signature));
    }

    @Override
    public synchronized ClientHello createClientHello(ProtocolVersion legacy_version,
                                                      Random random,
                                                      byte[] legacy_session_id,
                                                      List<CipherSuite> cipher_suites,
                                                      List<CompressionMethod> legacy_compression_methods,
                                                      List<Extension> extensions) {

        return handle(factory.createClientHello(legacy_version, random,
                legacy_session_id, cipher_suites, legacy_compression_methods, extensions));
    }

    @Override
    public synchronized EncryptedExtensions createEncryptedExtensions(Extension... extensions) {
        return handle(factory.createEncryptedExtensions(extensions));
    }

    @Override
    public synchronized EndOfEarlyData createEndOfEarlyData() {
        return handle(factory.createEndOfEarlyData());
    }

    @Override
    public synchronized Finished createFinished(byte[] verify_data) {
        return handle(factory.createFinished(verify_data));
    }

    @Override
    public synchronized HelloRetryRequest createHelloRetryRequest() {
        return handle(factory.createHelloRetryRequest());
    }

    @Override
    public ServerHello createServerHello(ProtocolVersion version,
                                         Random random,
                                         byte[] legacy_session_id_echo,
                                         CipherSuite cipher_suite,
                                         CompressionMethod legacy_compression_method,
                                         List<Extension> extensions) {

        return handle(factory.createServerHello(version, random, legacy_session_id_echo,
                cipher_suite, legacy_compression_method, extensions));
    }

    @Override
    public NewSessionTicket createNewSessionTicket(UInt32 ticket_lifetime,
                                                   UInt32 ticket_age_add,
                                                   Vector<Byte> ticket_nonce,
                                                   Vector<Byte> ticket,
                                                   Vector<Extension> extensions) {
        return handle(factory.createNewSessionTicket(
                ticket_lifetime, ticket_age_add, ticket_nonce, ticket, extensions));
    }

    // override the rest of the methods

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
    public TLSInnerPlaintext createTLSInnerPlaintext(ContentType type,
                                                     byte[] content,
                                                     byte[] zeros) {
        return factory.createTLSInnerPlaintext(type, content, zeros);
    }

    @Override
    public TLSPlaintext createTLSPlaintext(ContentType type,
                                           ProtocolVersion version,
                                           byte[] content) {
        return factory.createTLSPlaintext(type, version, content);
    }

    @Override
    public TLSPlaintext[] createTLSPlaintexts(ContentType type,
                                              ProtocolVersion version,
                                              byte[] content) {
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
    public Cookie createCookie(byte[] cookie) {
        return factory.createCookie(cookie);
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
    public OCSPStatusRequest createOCSPStatusRequest(
            Vector<ResponderID> responder_id_list, Vector<Byte> extensions) {
        return factory.createOCSPStatusRequest(responder_id_list, extensions);
    }

    @Override
    public CertificateStatusRequest createCertificateStatusRequest(
            CertificateStatusType status_type, OCSPStatusRequest request) {
        return factory.createCertificateStatusRequest(status_type, request);
    }

    @Override
    public PreSharedKeyExtension.ClientHello createPreSharedKeyExtensionForClientHello(
            OfferedPsks offeredPsks) {
        return factory.createPreSharedKeyExtensionForClientHello(offeredPsks);
    }

    @Override
    public PreSharedKeyExtension.ServerHello createPreSharedKeyExtensionForServerHello(
            UInt16 selected_identity) {
        return factory.createPreSharedKeyExtensionForServerHello(selected_identity);
    }

    @Override
    public OfferedPsks createOfferedPsks(Vector<PskIdentity> identities,
                                         Vector<PskBinderEntry> binders) {
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
    public StructParser parser() {
        return factory.parser();
    }

}
