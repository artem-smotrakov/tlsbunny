package com.gypsyengineer.tlsbunny.tls13.fuzzer;

import com.gypsyengineer.tlsbunny.fuzzer.Fuzzer;
import com.gypsyengineer.tlsbunny.tls.Random;
import com.gypsyengineer.tlsbunny.tls.Struct;
import com.gypsyengineer.tlsbunny.tls13.struct.*;
import com.gypsyengineer.tlsbunny.output.Output;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Scanner;

import static com.gypsyengineer.tlsbunny.tls13.fuzzer.FuzzedStruct.fuzzedHandshakeMessage;
import static com.gypsyengineer.tlsbunny.utils.HexDump.printHexDiff;
import static com.gypsyengineer.tlsbunny.utils.Utils.cast;
import static com.gypsyengineer.tlsbunny.utils.WhatTheHell.whatTheHell;

public class DeepHandshakeFuzzer extends StructFactoryWrapper
        implements Fuzzer<HandshakeMessage> {

    private Output output;
    private Fuzzer<byte[]> fuzzer;

    private Mode mode;

    private final List<Holder> recorded = new ArrayList<>();
    private int currentHolderIndex = 0;
    private int currentPathIndex = 0;
    private int round = 0;
    private int rounds = 10;

    public static DeepHandshakeFuzzer deepHandshakeFuzzer() {
        return deepHandshakeFuzzer(StructFactory.getDefault(), Output.standard());
    }

    public static DeepHandshakeFuzzer deepHandshakeFuzzer(Output output) {
        return deepHandshakeFuzzer(StructFactory.getDefault(), output);
    }

    public static DeepHandshakeFuzzer deepHandshakeFuzzer(
            StructFactory factory, Output output) {

        return new DeepHandshakeFuzzer(factory, output);
    }

    private DeepHandshakeFuzzer(StructFactory factory, Output output) {
        super(factory);
        this.output = output;
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

    public DeepHandshakeFuzzer fuzzer(Fuzzer<byte[]> fuzzer) {
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

        explain(target.getClass().getSimpleName(), encoding, fuzzed);

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

    private void explain(String what, byte[] encoding, byte[] fuzzed) {
        output.info("%s (original): %n", what);
        output.increaseIndent();
        output.info("%s%n", printHexDiff(encoding, fuzzed));
        output.decreaseIndent();
        output.info("%s (fuzzed): %n", what);
        output.increaseIndent();
        output.info("%s%n", printHexDiff(fuzzed, encoding));
        output.decreaseIndent();

        if (Arrays.equals(encoding, fuzzed)) {
            output.important("nothing actually fuzzed");
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

    // override only methods for creating Handshake messages

    @Override
    public synchronized Certificate createCertificate(byte[] certificate_request_context,
                                                      CertificateEntry... certificate_list) {

        return handle(super.createCertificate(certificate_request_context, certificate_list));
    }

    @Override
    public CertificateRequest createCertificateRequest(byte[] certificate_request_context,
                                                       List<Extension> extensions) {
        return handle(super.createCertificateRequest(certificate_request_context, extensions));
    }

    @Override
    public synchronized CertificateVerify createCertificateVerify(SignatureScheme algorithm,
                                                                  byte[] signature) {

        return handle(super.createCertificateVerify(algorithm, signature));
    }

    @Override
    public synchronized ClientHello createClientHello(ProtocolVersion legacy_version,
                                                      Random random,
                                                      byte[] legacy_session_id,
                                                      List<CipherSuite> cipher_suites,
                                                      List<CompressionMethod> legacy_compression_methods,
                                                      List<Extension> extensions) {

        return handle(super.createClientHello(legacy_version, random,
                legacy_session_id, cipher_suites, legacy_compression_methods, extensions));
    }

    @Override
    public synchronized EncryptedExtensions createEncryptedExtensions(Extension... extensions) {
        return handle(super.createEncryptedExtensions(extensions));
    }

    @Override
    public synchronized EndOfEarlyData createEndOfEarlyData() {
        return handle(super.createEndOfEarlyData());
    }

    @Override
    public synchronized Finished createFinished(byte[] verify_data) {
        return handle(super.createFinished(verify_data));
    }

    @Override
    public synchronized HelloRetryRequest createHelloRetryRequest() {
        return handle(super.createHelloRetryRequest());
    }

    @Override
    public ServerHello createServerHello(ProtocolVersion version,
                                         Random random,
                                         byte[] legacy_session_id_echo,
                                         CipherSuite cipher_suite,
                                         CompressionMethod legacy_compression_method,
                                         List<Extension> extensions) {

        return handle(super.createServerHello(version, random, legacy_session_id_echo,
                cipher_suite, legacy_compression_method, extensions));
    }

    @Override
    public DeepHandshakeFuzzer set(Output output) {
        this.output = output;
        return this;
    }

    @Override
    public Output output() {
        return output;
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
}
