package com.gypsyengineer.tlsbunny.tls13.fuzzer;

import com.gypsyengineer.tlsbunny.tls.Random;
import com.gypsyengineer.tlsbunny.tls13.struct.*;
import com.gypsyengineer.tlsbunny.output.Output;

import java.io.IOException;
import java.util.Arrays;
import java.util.List;

import static com.gypsyengineer.tlsbunny.tls13.fuzzer.Target.*;
import static com.gypsyengineer.tlsbunny.utils.HexDump.printHexDiff;

public class MutatedStructFactory extends FuzzyStructFactory<byte[]> {

    public static MutatedStructFactory mutatedStructFactory() {
        return new MutatedStructFactory();
    }

    public MutatedStructFactory() {
        this(StructFactory.getDefault(), Output.standard());
    }

    public MutatedStructFactory(StructFactory factory, Output output) {
        super(factory, output);
        targets(tls_plaintext);
    }

    @Override
    synchronized public TLSPlaintext[] createTLSPlaintexts(
            ContentType type, ProtocolVersion version, byte[] content) {

        TLSPlaintext[] tlsPlaintexts = factory.createTLSPlaintexts(
                type, version, content);

        if (targeted(tls_plaintext)) {
            int index = 0;
            try {
                byte[] encoding = tlsPlaintexts[index].encoding();
                output.info("fuzz TLSPlaintext[%d] (total is %d)",
                        index, tlsPlaintexts.length);
                tlsPlaintexts[index] = new MutatedStruct(fuzz(encoding));
            } catch (IOException e) {
                output.achtung("I couldn't fuzz TLSPlaintext[%d]: %s",
                        e.getMessage(), index);
            }
        }

        return tlsPlaintexts;
    }

    @Override
    synchronized public TLSPlaintext createTLSPlaintext(
            ContentType type, ProtocolVersion version, byte[] content) {

        TLSPlaintext tlsPlaintext = factory.createTLSPlaintext(
                type, version, content);

        if (targeted(tls_plaintext)) {
            output.info("fuzz TLSPlaintext");
            try {
                tlsPlaintext = new MutatedStruct(fuzz(tlsPlaintext.encoding()));
            } catch (IOException e) {
                output.achtung("I couldn't fuzz TLSPlaintext: %s", e.getMessage());
            }
        }

        return tlsPlaintext;
    }

    @Override
    synchronized public Handshake createHandshake(HandshakeType type, byte[] content) {
        Handshake handshake = factory.createHandshake(type, content);

        if (targeted(Target.handshake)) {
            output.info("fuzz Handshake");
            try {
                handshake = new MutatedStruct(fuzz(handshake.encoding()));
            } catch (IOException e) {
                output.achtung("I couldn't fuzz Handshake: %s", e.getMessage());
            }
        }

        return handshake;
    }

    @Override
    synchronized public ClientHello createClientHello(
            ProtocolVersion legacy_version,
            Random random,
            byte[] legacy_session_id,
            List<CipherSuite> cipher_suites,
            List<CompressionMethod> legacy_compression_methods,
            List<Extension> extensions) {

        ClientHello clientHello = factory.createClientHello(
                legacy_version, random, legacy_session_id, cipher_suites,
                legacy_compression_methods, extensions);

        if (targeted(client_hello)) {
            output.info("fuzz ClientHello");
            try {
                byte[] fuzzed = fuzz(clientHello.encoding());
                clientHello = new MutatedStruct(
                        fuzzed.length, fuzzed, HandshakeType.client_hello);
            } catch (IOException e) {
                output.achtung("I couldn't fuzz ClientHello: %s", e.getMessage());
            }
        }

        return clientHello;
    }

    @Override
    public ServerHello createServerHello(ProtocolVersion version,
                                         Random random,
                                         byte[] legacy_session_id_echo,
                                         CipherSuite cipher_suite,
                                         CompressionMethod legacy_compression_method,
                                         List<Extension> extensions) {

        ServerHello serverHello = factory.createServerHello(
                version, random, legacy_session_id_echo, cipher_suite,
                legacy_compression_method, extensions);

        if (targeted(server_hello)) {
            output.info("fuzz ServerHello");
            try {
                byte[] fuzzed = fuzz(serverHello.encoding());
                serverHello = new MutatedStruct(
                        fuzzed.length, fuzzed, HandshakeType.server_hello);
            } catch (IOException e) {
                output.achtung("I couldn't fuzz ServerHello: %s", e.getMessage());
            }
        }

        return serverHello;
    }

    @Override
    public EncryptedExtensions createEncryptedExtensions(Extension... extensions) {
        EncryptedExtensions encryptedExtensions = factory.createEncryptedExtensions(extensions);

        if (targeted(encrypted_extensions)) {
            output.info("fuzz EncryptedExtensions");
            try {
                byte[] fuzzed = fuzz(encryptedExtensions.encoding());
                encryptedExtensions = new MutatedStruct(
                        fuzzed.length, fuzzed, HandshakeType.encrypted_extensions);
            } catch (IOException e) {
                output.achtung("I couldn't fuzz EncryptedExtensions: %s", e.getMessage());
            }
        }

        return encryptedExtensions;
    }

    @Override
    synchronized public Finished createFinished(byte[] verify_data) {
        Finished finished = factory.createFinished(verify_data);

        if (targeted(Target.finished)) {
            output.info("fuzz Finished");
            try {
                byte[] fuzzed = fuzz(finished.encoding());
                finished = new MutatedStruct(
                        fuzzed.length, fuzzed, HandshakeType.finished);
            } catch (IOException e) {
                output.achtung("I couldn't fuzz Finished: %s", e.getMessage());
            }
        }

        return finished;
    }

    @Override
    synchronized public Certificate createCertificate(
            byte[] certificate_request_context, CertificateEntry... certificate_list) {

        Certificate certificate = factory.createCertificate(
                certificate_request_context, certificate_list);

        if (targeted(Target.certificate)) {
            output.info("fuzz Certificate");
            try {
                byte[] fuzzed = fuzz(certificate.encoding());
                certificate = new MutatedStruct(
                        fuzzed.length, fuzzed, HandshakeType.certificate);
            } catch (IOException e) {
                output.achtung("I couldn't fuzz Certificate: %s", e.getMessage());
            }
        }

        return certificate;
    }

    @Override
    synchronized public CertificateVerify createCertificateVerify(
            SignatureScheme algorithm, byte[] signature) {

        CertificateVerify certificateVerify = factory.createCertificateVerify(
                algorithm, signature);

        if (targeted(certificate_verify)) {
            output.info("fuzz CertificateVerify");
            try {
                byte[] fuzzed = fuzz(certificateVerify.encoding());
                certificateVerify = new MutatedStruct(
                        fuzzed.length, fuzzed, HandshakeType.certificate);
            } catch (IOException e) {
                output.achtung("I couldn't fuzz CertificateVerify: %s", e.getMessage());
            }
        }

        return certificateVerify;
    }

    @Override
    synchronized public ChangeCipherSpec createChangeCipherSpec(int value) {
        ChangeCipherSpec ccs = factory.createChangeCipherSpec(value);

        if (targeted(Target.ccs)) {
            output.info("fuzz ChangeCipherSpec");
            try {
                byte[] fuzzed = fuzz(ccs.encoding());
                ccs = new MutatedStruct(fuzzed.length, fuzzed);
            } catch (IOException e) {
                output.achtung("I couldn't fuzz ChangeCipherSpec: %s", e.getMessage());
            }
        }

        return ccs;
    }

    @Override
    synchronized public byte[] fuzz(byte[] encoding) {
        byte[] fuzzed = fuzzer.fuzz(encoding);

        output.info("original:");
        output.increaseIndent();
        output.info("%s%n", printHexDiff(encoding, fuzzed));
        output.decreaseIndent();
        output.info("fuzzed:");
        output.increaseIndent();
        output.info("%s%n", printHexDiff(fuzzed, encoding));
        output.decreaseIndent();

        if (Arrays.equals(encoding, fuzzed)) {
            output.important("nothing actually fuzzed");
        }

        return fuzzed;
    }

}
