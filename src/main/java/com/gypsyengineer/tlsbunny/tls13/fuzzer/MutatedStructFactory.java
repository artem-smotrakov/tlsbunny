package com.gypsyengineer.tlsbunny.tls13.fuzzer;

import com.gypsyengineer.tlsbunny.tls.Random;
import com.gypsyengineer.tlsbunny.tls13.struct.*;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.io.IOException;
import java.util.Arrays;
import java.util.List;

import static com.gypsyengineer.tlsbunny.tls13.fuzzer.Target.*;
import static com.gypsyengineer.tlsbunny.utils.HexDump.printHexDiff;

public class MutatedStructFactory extends FuzzyStructFactory<byte[]> {

    private static final Logger logger = LogManager.getLogger(MutatedStructFactory.class);

    public static MutatedStructFactory mutatedStructFactory() {
        return new MutatedStructFactory();
    }

    public MutatedStructFactory() {
        this(StructFactory.getDefault());
    }

    public MutatedStructFactory(StructFactory factory) {
        super(factory);
        targets(tls_plaintext);
    }

    @Override
    public synchronized TLSPlaintext[] createTLSPlaintexts(
            ContentType type, ProtocolVersion version, byte[] content) {

        TLSPlaintext[] tlsPlaintexts = factory.createTLSPlaintexts(
                type, version, content);

        if (targeted(tls_plaintext)) {
            int index = 0;
            try {
                byte[] encoding = tlsPlaintexts[index].encoding();
                logger.info("fuzz TLSPlaintext[{}] (total is {})",
                        index, tlsPlaintexts.length);
                tlsPlaintexts[index] = new MutatedStruct(fuzz(encoding));
            } catch (IOException e) {
                logger.warn("I couldn't fuzz TLSPlaintext[{}]: {}",
                        e.getMessage(), index);
            }
        }

        return tlsPlaintexts;
    }

    @Override
    public synchronized TLSPlaintext createTLSPlaintext(
            ContentType type, ProtocolVersion version, byte[] content) {

        TLSPlaintext tlsPlaintext = factory.createTLSPlaintext(
                type, version, content);

        if (targeted(tls_plaintext)) {
            logger.info("fuzz TLSPlaintext");
            try {
                tlsPlaintext = new MutatedStruct(fuzz(tlsPlaintext.encoding()));
            } catch (IOException e) {
                logger.warn("I couldn't fuzz TLSPlaintext: {}", e.getMessage());
            }
        }

        return tlsPlaintext;
    }

    @Override
    public synchronized Handshake createHandshake(HandshakeType type, byte[] content) {
        Handshake handshake = factory.createHandshake(type, content);

        if (targeted(Target.handshake)) {
            logger.info("fuzz Handshake");
            try {
                handshake = new MutatedStruct(fuzz(handshake.encoding()));
            } catch (IOException e) {
                logger.warn("I couldn't fuzz Handshake: {}", e.getMessage());
            }
        }

        return handshake;
    }

    @Override
    public synchronized ClientHello createClientHello(
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
            logger.info("fuzz ClientHello");
            try {
                byte[] fuzzed = fuzz(clientHello.encoding());
                clientHello = new MutatedStruct(
                        fuzzed.length, fuzzed, HandshakeType.client_hello);
            } catch (IOException e) {
                logger.warn("I couldn't fuzz ClientHello: {}", e.getMessage());
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
            logger.info("fuzz ServerHello");
            try {
                byte[] fuzzed = fuzz(serverHello.encoding());
                serverHello = new MutatedStruct(
                        fuzzed.length, fuzzed, HandshakeType.server_hello);
            } catch (IOException e) {
                logger.warn("I couldn't fuzz ServerHello: {}", e.getMessage());
            }
        }

        return serverHello;
    }

    @Override
    public EncryptedExtensions createEncryptedExtensions(Extension... extensions) {
        EncryptedExtensions encryptedExtensions = factory.createEncryptedExtensions(extensions);

        if (targeted(encrypted_extensions)) {
            logger.info("fuzz EncryptedExtensions");
            try {
                byte[] fuzzed = fuzz(encryptedExtensions.encoding());
                encryptedExtensions = new MutatedStruct(
                        fuzzed.length, fuzzed, HandshakeType.encrypted_extensions);
            } catch (IOException e) {
                logger.warn("I couldn't fuzz EncryptedExtensions: {}", e.getMessage());
            }
        }

        return encryptedExtensions;
    }

    @Override
    public synchronized Finished createFinished(byte[] verify_data) {
        Finished finished = factory.createFinished(verify_data);

        if (targeted(Target.finished)) {
            logger.info("fuzz Finished");
            try {
                byte[] fuzzed = fuzz(finished.encoding());
                finished = new MutatedStruct(
                        fuzzed.length, fuzzed, HandshakeType.finished);
            } catch (IOException e) {
                logger.warn("I couldn't fuzz Finished: {}", e.getMessage());
            }
        }

        return finished;
    }

    @Override
    public synchronized Certificate createCertificate(
            byte[] certificate_request_context, CertificateEntry... certificate_list) {

        Certificate certificate = factory.createCertificate(
                certificate_request_context, certificate_list);

        if (targeted(Target.certificate)) {
            logger.info("fuzz Certificate");
            try {
                byte[] fuzzed = fuzz(certificate.encoding());
                certificate = new MutatedStruct(
                        fuzzed.length, fuzzed, HandshakeType.certificate);
            } catch (IOException e) {
                logger.warn("I couldn't fuzz Certificate: {}", e.getMessage());
            }
        }

        return certificate;
    }

    @Override
    public synchronized CertificateVerify createCertificateVerify(
            SignatureScheme algorithm, byte[] signature) {

        CertificateVerify certificateVerify = factory.createCertificateVerify(
                algorithm, signature);

        if (targeted(certificate_verify)) {
            logger.info("fuzz CertificateVerify");
            try {
                byte[] fuzzed = fuzz(certificateVerify.encoding());
                certificateVerify = new MutatedStruct(
                        fuzzed.length, fuzzed, HandshakeType.certificate);
            } catch (IOException e) {
                logger.warn("I couldn't fuzz CertificateVerify: {}", e.getMessage());
            }
        }

        return certificateVerify;
    }

    @Override
    public synchronized ChangeCipherSpec createChangeCipherSpec(int value) {
        ChangeCipherSpec ccs = factory.createChangeCipherSpec(value);

        if (targeted(Target.ccs)) {
            logger.info("fuzz ChangeCipherSpec");
            try {
                byte[] fuzzed = fuzz(ccs.encoding());
                ccs = new MutatedStruct(fuzzed.length, fuzzed);
            } catch (IOException e) {
                logger.warn("I couldn't fuzz ChangeCipherSpec: {}", e.getMessage());
            }
        }

        return ccs;
    }

    @Override
    public synchronized byte[] fuzz(byte[] encoding) {
        byte[] fuzzed = fuzzer.fuzz(encoding);

        logger.info("original:");
        logger.info("{}%n", printHexDiff(encoding, fuzzed));
        logger.info("fuzzed:");
        logger.info("{}%n", printHexDiff(fuzzed, encoding));

        if (Arrays.equals(encoding, fuzzed)) {
            logger.info("nothing actually fuzzed");
        }

        return fuzzed;
    }

}
