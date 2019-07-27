package com.gypsyengineer.tlsbunny.tls13.struct.impl;

import com.gypsyengineer.tlsbunny.tls.*;
import com.gypsyengineer.tlsbunny.tls13.struct.*;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.util.Arrays;

public class StructParserImpl implements StructParser {

    @Override
    public Handshake parseHandshake(ByteBuffer buffer) {
        HandshakeType msg_type = parseHandshakeType(buffer);
        UInt24 length = UInt24.parse(buffer);
        Bytes body = Bytes.parse(buffer, length.value);

        return new HandshakeImpl(msg_type, length, body);
    }

    @Override
    public ServerHello parseServerHello(ByteBuffer buffer) {
        return new ServerHelloImpl(
                parseProtocolVersion(buffer),
                Random.parse(buffer),
                Vector.parse(
                        buffer,
                        ServerHello.legacy_session_id_echo_length_bytes,
                        buf -> buf.get()),
                parseCipherSuite(buffer),
                parseCompressionMethod(buffer),
                Vector.parse(
                    buffer,
                    ServerHello.extensions_length_bytes,
                    buf -> parseExtension(buf)));
    }

    @Override
    public TLSInnerPlaintext parseTLSInnerPlaintext(byte[] bytes) {
        int i = bytes.length - 1;
        while (i > 0) {
            if (bytes[i] != 0) {
                break;
            }

            i--;
        }

        if (i == 0) {
            throw new IllegalArgumentException();
        }

        byte[] zeros = new byte[bytes.length - 1 - i];
        byte[] content = Arrays.copyOfRange(bytes, 0, i);

        return new TLSInnerPlaintextImpl(
                new Bytes(content),
                new ContentTypeImpl(bytes[i]),
                new Bytes(zeros));
    }

    @Override
    public TLSPlaintext parseTLSPlaintext(ByteBuffer buffer) throws IOException {
        int n = buffer.remaining();
        if (n < TLSPlaintext.MIN_ENCODING_LENGTH) {
            throw new IOException(String.format(
                    "expected at least %d bytes but received only %d",
                            TLSPlaintext.MIN_ENCODING_LENGTH, n));
        }
        ContentType type = parseContentType(buffer);
        ProtocolVersion legacy_record_version = parseProtocolVersion(buffer);
        UInt16 length = UInt16.parse(buffer);
        Bytes fragment = Bytes.parse(buffer, length.value);

        return new TLSPlaintextImpl(type, legacy_record_version, length, fragment);
    }

    @Override
    public ContentType parseContentType(ByteBuffer buffer) {
        return new ContentTypeImpl(buffer.get() & 0xFF);
    }

    @Override
    public ProtocolVersion parseProtocolVersion(ByteBuffer buffer) {
        return new ProtocolVersionImpl(buffer.get() & 0xFF, buffer.get() & 0xFF);
    }

    @Override
    public CipherSuite parseCipherSuite(ByteBuffer buffer) {
        return new CipherSuiteImpl(buffer.get() & 0xFF, buffer.get() & 0xFF);
    }

    @Override
    public ChangeCipherSpec parseChangeCipherSpec(ByteBuffer buffer) {
        return new ChangeCipherSpecImpl(buffer.get() & 0xFF);
    }

    @Override
    public Alert parseAlert(ByteBuffer buffer) {
        return new AlertImpl(
                parseAlertLevel(buffer),
                parseAlertDescription(buffer));
    }

    @Override
    public AlertLevel parseAlertLevel(ByteBuffer buffer) {
        return new AlertLevelImpl(buffer.get() & 0xFF);
    }

    @Override
    public AlertDescription parseAlertDescription(ByteBuffer buffer) {
        return new AlertDescriptionImpl(buffer.get() & 0xFF);
    }

    @Override
    public Certificate parseCertificate(
            ByteBuffer buffer, Vector.ContentParser certificateEntityParser) {

        return new CertificateImpl(
                Vector.parse(buffer,
                    Certificate.context_length_bytes,
                    buf -> buf.get()),
                Vector.parse(
                    buffer,
                    Certificate.certificate_list_length_bytes,
                    certificateEntityParser));
    }

    @Override
    public CertificateRequest parseCertificateRequest(ByteBuffer buffer) {
        return new CertificateRequestImpl(Vector.parse(
                    buffer,
                    CertificateRequest.certificate_request_context_length_bytes,
                    buf -> buf.get()),
                Vector.parse(
                    buffer,
                    CertificateRequest.extensions_length_bytes,
                    buf -> parseExtension(buf)));
    }

    @Override
    public CertificateVerify parseCertificateVerify(ByteBuffer buffer) {
        return new CertificateVerifyImpl(
                parseSignatureScheme(buffer),
                Vector.parseOpaqueVector(buffer, CertificateVerify.signature_length_bytes));
    }

    @Override
    public ClientHello parseClientHello(ByteBuffer buffer) {
        ProtocolVersion legacy_version = parseProtocolVersion(buffer);
        Random random = Random.parse(buffer);
        Vector<Byte> legacy_session_id = Vector.parse(
                buffer,
                ClientHello.legacy_session_id_length_bytes,
                buf -> buf.get());
        Vector<CipherSuite> cipher_suites = Vector.parse(
                buffer,
                ClientHello.cipher_suites_length_bytes,
                buf -> parseCipherSuite(buf));
        Vector<CompressionMethod> legacy_compression_methods = Vector.parse(
                buffer,
                ClientHello.legacy_compression_methods_length_bytes,
                buf -> parseCompressionMethod(buf));
        Vector<Extension> extensions = Vector.parse(
                buffer,
                ClientHello.extensions_length_bytes,
                buf -> parseExtension(buf));

        return new ClientHelloImpl(legacy_version, random, legacy_session_id,
                cipher_suites, legacy_compression_methods, extensions);
    }

    @Override
    public EncryptedExtensions parseEncryptedExtensions(ByteBuffer buffer) {
        return new EncryptedExtensionsImpl(
                Vector.parse(
                    buffer,
                    EncryptedExtensions.length_bytes,
                    buf -> parseExtension(buf)));
    }

    @Override
    public Finished parseFinished(ByteBuffer buffer, int hashLen) {
        byte[] verify_data = new byte[hashLen];
        buffer.get(verify_data);

        return new FinishedImpl(new Bytes(verify_data));
    }

    @Override
    public HelloRetryRequest parseHelloRetryRequest(ByteBuffer buffer) {
        return new HelloRetryRequestImpl(
                parseProtocolVersion(buffer),
                Random.parse(buffer),
                Vector.parse(
                        buffer,
                        HelloRetryRequestImpl.legacy_session_id_echo_length_bytes,
                        buf -> buf.get()),
                parseCipherSuite(buffer),
                parseCompressionMethod(buffer),
                Vector.parse(
                    buffer,
                    HelloRetryRequestImpl.extensions_length_bytes,
                    buf -> parseExtension(buf)));
    }

    @Override
    public SignatureScheme parseSignatureScheme(ByteBuffer buffer) {
        return new SignatureSchemeImpl(buffer.getShort());
    }

    @Override
    public TLSInnerPlaintext parseTLSInnerPlaintext(ByteBuffer buffer) {
        throw new UnsupportedOperationException();
    }

    @Override
    public EndOfEarlyData parseEndOfEarlyData(ByteBuffer buffer) {
        throw new UnsupportedOperationException();
    }

    @Override
    public SignatureSchemeList parseSignatureSchemeList(ByteBuffer buffer) {
        return new SignatureSchemeListImpl(
                Vector.parse(
                        buffer,
                        SignatureSchemeList.length_bytes,
                        buf -> parseSignatureScheme(buf)));
    }

    @Override
    public SupportedVersions.ClientHello parseSupportedVersionsClientHello(ByteBuffer buffer) {
        return new SupportedVersionsImpl.ClientHelloImpl(
                    Vector.parse(
                            buffer,
                            SupportedVersions.ClientHello.versions_length_bytes,
                            buf -> parseProtocolVersion(buf)));
    }

    @Override
    public SupportedVersions.ServerHello parseSupportedVersionsServerHello(ByteBuffer buffer) {
        return new SupportedVersionsImpl.ServerHelloImpl(parseProtocolVersion(buffer));
    }

    @Override
    public CertificateEntry.X509 parseX509CertificateEntry(ByteBuffer buffer) {
        return new CertificateEntryImpl.X509Impl(
                    Vector.parseOpaqueVector(buffer, CertificateEntry.X509.length_bytes),
                    Vector.parse(
                        buffer,
                        CertificateEntry.X509.extensions_length_bytes,
                        buf -> parseExtension(buf)));
    }

    @Override
    public CertificateEntry.RawPublicKey parseRawPublicKeyCertificateEntry(ByteBuffer buffer) {
        return new CertificateEntryImpl.RawPublicKeyImpl(
                    Vector.parseOpaqueVector(
                            buffer,
                            CertificateEntry.RawPublicKey.length_bytes),
                    Vector.parse(
                        buffer,
                        CertificateEntry.RawPublicKey.extensions_length_bytes,
                        buf -> parseExtension(buf)));
    }

    @Override
    public NamedGroupList parseNamedGroupList(ByteBuffer buffer) {
        return new NamedGroupListImpl(
                Vector.parse(
                        buffer,
                        NamedGroupList.length_bytes,
                        buf -> parseNamedGroup(buf)));
    }

    @Override
    public KeyShare.ClientHello parseKeyShareFromClientHello(ByteBuffer buffer) {
            return new KeyShareImpl.ClientHelloImpl(
                    Vector.parse(
                        buffer,
                        KeyShare.ClientHello.length_bytes,
                        buf -> parseKeyShareEntry(buf)));
    }

    @Override
    public CompressionMethod parseCompressionMethod(ByteBuffer buffer) {
        return new CompressionMethodImpl(buffer.get() & 0xFF);
    }

    @Override
    public Extension parseExtension(ByteBuffer buffer) {
        ExtensionType extension_type = parseExtensionType(buffer);
        Vector<Byte> extension_data = Vector.parseOpaqueVector(
                buffer, Extension.extension_data_length_bytes);

        return new ExtensionImpl(extension_type, extension_data);
    }

    @Override
    public ExtensionType parseExtensionType(ByteBuffer buffer) {
        return new ExtensionTypeImpl(buffer.getShort() & 0xFFFF);
    }

    @Override
    public HandshakeType parseHandshakeType(ByteBuffer buffer) {
        return new HandshakeTypeImpl(buffer.get() & 0xFF);
    }

    @Override
    public KeyShareEntry parseKeyShareEntry(ByteBuffer buffer) {
        return new KeyShareEntryImpl(
                parseNamedGroup(buffer),
                Vector.parseOpaqueVector(
                    buffer, KeyShareEntry.key_exchange_length_bytes));
    }

    @Override
    public NamedGroup parseNamedGroup(ByteBuffer buffer) {
        return new NamedGroupImpl(buffer.getShort());
    }

    @Override
    public KeyShare.ServerHello parseKeyShareFromServerHello(ByteBuffer buffer) {
        return new KeyShareImpl.ServerHelloImpl(parseKeyShareEntry(buffer));
    }

    @Override
    public KeyShare.HelloRetryRequest parseKeyShareFromHelloRetryRequest(ByteBuffer buffer) {
        return new KeyShareImpl.HelloRetryRequestImpl(parseNamedGroup(buffer));
    }

    @Override
    public UncompressedPointRepresentationImpl parseUncompressedPointRepresentation(
            ByteBuffer buffer, int coordinate_length) {

        byte legacy_form = buffer.get();
        if (legacy_form != 4) {
            throw new IllegalArgumentException();
        }

        byte[] X = new byte[coordinate_length];
        byte[] Y = new byte[coordinate_length];
        buffer.get(X);
        buffer.get(Y);

        return new UncompressedPointRepresentationImpl(X, Y);
    }

    @Override
    public NewSessionTicket parseNewSessionTicket(ByteBuffer buffer) {
        return new NewSessionTicketImpl(
                UInt32.parse(buffer),
                UInt32.parse(buffer),
                Vector.parseOpaqueVector(buffer,
                        NewSessionTicket.nonce_length_bytes),
                Vector.parseOpaqueVector(buffer,
                        NewSessionTicket.ticket_length_bytes),
                Vector.parse(
                        buffer,
                        NewSessionTicket.extensions_length_bytes,
                        buf -> parseExtension(buf)));
    }
}
