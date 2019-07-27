package com.gypsyengineer.tlsbunny.tls13.struct;

import com.gypsyengineer.tlsbunny.tls.Vector;

import java.io.IOException;
import java.nio.ByteBuffer;

public interface StructParser {

    CompressionMethod parseCompressionMethod(ByteBuffer buffer);
    ContentType parseContentType(ByteBuffer buffer);
    ProtocolVersion parseProtocolVersion(ByteBuffer buffer);
    CipherSuite parseCipherSuite(ByteBuffer buffer);
    ChangeCipherSpec parseChangeCipherSpec(ByteBuffer buffer);
    Alert parseAlert(ByteBuffer buffer);
    AlertLevel parseAlertLevel(ByteBuffer buffer);
    AlertDescription parseAlertDescription(ByteBuffer buffer);
    Certificate parseCertificate(ByteBuffer buffer, Vector.ContentParser certificateEntityParser);
    CertificateRequest parseCertificateRequest(ByteBuffer buffer);
    CertificateVerify parseCertificateVerify(ByteBuffer buffer);
    ClientHello parseClientHello(ByteBuffer buffer);
    EncryptedExtensions parseEncryptedExtensions(ByteBuffer buffer);
    EndOfEarlyData parseEndOfEarlyData(ByteBuffer buffer);
    Finished parseFinished(ByteBuffer buffer, int hashLen);
    Handshake parseHandshake(ByteBuffer buffer);
    HelloRetryRequest parseHelloRetryRequest(ByteBuffer buffer);
    ServerHello parseServerHello(ByteBuffer buffer);
    TLSInnerPlaintext parseTLSInnerPlaintext(ByteBuffer buffer);
    TLSPlaintext parseTLSPlaintext(ByteBuffer buffer) throws IOException;
    SignatureScheme parseSignatureScheme(ByteBuffer buffer);
    SignatureSchemeList parseSignatureSchemeList(ByteBuffer buffer);
    SupportedVersions.ClientHello parseSupportedVersionsClientHello(ByteBuffer buffer);
    SupportedVersions.ServerHello parseSupportedVersionsServerHello(ByteBuffer buffer);
    CertificateEntry.X509 parseX509CertificateEntry(ByteBuffer buffer);
    CertificateEntry.RawPublicKey parseRawPublicKeyCertificateEntry(ByteBuffer buffer);
    NamedGroupList parseNamedGroupList(ByteBuffer buffer);
    KeyShare.ClientHello parseKeyShareFromClientHello(ByteBuffer buffer);
    KeyShare.ServerHello parseKeyShareFromServerHello(ByteBuffer buffer);
    KeyShare.HelloRetryRequest parseKeyShareFromHelloRetryRequest(ByteBuffer buffer);
    Extension parseExtension(ByteBuffer buffer);
    ExtensionType parseExtensionType(ByteBuffer buffer);
    HandshakeType parseHandshakeType(ByteBuffer buffer);
    KeyShareEntry parseKeyShareEntry(ByteBuffer buffer);
    NamedGroup parseNamedGroup(ByteBuffer buffer);
    UncompressedPointRepresentation parseUncompressedPointRepresentation(
            ByteBuffer buffer, int coordinate_length);
    NewSessionTicket parseNewSessionTicket(ByteBuffer buffer);

    default ContentType parseContentType(byte[] bytes) {
        return parseContentType(ByteBuffer.wrap(bytes));
    }

    default CipherSuite parseCipherSuite(byte[] bytes) {
        return parseCipherSuite(ByteBuffer.wrap(bytes));
    }

    default ProtocolVersion parseProtocolVersion(byte[] bytes) {
        return parseProtocolVersion(ByteBuffer.wrap(bytes));
    }

    default ChangeCipherSpec parseChangeCipherSpec(byte[] bytes) {
        return parseChangeCipherSpec(ByteBuffer.wrap(bytes));
    }

    default Alert parseAlert(byte[] bytes) {
        return parseAlert(ByteBuffer.wrap(bytes));
    }

    default AlertLevel parseAlertLevel(byte[] bytes) {
        return parseAlertLevel(ByteBuffer.wrap(bytes));
    }

    default AlertDescription parseAlertDescription(byte[] bytes) {
        return parseAlertDescription(ByteBuffer.wrap(bytes));
    }

    default Certificate parseCertificate(byte[] bytes, Vector.ContentParser certificateEntityParser) {
        return parseCertificate(ByteBuffer.wrap(bytes), certificateEntityParser);
    }

    default CertificateRequest parseCertificateRequest(byte[] bytes) {
        return parseCertificateRequest(ByteBuffer.wrap(bytes));
    }

    default CertificateVerify parseCertificateVerify(byte[] bytes) {
        return parseCertificateVerify(ByteBuffer.wrap(bytes));
    }

    default ClientHello parseClientHello(byte[] bytes) {
        return parseClientHello(ByteBuffer.wrap(bytes));
    }

    default EndOfEarlyData parseEndOfEarlyData(byte[] bytes) {
        return parseEndOfEarlyData(ByteBuffer.wrap(bytes));
    }

    default Finished parseFinished(byte[] bytes, int hashLen) {
        return parseFinished(ByteBuffer.wrap(bytes), hashLen);
    }

    default EncryptedExtensions parseEncryptedExtensions(byte[] bytes) {
        return parseEncryptedExtensions(ByteBuffer.wrap(bytes));
    }

    default Handshake parseHandshake(byte[] bytes) {
        return parseHandshake(ByteBuffer.wrap(bytes));
    }

    default HelloRetryRequest parseHelloRetryRequest(byte[] bytes) {
        return parseHelloRetryRequest(ByteBuffer.wrap(bytes));
    }

    default ServerHello parseServerHello(byte[] bytes) {
        return parseServerHello(ByteBuffer.wrap(bytes));
    }

    default TLSInnerPlaintext parseTLSInnerPlaintext(byte[] bytes) {
        return parseTLSInnerPlaintext(ByteBuffer.wrap(bytes));
    }

    default TLSPlaintext parseTLSPlaintext(byte[] bytes) throws IOException {
        return parseTLSPlaintext(ByteBuffer.wrap(bytes));
    }

    default SupportedVersions.ClientHello parseSupportedVersionsClientHello(byte[] bytes) {
        return parseSupportedVersionsClientHello(ByteBuffer.wrap(bytes));
    }

    default SupportedVersions.ServerHello parseSupportedVersionsServerHello(byte[] bytes) {
        return parseSupportedVersionsServerHello(ByteBuffer.wrap(bytes));
    }

    default CertificateEntry.X509 parseX509CertificateEntry(byte[] bytes) {
        return parseX509CertificateEntry(ByteBuffer.wrap(bytes));
    }

    default CertificateEntry.RawPublicKey parseRawPublicKeyCertificateEntry(byte[] bytes) {
        return parseRawPublicKeyCertificateEntry(ByteBuffer.wrap(bytes));
    }

    default SignatureSchemeList parseSignatureSchemeList(byte[] bytes) {
        return parseSignatureSchemeList(ByteBuffer.wrap(bytes));
    }

    default NamedGroupList parseNamedGroupList(byte[] bytes) {
        return parseNamedGroupList(ByteBuffer.wrap(bytes));
    }

    default KeyShare.ClientHello parseKeyShareFromClientHello(byte[] bytes) {
        return parseKeyShareFromClientHello(ByteBuffer.wrap(bytes));
    }

    default CompressionMethod parseCompressionMethod(byte[] bytes) {
        return parseCompressionMethod(ByteBuffer.wrap(bytes));
    }

    default Extension parseExtension(byte[] bytes) {
        return parseExtension(ByteBuffer.wrap(bytes));
    }

    default ExtensionType parseExtensionType(byte[] bytes) {
        return parseExtensionType(ByteBuffer.wrap(bytes));
    }

    default HandshakeType parseHandshakeType(byte[] bytes) {
        return parseHandshakeType(ByteBuffer.wrap(bytes));
    }

    default KeyShareEntry parseKeyShareEntry(byte[] bytes) {
        return parseKeyShareEntry(ByteBuffer.wrap(bytes));
    }

    default NamedGroup parseNamedGroup(byte[] bytes) {
        return parseNamedGroup(ByteBuffer.wrap(bytes));
    }

    default KeyShare.ServerHello parseKeyShareFromServerHello(byte[] bytes) {
        return parseKeyShareFromServerHello(ByteBuffer.wrap(bytes));
    }

    default KeyShare.HelloRetryRequest parseKeyShareFromHelloRetryRequest(byte[] bytes) {
        return parseKeyShareFromHelloRetryRequest(ByteBuffer.wrap(bytes));
    }

    default UncompressedPointRepresentation parseUncompressedPointRepresentation(
            byte[] bytes, int coordinate_length) {

        return parseUncompressedPointRepresentation(
                ByteBuffer.wrap(bytes), coordinate_length);
    }

    default NewSessionTicket parseNewSessionTicket(byte[] bytes) {
        return parseNewSessionTicket(ByteBuffer.wrap(bytes));
    }
}
