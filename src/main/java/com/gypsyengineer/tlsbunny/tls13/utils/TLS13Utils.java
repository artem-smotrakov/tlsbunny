package com.gypsyengineer.tlsbunny.tls13.utils;

import com.gypsyengineer.tlsbunny.tls13.struct.*;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.util.List;

import static com.gypsyengineer.tlsbunny.utils.WhatTheHell.whatTheHell;

public class TLS13Utils {

    public static ByteBuffer store(TLSPlaintext[] tlsPlaintexts) throws IOException {
        int length = 0;
        for (TLSPlaintext tlsPlaintext : tlsPlaintexts) {
            length += tlsPlaintext.encodingLength();
        }

        ByteBuffer buffer = ByteBuffer.allocate(length);
        for (TLSPlaintext tlsPlaintext : tlsPlaintexts) {
            buffer.put(tlsPlaintext.encoding());
        }

        buffer.position(0);

        return buffer;
    }

    public static Extension findExtension(ExtensionType type, List<Extension> extensions) {
        for (Extension extension : extensions) {
            if (type.equals(extension.extensionType())) {
                return extension;
            }
        }

        return null;
    }

    public static KeyShare.ClientHello findKeyShare(StructFactory factory, ClientHello hello)
            throws IOException {

        return factory.parser()
                .parseKeyShareFromClientHello(
                        hello.find(ExtensionType.key_share)
                                .extensionData().bytes());
    }

    public static KeyShare.ServerHello findKeyShare(StructFactory factory, ServerHello hello)
            throws IOException {

        Extension ext = hello.find(ExtensionType.key_share);
        if (ext == null) {
            throw new IOException("could not find key_share extension (null)");
        }

        return factory.parser()
                .parseKeyShareFromServerHello(
                        ext.extensionData().bytes());
    }

    public static SupportedVersions.ServerHello findSupportedVersion(
            StructFactory factory, ServerHello hello) throws IOException {

        Extension ext = hello.find(ExtensionType.supported_versions);
        if (ext == null) {
            throw new IOException("could not find supported_versions extension (null)");
        }

        return factory.parser().parseSupportedVersionsServerHello(
                ext.extensionData().bytes());
    }

    public static int getCoordinateLength(NamedGroup group) {
        if (group instanceof NamedGroup.Secp == false) {
            throw whatTheHell("expected NamedGroup.Secp!");
        }
        NamedGroup.Secp secp = (NamedGroup.Secp) group;

        switch (secp.getCurve()) {
            case "secp256r1":
                return 32;
            case "secp384r1":
                return 48;
            case "secp521r1":
                return 66;
            default:
                throw new IllegalArgumentException(
                        String.format("unknown groups: %s", group));
        }
    }

}
