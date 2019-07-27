package com.gypsyengineer.tlsbunny.tls13.struct.impl;

import com.gypsyengineer.tlsbunny.tls.Vector;
import com.gypsyengineer.tlsbunny.tls13.struct.CertificateRequest;
import com.gypsyengineer.tlsbunny.tls13.struct.Extension;
import com.gypsyengineer.tlsbunny.tls13.struct.HandshakeType;
import com.gypsyengineer.tlsbunny.utils.Utils;
import java.io.IOException;
import java.util.Objects;

public class CertificateRequestImpl implements CertificateRequest {

    private final Vector<Byte> certificate_request_context;
    private final Vector<Extension> extensions;

    CertificateRequestImpl(Vector<Byte> certificate_request_context, 
                           Vector<Extension> extensions) {

        this.certificate_request_context = certificate_request_context;
        this.extensions = extensions;
    }

    @Override
    public int encodingLength() {
        return Utils.getEncodingLength(certificate_request_context, extensions);
    }

    @Override
    public byte[] encoding() throws IOException {
        return Utils.encoding(certificate_request_context, extensions);
    }

    @Override
    public CertificateRequestImpl copy() {
        return new CertificateRequestImpl(
                (Vector<Byte>) certificate_request_context.copy(),
                (Vector<Extension>) extensions.copy());
    }

    @Override
    public Vector<Byte> certificateRequestContext() {
        return certificate_request_context;
    }

    @Override
    public Vector<Extension> extensions() {
        return extensions;
    }

    @Override
    public HandshakeType type() {
        return HandshakeTypeImpl.certificate_request;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) {
            return true;
        }
        if (o == null || getClass() != o.getClass()) {
            return false;
        }
        CertificateRequestImpl that = (CertificateRequestImpl) o;
        return Objects.equals(certificate_request_context, that.certificate_request_context) &&
                Objects.equals(extensions, that.extensions);
    }

    @Override
    public int hashCode() {
        return Objects.hash(certificate_request_context, extensions);
    }
}
