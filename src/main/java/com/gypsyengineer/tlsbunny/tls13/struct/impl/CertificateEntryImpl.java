package com.gypsyengineer.tlsbunny.tls13.struct.impl;

import com.gypsyengineer.tlsbunny.tls.Struct;
import com.gypsyengineer.tlsbunny.tls.Vector;
import com.gypsyengineer.tlsbunny.tls13.struct.CertificateEntry;
import com.gypsyengineer.tlsbunny.tls13.struct.Extension;
import com.gypsyengineer.tlsbunny.tls13.struct.ExtensionType;
import com.gypsyengineer.tlsbunny.utils.Utils;
import java.io.IOException;
import java.util.Objects;

import static com.gypsyengineer.tlsbunny.utils.Utils.cast;
import static com.gypsyengineer.tlsbunny.utils.WhatTheHell.whatTheHell;

public abstract class CertificateEntryImpl implements CertificateEntry {

    Vector<Extension> extensions;

    CertificateEntryImpl(Vector<Extension> extensions) {
        this.extensions = extensions;
    }

    @Override
    public Vector<Extension> extensions() {
        return extensions;
    }

    @Override
    public Extension extension(ExtensionType type) {
        for (Extension extension : extensions.toList()) {
            if (type.equals(extension.extensionType())) {
                return extension;
            }
        }

        return null;
    }

    @Override
    public boolean composite() {
        return true;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) {
            return true;
        }
        if (o == null || getClass() != o.getClass()) {
            return false;
        }
        CertificateEntryImpl that = (CertificateEntryImpl) o;
        return Objects.equals(extensions, that.extensions);
    }

    @Override
    public int hashCode() {
        return Objects.hash(extensions);
    }

    public static class X509Impl extends CertificateEntryImpl implements X509 {
    
        private Vector<Byte> cert_data;
        
        public X509Impl(Vector<Byte> cert_data, Vector<Extension> extensions) {
            super(extensions);
            this.cert_data = cert_data;
        }

        @Override
        public Vector<Byte> certData() {
            return cert_data;
        }

        @Override
        public int encodingLength() {
            return Utils.getEncodingLength(cert_data, extensions);
        }

        @Override
        public byte[] encoding() throws IOException {
            return Utils.encoding(cert_data, extensions);
        }

        @Override
        public X509Impl copy() {
            return new X509Impl(
                    (Vector<Byte>) cert_data.copy(),
                    (Vector<Extension>) extensions.copy());
        }

        @Override
        public int total() {
            return 2;
        }

        @Override
        public Struct element(int index) {
            switch (index) {
                case 0:
                    return cert_data;
                case 1:
                    return extensions;
                default:
                    throw whatTheHell("incorrect index %d!", index);
            }
        }

        @Override
        public void element(int index, Struct element) {
            if (element == null) {
                throw whatTheHell("element can't be null!");
            }
            switch (index) {
                case 0:
                    cert_data = cast(element, Vector.class);
                    break;
                case 1:
                    extensions = cast(element, Vector.class);
                    break;
                default:
                    throw whatTheHell("incorrect index %d!", index);
            }
        }

        @Override
        public boolean equals(Object o) {
            if (this == o) {
                return true;
            }
            if (o == null || getClass() != o.getClass()) {
                return false;
            }
            if (!super.equals(o)) {
                return false;
            }
            X509Impl x509 = (X509Impl) o;
            return Objects.equals(cert_data, x509.cert_data);
        }

        @Override
        public int hashCode() {
            return Objects.hash(super.hashCode(), cert_data);
        }
    }

    public static class RawPublicKeyImpl extends CertificateEntryImpl 
            implements RawPublicKey {
    
        private Vector<Byte> ASN1_subjectPublicKeyInfo;
        
        RawPublicKeyImpl(Vector<Byte> ASN1_subjectPublicKeyInfo,
                Vector<Extension> extensions) {
            
            super(extensions);
            this.ASN1_subjectPublicKeyInfo = ASN1_subjectPublicKeyInfo;
        }

        @Override
        public RawPublicKeyImpl copy() {
            return new RawPublicKeyImpl(
                    (Vector<Byte>) ASN1_subjectPublicKeyInfo.copy(),
                    (Vector<Extension>) extensions.copy());
        }

        @Override
        public Vector<Byte> asn1SubjectPublicKeyInfo() {
            return ASN1_subjectPublicKeyInfo;
        }

        @Override
        public int encodingLength() {
            return Utils.getEncodingLength(ASN1_subjectPublicKeyInfo, extensions);
        }

        @Override
        public byte[] encoding() throws IOException {
            return Utils.encoding(ASN1_subjectPublicKeyInfo, extensions);
        }

        @Override
        public int total() {
            return 2;
        }

        @Override
        public Struct element(int index) {
            switch (index) {
                case 0:
                    return ASN1_subjectPublicKeyInfo;
                case 1:
                    return extensions;
                default:
                    throw whatTheHell("incorrect index %d!", index);
            }
        }

        @Override
        public void element(int index, Struct element) {
            if (element == null) {
                throw whatTheHell("element can't be null!");
            }
            switch (index) {
                case 0:
                    ASN1_subjectPublicKeyInfo = cast(element, Vector.class);
                    break;
                case 1:
                    extensions = cast(element, Vector.class);
                    break;
                default:
                    throw whatTheHell("incorrect index %d!", index);
            }
        }

        @Override
        public boolean equals(Object o) {
            if (this == o) {
                return true;
            }
            if (o == null || getClass() != o.getClass()) {
                return false;
            }
            if (!super.equals(o)) {
                return false;
            }
            RawPublicKeyImpl that = (RawPublicKeyImpl) o;
            return Objects.equals(ASN1_subjectPublicKeyInfo, that.ASN1_subjectPublicKeyInfo);
        }

        @Override
        public int hashCode() {
            return Objects.hash(super.hashCode(), ASN1_subjectPublicKeyInfo);
        }
    }

}
