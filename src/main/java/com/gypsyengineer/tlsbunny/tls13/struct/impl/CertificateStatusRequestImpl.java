package com.gypsyengineer.tlsbunny.tls13.struct.impl;

import com.gypsyengineer.tlsbunny.tls13.struct.CertificateStatusRequest;
import com.gypsyengineer.tlsbunny.tls13.struct.CertificateStatusType;
import com.gypsyengineer.tlsbunny.tls13.struct.OCSPStatusRequest;
import com.gypsyengineer.tlsbunny.utils.Utils;

import java.io.IOException;
import java.util.Objects;

public class CertificateStatusRequestImpl implements CertificateStatusRequest {

    private CertificateStatusType status_type;
    private OCSPStatusRequest request;

    CertificateStatusRequestImpl(CertificateStatusType status_type,
                                 OCSPStatusRequest request) {

        this.status_type = status_type;
        this.request = request;
    }

    @Override
    public CertificateStatusType getCertificateStatusType() {
        return status_type;
    }

    @Override
    public OCSPStatusRequest getRequest() {
        return request;
    }

    @Override
    public int encodingLength() {
        return Utils.getEncodingLength(status_type, request);
    }

    @Override
    public byte[] encoding() throws IOException {
        return Utils.encoding(status_type, request);
    }

    @Override
    public CertificateStatusRequestImpl copy() {
        return new CertificateStatusRequestImpl(
                (CertificateStatusType) status_type.copy(),
                (OCSPStatusRequest) request.copy());
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) {
            return true;
        }
        if (o == null || getClass() != o.getClass()) {
            return false;
        }
        CertificateStatusRequestImpl that = (CertificateStatusRequestImpl) o;
        return Objects.equals(status_type, that.status_type) &&
                Objects.equals(request, that.request);
    }

    @Override
    public int hashCode() {
        return Objects.hash(status_type, request);
    }
}
