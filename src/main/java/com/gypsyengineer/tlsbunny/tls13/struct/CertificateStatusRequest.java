package com.gypsyengineer.tlsbunny.tls13.struct;

import com.gypsyengineer.tlsbunny.tls.Struct;

public interface CertificateStatusRequest extends Struct {

    CertificateStatusType getCertificateStatusType();
    OCSPStatusRequest getRequest();
}
