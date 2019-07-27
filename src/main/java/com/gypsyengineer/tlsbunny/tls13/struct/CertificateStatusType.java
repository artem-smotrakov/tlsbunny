package com.gypsyengineer.tlsbunny.tls13.struct;

import com.gypsyengineer.tlsbunny.tls.Struct;

public interface CertificateStatusType extends Struct {

    int encoding_length = 1;

    CertificateStatusType ocsp = StructFactory.getDefault().createCertificateStatusType(1);

    int getCode();
}
