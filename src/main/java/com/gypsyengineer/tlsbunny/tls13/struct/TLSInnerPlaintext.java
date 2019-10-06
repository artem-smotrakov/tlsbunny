package com.gypsyengineer.tlsbunny.tls13.struct;

import com.gypsyengineer.tlsbunny.tls.Bytes;
import com.gypsyengineer.tlsbunny.tls.Struct;

public interface TLSInnerPlaintext extends Struct {

    boolean containsAlert();
    boolean containsApplicationData();
    boolean containsHandshake();
    byte[] getContent();
    ContentType getType();
    Bytes getZeros();
}
