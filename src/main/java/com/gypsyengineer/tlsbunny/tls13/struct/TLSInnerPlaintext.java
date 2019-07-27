package com.gypsyengineer.tlsbunny.tls13.struct;

import com.gypsyengineer.tlsbunny.tls.Bytes;
import com.gypsyengineer.tlsbunny.tls.Struct;
import com.gypsyengineer.tlsbunny.utils.Utils;

public interface TLSInnerPlaintext extends Struct {

    byte[] no_padding = Utils.empty_array;

    boolean containsAlert();
    boolean containsApplicationData();
    boolean containsHandshake();
    byte[] getContent();
    ContentType getType();
    Bytes getZeros();
}
