package com.gypsyengineer.tlsbunny.tls13.struct;

import com.gypsyengineer.tlsbunny.tls.Struct;

public interface PskKeyExchangeMode extends Struct {

    int encoding_length = 1;
    int min = 0;
    int max = 255;

    PskKeyExchangeMode psk_ke = StructFactory.getDefault().createPskKeyExchangeMode(0);
    PskKeyExchangeMode psk_dhe_ke = StructFactory.getDefault().createPskKeyExchangeMode(1);

    int getCode();
}
