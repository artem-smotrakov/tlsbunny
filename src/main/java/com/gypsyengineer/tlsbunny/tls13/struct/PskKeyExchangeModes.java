package com.gypsyengineer.tlsbunny.tls13.struct;

import com.gypsyengineer.tlsbunny.tls.Struct;
import com.gypsyengineer.tlsbunny.tls.Vector;

public interface PskKeyExchangeModes extends Struct {

    int ke_modes_length_bytes = 1;

    Vector<PskKeyExchangeMode> keModes();
}
