package com.gypsyengineer.tlsbunny.tls13.struct;

import com.gypsyengineer.tlsbunny.tls.Struct;
import com.gypsyengineer.tlsbunny.tls.Vector;

public interface PskBinderEntry extends Struct {

    int length_bytes = 1;

    Vector<Byte> content();
}
