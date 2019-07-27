package com.gypsyengineer.tlsbunny.tls13.struct;

import com.gypsyengineer.tlsbunny.tls.Struct;
import com.gypsyengineer.tlsbunny.tls.UInt16;
import com.gypsyengineer.tlsbunny.tls.Vector;

public interface HkdfLabel extends Struct {

    int context_length_bytes = 1;
    int label_length_bytes = 1;
    int max_context_length = 255;
    int max_label_length = 255;

    Vector<Byte> getContext();
    Vector<Byte> getLabel();
    UInt16 getLength();
}
